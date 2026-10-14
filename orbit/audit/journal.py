"""
orbit/audit/journal.py — THE DURABLE WRITE-AHEAD JOURNAL.

ORBIT-AGENT-ARCH-001, build step 5b.

Step 4's reconciler assumes a durable local record of intent exists. This is
that record. It is the only thing standing between a process crash and ORBIT
believing something false about its own positions.

GUARANTEES

  W1 WRITE-AHEAD. An INTENT record is durably committed (write + flush + fsync)
     BEFORE the exchange is touched. After any crash we always know an order
     MIGHT exist for that deterministic client order id, and can ask.

  W2 ATOMIC GROUPS. Events that must not be seen half-applied are written as
     ONE physical record. A crash loses the whole group or none of it.

  W3 TAMPER-EVIDENT, WITH ITS LIMIT STATED. Records are hash-chained, so
     rewriting a retained record breaks every subsequent hash and the loader
     refuses to trust it. A forward hash chain CANNOT detect deletion of its own
     suffix — the remaining prefix is valid on its own — so an external
     monotonic committed-head checkpoint supplies that evidence
     (orbit/audit/checkpoint.py, SAFETY CLOSURE ROUND 3, finding R3-6). The
     claim is exact: tamper-evident against rewriting of retained records and
     against loss of committed ones, for any actor without write access to BOTH
     the journal and its checkpoint.

  W4 TORN TAIL IS NOT CORRUPTION. A partial final line is the normal signature
     of a crash mid-write. It is discarded as UNCOMMITTED, and the prefix
     remains trusted. A broken hash with valid records AFTER it is different:
     that is rewriting, and the journal is untrusted.

  W5 SEQUENCE CONTIGUITY IS ENFORCED, NOT ASSUMED. The first record is seq 1
     and every record after it is exactly one more than its predecessor. A hash
     chain proves each record follows THE record before it; it does not prove
     the record before it was the one whose sequence number it claims, because
     `seq` is hashed as ordinary body content and a forged chain can carry any
     numbering it likes. The loader therefore checks the numbering itself:
     a wrong start, a gap, a duplicate, a decreasing step or a non-integer seq
     is REWRITING, and the journal is untrusted. (R4C4-JSEQ-1; recorded as
     NOTE-3 by the F4 review, pre-existing and broader than F4.)

  W6 IDEMPOTENT. A repeated action_id or fill_id is recorded as a duplicate and
     does not change state. SAFETY CLOSURE ROUND 2, finding N1: the uniqueness
     DECISION and the durable APPEND are one cross-process critical section,
     taken against FRESH durable state. Previously `has_action()` read an
     in-memory set before the lock was acquired and `append()` took the lock
     afterwards — two critical sections, so eight processes each held their own
     empty cache, each saw "not present", and each committed. The lock had
     always protected sequence numbers and the hash chain. It had never
     protected uniqueness, and the journal reported itself trusted because it
     WAS internally consistent; it was simply wrong.

RUNTIME CONTRACT. The append lock is fcntl.flock: POSIX only, local filesystems
only. It is asserted at import (see orbit/runtime.py, finding N5) rather than
left to surface as an ImportError inside someone's traceback.

The journal is append-only. There is no update and no delete. Reconstructed
state is APPENDED as a RECONSTRUCTION event with its evidence; it never
overwrites what came before.
"""

from __future__ import annotations

import errno
import json
import os

from orbit.runtime import require_supported_platform

# Stated where the dependency lives, not in a comment somewhere else.
require_supported_platform()
import fcntl                                              # noqa: E402
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from orbit.audit.checkpoint import HeadCheckpoint, classify_head
from orbit.audit.locks import RANK_APPEND, RankedFileLock
from orbit.audit.records import (E, GENESIS, canonical, event, make_record,
                                 verify_record)


# Only these events CLAIM an action id for idempotency purposes. An
# informational record that merely references a decision must never make the
# write-ahead intent for that decision look like a duplicate.
ACTION_CLAIMING = {E.INTENT.value, E.PROTECTIVE_INTENT.value}

# R4C4-JSEQ-1. The authoritative initial sequence number. `Journal` starts with
# `_seq = 0` and every write is `_seq + 1`, so the first record ORBIT has ever
# been able to produce is seq 1 — including the one `_repair_tail` writes after
# a torn tail. It is named here because the loader now REFUSES a journal that
# starts anywhere else, and a magic 1 buried in a comparison is not a stated
# invariant.
INITIAL_SEQ = 1


class TamperedJournalError(RuntimeError):
    """The chain is broken in the middle. Fail closed: never append onto
    evidence that may have been rewritten."""


class SimulatedCrash(RuntimeError):
    """Raised by an injected fault. Never raised in production paths."""


class CrashPoint(str):
    BEFORE_WRITE = "BEFORE_WRITE"          # nothing reaches the file
    TORN = "TORN"                          # a partial line reaches the file
    AFTER_WRITE_BEFORE_FSYNC = "AFTER_WRITE_BEFORE_FSYNC"   # lost on power loss
    AFTER_FSYNC = "AFTER_FSYNC"            # committed, then we die


@dataclass
class Fault:
    """Deterministic crash injection. Test-only; None in production."""
    at_event: Optional[str] = None         # crash on the first record containing this event
    at_seq: Optional[int] = None
    point: str = CrashPoint.BEFORE_WRITE
    armed: bool = True

    def triggers(self, seq: int, events: List[Dict[str, Any]]) -> bool:
        if not self.armed:
            return False
        if self.at_seq is not None and seq == self.at_seq:
            return True
        if self.at_event is not None and any(x["e"] == self.at_event for x in events):
            return True
        return False


class AppendLock:
    """Cross-process mutual exclusion for the append path (BLOCKER G).

    Two Journal objects cached their own `seq`/`prev_hash`. A second writer
    created before the first committed would append using a stale head, producing
    a duplicate sequence number and a broken chain — and the file was then
    permanently untrusted. An in-memory head cannot be authoritative for a file
    that other processes can write.

    `flock` is held for the whole read-head / write / fsync critical section, so
    the head is re-read from disk under the lock every time. This does NOT
    depend on writer authority: the journal must stay consistent even for the
    records that describe authority itself, so making journal integrity depend
    on the lease would be circular.

    A.2-R, item A2R-2. This is now a RANKED lock. It is rank `RANK_APPEND`, and
    the checkpoint's lock is the leaf below it, so the append path's legal
    order — take the append lock, then commit the checkpoint under it — is the
    only order the rank guard permits. Taking them the other way round raises
    `LockOrderViolation` instead of deadlocking on a `flock` that has no
    timeout. The class is kept (rather than replaced by `RankedFileLock` at the
    call sites) because it is the named concept BLOCKER G was closed with, and
    because the stress tooling instruments `__enter__`/`__exit__` on it.
    """

    def __init__(self, path: str):
        self.path = path + ".lock"
        self._lock = RankedFileLock(self.path, RANK_APPEND)

    def __enter__(self):
        self._lock.__enter__()
        return self

    def __exit__(self, *exc):
        return self._lock.__exit__(*exc)


@dataclass
class LoadResult:
    records: List[Dict[str, Any]]
    chain_ok: bool
    discarded_tail: int                    # uncommitted trailing bytes/lines
    tamper_detected: bool
    reason: str = ""
    good_bytes: int = 0                    # offset of the end of the last
                                           # fully committed record
    # A.2-R, item A2R-3. The legitimate one-record crash window, reported as a
    # FACT by a read that does not repair it. `_prepare_locked` closes it under
    # `AppendLock`; readers (including `ToolSession._pin_journal`) simply see it.
    head_window: bool = False
    head_roll_to_seq: int = 0
    head_roll_to_hash: str = ""

    @property
    def trusted(self) -> bool:
        return self.chain_ok and not self.tamper_detected


class Journal:
    def __init__(self, path: str, fault: Optional[Fault] = None,
                 clock: Optional[Callable[[], datetime]] = None):
        self.path = path
        self.fault = fault
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._seq = 0
        self._prev = GENESIS
        self._action_ids = set()
        self._fill_ids = set()
        if os.path.exists(path):
            lr = self.load(path)
            if lr.records:
                self._seq = lr.records[-1]["seq"]
                self._prev = lr.records[-1]["hash"]
            for r in lr.records:
                for ev in r["events"]:
                    if ev["e"] in ACTION_CLAIMING and ev.get("action_id"):
                        self._action_ids.add(ev["action_id"])
                    if ev["e"] == E.FILL.value and ev.get("fill_id"):
                        self._fill_ids.add(ev["fill_id"])

    # ------------------------------------------------------------------
    def append(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Write ONE physical record atomically: write, flush, fsync.

        The whole list commits together or not at all. The head is re-read from
        disk INSIDE the cross-process lock, so a cached in-memory head can never
        cause a duplicate sequence number (BLOCKER G)."""
        with AppendLock(self.path):
            self._prepare_locked()
            return self._write_locked(events)

    def _append_locked(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        self._prepare_locked()
        return self._write_locked(events)

    def _prepare_locked(self) -> LoadResult:
        """Read FRESH durable state under the lock. Every decision that follows
        — uniqueness included — is made against what this returns, never
        against an in-memory cache."""
        head = self.load(self.path)
        if head.tamper_detected:
            raise TamperedJournalError(
                f"refusing to append to a journal whose chain is broken: "
                f"{head.reason}")
        if head.discarded_tail:
            self._repair_tail(head)
            head = self.load(self.path)
        # A.2-R, item A2R-1. CLOSE THE CRASH WINDOW HERE, under `AppendLock`.
        #
        # The roll-forward used to happen inside `Journal.load()` — on a read
        # path, unlocked — and a concurrent locked writer could advance the head
        # between that read and its replace, so the unlocked write landed as a
        # REGRESSION. Readers now only report the window; this is the one place
        # that closes it, and it is reached only from inside the append lock, so
        # no writer can interleave. `commit_monotonic` re-checks under the
        # checkpoint lock as well: the window may already have been closed by
        # whoever held the append lock before us, and re-committing the same
        # (seq, hash) is an idempotent no-op.
        if head.head_window and head.head_roll_to_seq:
            HeadCheckpoint(self.path).commit_monotonic(
                head.head_roll_to_seq, head.head_roll_to_hash)
        self._seq = head.records[-1]["seq"] if head.records else 0
        self._prev = head.records[-1]["hash"] if head.records else GENESIS
        self._action_ids = {
            ev["action_id"] for r in head.records for ev in r["events"]
            if ev["e"] in ACTION_CLAIMING and ev.get("action_id")}
        self._fill_ids = {
            ev["fill_id"] for r in head.records for ev in r["events"]
            if ev["e"] == E.FILL.value and ev.get("fill_id")}
        return head

    def _write_locked(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        seq = self._seq + 1
        rec = make_record(seq, self._clock().isoformat(), events, self._prev)
        line = canonical(rec) + "\n"

        if self.fault and self.fault.triggers(seq, events):
            p = self.fault.point
            if p == CrashPoint.BEFORE_WRITE:
                raise SimulatedCrash(f"crash before writing seq {seq}")
            if p == CrashPoint.TORN:
                with open(self.path, "a") as fh:
                    fh.write(line[: max(8, len(line) // 2)])   # no newline
                    fh.flush()
                    os.fsync(fh.fileno())
                raise SimulatedCrash(f"crash mid-write at seq {seq}")
            if p == CrashPoint.AFTER_WRITE_BEFORE_FSYNC:
                # Written to the OS but never synced: a power loss discards it.
                # Modelled by not writing at all, which is the observable result.
                raise SimulatedCrash(f"crash before fsync at seq {seq}")
            # AFTER_FSYNC falls through: commit first, then die.

        with open(self.path, "a") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

        # The record is COMMITTED. Anchor it externally before anything else,
        # so the window in which the journal is ahead of its checkpoint is as
        # small as an fsync (SAFETY CLOSURE ROUND 3, R3-6).
        HeadCheckpoint(self.path).commit(seq, rec["hash"])

        self._seq = seq
        self._prev = rec["hash"]
        for ev in events:
            if ev["e"] in ACTION_CLAIMING and ev.get("action_id"):
                self._action_ids.add(ev["action_id"])
            if ev["e"] == E.FILL.value and ev.get("fill_id"):
                self._fill_ids.add(ev["fill_id"])

        if self.fault and self.fault.triggers(seq, events) \
                and self.fault.point == CrashPoint.AFTER_FSYNC:
            raise SimulatedCrash(f"crash after committing seq {seq}")
        return rec

    def append_one(self, kind: E, action_id: Optional[str] = None, **payload):
        return self.append([event(kind, action_id, **payload)])

    # ------------------------------------------------------------------
    # IDEMPOTENCY — ONE CRITICAL SECTION, FRESH DURABLE STATE (N1)
    # ------------------------------------------------------------------
    @staticmethod
    def _head_has_action(head: LoadResult, action_id: str) -> bool:
        return any(ev["e"] in ACTION_CLAIMING and ev.get("action_id") == action_id
                   for r in head.records for ev in r["events"])

    @staticmethod
    def _head_has_fill(head: LoadResult, fill_id: str) -> bool:
        return any(ev["e"] == E.FILL.value and ev.get("fill_id") == fill_id
                   for r in head.records for ev in r["events"])

    def has_action(self, action_id: str) -> bool:
        """Durable, not cached. The cheap in-memory answer is exactly what
        finding N1 was: it is right about this process and silent about every
        other one."""
        with AppendLock(self.path):
            return self._head_has_action(self.load(self.path), action_id)

    def has_fill(self, fill_id: str) -> bool:
        with AppendLock(self.path):
            return self._head_has_fill(self.load(self.path), fill_id)

    def append_unique(self, events: List[Dict[str, Any]], *,
                      action_id: Optional[str] = None,
                      fill_id: Optional[str] = None,
                      note: str = "duplicate suppressed (idempotency)"
                      ) -> Optional[Dict]:
        """Append `events` as ONE record if and only if the claimed id is not
        already durably present.

            lock
              -> read trusted durable head
              -> is the id already claimed?
              -> if yes: record the suppression, return None
              -> if no:  append exactly once, fsync
            unlock

        The whole group is governed by the one claim, so a duplicated fill
        cannot land a POSITION_STATE or a COUNTERS record either.

        The lock is NOT reentrant across separate file descriptors, so every
        write inside here goes through `_write_locked`, never through the
        public `append`."""
        with AppendLock(self.path):
            head = self._prepare_locked()
            taken = ((action_id is not None
                      and self._head_has_action(head, action_id))
                     or (fill_id is not None
                         and self._head_has_fill(head, fill_id)))
            if taken:
                self._write_locked([event(E.REMEDIATION, action_id, note=note)])
                return None
            return self._write_locked(events)

    def record_intent(self, action_id: str, **payload) -> Optional[Dict]:
        """WRITE-AHEAD. Returns None if this action_id was already journalled —
        a replayed command must never create a second intent, and neither must a
        second PROCESS that has never seen the first one's write."""
        return self.append_unique(
            [event(E.INTENT, action_id, **payload)], action_id=action_id,
            note="duplicate INTENT suppressed (idempotency)")

    def record_fill(self, action_id: str, fill_id: str, **payload) -> Optional[Dict]:
        """Returns None for a replayed fill_id — the exchange may deliver the
        same fill twice and it must not be counted twice."""
        return self.append_unique(
            [event(E.FILL, action_id, fill_id=fill_id, **payload)],
            fill_id=fill_id,
            note=f"duplicate FILL {fill_id} suppressed (idempotency)")

    def _repair_tail(self, head: LoadResult) -> None:
        """BLOCKER F. A torn final record is the normal signature of a crash
        mid-write. Appending after it produced 'partial JSON + valid JSON' and
        the journal became permanently untrusted.

        Repair truncates to the end of the last FULLY COMMITTED record, fsyncs
        the file and its directory, and records the repair durably. It is
        idempotent, and it is only ever reached for a TORN TAIL: a broken hash
        or a damaged middle record is corruption and fails closed above."""
        with open(self.path, "r+b") as fh:
            fh.truncate(head.good_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        try:
            dfd = os.open(d, os.O_RDONLY)
            os.fsync(dfd)
            os.close(dfd)
        except OSError:
            pass
        self._seq = head.records[-1]["seq"] if head.records else 0
        self._prev = head.records[-1]["hash"] if head.records else GENESIS
        rec = make_record(self._seq + 1, self._clock().isoformat(),
                          [event(E.REMEDIATION, None,
                                 note="TORN_TAIL_REPAIRED",
                                 discarded_records=head.discarded_tail,
                                 truncated_to_byte=head.good_bytes)],
                          self._prev)
        with open(self.path, "a") as fh:
            fh.write(canonical(rec) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        HeadCheckpoint(self.path).commit(rec["seq"], rec["hash"])
        self._seq, self._prev = rec["seq"], rec["hash"]

    # ------------------------------------------------------------------
    @staticmethod
    def _seq_violation(rec: Dict[str, Any], expected: int) -> str:
        """R4C4-JSEQ-1. Why `rec` may not occupy this position, or "".

        PURE. The record has already proved its hash and its link to its
        predecessor by the time this is asked; what it has NOT proved is that
        it is the `expected`-th record. `seq` is hashed as ordinary body
        content, so a forged chain re-generated end to end carries whatever
        numbering its author chose and every hash still verifies. This is the
        one property the chain cannot supply and the loader must check.

        `expected` is the 1-based position in the file, so a single equality
        test covers every shape the finding names: a start other than
        `INITIAL_SEQ`, a gap, a duplicate and a decreasing step all put some
        record at a position its own number contradicts.

        The type is checked before the value. A record carrying `"seq": "3"`,
        `"seq": true` or no `seq` at all is hash-valid, and `records[-1]["seq"]`
        is then used as an INTEGER to number the next append — so a malformed
        seq is a refusal, not a coercion. `bool` is excluded explicitly because
        it is an `int` subclass and `True == 1`.
        """
        v = rec.get("seq")
        if isinstance(v, bool) or not isinstance(v, int):
            return (f"record {expected} of the journal carries seq {v!r}, "
                    f"which is not an integer sequence number")
        if v == expected:
            return ""
        if expected == INITIAL_SEQ:
            return (f"the journal begins at seq {v}, not at the authoritative "
                    f"initial sequence {INITIAL_SEQ}; records that were "
                    f"committed before it are unaccounted for")
        how = "repeats or goes backwards" if v <= expected - 1 else "skips"
        return (f"sequence is not contiguous: record {expected} of the journal "
                f"claims seq {v}, but the record before it claims "
                f"{expected - 1}, so the numbering {how} here")

    @staticmethod
    def load(path: str) -> LoadResult:
        if not os.path.exists(path):
            return LoadResult([], True, 0, False, "no journal file")
        records: List[Dict[str, Any]] = []
        prev = GENESIS
        discarded = 0
        tamper = False
        reason = ""
        good = 0
        with open(path, "r") as fh:
            raw = fh.read()
        lines = raw.split("\n")
        if lines and lines[-1] == "":
            lines.pop()                        # trailing newline is normal
        else:
            pass                               # final line has no newline: torn

        for i, line in enumerate(lines):
            last = (i == len(lines) - 1)
            try:
                rec = json.loads(line)
            except Exception:
                if last and not raw.endswith("\n"):
                    discarded += 1             # torn tail: expected after a crash
                    reason = "torn final record discarded as uncommitted"
                else:
                    tamper = True
                    reason = f"unparseable record at line {i} with data after it"
                break
            if not verify_record(rec) or rec["prev_hash"] != prev:
                if last and not raw.endswith("\n"):
                    discarded += 1
                    reason = "torn final record discarded as uncommitted"
                else:
                    tamper = True
                    reason = (f"hash chain broken at seq {rec.get('seq')}; "
                              f"history has been rewritten")
                break
            # R4C4-JSEQ-1. The hash chain has just proved this record follows
            # its predecessor unaltered. It has NOT proved the numbering, so
            # that is proved here, before the record is retained.
            #
            # A violation is ALWAYS tampering, never a torn tail — including on
            # the final line. A crash mid-write leaves a BYTE PREFIX of a
            # canonical record, which cannot parse and hash-verify while
            # carrying a different sequence number than the writer put in it;
            # the writer only ever emits `_seq + 1`. So there is no crash that
            # produces this, and it is not given the torn-tail benefit that the
            # parse and hash failures above are given.
            bad_seq = Journal._seq_violation(rec, len(records) + 1)
            if bad_seq:
                tamper = True
                reason = f"{bad_seq}; history has been rewritten"
                break

            records.append(rec)
            prev = rec["hash"]
            good += len(line.encode()) + 1        # the record and its newline

        if not tamper:
            # A.2-R, item A2R-3. PURE. This classifies and never writes; before
            # A.2-R it could roll the checkpoint forward from here, with no lock
            # held, which is the race finding 4 reproduced.
            v = classify_head(path, records, discarded)
            if not v.ok:
                # A truncated suffix is not a torn tail. Saying so is the whole
                # point: one is the ordinary signature of a crash, the other is
                # evidence that committed history is gone.
                return LoadResult(records, False, discarded, True, v.reason, good)
            return LoadResult(records, True, discarded, False, reason, good,
                              head_window=v.window,
                              head_roll_to_seq=v.roll_to_seq,
                              head_roll_to_hash=v.roll_to_hash)

        return LoadResult(records, not tamper, discarded, tamper, reason, good)
