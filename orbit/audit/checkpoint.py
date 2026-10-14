"""
orbit/audit/checkpoint.py — AN EXTERNAL, MONOTONIC COMMITTED-HEAD ANCHOR.

ORBIT A1 SAFETY CLOSURE ROUND 3, finding R3-6.

THE LIMITATION, STATED PLAINLY FIRST.

A forward hash chain proves that the records it STILL HOLDS have not been
altered. It cannot prove how many there were. Every record's hash depends on its
predecessors and on nothing that comes after it, so deleting a suffix leaves a
perfectly valid, perfectly self-consistent, shorter chain. There is no clever
arrangement of the same data that fixes this: the missing evidence is missing.

Observed on the 507/507 archive, both with fully committed and fsynced records:

    half of the final COMMITTED record removed -> trusted=True discarded_tail=1
                                                  (mistaken for a crash-torn
                                                   write, which it was not)
    the whole final COMMITTED record removed   -> trusted=True discarded_tail=0
                                                  (no evidence of anything)

The round-1 F7 test asserted that a REWRITTEN MIDDLE record is detected. That is
a different failure, and passing it said nothing about this one.

WHAT WAS DECIDED.

Truncation resistance IS part of ORBIT's audit guarantee, because the whole
point of the journal is to answer "did we place that order?" after something has
gone wrong. So the last-known-committed head is written OUTSIDE the file whose
truncation we are trying to detect:

    <journal>.head   {"seq": N, "hash": "...", "ts": "..."}

written after each record commits, monotonic (it refuses to move backwards),
updated atomically (temp file, fsync, rename, directory fsync).

THE PROTOCOL, and its one legitimate divergence.

    1. append the record, fsync          <- the record is now COMMITTED
    2. write the checkpoint, fsync

A crash between 1 and 2 leaves the journal exactly ONE committed record ahead of
the checkpoint. That is the defined crash window and it recovers: the checkpoint
rolls forward. Anything else is not a crash:

    checkpoint AHEAD of the journal     records that were committed are GONE
                                        -> fail closed
    journal 2+ ahead of the checkpoint  the checkpoint missed more than one
                                        commit, which this protocol cannot
                                        produce -> fail closed

WHAT THIS IS STILL NOT.

It is not a defence against an attacker with write access to both files: such an
attacker rewrites the journal and the checkpoint together. Raising that bar
needs an anchor ORBIT cannot itself rewrite — an append-only remote log, a
signed or TPM-backed head — and that is a deployment decision, not a code
change. The claim made here is therefore narrowed and exact:

    TAMPER-EVIDENT against rewriting of retained records (hash chain), and
    against loss of committed records (this checkpoint), for any actor that
    does not have write access to BOTH the journal and its checkpoint.

A journal with NO checkpoint beside it gets the old, weaker guarantee — the
chain alone — because there is no external evidence to compare against. That is
stated rather than hidden: `HeadCheckpoint.exists` is how a caller can tell
which guarantee it actually has.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple

from orbit.audit.locks import RANK_CHECKPOINT, RankedFileLock

A2R_NOTE = """
SAFETY CLOSURE ROUND 4C4, CHECKPOINT A.2-R, items A2R-1 and A2R-3.

THE DEFECT REPAIRED HERE (checkpoint A.1 review finding 4: reproduced there,
deliberately not fixed there).

`verify_against_head` performed a WRITE on a READ path. When it observed the
legitimate one-record crash window it rolled the checkpoint forward by calling
`HeadCheckpoint.commit()` — from `Journal.load()`, which holds no lock. And
`commit()` was read-then-replace with a gap between the two:

    unlocked reader: read head = N
    locked writers:  commit N+1, commit N+2      (checkpoint now N+2)
    unlocked reader: replace  ->  checkpoint REGRESSES to N

Every later load then saw a lag of 2 and refused the journal. The stress tool
observed 8,968 checkpoint writes performed without the append lock, and 43 of
200 iterations failing. A second face of the same defect: when the interleaving
landed on the other read, `commit` saw a head ahead of itself and raised
`CheckpointRegressed` OUT OF `Journal.load` — a read path that raises, reachable
from `Journal.__init__` and from `ToolSession._pin_journal` inside an action.

THE REPAIR, in three parts.

  1. READS DO NOT WRITE. `classify_head` is pure: it reports the one-record
     window as a fact (`window=True`) and repairs nothing. `verify_against_head`
     is an equally pure wrapper kept for callers that want only (ok, reason).

  2. THE ROLL-FORWARD MOVED TO THE APPEND PATH. `Journal._prepare_locked` —
     which by construction runs inside `AppendLock` — performs it. Readers
     report the window; writers close it.

  3. ADVANCEMENT IS ATOMIC AND MONOTONIC. `commit_monotonic` does its
     read-compare-replace inside `CheckpointLock`, so nothing can interleave
     between the decision and the write. Re-committing the same (seq, hash) is
     an idempotent no-op that writes nothing at all.

WHAT IS DELIBERATELY UNCHANGED. A checkpoint AHEAD of the journal still fails
closed, and a lag of two or more still fails closed: a genuine loss of committed
records must remain distinguishable from the crash window, which is the whole
point of R3-6. `_write_unchecked` stays lock-free and unchecked so tests can
still place a checkpoint deliberately.
"""

THREAT_MODEL = """
A hash chain CANNOT detect deletion of its own suffix: the remaining prefix is
valid on its own. The external monotonic committed-head checkpoint beside the
journal supplies the missing evidence, and the protocol tolerates exactly one
crash window (record committed, checkpoint not yet written). It does not defend
against an actor with write access to BOTH files; that requires an anchor ORBIT
cannot rewrite, which is a deployment decision.
"""


class CheckpointRegressed(RuntimeError):
    """A committed head may only move forward."""


@dataclass(frozen=True)
class Head:
    seq: int
    hash: str
    ts: str = ""

    @property
    def exists(self) -> bool:
        return self.seq > 0


EMPTY = Head(0, "", "")


class CheckpointLock(RankedFileLock):
    """Cross-process mutual exclusion for checkpoint advancement (A2R-1/A2R-2).

    A LEAF lock: it is taken last, nothing is acquired while it is held, and the
    only work inside it is the read-compare-replace of the head file. It is
    ranked below `AppendLock`, so the append path's `AppendLock -> CheckpointLock`
    is legal and the reverse raises instead of deadlocking.

    It locks `<journal>.head.lock` — a file of its own, NOT the head file it
    guards, because the head is replaced by `os.replace` and a lock held on the
    replaced inode would protect nothing after the first write.
    """

    def __init__(self, journal_path: str):
        super().__init__(journal_path + ".head.lock", RANK_CHECKPOINT)


@dataclass(frozen=True)
class HeadVerdict:
    """The result of comparing retained records with the external head. PURE."""
    ok: bool
    reason: str = ""
    window: bool = False              # the legitimate one-record crash window
    roll_to_seq: int = 0              # what a WRITER should advance the head to
    roll_to_hash: str = ""

    def as_tuple(self) -> Tuple[bool, str]:
        return self.ok, self.reason


class HeadCheckpoint:
    """The last committed head, stored beside the journal and never behind it
    by more than the one crash window."""

    def __init__(self, journal_path: str):
        self.journal_path = journal_path
        self.path = journal_path + ".head"

    @property
    def exists(self) -> bool:
        return os.path.exists(self.path)

    def read(self) -> Head:
        if not os.path.exists(self.path):
            return EMPTY
        try:
            with open(self.path, "r") as fh:
                d = json.load(fh)
            return Head(int(d["seq"]), str(d["hash"]), str(d.get("ts", "")))
        except Exception:                                    # noqa: BLE001
            # An unreadable checkpoint is not "no checkpoint". Treat it as a
            # head we cannot verify, which the loader must fail closed on.
            return Head(-1, "", "")

    def commit(self, seq: int, rec_hash: str) -> Head:
        """Advance the committed head. Monotonic, atomic, idempotent.

        A.2-R: this was read-then-replace with a gap between the check and the
        write, and callers reached it from unlocked read paths. It now delegates
        to `commit_monotonic`, so EVERY caller — including any that predates
        this repair — gets the locked, atomic path. The name is kept because it
        is the protocol's verb; the behaviour behind it is what changed.
        """
        return self.commit_monotonic(seq, rec_hash)

    def commit_monotonic(self, seq: int, rec_hash: str) -> Head:
        """Read, compare and replace INSIDE `CheckpointLock` (A2R-1).

        The three outcomes, all decided under the lock:

          seq  <  current   -> `CheckpointRegressed`. The head never moves back.
          seq == current    -> idempotent. Same hash: no write at all, the
                               existing head is returned. Different hash at the
                               same seq means two different records claim one
                               sequence number, which is corruption, not a
                               retry -> `CheckpointRegressed`.
          seq  >  current   -> replace atomically.

        Holding the lock across the read AND the replace is the repair: it is
        what makes "it is not ahead of me" still true at the moment of writing.
        """
        with CheckpointLock(self.journal_path):
            cur = self.read()
            if cur.seq > seq:
                raise CheckpointRegressed(
                    f"the committed head is at {cur.seq}; it cannot be moved "
                    f"back to {seq}")
            if cur.seq == seq and cur.exists:
                if cur.hash == rec_hash:
                    return cur                    # idempotent: nothing written
                raise CheckpointRegressed(
                    f"the committed head at seq {seq} names a different record "
                    f"({cur.hash[:16]}... vs {rec_hash[:16]}...); two records "
                    f"cannot hold one sequence number")
            return self._write_unchecked(seq, rec_hash)

    def _write_unchecked(self, seq: int, rec_hash: str) -> Head:
        """Atomic replace. Used by `commit`, and by tests that need to place the
        checkpoint deliberately."""
        head = Head(seq, rec_hash, datetime.now(timezone.utc).isoformat())
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".head.part")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump({"seq": head.seq, "hash": head.hash, "ts": head.ts}, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        try:
            dfd = os.open(d, os.O_RDONLY)
            os.fsync(dfd)
            os.close(dfd)
        except OSError:
            pass
        return head


def classify_head(path: str, records, discarded_tail: int) -> HeadVerdict:
    """Compare the retained records with the external head. PURE — never writes.

    A.2-R, item A2R-1/A2R-3. This is the function that used to roll the
    checkpoint forward from inside `Journal.load()`, with no lock held. It now
    only CLASSIFIES. When it finds the legitimate one-record crash window it
    says so (`window=True`) and names what a writer should advance the head to;
    closing the window is the append path's job, under `AppendLock`.

    Returns ok=True when there is no checkpoint at all — the weaker, chain-only
    guarantee — so that a journal written before this existed, or one built by
    hand, still loads. `HeadCheckpoint.exists` tells a caller which guarantee is
    in force.
    """
    cp = HeadCheckpoint(path)
    head = cp.read()
    if head.seq == 0 and not cp.exists:
        return HeadVerdict(True, "")
    if head.seq < 0:
        return HeadVerdict(False, "the committed-head checkpoint is unreadable; "
                                  "the journal cannot be shown to be complete")

    last_seq = records[-1]["seq"] if records else 0
    last_hash = records[-1]["hash"] if records else ""

    if head.seq > last_seq:
        return HeadVerdict(False, (
            f"the committed-head checkpoint records seq {head.seq} but the "
            f"journal ends at seq {last_seq}: {head.seq - last_seq} COMMITTED "
            f"record(s) are missing. A hash chain cannot detect the loss of its "
            f"own suffix; this is the external evidence that can."))
    if head.seq == last_seq:
        if head.hash and last_hash and head.hash != last_hash:
            return HeadVerdict(False, (
                f"the committed-head checkpoint names a different record at seq "
                f"{head.seq}; the journal's head has been replaced"))
        return HeadVerdict(True, "")
    behind = last_seq - head.seq
    if behind == 1:
        # The defined crash window: the record committed, the checkpoint had not
        # been written yet.
        #
        # A.2-R. This is where the roll-forward used to happen — a write, from a
        # read path, with no lock held. It is now REPORTED and not repaired:
        # the journal is trusted (the window is legitimate and the record is
        # committed), and `Journal._prepare_locked` closes the window under
        # `AppendLock` the next time anything appends. A reader that never
        # writes cannot regress the head.
        #
        # F4 (independent review, MINOR). This branch used to check only the
        # SEQUENCE relationship. It never compared the head's stored hash with
        # the retained record at that sequence, so a checkpoint naming the WRONG
        # record at seq N-1 was accepted as the legitimate crash window and the
        # journal loaded trusted. The equal-head branch above has always
        # compared hashes and failed closed on a mismatch; this one now does the
        # same, because a window is only a crash window if the head it names is
        # the head that was actually committed.
        prior = None
        for r in records:
            if r["seq"] == head.seq:
                prior = r
                break
        if prior is None:
            if head.seq > 0:
                return HeadVerdict(False, (
                    f"the committed-head checkpoint names seq {head.seq}, which "
                    f"is not among the retained records; the journal cannot be "
                    f"shown to be complete"))
            # seq 0 is the genesis head: there is no record to name, so there is
            # nothing to compare. Unchanged from before F4.
        elif head.hash and prior["hash"] and head.hash != prior["hash"]:
            return HeadVerdict(False, (
                f"the committed-head checkpoint names a different record at seq "
                f"{head.seq}: it stores hash {head.hash[:16]}... but the "
                f"retained record hashes {prior['hash'][:16]}.... This is not "
                f"the one-record crash window; the checkpoint or the journal "
                f"has been replaced."))
        return HeadVerdict(True, "", window=True,
                           roll_to_seq=last_seq, roll_to_hash=last_hash)
    return HeadVerdict(False, (
        f"the committed-head checkpoint is {behind} records behind the journal. "
        f"The protocol writes the checkpoint immediately after each commit, so "
        f"it can lag by at most one; a larger gap means the checkpoint or the "
        f"journal has been replaced."))


def verify_against_head(path: str, records, discarded_tail: int):
    """(ok, reason) — the pre-A.2-R signature, now PURE.

    Kept for callers that want only the verdict. It no longer writes anything;
    use `classify_head` when the one-record window matters.
    """
    return classify_head(path, records, discarded_tail).as_tuple()
