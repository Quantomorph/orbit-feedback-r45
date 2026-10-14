"""
tests/test_safety_closure_r4c4_a2r.py — ORBIT A1 SAFETY CLOSURE, ROUND 4C4,
CHECKPOINT A.2-R (reconstructed successor).

A.2-R IS NOT HISTORICAL CHECKPOINT A.2. The original A.2 archive is not
recovered. These assertions were written against the defect as checkpoint A.1
reproduced it, not against any surviving A.2 bytes.

THE DEFECT (A.1 review finding 4: reproduced there, deliberately not fixed):

    `Journal.load()` holds no lock. On observing the legitimate one-record
    crash window it rolled the committed-head checkpoint FORWARD — a write, on
    a read path, unlocked. `HeadCheckpoint.commit()` was read-then-replace with
    a gap, so locked writers could advance the head between the reader's read
    and its replace, and the unlocked replace landed as a REGRESSION: checkpoint
    at N, journal at N+2, every later load refusing the journal. The stress tool
    saw 8,968 unlocked checkpoint writes and 43 of 200 iterations fail.

    Second face: on the other interleaving `commit` saw a head ahead of itself
    and raised `CheckpointRegressed` OUT OF a read path — reachable from
    `Journal.__init__` and from `ToolSession._pin_journal` inside an action.

WHAT IS ASSERTED HERE.

    C1  READS DO NOT WRITE. A load never changes the head file, ever.
    C2  THE WINDOW IS REPORTED, NOT REPAIRED, BY READERS.
    C3  THE APPEND PATH CLOSES THE WINDOW, under the append lock.
    C4  ADVANCEMENT IS MONOTONIC AND ATOMIC, and idempotent for a repeat.
    C5  LOCK RANK IS ENFORCED: append before checkpoint, checkpoint is a leaf,
        reverse and re-entrant acquisition raise instead of deadlocking.
    C6  LOCKS ARE RELEASED ON EXCEPTION.
    C7  GENUINE LOSS STILL FAILS CLOSED — the repair must not have bought
        availability by weakening R3-6.
    C8  THE ORIGINAL RACE, run deterministically, NO LONGER REGRESSES THE HEAD
        (the A.1 reproducer, promoted with its polarity corrected), and the
        reader/writer processes exit cleanly.
    C9  THE STALE-REPLACE REGRESSION FACE, driven directly and without any
        reliance on scheduler timing.
    C10 THE CRASH WINDOW MUST PROVE ITS HASH, not just its sequence (F4).

    A READER THAT REPAIRS DURABLE STATE IS NOT A READER.
    A HEAD THAT CAN MOVE BACKWARDS IS NOT A COMMITTED HEAD.

OPEN FINDING, DELIBERATELY NOT REPAIRED HERE — F4 (independent review).

    When the checkpoint is exactly ONE record behind, `classify_head` compares
    only the SEQUENCE NUMBERS. It does not compare the head's stored hash with
    the corresponding retained journal record. A one-record window whose head
    names the WRONG hash for that sequence therefore returns ok=True,
    window=True and `trusted=True`.

    Reproduced independently during this narrow repair: journal at seq 3, head
    written as seq 2 with hash "dddd..." while the real seq-2 record hashes
    "88c41e8e..." -> classify_head ok=True, Journal.load trusted=True.

    Note the exact-match branch (`head.seq == last_seq`) DOES compare hashes and
    fails closed on a mismatch; only the one-behind branch does not.

    This is a PRE-EXISTING weakness, not something A.2-R introduced, and it is a
    PRODUCTION change. The present pass is test-evidence only, so it is recorded
    here for owner/reviewer disposition and NOT silently folded in. No assertion
    in this file asserts the current (permissive) behaviour, so repairing F4
    later will not require weakening anything written here.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from orbit.audit.checkpoint import (CheckpointLock, CheckpointRegressed, Head,
                                    HeadCheckpoint, classify_head,
                                    verify_against_head)
from orbit.audit.journal import AppendLock, Journal
from orbit.audit.locks import (RANK_APPEND, RANK_CHECKPOINT, LockOrderViolation,
                               RankedFileLock, held_ranks)
from orbit.audit.records import E

PASS, FAIL = [], []
TMP = tempfile.mkdtemp(prefix="orbit_a2r_")
_n = [0]


def check(name, ok, detail=""):
    if ok:
        PASS.append(name)
    else:
        FAIL.append(f"{name} :: {detail}")


def journal_with(n, tag):
    """A fresh journal holding n committed records."""
    _n[0] += 1
    p = os.path.join(TMP, f"{tag}_{_n[0]}.jsonl")
    j = Journal(p)
    for i in range(n):
        j.append_one(E.REMEDIATION, None, note=f"r{i}")
    return p, Journal.load(p).records


def head_bytes(p):
    hp = p + ".head"
    return open(hp, "rb").read() if os.path.exists(hp) else b""


# ======================================================================
# C1 — READ PATHS DO NOT WRITE
# ======================================================================

p, recs = journal_with(3, "c1_clean")
before = head_bytes(p)
for _ in range(25):
    Journal.load(p)
check("C1.1 a clean load writes nothing to the head file",
      head_bytes(p) == before, "head bytes changed across 25 loads")

p, recs = journal_with(3, "c1_window")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
before = head_bytes(p)
for _ in range(25):
    Journal.load(p)
check("C1.2 a load that OBSERVES the one-record crash window still writes "
      "nothing (this is the repaired defect)",
      head_bytes(p) == before,
      f"head moved to seq {HeadCheckpoint(p).read().seq}; a read repaired "
      f"durable state")

p, recs = journal_with(3, "c1_init")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
before = head_bytes(p)
Journal(p)                                    # constructor performs a load
check("C1.3 Journal.__init__ over the crash window writes nothing",
      head_bytes(p) == before, "the constructor repaired the head")

p, recs = journal_with(3, "c1_raise")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
try:
    lr = Journal.load(p)
    raised = None
except BaseException as e:                                       # noqa: BLE001
    raised = type(e).__name__
check("C1.4 a load over the crash window does not raise out of the read path",
      raised is None, f"raised {raised}")

p, recs = journal_with(3, "c1_ahead_raise")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
try:
    v = classify_head(p, recs, 0)
    raised = None
except BaseException as e:                                       # noqa: BLE001
    raised = type(e).__name__
check("C1.5 classify_head never raises CheckpointRegressed out of a read "
      "(finding 4, second face)",
      raised is None, f"raised {raised}")

# ======================================================================
# C2 — THE WINDOW IS REPORTED AS A FACT
# ======================================================================

p, recs = journal_with(3, "c2")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
lr = Journal.load(p)
check("C2.1 the one-record window is reported on the LoadResult",
      lr.head_window is True, f"head_window={lr.head_window}")
check("C2.2 the window names the head a writer should advance to",
      lr.head_roll_to_seq == 3 and lr.head_roll_to_hash == recs[2]["hash"],
      f"roll_to={lr.head_roll_to_seq}")
check("C2.3 the journal in the crash window is still TRUSTED (the record is "
      "committed; the window is legitimate)",
      lr.trusted is True, f"trusted={lr.trusted} {lr.reason[:60]}")

p, recs = journal_with(3, "c2_clean")
lr = Journal.load(p)
check("C2.4 a journal with no window does not claim one",
      lr.head_window is False and lr.head_roll_to_seq == 0,
      f"head_window={lr.head_window}")

p, recs = journal_with(3, "c2_verdict")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
_before = head_bytes(p)
ok, why = verify_against_head(p, recs, 0)
check("C2.5 the legacy (ok, reason) wrapper is preserved and is also pure",
      ok is True and head_bytes(p) == _before
      and HeadCheckpoint(p).read().seq == 2,
      f"ok={ok} head={HeadCheckpoint(p).read().seq} "
      f"bytes_changed={head_bytes(p) != _before}")

# ======================================================================
# C3 — THE APPEND PATH CLOSES THE WINDOW
# ======================================================================

p, recs = journal_with(3, "c3")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
j = Journal(p)
j.append_one(E.REMEDIATION, None, note="closes the window")
h = HeadCheckpoint(p).read()
last = Journal.load(p).records[-1]
check("C3.1 an append closes the crash window and the head matches the new "
      "last record",
      h.seq == last["seq"] and h.hash == last["hash"],
      f"head={h.seq} last={last['seq']}")

p, recs = journal_with(3, "c3_roll")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
seen = {}
_real = HeadCheckpoint.commit_monotonic


def _watch(self, seq, h, _r=_real):
    seen[seq] = held_ranks()[:]              # ranks held at the moment of commit
    return _r(self, seq, h)


HeadCheckpoint.commit_monotonic = _watch
Journal(p).append_one(E.REMEDIATION, None, note="x")
HeadCheckpoint.commit_monotonic = _real
check("C3.2 EVERY checkpoint advancement during an append happens with the "
      "append lock held (zero unlocked checkpoint writes)",
      bool(seen) and all(RANK_APPEND in r for r in seen.values()),
      f"ranks observed: {seen}")

check("C3.3 the roll-forward of the window is one of those locked writes",
      3 in seen, f"commits seen: {sorted(seen)}")

# ======================================================================
# C4 — MONOTONIC, ATOMIC, IDEMPOTENT ADVANCEMENT
# ======================================================================

p, recs = journal_with(3, "c4")
cp = HeadCheckpoint(p)
before = head_bytes(p)
cp.commit_monotonic(3, recs[2]["hash"])
check("C4.1 re-committing the SAME (seq, hash) is an idempotent no-op that "
      "writes nothing",
      head_bytes(p) == before, "the head file was rewritten for a no-op")

try:
    cp.commit_monotonic(1, recs[0]["hash"])
    err = None
except CheckpointRegressed as e:
    err = "CheckpointRegressed"
except BaseException as e:                                       # noqa: BLE001
    err = type(e).__name__
check("C4.2 the head refuses to move BACKWARDS", err == "CheckpointRegressed",
      f"got {err}")
check("C4.3 a refused regression leaves the head untouched",
      HeadCheckpoint(p).read().seq == 3,
      f"head={HeadCheckpoint(p).read().seq}")

try:
    cp.commit_monotonic(3, "e" * 64)
    err = None
except CheckpointRegressed:
    err = "CheckpointRegressed"
except BaseException as e:                                       # noqa: BLE001
    err = type(e).__name__
check("C4.4 two different records cannot claim one sequence number",
      err == "CheckpointRegressed", f"got {err}")

p, recs = journal_with(4, "c4_fwd")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
HeadCheckpoint(p).commit_monotonic(4, recs[3]["hash"])
check("C4.5 the head advances forward normally",
      HeadCheckpoint(p).read().seq == 4,
      f"head={HeadCheckpoint(p).read().seq}")

# F1 (review, MAJOR). The previous C4.6 asserted a literal True: removing
# `with CheckpointLock(...)` from `commit_monotonic` left the whole suite
# green. The lock is load-bearing — the reviewer measured 233 checkpoint
# regressions without it and 0 with it under an identical widened window — so
# it needs evidence that fails when it is removed.
#
# The read, the compare and the replace are ONE critical section. Both the
# read and the write are observed from inside `commit_monotonic`, and each
# must report RANK_CHECKPOINT held at the moment it runs. If the `with` is
# deleted, `held_ranks()` is empty at both points and these fail.
p, recs = journal_with(4, "c4_lock")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
obs = {"read": [], "write": []}
_o_read, _o_write = HeadCheckpoint.read, HeadCheckpoint._write_unchecked


def _spy_read(self, _f=_o_read):
    obs["read"].append(held_ranks()[:])
    return _f(self)


def _spy_write(self, seq, h, _f=_o_write):
    obs["write"].append(held_ranks()[:])
    return _f(self, seq, h)


HeadCheckpoint.read, HeadCheckpoint._write_unchecked = _spy_read, _spy_write
try:
    HeadCheckpoint(p).commit_monotonic(4, recs[3]["hash"])
finally:
    HeadCheckpoint.read, HeadCheckpoint._write_unchecked = _o_read, _o_write

check("C4.6 the checkpoint READ inside commit_monotonic runs with "
      "RANK_CHECKPOINT held (fails if `with CheckpointLock` is removed)",
      bool(obs["read"]) and all(RANK_CHECKPOINT in r for r in obs["read"]),
      f"ranks at read: {obs['read']}")
check("C4.7 the checkpoint REPLACE inside commit_monotonic runs with "
      "RANK_CHECKPOINT held (fails if `with CheckpointLock` is removed)",
      bool(obs["write"]) and all(RANK_CHECKPOINT in r for r in obs["write"]),
      f"ranks at write: {obs['write']}")
check("C4.8 read and replace are ONE critical section: the lock observed at "
      "the read is still held at the replace",
      bool(obs["read"]) and bool(obs["write"])
      and obs["read"][-1] == obs["write"][-1],
      f"read={obs['read']} write={obs['write']}")
check("C4.9 the head actually advanced under that locked section",
      HeadCheckpoint(p).read().seq == 4,
      f"head={HeadCheckpoint(p).read().seq}")

# The same, reached through the append path: BOTH ranks must be held there.
p, recs = journal_with(2, "c4_lock_append")
obs2 = {"write": []}
_o_write = HeadCheckpoint._write_unchecked


def _spy_write2(self, seq, h, _f=_o_write):
    obs2["write"].append(held_ranks()[:])
    return _f(self, seq, h)


HeadCheckpoint._write_unchecked = _spy_write2
try:
    Journal(p).append_one(E.REMEDIATION, None, note="ranked")
finally:
    HeadCheckpoint._write_unchecked = _o_write
check("C4.10 a checkpoint replace on the APPEND path holds BOTH ranks, in "
      "order: AppendLock then CheckpointLock",
      bool(obs2["write"])
      and all(r[:2] == [RANK_APPEND, RANK_CHECKPOINT] for r in obs2["write"]),
      f"ranks at write: {obs2['write']}")

# ======================================================================
# C5 — LOCK RANK AND DEADLOCK AVOIDANCE
# ======================================================================

p, _ = journal_with(1, "c5")
check("C5.1 no ranks are held at rest", held_ranks() == [], f"{held_ranks()}")

with AppendLock(p):
    inside_append = held_ranks()[:]
    with CheckpointLock(p):
        both = held_ranks()[:]
check("C5.2 the legal order AppendLock -> CheckpointLock is permitted",
      inside_append == [RANK_APPEND] and both == [RANK_APPEND, RANK_CHECKPOINT],
      f"{inside_append} then {both}")
check("C5.3 both locks are released on normal exit", held_ranks() == [],
      f"{held_ranks()}")

err = None
try:
    with CheckpointLock(p):
        with AppendLock(p):
            pass
except LockOrderViolation:
    err = "LockOrderViolation"
except BaseException as e:                                       # noqa: BLE001
    err = type(e).__name__
check("C5.4 the REVERSE order raises instead of deadlocking",
      err == "LockOrderViolation", f"got {err}")
check("C5.5 a refused reverse acquisition leaks no rank", held_ranks() == [],
      f"{held_ranks()}")

err = None
try:
    with AppendLock(p):
        with AppendLock(p):
            pass
except LockOrderViolation:
    err = "LockOrderViolation"
except BaseException as e:                                       # noqa: BLE001
    err = type(e).__name__
check("C5.6 re-entering the append lock raises instead of self-deadlocking "
      "(flock conflicts between two descriptors in one process)",
      err == "LockOrderViolation", f"got {err}")

err = None
try:
    with CheckpointLock(p):
        with CheckpointLock(p):
            pass
except LockOrderViolation:
    err = "LockOrderViolation"
except BaseException as e:                                       # noqa: BLE001
    err = type(e).__name__
check("C5.7 the checkpoint lock is a LEAF: nothing may be acquired while it "
      "is held", err == "LockOrderViolation", f"got {err}")

# deadlock canary: the legal nesting must complete promptly under contention.
done = []


def _worker(path):
    for _ in range(12):
        Journal(path).append_one(E.REMEDIATION, None, note="canary")
    done.append(True)


p, _ = journal_with(1, "c5_canary")
ts = [threading.Thread(target=_worker, args=(p,)) for _ in range(3)]
t0 = time.time()
for t in ts:
    t.start()
for t in ts:
    t.join(timeout=60)
elapsed = time.time() - t0
check("C5.8 DEADLOCK CANARY: 3 threads x 12 appends complete within 60s",
      len(done) == 3 and not any(t.is_alive() for t in ts),
      f"completed={len(done)} elapsed={elapsed:.1f}s")
check("C5.9 the canary leaves the chain valid and the head at the last record",
      Journal.load(p).trusted
      and HeadCheckpoint(p).read().seq == Journal.load(p).records[-1]["seq"],
      f"head={HeadCheckpoint(p).read().seq}")

# ======================================================================
# C6 — RELEASE ON EXCEPTION
# ======================================================================

p, _ = journal_with(1, "c6")
try:
    with AppendLock(p):
        raise RuntimeError("boom")
except RuntimeError:
    pass
check("C6.1 the append lock releases when the body raises", held_ranks() == [],
      f"{held_ranks()}")

try:
    with CheckpointLock(p):
        raise RuntimeError("boom")
except RuntimeError:
    pass
check("C6.2 the checkpoint lock releases when the body raises",
      held_ranks() == [], f"{held_ranks()}")

with AppendLock(p):
    pass
check("C6.3 the append lock is re-acquirable after an exception (the flock "
      "was really released)", held_ranks() == [], f"{held_ranks()}")

p, recs = journal_with(3, "c6_commit")
try:
    HeadCheckpoint(p).commit_monotonic(1, recs[0]["hash"])
except CheckpointRegressed:
    pass
check("C6.4 a raising commit_monotonic releases the checkpoint lock",
      held_ranks() == [], f"{held_ranks()}")
HeadCheckpoint(p).commit_monotonic(3, recs[2]["hash"])
check("C6.5 the checkpoint lock is usable again after a raise: the next "
      "advancement actually lands and leaves no rank held",
      HeadCheckpoint(p).read().seq == 3 and held_ranks() == [],
      f"head={HeadCheckpoint(p).read().seq} ranks={held_ranks()}")

# ======================================================================
# C7 — GENUINE LOSS STILL FAILS CLOSED (R3-6 must not have been weakened)
# ======================================================================

p, recs = journal_with(3, "c7_ahead")
HeadCheckpoint(p)._write_unchecked(recs[-1]["seq"] + 5, "f" * 64)
lr = Journal.load(p)
check("C7.1 a checkpoint AHEAD of the journal still fails closed",
      (not lr.trusted) and lr.tamper_detected,
      f"trusted={lr.trusted}")

p, recs = journal_with(4, "c7_lag2")
HeadCheckpoint(p)._write_unchecked(recs[1]["seq"], recs[1]["hash"])
lr = Journal.load(p)
check("C7.2 a lag of TWO still fails closed (the window is one, and only one)",
      (not lr.trusted) and "2 records behind" in lr.reason,
      f"trusted={lr.trusted} {lr.reason[:60]}")
check("C7.3 a two-record lag is NOT reported as the benign window",
      lr.head_window is False, f"head_window={lr.head_window}")

p, recs = journal_with(3, "c7_replaced")
HeadCheckpoint(p)._write_unchecked(recs[-1]["seq"], "a" * 64)
lr = Journal.load(p)
check("C7.4 a head naming a DIFFERENT record at the same seq fails closed",
      not lr.trusted, f"trusted={lr.trusted}")

p, recs = journal_with(3, "c7_unreadable")
open(p + ".head", "w").write("{ not json")
lr = Journal.load(p)
check("C7.5 an unreadable checkpoint fails closed", not lr.trusted,
      f"trusted={lr.trusted}")

p, recs = journal_with(3, "c7_nocp")
os.unlink(p + ".head")
lr = Journal.load(p)
check("C7.6 a journal with NO checkpoint keeps the weaker chain-only "
      "guarantee and still loads", lr.trusted, f"trusted={lr.trusted}")

p, recs = journal_with(3, "c7_suffix")
lines = open(p).read().rstrip("\n").split("\n")
open(p, "w").write("\n".join(lines[:-1]) + "\n")
lr = Journal.load(p)
check("C7.7 a removed COMMITTED suffix is still detected by the external head",
      (not lr.trusted) and lr.tamper_detected, f"trusted={lr.trusted}")

# ======================================================================
# C8 — THE ORIGINAL RACE, DETERMINISTICALLY, WITH ITS POLARITY CORRECTED
# ======================================================================
#
# This is the A.1 reproducer (tests/repro_checkpoint_regression.py) promoted
# into the suite. Under A.1 the interposed read let locked writers advance the
# head between the unlocked reader's read and its replace, and the checkpoint
# REGRESSED. The same interleaving is driven here and must NOT regress.

p, recs = journal_with(3, "c8")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])          # crash window
_orig_read = HeadCheckpoint.read
_calls = {"n": 0}
_reads_during_classify = {"n": 0}


def _read_then_others_advance(self, _o=_orig_read):
    """Drive the exact A.1 interleaving.

    The reader observes the window (head seq 2). Before it can act on that
    observation, two LOCKED writers commit 4 and 5 and advance the head to 5.
    Under A.1 the reader then wrote: either replacing 5 with 3 (regression), or
    raising `CheckpointRegressed` out of the read path. Under A.2-R the reader
    has nothing to write with, so neither can happen.
    """
    head = _o(self)
    _calls["n"] += 1
    if _calls["n"] == 1 and head.seq == 2:
        HeadCheckpoint.read = _o
        w = Journal(p)                       # locked writers, elsewhere
        w.append_one(E.REMEDIATION, None, note="r3")
        w.append_one(E.REMEDIATION, None, note="r4")
        HeadCheckpoint.read = _read_then_others_advance
    return head


HeadCheckpoint.read = _read_then_others_advance
raised = None
try:
    v = classify_head(p, recs, 0)
except BaseException as e:                                       # noqa: BLE001
    raised = type(e).__name__
finally:
    HeadCheckpoint.read = _orig_read
    _reads_during_classify["n"] = _calls["n"]

cp_seq = HeadCheckpoint(p).read().seq
j_last = Journal.load(p).records[-1]["seq"]
# F2 (review, MINOR). This assertion was titled as if it covered the
# stale-replace regression face, but it passes when the historical A.1 defect
# is restored: under A.1 this interleaving RAISES out of commit() before any
# write lands, so "the head is where the writers left it" is satisfied
# vacuously. Retitled to the property it actually tests. The regression face
# itself is covered deterministically by C8.9-C8.11 below.
check("C8.1 after this interleaving the head is where the LOCKED writers left "
      "it and the journal agrees (NOTE: does not by itself discriminate the "
      "stale-replace face — see C9)",
      cp_seq == 5 and j_last == 5, f"checkpoint={cp_seq} journal={j_last}")
check("C8.2 and it does not raise CheckpointRegressed out of the read path "
      "(finding 4, second face)", raised is None, f"raised {raised}")
check("C8.3 after the race the journal still loads TRUSTED (under A.1 this "
      "was '2 records behind the journal', refused)",
      Journal.load(p).trusted,
      f"trusted={Journal.load(p).trusted} {Journal.load(p).reason[:60]}")
check("C8.4 the checkpoint is never behind the journal by more than the "
      "one-record window", j_last - cp_seq <= 1,
      f"checkpoint={cp_seq} journal={j_last}")
check("C8.5 the repaired read path consults the head exactly ONCE — the "
      "second read was commit()'s, and commit() is no longer on a read path",
      _reads_during_classify["n"] == 1,
      f"reads during classify_head: {_reads_during_classify['n']}")

# multi-process: concurrent readers must not disturb concurrent writers.
p, _ = journal_with(1, "c8_mp")
reader = subprocess.Popen(
    [sys.executable, "-c",
     "import sys,time;sys.path.insert(0,'.');"
     "from orbit.audit.journal import Journal;"
     f"t=time.time()\nwhile time.time()-t<4.0: Journal.load({p!r})"],
    cwd=os.getcwd(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
writers = [subprocess.Popen(
    [sys.executable, "-c",
     "import sys;sys.path.insert(0,'.');"
     "from orbit.audit.journal import Journal;"
     "from orbit.audit.records import E;"
     f"[Journal({p!r}).append_one(E.REMEDIATION,None,note='w{k}-%d'%i) "
     "for i in range(15)]"],
    cwd=os.getcwd(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for k in range(4)]
rcs = [w.wait(timeout=120) for w in writers]
reader_rc = reader.wait(timeout=120)
reader_err = reader.communicate()[1].decode("utf-8", "replace")
writer_errs = [w.communicate()[1].decode("utf-8", "replace") for w in writers]
lr = Journal.load(p)
cp_seq = HeadCheckpoint(p).read().seq
check("C8.6 4 writer processes x 15 appends all succeed alongside a "
      "continuous reader process",
      all(r == 0 for r in rcs), f"writer rcs={rcs}")
check("C8.7 every append is present and the chain is valid",
      lr.trusted and len(lr.records) == 61,
      f"trusted={lr.trusted} records={len(lr.records)}")
check("C8.8 the head is not left behind by a concurrent reader",
      lr.records[-1]["seq"] - cp_seq <= 1,
      f"checkpoint={cp_seq} journal={lr.records[-1]['seq']}")

# F3 (review, MINOR). The reader's exit status and stderr were discarded, so a
# real reader-side `CheckpointRegressed` crash — which the reviewer observed
# with the historical defect restored — passed unnoticed. A pure reader must
# exit cleanly and say nothing.
check("C8.9 the READER process exits successfully (a read path that raises is "
      "the second face of finding 4)",
      reader_rc == 0, f"reader rc={reader_rc} stderr={reader_err[-300:]!r}")
check("C8.10 the reader emits no exception on stderr",
      "Traceback" not in reader_err and "CheckpointRegressed" not in reader_err,
      f"reader stderr={reader_err[-300:]!r}")
check("C8.11 no writer process emits an exception on stderr",
      all("Traceback" not in e for e in writer_errs),
      f"writer stderr={[e[-160:] for e in writer_errs if e.strip()]!r}")


# ======================================================================
# C9 — THE STALE-REPLACE REGRESSION FACE, DETERMINISTICALLY
# ======================================================================
#
# F2 (review, MINOR). C8.1 did not discriminate this face: under the historical
# defect that interleaving raises before any write lands. This group drives the
# face directly and uses NO scheduler timing at all.
#
# The shape: a reader observes the head at seq 2, the head then advances to 5
# underneath it, and the reader acts on its STALE observation. Under A.1 the
# read path would call `commit(3, ...)`, whose own read is equally stale, and
# `_write_unchecked(3)` would REPLACE a head that already said 5 — the
# regression. Under A.2-R the read path has nothing to write with.

p, recs = journal_with(5, "c9_stale")
first3 = recs[:3]
assert HeadCheckpoint(p).read().seq == 5
_o_read = HeadCheckpoint.read
_stale = Head(2, recs[1]["hash"], "")


def _always_stale(self, _s=_stale):
    """Every read of the head returns the pre-advance observation."""
    return _s


HeadCheckpoint.read = _always_stale
c9_raised = None
try:
    classify_head(p, first3, 0)
except BaseException as e:                                       # noqa: BLE001
    c9_raised = type(e).__name__
finally:
    HeadCheckpoint.read = _o_read

c9_head = HeadCheckpoint(p).read().seq
check("C9.1 a read path acting on a STALE head observation does not replace a "
      "head that has since advanced (the regression face: under A.1 this "
      "rewrote seq 5 as seq 3)",
      c9_head == 5, f"head is now {c9_head}, expected 5")
check("C9.2 and it does not raise out of the read path while doing so",
      c9_raised is None, f"raised {c9_raised}")
check("C9.3 the journal still loads TRUSTED after the stale-read attempt",
      Journal.load(p).trusted,
      f"trusted={Journal.load(p).trusted} {Journal.load(p).reason[:70]}")

# The same property at the checkpoint API, without any interposition: a stale
# advancement attempt arriving after the head has moved must be REFUSED, not
# applied. This is what makes the locked read-compare-replace worth holding.
p, recs = journal_with(5, "c9_api")
stale_target = (3, recs[2]["hash"])          # computed from an old observation
assert HeadCheckpoint(p).read().seq == 5
try:
    HeadCheckpoint(p).commit_monotonic(*stale_target)
    c9_err = None
except CheckpointRegressed:
    c9_err = "CheckpointRegressed"
except BaseException as e:                                       # noqa: BLE001
    c9_err = type(e).__name__
check("C9.4 a stale advancement arriving after the head moved is REFUSED",
      c9_err == "CheckpointRegressed", f"got {c9_err}")
check("C9.5 and the head is left exactly where the winner put it",
      HeadCheckpoint(p).read().seq == 5,
      f"head={HeadCheckpoint(p).read().seq}")


# ======================================================================
# C10 — F4: THE CRASH WINDOW MUST ALSO PROVE ITS HASH
# ======================================================================
#
# F4 (independent review, MINOR; repaired in this commit). The one-record-behind
# branch checked only the SEQUENCE relationship. It never compared the head's
# stored hash against the retained record at that sequence, so a checkpoint
# naming the WRONG record at seq N-1 was still accepted as the legitimate crash
# window and the journal still loaded trusted=True.
#
# That was inconsistent with the equal-head branch, which has always compared
# hashes and failed closed on a mismatch. A window is only a crash window if the
# head it names is the head that was actually committed.

p, recs = journal_with(3, "c10_wrong")
real_hash = recs[1]["hash"]
HeadCheckpoint(p)._write_unchecked(2, "d" * 64)     # one behind, WRONG hash
v = classify_head(p, recs, 0)
lr = Journal.load(p)
check("C10.1 a one-record-behind head naming the WRONG record is NOT the "
      "legitimate crash window",
      v.window is False, f"window={v.window}")
check("C10.2 and it fails closed rather than loading trusted",
      v.ok is False and lr.trusted is False,
      f"ok={v.ok} trusted={lr.trusted} {lr.reason[:70]}")
check("C10.3 the refusal names the hash mismatch, not a lag",
      ("hash" in lr.reason.lower() or "different record" in lr.reason.lower()),
      f"reason={lr.reason[:110]!r}")
check("C10.4 a rejected window offers no roll-forward target",
      v.roll_to_seq == 0 and v.roll_to_hash == "",
      f"roll_to={v.roll_to_seq}/{v.roll_to_hash[:16]}")

_before = head_bytes(p)
Journal.load(p)
Journal(p)
check("C10.5 a rejected window is still not repaired by a read",
      head_bytes(p) == _before, "a read wrote to the head file")

# The positive case must be preserved exactly: correct hash is still the
# legitimate crash window, still trusted, still rolled forward by an append.
p, recs = journal_with(3, "c10_right")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])   # one behind, CORRECT
v = classify_head(p, recs, 0)
lr = Journal.load(p)
check("C10.6 a one-record-behind head naming the CORRECT record is still the "
      "legitimate crash window",
      v.ok is True and v.window is True, f"ok={v.ok} window={v.window}")
check("C10.7 and the journal still loads TRUSTED",
      lr.trusted is True and lr.head_window is True,
      f"trusted={lr.trusted} head_window={lr.head_window}")
check("C10.8 and it still names the roll-forward target",
      v.roll_to_seq == 3 and v.roll_to_hash == recs[2]["hash"],
      f"roll_to={v.roll_to_seq}")
Journal(p).append_one(E.REMEDIATION, None, note="closes")
check("C10.9 and an append still closes that window under the append lock",
      HeadCheckpoint(p).read().seq == 4,
      f"head={HeadCheckpoint(p).read().seq}")

# An empty head hash is not a mismatch: the equal-head branch has always
# tolerated it, and F4 must not make a legacy head stricter than that branch.
p, recs = journal_with(3, "c10_empty")
HeadCheckpoint(p)._write_unchecked(2, "")
v = classify_head(p, recs, 0)
check("C10.10 a head carrying NO hash is treated as the equal-head branch "
      "treats it — tolerated, not a mismatch",
      v.ok is True and v.window is True, f"ok={v.ok} window={v.window}")


# ======================================================================
print(f"\nRESULTS: {len(PASS)} passed, {len(FAIL)} failed")
for f in FAIL:
    print(f"  FAILED: {f}")
sys.exit(1 if FAIL else 0)
