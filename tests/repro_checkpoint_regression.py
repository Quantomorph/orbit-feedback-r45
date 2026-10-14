"""
tests/repro_checkpoint_regression.py — DETERMINISTIC MINIMAL REPRODUCER,
POLARITY CORRECTED AT CHECKPOINT A.2-R.

SAFETY CLOSURE ROUND 4C4, checkpoint A.1 review finding 4, REPAIRED in A.2-R.

ORIGINAL PURPOSE (checkpoint A.1): demonstrate a defect that A.1 deliberately
did not fix. Exit status 0 meant "the defect was demonstrated".

CURRENT PURPOSE (checkpoint A.2-R): drive the SAME interleaving and prove the
defect is gone. Exit status 0 now means "the head did NOT regress". The
polarity is inverted, not the mechanism: this script still forces locked
writers in between the unlocked reader's observation and whatever it does next.

The suite assertion that must not be skipped lives in
`tests/test_safety_closure_r4c4_a2r.py` (group C8) and runs under
RUN_TESTS.sh. This script is retained as the standalone, human-readable trace.

THE MECHANISM, in one process with a controlled interleaving:

  1. `Journal.load()` is called WITHOUT the append lock by `Journal.__init__`
     (and by every other reader). When it observes the legitimate one-record
     crash window (journal at N, checkpoint at N-1) it ROLLS THE CHECKPOINT
     FORWARD by calling `HeadCheckpoint.commit(N)` — still without the lock.
  2. `HeadCheckpoint.commit()` is READ-THEN-REPLACE: it reads the current head,
     checks it is not ahead, then atomically replaces the file. The check and
     the replace are not one operation.
  3. Between that read and that replace, locked writers commit N+1 and N+2.
  4. The unlocked reader's replace lands: the checkpoint REGRESSES to N while
     the journal stands at N+2. Every subsequent load sees lag 2 and refuses:
     "the committed-head checkpoint is 2 records behind the journal".

The stress tool (tests/stress_journal_checkpoint.py) shows this happening
naturally under contention; this script shows it with no timing luck.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orbit.audit import checkpoint as cpmod            # noqa: E402
from orbit.audit.checkpoint import HeadCheckpoint      # noqa: E402
from orbit.audit.journal import Journal                # noqa: E402
from orbit.audit.records import E                      # noqa: E402

tmp = tempfile.mkdtemp(prefix="orbit_cp_repro_")
path = os.path.join(tmp, "j.jsonl")
j = Journal(path)
for i in range(3):
    j.append_one(E.REMEDIATION, None, note=f"r{i}")
recs = Journal.load(path).records
assert recs[-1]["seq"] == 3 and HeadCheckpoint(path).read().seq == 3
print("step 0: journal at seq 3, checkpoint at 3")

# 1. the legitimate crash window: record 3 committed, checkpoint not yet
#    advanced (as if the process died between the two fsyncs).
HeadCheckpoint(path)._write_unchecked(2, recs[1]["hash"])
print("step 1: crash window simulated -> journal 3, checkpoint 2 (lag 1)")

# 2/3. an UNLOCKED reader observes the window and rolls forward. Its
#      commit() reads the head (2) ... and before it replaces the file, two
#      locked writers append 4 and 5 and advance the checkpoint to 5.
_orig_read = HeadCheckpoint.read
_calls = {"n": 0}


def _read_then_others_advance(self):
    head = _orig_read(self)
    _calls["n"] += 1
    # A.1: verify_against_head() read once itself, then commit() read again,
    # and the window was between commit()'s read and its replace.
    # A.2-R: commit() is no longer on the read path at all, so the read path
    # consults the head EXACTLY ONCE. Firing on that single read drives the
    # same interleaving: the reader has observed the window, and the locked
    # writers then race ahead of whatever it might do next.
    if _calls["n"] == 1 and head.seq == 2:
        HeadCheckpoint.read = _orig_read          # the interposition fires once
        print(f"step 2: unlocked reader's commit() read head seq={head.seq}")
        w = Journal(path)                         # a locked writer, elsewhere
        w.append_one(E.REMEDIATION, None, note="r3")
        w.append_one(E.REMEDIATION, None, note="r4")
        print(f"step 3: locked writers committed seq 4 and 5; checkpoint now "
              f"{_orig_read(HeadCheckpoint(path)).seq}")
    return head


HeadCheckpoint.read = _read_then_others_advance
# A.2-R: `verify_against_head` (now a pure wrapper over `classify_head`) sees
# lag == 1 from `Journal.load`, from `Journal.__init__`, with no lock — and
# writes NOTHING. Under A.1 this is where the unlocked roll-forward happened.
raised = None
try:
    ok, why = cpmod.verify_against_head(path, recs, 0)
except BaseException as e:                                       # noqa: BLE001
    ok, why, raised = None, "", type(e).__name__
HeadCheckpoint.read = _orig_read
cp_now = HeadCheckpoint(path).read().seq
j_now = Journal.load(path).records[-1]["seq"]
print(f"step 4: the read returned ok={ok} (raised={raised}); checkpoint is "
      f"{cp_now} while the journal is at {j_now}")

# 5. the next reader - any reader, locked or not - must still TRUST the journal.
load = Journal.load(path)
print(f"step 5: Journal.load -> trusted={load.trusted}")
if load.reason:
    print(f"        reason: {load.reason}")

repaired = (
    raised is None                     # no CheckpointRegressed out of a read
    and load.trusted                   # the journal is not self-inflicted-untrusted
    and cp_now == 5                    # the head is where the LOCKED writers left it
    and j_now - cp_now <= 1            # never behind by more than the window
)
print("\nREPAIR CONFIRMED: the head did not regress"
      if repaired else "\nREGRESSION STILL PRESENT")
sys.exit(0 if repaired else 1)
