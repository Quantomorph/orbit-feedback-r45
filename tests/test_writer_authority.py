"""
tests/test_writer_authority.py — SINGLE-WRITER AUTHORITY, ADVERSARIALLY.

ORBIT-AGENT-ARCH-001, step 6D / 6J.

    AT MOST ONE AUTHORITATIVE ORBIT EXECUTION CYCLE MAY MUTATE TRADING STATE
    AT A TIME.

Two independent `WriterAuthority` objects over the same directory ARE two
processes for every purpose that matters here: all shared state is on disk.
Threads are used where the question is genuinely about simultaneity.

No network, no credentials, no model.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, pos, stop_order
from orbit.exec.adapter import WriteAheadViolation
from orbit.exec.writer import (AuthorityCorruptError, Lease, StaleWriterError,
                               WriterAuthority, WriterUnavailableError)

PASS, FAIL = [], []
TMP = tempfile.mkdtemp(prefix="orbit_w6_")


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def banner(t):
    print("\n" + "-" * 76)
    print(t)


def wdir(n):
    return os.path.join(TMP, f"w{n}")


print("=" * 76)
print("ORBIT A1 — SINGLE-WRITER AUTHORITY")
print("=" * 76)

banner("W — MUTUAL EXCLUSION ACROSS INDEPENDENT WORKERS")
a = WriterAuthority(wdir(1), owner_id="A")
b = WriterAuthority(wdir(1), owner_id="B")
la = a.acquire()
check("W1. the first worker acquires epoch 1", la.epoch == 1)
try:
    b.acquire()
    check("W2. a second worker is refused while authority is valid", False)
except WriterUnavailableError as e:
    check("W2. a second worker is refused while authority is valid", True, str(e)[:56])

a.release(la)
lb = b.acquire()
check("W3. after release the next worker takes a HIGHER epoch, never the same",
      lb.epoch == 2)

banner("F — FENCING: HOLDING THE OBJECT IS NOT AUTHORITY")
try:
    a.fence(la)
    check("F1. the superseded worker is fenced", False)
except StaleWriterError as e:
    check("F1. the superseded worker is fenced", "epoch 1" in str(e), str(e)[:64])
b.fence(lb)
check("F2. the current worker passes the fence", True)

exp = WriterAuthority(wdir(2), owner_id="C", ttl_seconds=0.05)
lc = exp.acquire()
time.sleep(0.08)
try:
    exp.fence(lc)
    check("F3. an EXPIRED lease is fenced even with no successor", False)
except StaleWriterError as e:
    check("F3. an EXPIRED lease is fenced even with no successor — the worker "
          "cannot know whether anyone acted meanwhile", True, str(e)[:56])

d = WriterAuthority(wdir(2), owner_id="D", ttl_seconds=30)
ld = d.acquire()
check("F4. an expired lease can be taken over at a higher epoch", ld.epoch == 2)
try:
    exp.renew(lc)
    check("F5. a superseded lease cannot be renewed back into authority", False)
except StaleWriterError:
    check("F5. a superseded lease cannot be renewed back into authority", True)

banner("R — SIMULTANEITY: MANY THREADS, ONE WINNER")
res, err = [], []
barrier = threading.Barrier(12)


def racer(i):
    au = WriterAuthority(wdir(3), owner_id=f"T{i}")
    barrier.wait()
    try:
        res.append(au.acquire())
    except WriterUnavailableError:
        err.append(i)


ts = [threading.Thread(target=racer, args=(i,)) for i in range(12)]
[t.start() for t in ts]
[t.join() for t in ts]
check("R1. exactly one of twelve simultaneous acquirers wins",
      len(res) == 1 and len(err) == 11, f"{len(res)} won, {len(err)} refused")
check("R2. the winner holds epoch 1 and the directory holds exactly one grant",
      res[0].epoch == 1 and len(os.listdir(wdir(3))) == 1)

# A single race can pass by luck. Repeat it.
rounds, bad = 30, []
for rd in range(rounds):
    d = wdir(f"race{rd}")
    won, lost = [], []
    bar = threading.Barrier(8)

    def r2(i, d=d, won=won, lost=lost, bar=bar):
        au = WriterAuthority(d, owner_id=f"T{i}")
        bar.wait()
        try:
            won.append(au.acquire())
        except WriterUnavailableError:
            lost.append(i)

    th = [threading.Thread(target=r2, args=(i,)) for i in range(8)]
    [t.start() for t in th]
    [t.join() for t in th]
    if len(won) != 1 or len(os.listdir(d)) != 1:
        bad.append((rd, len(won), sorted(os.listdir(d))))
check(f"R3. {rounds} independent 8-way races each produce exactly ONE winner",
      not bad, str(bad[:3]))

banner("K — CORRUPT AUTHORITY IS NOT AN OPEN DOOR")
cd = wdir("corrupt")
ca = WriterAuthority(cd, owner_id="CA")
lca = ca.acquire()
with open(os.path.join(cd, "e1.json"), "w") as fh:
    fh.write("{ this is not json")
try:
    WriterAuthority(cd, owner_id="CB").acquire()
    check("K1. an unreadable authority record refuses new acquisition", False)
except AuthorityCorruptError:
    check("K1. an unreadable authority record refuses new acquisition — it is "
          "indistinguishable from a grant held by someone we cannot see", True)
try:
    ca.fence(lca)
    check("K2. and the existing holder is fenced too", False)
except AuthorityCorruptError:
    check("K2. and the existing holder is fenced too", True)

banner("C — CRASH AND RECOVERY OF AUTHORITY")
k = WriterAuthority(wdir(4), owner_id="K", ttl_seconds=0.05)
lk = k.acquire()
del lk                                   # worker dies holding authority
time.sleep(0.08)
m = WriterAuthority(wdir(4), owner_id="M", ttl_seconds=30)
lm = m.acquire()
check("C1. authority is recoverable after a holder dies, at a higher epoch",
      lm.epoch == 2)
zombie = Lease("K", 1, 0.0, time.time() + 999, os.getpid(), "host")
try:
    m.fence(zombie)
    check("C2. a resurrected worker with an old in-memory lease is fenced", False)
except StaleWriterError as e:
    check("C2. a resurrected worker with an old in-memory lease is fenced — "
          "even one whose object claims not to have expired", True, str(e)[:56])

banner("X — THE FENCE IS AT THE EXCHANGE BOUNDARY, NOT MERELY IN THE SESSION")
rig = Rig(TMP, "fence_exch", intended=flat())
lease1 = rig.acquire()
other = WriterAuthority(rig.wdir, owner_id="OTHER")
rig.authority.release(lease1)
lease2 = other.acquire()                 # authority moves on
s = rig.session(lease=lease1)            # session still holds the OLD lease
r = s.propose_order(side="long", stop="29700.1")
check("X1. a stale worker's action is BLOCKED as STALE_WRITER",
      r.status.value == "BLOCKED" and r.code == "STALE_WRITER", r.code)
check("X2. and it never reached the exchange adapter",
      len(rig.adapter.calls) == 0, f"{len(rig.adapter.calls)} calls")

rig2 = Rig(TMP, "fence_direct", intended=flat())
l2 = rig2.acquire()
rig2.journal.record_intent("a-direct", client_order_id="cid-direct",
                           contracts="2.38")
o2 = WriterAuthority(rig2.wdir, owner_id="OTHER2")
rig2.authority.release(l2)
o2.acquire()
try:
    rig2.adapter.submit_order(l2, "cid-direct", "long", 1, "market")
    check("X3. the adapter itself refuses a fenced caller, even with a valid "
          "durable intent", False)
except StaleWriterError:
    check("X3. the adapter itself refuses a fenced caller, even with a valid "
          "durable intent", True)

banner("WA — NO EXCHANGE MUTATION WITHOUT A DURABLE INTENT")
rig3 = Rig(TMP, "wa", intended=flat())
l3 = rig3.acquire()
try:
    rig3.adapter.submit_order(l3, "never-journalled", "long", 1, "market")
    check("WA1. the adapter refuses a mutation with no INTENT behind it", False)
except WriteAheadViolation as e:
    check("WA1. the adapter refuses a mutation with no INTENT behind it — the "
          "ordering does not depend on call sites remembering", True, str(e)[:56])
check("WA2. and nothing was recorded as an exchange call",
      len(rig3.adapter.calls) == 0)

shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 76)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 76)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("One writer, fenced at the boundary. No model, no credentials, no network.")
