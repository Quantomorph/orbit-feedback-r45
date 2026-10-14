"""
tests/test_safety_closure_r4b2.py — ORBIT A1 SAFETY CLOSURE, ROUND 4B2.

Independent review reopened Round 4B and found three failures inside the very
surface Round 4B built:

    I1  "ever had an INTENT" was treated as sufficient ownership
    I2  an unreadable TARGET price skipped the no-widening comparison
    I3  a reduction checked under-coverage and never over-coverage

Each was a case of one boolean standing in for a claim it could not prove.

    HISTORICAL AUTHORSHIP   ORBIT once intended this identity.
    CURRENT LIVE OWNERSHIP  the durable lifecycle does not contradict a live
                            row bearing it.
    AUTHORITY TO MUTATE     both, AND the durable role agrees with the role the
                            row is observed to have.

Every test here was written to FAIL against the 652/652 Round-4B archive.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, held, owning, pos, stop_order
from orbit.audit.records import E
from orbit.exec.operations import OperationLedger
from orbit.exec.recon import ExchangeOrder, F, reconcile
from orbit.risk.limits import RunState
from orbit.tools.session import ActionStatus

PASS, FAIL = [], []
TMP = tempfile.mkdtemp()
N = [0]


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def banner(t):
    print("\n" + "-" * 78)
    print(t)


def rig(orders, intended=None, own=(), entry=()):
    N[0] += 1
    r = Rig(TMP, f"c{N[0]}", intended=intended or held(),
            exch=Exch(position=pos(), orders=list(orders)))
    r.acquire()
    if own:
        owning(r, *own)
    for cid in entry:
        owning(r, cid, protective=False)
    return r


calls = lambda r: [(c.method, c.args.get("target_client_order_id"))
                   for c in r.adapter.calls]
OURS = stop_order("stop1", "2.38", "29700.1")


def status(r, cid, st):
    r.journal.append_one(E.ORDER_STATUS, "own-" + cid, client_order_id=cid,
                         status=st)
    return r


# ======================================================================
banner("R4B2.1  I1 — authorship, live ownership and authority are three things")
# ======================================================================
r = rig([OURS], own=("stop1",))
check("R4B2.1.1  a valid protective intent, resting -> the model may manage it",
      r.session().modify_stop("29800").status is ActionStatus.ACKNOWLEDGED
      and calls(r) == [("amend_stop", "stop1")], str(calls(r)))

for label, st, code in (("definitively REJECTED", "REJECTED",
                         "ORDER_STATE_CONTRADICTED"),
                        ("locally CANCELLED", "CANCELLED",
                         "ORDER_STATE_CONTRADICTED"),
                        ("locally FILLED", "FILLED",
                         "ORDER_STATE_CONTRADICTED"),
                        ("locally EXPIRED", "EXPIRED",
                         "ORDER_STATE_CONTRADICTED")):
    r = status(rig([OURS], own=("stop1",)), "stop1", st)
    out = r.session().modify_stop("29800")
    check(f"R4B2.1.2  {label} + the same id still resting -> contradiction, "
          f"no authority",
          out.code == code and calls(r) == [], f"{out.code} {calls(r)}")

r = status(rig([OURS], own=("stop1",)), "stop1", "REJECTED")
check("R4B2.1.3  historical AUTHORSHIP is still true — the two are not the "
      "same claim",
      OperationLedger(r.path).owns("stop1")
      and not OperationLedger(r.path).resting_authority("stop1", OURS)[0])

# UNKNOWN must NOT be collapsed into rejection: it is why resolution exists.
r = rig([OURS], own=("stop1",))
r.journal.append_one(E.ORDER_STATUS, "own-stop1", client_order_id="stop1",
                     status="UNKNOWN")
out = r.session().modify_stop("29800")
check("R4B2.1.4  an UNKNOWN submission with a matching resting row KEEPS "
      "authority — it may genuinely have reached the venue",
      out.status is ActionStatus.ACKNOWLEDGED, f"{out.code}")

r = rig([OURS, stop_order("entry-1", "2.38", "29700.1")], own=("stop1",),
        entry=("entry-1",))
out = r.session().cancel_order("stop1", replacement_client_order_id="entry-1")
check("R4B2.1.5  an ENTRY intent presented as protective cannot become an "
      "authorised replacement",
      out.code == "ORDER_ROLE_CONTRADICTED" and calls(r) == [],
      f"{out.code} {calls(r)}")

r = rig([OURS, stop_order("admin-1", "2.38", "29700.1")], own=("stop1",))
r.journal.record_intent("admin-1", client_order_id="admin-1",
                        instrument="BTC-USDT-SWAP", order_kind="CANCEL",
                        role="ADMIN", reduce_only=False, contracts="2.38")
out = r.session().cancel_order("stop1", replacement_client_order_id="admin-1")
check("R4B2.1.6  an ADMIN mutation id presented as protective cannot become "
      "an authorised replacement",
      out.code == "ORDER_ROLE_CONTRADICTED" and calls(r) == [],
      f"{out.code} {calls(r)}")

# Found by the round-4B2 review of this predicate: it was first written as
# deny-lists and EFFECTIVE fell through both, keeping authority. Enumerating
# what is forbidden is the wrong shape — every status added later defaults to
# permitted. The predicate is now an allow-list of the statuses under which a
# live resting order is a coherent claim.
_r = rig([OURS], own=("stop1",))
_led = OperationLedger(_r.path)
from orbit.exec.operations import OpStatus as _S
_grant = set()
for _st in [x.value for x in _S]:
    _q = status(rig([OURS], own=("stop1",)), "stop1", _st)
    if OperationLedger(_q.path).resting_authority("stop1", OURS)[0]:
        _grant.add(_st)
check("R4B2.1.7a authority is an ALLOW-LIST: exactly the nonterminal statuses, "
      "UNKNOWN included, and nothing terminal",
      _grant == {"PENDING", "SUBMITTED", "ACK", "PARTIALLY_FILLED", "UNKNOWN"},
      f"granted={sorted(_grant)}")

r = rig([stop_order("orbitA1deadbeefdeadbeefdeadbe", "2.38", "29700.1")],
        intended=held(cid="orbitA1deadbeefdeadbeefdeadbe",
                      orbit_stop=False))
out = r.session().modify_stop("29800")
check("R4B2.1.7  a spoofed id with no durable history is still refused",
      out.code == "NOT_OUR_ORDER" and calls(r) == [], f"{out.code}")

r = status(rig([OURS], own=("stop1",)), "stop1", "REJECTED")
led2 = OperationLedger(r.path)          # rebuilt from disk alone
check("R4B2.1.8  the verdict survives a rebuild from the journal",
      not led2.resting_authority("stop1", OURS)[0]
      and led2.resting_authority("stop1", OURS)[1]
      == "ORDER_STATE_CONTRADICTED")

# ======================================================================
banner("R4B2.2  I2 — no widening must be PROVED, in both directions")
# ======================================================================
BLIND_T = ExchangeOrder("stop1", D("2.38"), True, None)
CASES = [
    ("R4B2.2.1  target readable, replacement equal -> allowed",
     [OURS, stop_order("rep", "2.38", "29700.1")], True, None),
    ("R4B2.2.2  target readable, replacement tighter -> allowed",
     [OURS, stop_order("rep", "2.38", "29800")], True, None),
    ("R4B2.2.3  target readable, replacement wider -> refused",
     [OURS, stop_order("rep", "2.38", "29000")], False,
     "REPLACEMENT_LESS_PROTECTIVE"),
    ("R4B2.2.4  target UNKNOWN, replacement WIDER than intended -> refused",
     [BLIND_T, stop_order("rep", "2.38", "29000")], False,
     "REPLACEMENT_LESS_PROTECTIVE"),
    ("R4B2.2.5  target UNKNOWN, replacement EQUAL to intended -> allowed, and "
     "provably so",
     [BLIND_T, stop_order("rep", "2.38", "29700.1")], True, None),
    ("R4B2.2.6  target UNKNOWN, replacement TIGHTER than intended -> allowed",
     [BLIND_T, stop_order("rep", "2.38", "29800")], True, None),
    ("R4B2.2.7  replacement UNKNOWN -> still refused",
     [OURS, ExchangeOrder("rep", D("2.38"), True, None)], False,
     "REPLACEMENT_STOP_PRICE_UNKNOWN"),
]
for name, orders, allow, code in CASES:
    r = rig(orders, own=("stop1", "rep"))
    out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
    ok = ((out.status is ActionStatus.ACKNOWLEDGED) if allow
          else (out.code == code and calls(r) == []))
    check(name, ok, f"{out.status.value}/{out.code} calls={calls(r)}")

# neither bound readable -> the claim is unprovable and fails closed
from datetime import timedelta
from orbit.exec.recon import (IntendedPosition, IntendedState, OrderStatus,
                              SubmittedOrder)
_c = D("2.38")
_no_stop = IntendedState(
    journal_loaded=True, clean_shutdown=True, entries_utc_day=1,
    position=IntendedPosition("long", _c, D("30000"), None, "stop1",
                              NOW - timedelta(minutes=30)),
    submitted_orders=(SubmittedOrder("e1", _c, _c, OrderStatus.FILLED, NOW),
                      SubmittedOrder("stop1", _c, D("0"), OrderStatus.ACK,
                                     NOW, True),
                      SubmittedOrder("rep", _c, D("0"), OrderStatus.ACK,
                                     NOW, True)))
r = rig([BLIND_T, stop_order("rep", "2.38", "29700.1")], own=("stop1", "rep"),
        intended=_no_stop)
out = r.session(intended=_no_stop).cancel_order(
    "stop1", replacement_client_order_id="rep")
check("R4B2.2.8  neither the target price nor an authorised stop is readable "
      "-> unprovable, fails closed",
      out.code == "CANNOT_PROVE_NO_WIDENING" and calls(r) == [], f"{out.code}")

# every ALLOWED cancellation must leave a state the model does not call widened
for label, orders, rep in (
        ("equal", [OURS, stop_order("rep", "2.38", "29700.1")], "rep"),
        ("tighter", [OURS, stop_order("rep", "2.38", "29800")], "rep"),
        ("unreadable target, equal replacement",
         [BLIND_T, stop_order("rep", "2.38", "29700.1")], "rep")):
    r = rig(orders, own=("stop1", "rep"))
    out = r.session().cancel_order("stop1", replacement_client_order_id=rep)
    after = reconcile(held(cid=rep, stop="29700.1"),
                      Exch(position=pos(),
                           orders=[o for o in orders
                                   if o.client_order_id != "stop1"]).view(),
                      NOW)
    bad = {F.STOP_PRICE_WIDER_THAN_INTENDED.value,
           F.RISK_BUDGET_EXCEEDED_BY_FILL.value}
    check(f"R4B2.2.9  the state after '{label}' does not widen authorised risk",
          out.status is ActionStatus.ACKNOWLEDGED
          and not (bad & {c.value for c in after.codes()}),
          f"{out.code} -> {[c.value for c in after.codes()]}")

# ======================================================================
banner("R4B2.3  I3 — a reduction must leave a safe protection relationship")
# ======================================================================
r = rig([OURS], own=("stop1",))
before = reconcile(r.intended, r.exch.view(), NOW)
out = r.session().reduce_position("0.5")
check("R4B2.3.1  a full-size stop + 50% reduce cannot silently create "
      "over-coverage",
      before.clean and out.code == "PROTECTION_WOULD_OVER_COVER_REMAINDER"
      and r.adapter.calls == [], f"{out.code}")

r = rig([stop_order("manual", "2.38", "29700.1")])
out = r.session().reduce_position("0.5")
check("R4B2.3.2  an ALIEN full-size stop + 50% reduce cannot leave an "
      "oversized stop ORBIT is not even permitted to resize",
      out.code == "PROTECTION_WOULD_OVER_COVER_REMAINDER"
      and not OperationLedger(r.path).owns("manual")
      and r.adapter.calls == [], f"{out.code}")

r = rig([stop_order("stop1", "0.50", "29700.1")], own=("stop1",))
out = r.session().reduce_position("0.5")
check("R4B2.3.3  an under-covered remainder remains refused",
      out.code == "PROTECTION_WOULD_NOT_COVER_REMAINDER"
      and r.adapter.calls == [], f"{out.code}")

r = rig([stop_order("stop1", "1.19", "29700.1")], own=("stop1",))
out = r.session().reduce_position("0.5")
check("R4B2.3.4  the exact safe case EXISTS and is allowed: protection "
      "already sized to the remainder",
      out.status is ActionStatus.ACKNOWLEDGED, f"{out.code}")

r = rig([OURS], own=("stop1",))
out = r.session().close_position()
check("R4B2.3.5  CLOSE remains available as the full risk-reducing escape",
      out.status is ActionStatus.ACKNOWLEDGED, f"{out.code}")

# 8 — the post-action state must satisfy the same invariant the reconciler does
r = rig([stop_order("stop1", "1.19", "29700.1")], own=("stop1",))
out = r.session().reduce_position("0.5")
after = reconcile(held(contracts="1.19", cid="stop1"),
                  Exch(position=pos(contracts="1.19"),
                       orders=[stop_order("stop1", "1.19", "29700.1")]).view(),
                  NOW)
check("R4B2.3.6  the simulated post-reduction state satisfies the SAME "
      "invariant the reconciler enforces",
      out.status is ActionStatus.ACKNOWLEDGED
      and F.STOP_SIZE_OVER_COVERS.value not in [c.value for c in after.codes()]
      and F.STOP_SIZE_MISMATCH.value not in [c.value for c in after.codes()],
      f"{[c.value for c in after.codes()]}")

# 6 — nothing here may depend on N7
import inspect
from orbit.tools.session import ToolSession
_guard = inspect.getsource(ToolSession._protection_guard)
check("R4B2.3.7  no branch of the guard defers repair to a component that "
      "does not exist", "N7" not in _guard.replace("NOTHING HERE MAY DEPEND "
                                                   "ON N7", ""))

shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("I1, I2 and I3 closed. Authorship is not authority; unknown is not safe "
      "in either direction; a reduction changes the protection relationship. "
      "No model. No credentials. No network. No live capital.")
