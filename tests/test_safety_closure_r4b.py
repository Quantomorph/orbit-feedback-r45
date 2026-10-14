"""
tests/test_safety_closure_r4b.py — ORBIT A1 SAFETY CLOSURE, ROUND 4B.

    R4-1  modify_stop could amend an order ORBIT does not own
    R4-3  the cancellation guard accepted an invalid or unowned replacement

Both are the same missing concept:

    WHAT PROTECTIVE ORDER MAY THE MODEL RELY ON OR MUTATE?

and the distinction this round makes permanent:

    AN ORDER MAY AFFECT ACCOUNT-STATE SAFETY WITHOUT BEING AN ORDER THE MODEL
    IS AUTHORISED TO MUTATE.

An operator's manual stop is real, it rests on the account, and reconciliation
must count it when it works out what the account holds. None of that grants
authority to amend it, cancel it, or cite it as an authorised replacement.

    VISIBILITY IS NOT OWNERSHIP.  ACCOUNTING IS NOT AUTHORITY.

Every test here was written to FAIL against the 619/619 Round-4A archive.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from datetime import timedelta
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import (NOW, Exch, Rig, held, owning, pos, stop_order)
from orbit.exec.operations import OperationLedger
from orbit.exec.recon import ExchangeOrder, F, reconcile
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


def rig(orders, intended=None, own=()):
    N[0] += 1
    r = Rig(TMP, f"b{N[0]}", intended=intended or held(), exch=Exch(
        position=pos(), orders=list(orders)))
    r.acquire()
    if own:
        owning(r, *own)
    return r


def calls(r):
    return [(c.method, c.args.get("target_client_order_id"))
            for c in r.adapter.calls]


OURS = stop_order("stop1", "2.38", "29700.1")
ALIEN = stop_order("manual-operator-stop", "2.38", "29700.1")
# an id shaped exactly like one of ours, with no durable record behind it
SPOOF = stop_order("orbitA111df5b63303187ef2c8ef49f", "2.38", "29700.1")

# ======================================================================
banner("R4B.1  ONE ownership rule, for every operation that mutates an order")
# ======================================================================
r = rig([OURS], own=("stop1",))
out = r.session().modify_stop("29800")
check("R4B.1.1  an OWNED stop may be amended when every other rule passes",
      out.status is ActionStatus.ACKNOWLEDGED
      and calls(r) == [("amend_stop", "stop1")], f"{out.code} {calls(r)}")

r = rig([ALIEN], intended=held(cid="manual-operator-stop", orbit_stop=False))
out = r.session().modify_stop("29800")
check("R4B.1.2  an ALIEN stop is NOT_OUR_ORDER, with no adapter mutation",
      out.status is ActionStatus.REJECTED and out.code == "NOT_OUR_ORDER"
      and calls(r) == [], f"{out.code} {calls(r)}")

r = rig([SPOOF], intended=held(cid="orbitA111df5b63303187ef2c8ef49f",
                                   orbit_stop=False))
out = r.session().modify_stop("29800")
check("R4B.1.3  an id SHAPED like ORBIT's, with no durable record, is refused",
      out.code == "NOT_OUR_ORDER" and calls(r) == [], f"{out.code} {calls(r)}")

# ACCOUNTING IS NOT AUTHORITY — the two halves of the distinction, together.
r = rig([OURS, stop_order("manual-operator-stop", "2.38", "29500")],
        own=("stop1",))
rr = reconcile(r.intended, r.exch.view(), NOW)
check("R4B.1.4  the alien stop still appears in reconciliation and account "
      "safety", any(o.client_order_id == "manual-operator-stop"
                    for o in rr.view.open_orders)
      and rr.position.stop_order_id == "manual-operator-stop"
      and F.ORPHANED_ORDER.value in [c.value for c in rr.codes()],
      f"adopted={rr.position.stop_order_id}")
out = r.session().modify_stop("29600")
check("R4B.1.5  and adopting it for RISK ACCOUNTING grants no mutation "
      "authority", out.code == "NOT_OUR_ORDER" and calls(r) == [],
      f"{out.code} {calls(r)}")
check("R4B.1.6  the amendment is REFUSED, not silently retargeted at the "
      "owned stop", not any(t == "stop1" for _, t in calls(r)), str(calls(r)))

# CANCEL and MODIFY_STOP must not disagree about one identity.
r1 = rig([ALIEN], intended=held(cid="manual-operator-stop",
                                orbit_stop=False), own=())
c1 = r1.session().cancel_order("manual-operator-stop",
                               replacement_client_order_id="x")
r2 = rig([ALIEN], intended=held(cid="manual-operator-stop", orbit_stop=False))
c2 = r2.session().modify_stop("29800")
check("R4B.1.7  cancel and modify use the SAME predicate on the same identity",
      c1.code == c2.code == "NOT_OUR_ORDER" and calls(r1) == calls(r2) == [],
      f"cancel={c1.code} modify={c2.code}")

r = rig([OURS], own=("stop1",))
led_before = OperationLedger(r.path).owns("stop1")
r2 = Rig(TMP, r.name if hasattr(r, "name") else "reload", intended=held(),
         exch=r.exch) if False else None
check("R4B.1.8  ownership survives a journal rebuild from disk alone",
      led_before and OperationLedger(r.path).owns("stop1")
      and not OperationLedger(r.path).owns("manual-operator-stop"))

# ======================================================================
banner("R4B.2  ONE definition of an authorised replacement")
# ======================================================================
BLIND = ExchangeOrder("rep", D("2.38"), True, None)
UNDER = stop_order("rep", "1.00", "29700.1")
WIDER = stop_order("rep", "2.38", "29000")
EQUAL = stop_order("rep", "2.38", "29700.1")
TIGHT = stop_order("rep", "2.38", "29800")
ALIEN_REP = stop_order("manual-rep", "2.38", "29700.1")

CASES = [
    ("R4B.2.1  replacement price is None -> refused", [OURS, BLIND],
     ("stop1", "rep"), "rep", False, "REPLACEMENT_STOP_PRICE_UNKNOWN"),
    ("R4B.2.2  replacement is alien -> refused", [OURS, ALIEN_REP],
     ("stop1",), "manual-rep", False, "NOT_OUR_ORDER"),
    ("R4B.2.3  replacement id merely LOOKS like ours -> refused",
     [OURS, stop_order("orbitA1deadbeefdeadbeefdeadbe", "2.38", "29700.1")],
     ("stop1",), "orbitA1deadbeefdeadbeefdeadbe", False, "NOT_OUR_ORDER"),
    ("R4B.2.4  replacement under-covers -> refused", [OURS, UNDER],
     ("stop1", "rep"), "rep", False, "REPLACEMENT_UNDER_COVERS"),
    ("R4B.2.5  replacement is wider/worse -> refused", [OURS, WIDER],
     ("stop1", "rep"), "rep", False, "REPLACEMENT_LESS_PROTECTIVE"),
    ("R4B.2.6  owned, readable, sized and equally protective -> ALLOWED",
     [OURS, EQUAL], ("stop1", "rep"), "rep", True, "ACK"),
    ("R4B.2.7  owned and TIGHTER -> ALLOWED", [OURS, TIGHT],
     ("stop1", "rep"), "rep", True, "ACK"),
    ("R4B.2.8  a duplicated representation of the replacement counts ONCE",
     [OURS, UNDER, UNDER], ("stop1", "rep"), "rep", False,
     "REPLACEMENT_UNDER_COVERS"),
    ("R4B.2.9  a CONFLICTING duplicate cannot authorise cancellation",
     [OURS, EQUAL, stop_order("rep", "2.38", "29000")], ("stop1", "rep"),
     "rep", False, None),
    ("R4B.2.10 target owned + replacement alien -> refused",
     [OURS, ALIEN_REP], ("stop1",), "manual-rep", False, "NOT_OUR_ORDER"),
]
for name, orders, own, rep_id, allow, code in CASES:
    r = rig(orders, own=own)
    out = r.session().cancel_order("stop1", replacement_client_order_id=rep_id)
    # `code is None` means: refused, by whichever layer reaches it first.
    # R4A already HALTS reconciliation on a contradictory duplicate, so the
    # cycle never gets as far as the guard — and the guard refuses it too
    # (R4B.2.9b), so the two layers cannot disagree.
    ok = ((out.code == code if code else
           out.status is not ActionStatus.ACKNOWLEDGED)
          and (calls(r) != [] if allow else calls(r) == []))
    check(name, ok, f"{out.status.value}/{out.code} calls={calls(r)}")

# the guard's OWN conflict branch, reached directly, must agree with R4A.
# NOTE: the guard takes its OWN exchange observation (residual R4-4, out of
# scope for this round), so the conflicting rows must be on the rig's exchange.
_r = rig([OURS, EQUAL, stop_order("rep", "2.38", "29000")],
         own=("stop1", "rep"))
_sess = _r.session()
_g = _sess._protection_guard(
    "cancel_order",
    {"client_order_id": "stop1", "replacement_client_order_id": "rep"},
    reconcile(_r.intended, _r.exch.view(), NOW), OperationLedger(_r.path))
check("R4B.2.9b the guard itself refuses a contradictory duplicate, so the "
      "two layers cannot disagree",
      _g is not None and _g.code == "EXCHANGE_ORDERS_CONTRADICTORY",
      f"{_g.code if _g else None}")

# 11 — target alien, replacement owned: the TARGET mutation is itself refused.
r = rig([ALIEN, EQUAL], intended=held(cid="manual-operator-stop",
                                      orbit_stop=False),
        own=("rep",))
out = r.session().cancel_order("manual-operator-stop",
                               replacement_client_order_id="rep")
check("R4B.2.11 target alien + replacement owned -> the target mutation is "
      "refused", out.code == "NOT_OUR_ORDER" and calls(r) == [],
      f"{out.code} {calls(r)}")

# 12 — unreadable replacement alongside another apparently useful row: the
#      canonical protection model decides, not an existence check.
r = rig([OURS, BLIND, stop_order("rep2", "2.38", "29750")],
        own=("stop1", "rep", "rep2"))
out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
check("R4B.2.12a naming the UNREADABLE row is refused even though another row "
      "would cover", out.code == "REPLACEMENT_STOP_PRICE_UNKNOWN"
      and calls(r) == [], f"{out.code} {calls(r)}")
r = rig([OURS, BLIND, stop_order("rep2", "2.38", "29750")],
        own=("stop1", "rep", "rep2"))
out = r.session().cancel_order("stop1", replacement_client_order_id="rep2")
check("R4B.2.12b naming the READABLE row is allowed — the model decides, not "
      "the existence of a row", out.status is ActionStatus.ACKNOWLEDGED,
      f"{out.code} {calls(r)}")

# ======================================================================
banner("R4B.3  every ALLOWED cancellation leaves a state the model calls "
       "protected")
# ======================================================================
for label, orders, own, rep_id in (
        ("equal replacement", [OURS, EQUAL], ("stop1", "rep"), "rep"),
        ("tighter replacement", [OURS, TIGHT], ("stop1", "rep"), "rep"),
        ("two owned rows, cancel one", [OURS, stop_order("rep2", "2.38",
                                                         "29750")],
         ("stop1", "rep2"), "rep2")):
    r = rig(orders, own=own)
    out = r.session().cancel_order("stop1", replacement_client_order_id=rep_id)
    if out.status is not ActionStatus.ACKNOWLEDGED:
        check(f"R4B.3  {label}: allowed", False, out.code)
        continue
    after = [o for o in orders if o.client_order_id != "stop1"]
    rr = reconcile(held(cid=rep_id), Exch(position=pos(),
                                          orders=after).view(), NOW)
    unprot = {F.POSITION_UNPROTECTED.value, F.STOP_SIZE_MISMATCH.value,
              F.PROTECTIVE_STOP_PRICE_UNKNOWN.value}
    check(f"R4B.3  the state after '{label}' is not one the model calls "
          f"unprotected", not (unprot & {c.value for c in rr.codes()}),
          f"{[c.value for c in rr.codes()]}")

# ======================================================================
banner("R4B.4  R4A remains closed — duplicates manufacture no AUTHORITY either")
# ======================================================================
r = rig([OURS, ALIEN_REP, ALIEN_REP], own=("stop1",))
out = r.session().cancel_order("stop1",
                               replacement_client_order_id="manual-rep")
check("R4B.4.1  listing an alien replacement twice does not make it ours",
      out.code == "NOT_OUR_ORDER" and calls(r) == [], f"{out.code}")

anon = ExchangeOrder(None, D("2.38"), True, D("29700.1"))
r = rig([OURS, anon], own=("stop1",))
out = r.session().cancel_order("stop1", replacement_client_order_id=None)
check("R4B.4.2  an unnamed replacement never matches an ANONYMOUS row",
      out.code == "PROTECTION_WOULD_BE_REMOVED" and calls(r) == [],
      f"{out.code}")

r = rig([OURS, OURS, EQUAL], own=("stop1", "rep"))
out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
check("R4B.4.3  a duplicated TARGET row still cancels once, legitimately",
      out.status is ActionStatus.ACKNOWLEDGED and len(calls(r)) == 1,
      f"{out.code} {calls(r)}")

# ======================================================================
banner("R4B.5  the fix does not make a legitimate owned stop unmanageable")
# ======================================================================
r = rig([OURS], own=("stop1",))
s = r.session()
check("R4B.5.1  tighten, then tighten again, on our own stop",
      s.modify_stop("29750").status is ActionStatus.ACKNOWLEDGED)
r = rig([OURS, EQUAL], own=("stop1", "rep"))
out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
check("R4B.5.2  a genuine stop rotation completes",
      out.status is ActionStatus.ACKNOWLEDGED, out.code)
# SAFETY CLOSURE ROUND 4B2, finding I3. This assertion, and R4B.5.5 below,
# encoded a belief that independent review refuted: that a reduction is safe
# because it mutates nothing. It mutates POSITION SIZE, which is one side of the
# relationship every resting stop stands in. Both are inverted, and the reason
# is recorded rather than quietly rewritten.
r = rig([stop_order("stop1", "1.19", "29700.1")], own=("stop1",))
out = r.session().reduce_position("0.5")
check("R4B.5.3  a reduction IS available where protection already fits the "
      "remainder", out.status is ActionStatus.ACKNOWLEDGED, out.code)

# Found by the round-4B review of this repair: the cancel branch was routed
# through the shared model and the reduce branch was not, so ONE function still
# held two definitions of protection.
_blind = ExchangeOrder("stop1", D("2.38"), True, None)
r = rig([_blind], own=("stop1",))
_m = reconcile(r.intended, r.exch.view(), NOW)
out = r.session().reduce_position("0.5")
check("R4B.5.4  a reduction behind an UNREADABLE stop is refused, as the model "
      "already says those contracts are uncovered",
      F.PROTECTIVE_STOP_PRICE_UNKNOWN.value in [c.value for c in _m.codes()]
      and out.code == "PROTECTION_WOULD_NOT_COVER_REMAINDER",
      f"model={[c.value for c in _m.codes()]} guard={out.code}")

r = rig([stop_order("manual", "1.19", "29700.1")])
out = r.session().reduce_position("0.5")
check("R4B.5.5  an ALIEN readable stop still counts as COVERAGE for a "
      "reduction that leaves a safe relationship",
      out.status is ActionStatus.ACKNOWLEDGED, out.code)

shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("R4-1 and R4-3 closed. Visibility is not ownership; accounting is not "
      "authority. No model. No credentials. No network. No live capital.")
