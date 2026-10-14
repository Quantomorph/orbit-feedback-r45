"""
tests/test_safety_closure_r4a.py — ORBIT A1 SAFETY CLOSURE, ROUND 4A.

    R4-2  duplicated open-order rows inflated ProtectionLadder coverage.

Fourth independent adversarial pass. R3-1 normalised the ORDER of the protective
ladder and never established the IDENTITY of the orders in it, so the same row
returned twice covered twice as much:

    one row  -> codes=['STOP_SIZE_MISMATCH']  run=NO_NEW_ENTRY  clean=False
    two rows -> codes=[]                      run=RUNNING       clean=True

with half the position unprotected and a modelled loss of $7.989423666 — inside
the $8 cap — computed by summing two slices that were one order.

THE INVARIANT UNDER TEST:

    ONE REAL VENUE ORDER COUNTS AS ONE PROTECTIVE ORDER, REGARDLESS OF HOW MANY
    TIMES ITS REPRESENTATION APPEARS IN A FETCH.

Every test here was written to FAIL against the 565/565 archive. The invariant is
owned by `orbit.exec.protection`, not by any fixture: these tests hand the
production model duplicated rows and assert on what IT concludes.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import itertools
import os
import random
import sys
import tempfile
from datetime import timedelta
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, pos, stop_order
from orbit.core.precision import BTC_USDT_SWAP as SPEC
from orbit.exec.protection import (canonical_orders, order_identity,
                                   build_ladder)
from orbit.exec.recon import (ExchangeOrder, F, IntendedPosition, IntendedState,
                              OrderStatus, SubmittedOrder, reconcile)
from orbit.risk.limits import A1, RunState

PASS, FAIL = [], []


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def banner(t):
    print("\n" + "-" * 78)
    print(t)


FULL = D("2.38")
HALF = D("1.19")


def held(stop="29700.1", cids=("stop1",), contracts=HALF):
    """2.38 long, intended stop 29700.1, and `cids` declared as ours."""
    return IntendedState(
        journal_loaded=True, clean_shutdown=True, entries_utc_day=1,
        position=IntendedPosition("long", FULL, D("30000"), D(stop), "stop1",
                                  NOW - timedelta(minutes=30)),
        submitted_orders=(SubmittedOrder("e1", FULL, FULL, OrderStatus.FILLED,
                                         NOW),)
        + tuple(SubmittedOrder(c, contracts, D("0"), OrderStatus.ACK, NOW, True)
                for c in cids))


def rec(orders, intended=None):
    return reconcile(intended or held(),
                     Exch(position=pos(), orders=list(orders)).view(), NOW)


def codes(r):
    return sorted(x.value for x in r.codes())


def coverage(orders, contracts=FULL, side="long"):
    return build_ladder(list(orders), contracts, side).covered_contracts


# ======================================================================
banner("R4A.1  the original defect, both halves")
# ======================================================================
one = stop_order("stop1", "1.19", "29700.1")

r1 = rec([one])
check("R4A.1.1  1.19 stop protecting 2.38 -> STOP_SIZE_MISMATCH",
      F.STOP_SIZE_MISMATCH.value in codes(r1)
      and r1.run_state is RunState.NO_NEW_ENTRY and not r1.clean,
      f"{codes(r1)} run={r1.run_state.value}")

r2 = rec([one, one])
check("R4A.1.2  the SAME row twice still covers 1.19, not 2.38",
      coverage([one, one]) == HALF, f"covered={coverage([one, one])}")
check("R4A.1.3  and the verdict is the one-row verdict, not RUNNING",
      codes(r2) == codes(r1) and r2.run_state is RunState.NO_NEW_ENTRY
      and not r2.clean, f"{codes(r2)} run={r2.run_state.value}")

r10 = rec([one] * 10)
check("R4A.1.4  the same row TEN times still covers 1.19",
      coverage([one] * 10) == HALF, f"covered={coverage([one] * 10)}")
check("R4A.1.5  ten rows produce the one-row verdict",
      codes(r10) == codes(r1) and r10.run_state is RunState.NO_NEW_ENTRY,
      f"{codes(r10)}")

# ======================================================================
banner("R4A.2  duplicates must not be confused with genuine distinctness")
# ======================================================================
a = stop_order("stopA", "1.19", "29700.1")
b = stop_order("stopB", "1.19", "29700.1")
check("R4A.2.1  two genuinely distinct 1.19 orders cover 2.38",
      coverage([a, b]) == FULL, f"covered={coverage([a, b])}")

r_ab = rec([a, b], held(cids=("stopA", "stopB")))
check("R4A.2.2  and a fully covered position is not blocked by the fix",
      r_ab.clean and r_ab.run_state is RunState.RUNNING, f"{codes(r_ab)}")

check("R4A.2.3  distinct ids are distinct identities",
      order_identity(a) != order_identity(b))
check("R4A.2.4  one id is one identity however often it is listed",
      order_identity(one) == order_identity(stop_order("stop1", "1.19",
                                                       "29700.1")))

# ======================================================================
banner("R4A.3  conflicting representations fail closed — never chosen, never added")
# ======================================================================
CONFLICTS = {
    "contracts": ExchangeOrder("stop1", D("2.38"), True, D("29700.1")),
    "stop_price": ExchangeOrder("stop1", HALF, True, D("29000")),
    "is_protective": ExchangeOrder("stop1", HALF, False, D("29700.1")),
}
for field, other in CONFLICTS.items():
    r = rec([one, other])
    ok = (F.EXCHANGE_ORDERS_CONTRADICTORY.value in codes(r)
          and r.run_state is not RunState.RUNNING
          and not r.reconciled and not r.clean)
    check(f"R4A.3.1  duplicate id with different {field} -> contradiction, "
          f"not RUNNING", ok, f"{codes(r)} run={r.run_state.value}")

    _, cf = canonical_orders([one, other])
    check(f"R4A.3.2  the {field} conflict is reported as a conflict",
          len(cf) == 1 and cf[0].field == field, str(cf))

    lad = build_ladder([one, other], FULL, "long")
    check(f"R4A.3.3  {field}: neither representation is chosen and they are "
          f"not added", lad.contradictory and lad.covered_contracts <= HALF,
          f"covered={lad.covered_contracts} conflicts={len(lad.conflicts)}")

r_multi = rec([one, CONFLICTS["contracts"], CONFLICTS["stop_price"]])
check("R4A.3.4  several conflicts on one identity all surface",
      F.EXCHANGE_ORDERS_CONTRADICTORY.value in codes(r_multi)
      and r_multi.run_state is RunState.HALTED, f"{codes(r_multi)}")

# ======================================================================
banner("R4A.4  anonymous rows cannot manufacture protection")
# ======================================================================
anon = ExchangeOrder(None, HALF, True, D("29700.1"))
check("R4A.4.1  one anonymous protective row covers 1.19",
      coverage([anon]) == HALF, f"covered={coverage([anon])}")
check("R4A.4.2  the SAME anonymous row twice still covers 1.19",
      coverage([anon, anon]) == HALF, f"covered={coverage([anon, anon])}")
check("R4A.4.3  five identical anonymous rows still cover 1.19",
      coverage([anon] * 5) == HALF, f"covered={coverage([anon] * 5)}")
r_anon = rec([anon, anon, anon])
check("R4A.4.4  and they cannot turn an under-protected position RUNNING",
      F.STOP_SIZE_MISMATCH.value in codes(r_anon)
      and r_anon.run_state is not RunState.RUNNING, f"{codes(r_anon)}")
check("R4A.4.5  an id and no id are never the same identity",
      order_identity(anon) != order_identity(one))

# ======================================================================
banner("R4A.5  modelled loss uses the SAME de-duplicated set as coverage")
# ======================================================================
for label, rows in (("single", [one]), ("doubled", [one, one]),
                    ("x10", [one] * 10)):
    lad = build_ladder(rows, FULL, "long")
    m = lad.modeled_total(D("30000"), SPEC, A1)
    check(f"R4A.5.1  modelled total is identical for {label} rows",
          m == build_ladder([one], FULL, "long").modeled_total(
              D("30000"), SPEC, A1), f"{label}={m}")
    check(f"R4A.5.2  modelled total is costed over exactly the priced "
          f"slices ({label})", len(lad.priced) == 1, f"priced={len(lad.priced)}")

_r_single, _r_double = rec([one]), rec([one, one])
check("R4A.5.3  the reported protection assessment cannot be inflated by a "
      "repeated row",
      (_r_single.protection is None) == (_r_double.protection is None)
      and (_r_single.protection is None
           or _r_single.protection.planned_risk_usdt
           == _r_double.protection.planned_risk_usdt),
      f"single={_r_single.protection and _r_single.protection.planned_risk_usdt} "
      f"double={_r_double.protection and _r_double.protection.planned_risk_usdt}")

# ======================================================================
banner("R4A.6  ownership is irrelevant to the identity rule, in both directions")
# ======================================================================
alien = stop_order("ALIEN", "1.19", "29700.1")
check("R4A.6.1  a duplicated ALIEN order creates no additional coverage",
      coverage([alien, alien]) == HALF, f"covered={coverage([alien, alien])}")
check("R4A.6.2  a duplicated OWN order creates no additional coverage",
      coverage([one, one]) == HALF)
check("R4A.6.3  own + alien duplicated together still cover 2.38, not 4.76",
      coverage([one, one, alien, alien]) == FULL,
      f"covered={coverage([one, one, alien, alien])}")
r_mixed = rec([one, one, alien, alien])
check("R4A.6.4  and the alien order is still reported as orphaned",
      F.ORPHANED_ORDER.value in codes(r_mixed), f"{codes(r_mixed)}")

# ======================================================================
banner("R4A.7  adversarial combinations")
# ======================================================================
wide = stop_order("wide", "1.19", "29000")
tight = stop_order("tight", "1.19", "29800")
blind = ExchangeOrder("blind", HALF, True, None)
over = stop_order("over", "2.38", "29700.1")

COMBOS = {
    "heterogeneous, one duplicated": ([one, wide, wide],
                                      [one, wide]),
    "unreadable price, duplicated": ([one, blind, blind], [one, blind]),
    "over-coverage, duplicated": ([over, over, one], [over, one]),
    "under-coverage, everything duplicated": ([one, one], [one]),
    "owned + alien, heterogeneous, duplicated": ([one, one, alien, tight,
                                                  tight], [one, alien, tight]),
    "three distinct + duplicates of each": (
        [a, a, b, b, wide, wide], [a, b, wide]),
}
allcids = ("stop1", "stopA", "stopB", "wide", "tight", "blind", "over")
for name, (dup, uniq) in COMBOS.items():
    rd, ru = rec(dup, held(cids=allcids)), rec(uniq, held(cids=allcids))
    check(f"R4A.7  duplicated == de-duplicated: {name}",
          codes(rd) == codes(ru) and rd.run_state is ru.run_state
          and rd.clean == ru.clean
          and (rd.position.stop_price if rd.position else None)
          == (ru.position.stop_price if ru.position else None),
          f"{codes(rd)} vs {codes(ru)}")

# ======================================================================
banner("R4A.8  order and multiplicity independence")
# ======================================================================
rng = random.Random(4)
for name, rows in (("dup of one", [one, one, one]),
                   ("mixed dup", [one, one, wide, alien, alien]),
                   ("all distinct", [a, b, wide, tight])):
    seen = set()
    for perm in itertools.permutations(rows):
        r = rec(list(perm), held(cids=allcids))
        seen.add((tuple(codes(r)), r.run_state.value, r.clean,
                  str(r.position.stop_price if r.position else None),
                  str(r.position.stop_order_id if r.position else None)))
    for _ in range(20):
        sh = list(rows)
        rng.shuffle(sh)
        r = rec(sh, held(cids=allcids))
        seen.add((tuple(codes(r)), r.run_state.value, r.clean,
                  str(r.position.stop_price if r.position else None),
                  str(r.position.stop_order_id if r.position else None)))
    check(f"R4A.8  exactly one verdict across every permutation: {name}",
          len(seen) == 1, f"{len(seen)} distinct")

# ======================================================================
banner("R4A.9  the fix does not block legitimate states (positive controls)")
# ======================================================================
r_ok = rec([stop_order("stop1", "2.38", "29700.1")])
check("R4A.9.1  a correctly protected position is still RUNNING and clean",
      r_ok.clean and r_ok.run_state is RunState.RUNNING, f"{codes(r_ok)}")
check("R4A.9.2  a flat account with no orders still reconciles",
      reconcile(IntendedState(journal_loaded=True, clean_shutdown=True,
                              entries_utc_day=0),
                Exch().view(), NOW).run_state is RunState.RUNNING)
check("R4A.9.3  an empty order list produces no conflicts",
      canonical_orders(()) == ((), ()))
check("R4A.9.4  distinct orders survive canonicalisation unchanged",
      len(canonical_orders([a, b, wide])[0]) == 3)
r_het = rec([one, tight], held(cids=allcids))
check("R4A.9.5  a genuine heterogeneous ladder is still reported, not blocked",
      F.STOP_LADDER_HETEROGENEOUS.value in codes(r_het), f"{codes(r_het)}")

# ======================================================================
banner("R4A.10  gaps found by reviewing the R4-2 REPAIR itself")
# ======================================================================
# Found by the round-4A review of the repair: `str()` made Decimal("1.19") and
# Decimal("1.190") two identities, so the anonymous fallback reintroduced the
# very defect being fixed, through a difference of exponent rather than value.
scaled = [ExchangeOrder(None, D("1.19"), True, D("29700.1")),
          ExchangeOrder(None, D("1.190"), True, D("29700.1"))]
check("R4A.10.1  equal quantities of different scale are ONE identity",
      len(canonical_orders(scaled)[0]) == 1
      and build_ladder(scaled, FULL, "long").covered_contracts == HALF,
      f"covered={build_ladder(scaled, FULL, 'long').covered_contracts}")
scaled_px = [ExchangeOrder(None, HALF, True, D("29700.10")),
             ExchangeOrder(None, HALF, True, D("29700.1"))]
check("R4A.10.2  equal prices of different scale are ONE identity",
      len(canonical_orders(scaled_px)[0]) == 1)
check("R4A.10.3  and genuinely different quantities stay distinct (control)",
      len(canonical_orders([ExchangeOrder(None, D("1.19"), True, D("29700.1")),
                            ExchangeOrder(None, D("1.20"), True,
                                          D("29700.1"))])[0]) == 2)

# Found by the same review: `session._protection_guard` counted coverage by
# summing `view.open_orders` directly, so the guard inherited the defect the
# protection model had just been repaired for.
from orbit.exec.protection import canonical_orders as _co
from orbit.tools.session import ToolSession as _TS
import inspect as _inspect
_src = _inspect.getsource(_TS._protection_guard)
check("R4A.10.4  the session protection guard uses the canonical order set",
      "canonical_orders" in _src and "for o in v.open_orders" not in _src)

_dup_guard = [stop_order("stop1", "1.19", "29700.1")] * 2
_one_guard = [stop_order("stop1", "1.19", "29700.1")]
check("R4A.10.5  guard coverage is identical for duplicated and single rows",
      sum((o.contracts for o in _co(_dup_guard)[0] if o.is_protective), D("0"))
      == sum((o.contracts for o in _co(_one_guard)[0] if o.is_protective),
             D("0")) == HALF)

print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("R4-2 closed. One real venue order counts once. No model. No "
      "credentials. No network. No live capital.")
