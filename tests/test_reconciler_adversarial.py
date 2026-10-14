"""
tests/test_reconciler_adversarial.py — FAULT INJECTION AGAINST RECONCILIATION.

ORBIT-AGENT-ARCH-001, build step 4 verification.

Covers every discrepancy class named in the step-4 approval, asserts the
disposition assigned to each, and then PROVES the invariant that the whole
layer exists for:

    If ORBIT cannot establish a trustworthy view of account / position / order
    state, ORBIT cannot open a new position.

The proof is not a claim in a docstring. Every scenario below is run end to end
through the real reconciler and the real gateway, and an OPEN is attempted. The
test fails if an OPEN is ever approved on anything but a clean reconciliation.

No model. No credentials. No network.

Run:  python tests/test_reconciler_adversarial.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

sys.path.insert(0, ".")

from orbit.exec.protection import MarginMode, assess
from orbit.exec.recon import (Disposition, ExchangeOrder, ExchangePosition,
                              ExchangeView, F, Fill, IntendedPosition,
                              IntendedState, OrderStatus, Remedy, SubmittedOrder,
                              reconcile)
from orbit.risk.gateway import Code, Gateway, Kind, ProposedAction
from orbit.risk.limits import A1, RunState

PASS, FAIL = [], []
GW = Gateway()
NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))
    return ok


def banner(t):
    print("\n" + "-" * 74)
    print(t)


# ---------------------------------------------------------------- builders
def ipos(side="long", contracts="2.38", entry="30000", stop="29700", cid="stop1"):
    return IntendedPosition(side, D(contracts), D(entry), D(stop), cid,
                            NOW - timedelta(minutes=30))


def intended(position=None, orders=(), journal=True, entries=0, pnl="0",
             clean=True):
    return IntendedState(journal_loaded=journal, position=position,
                         submitted_orders=tuple(orders),
                         entries_utc_day=entries, realized_pnl_utc_day=D(pnl),
                         clean_shutdown=clean)


def held(position, extra=()):
    """Intended state for a position ORBIT actually opened: the entry fill AND
    the protective order are recorded. The first version of this file omitted
    the protective order, so the exchange's own stop looked ORPHANED and several
    scenarios passed for the wrong reason. Fixed 2026-09-07."""
    # entries=1: a held position implies at least one entry today. The first
    # version omitted this, so every position fixture was internally
    # inconsistent -- caught by the DAY_COUNTERS_UNRELIABLE check added with
    # the crash-recovery work.
    return intended(position,
                    [SubmittedOrder("e1", position.contracts, position.contracts,
                                    OrderStatus.FILLED, NOW),
                     SubmittedOrder("stop1", position.contracts, D("0"),
                                    OrderStatus.ACK, NOW, True)] + list(extra),
                    entries=1)


def view(position=None, orders=(), fills=(), reachable=True, consistent=True,
         age_s=5, skew_s=0, equity="1000", mark="30000",
         can_place=True, fails=0, margin=MarginMode.UNKNOWN, iso=None):
    return ExchangeView(
        fetched_at=NOW - timedelta(seconds=age_s), reachable=reachable,
        consistent=consistent,
        server_time=NOW + timedelta(seconds=skew_s),
        equity=D(equity), mark_price=D(mark), margin_mode=margin,
        position=position, open_orders=tuple(orders), fills=tuple(fills),
        consecutive_failures=fails, can_place_orders=can_place,
        isolated_margin_posted=iso)


def xpos(side="long", contracts="2.38", entry="30000"):
    return ExchangePosition(side, D(contracts), D(entry))


def stop_order(cid="stop1", contracts="2.38", price="29700"):
    return ExchangeOrder(cid, D(contracts), True, D(price))


print("=" * 74)
print("ORBIT A1 — RECONCILER FAULT INJECTION")
print("=" * 74)

# ======================================================================
# The scenario table. Every row is run through recon AND the gateway.
# ======================================================================
CLEAN_FLAT = ("clean: flat everywhere", intended(), view(), Disposition.SAFE_TO_RECONCILE, None)
CLEAN_POS = ("clean: position matches and is protected",
             held(ipos()), view(xpos(), [stop_order()]),
             Disposition.SAFE_TO_RECONCILE, None)

SCENARIOS = [
    CLEAN_FLAT, CLEAN_POS,

    ("1  phantom exchange position (unprotected)",
     intended(), view(xpos()), Disposition.EMERGENCY_CLOSE, F.PHANTOM_POSITION),
    # EXPECTATION CORRECTED: a protected phantom is still a position ORBIT did
    # not open. REQUIRE_HUMAN_REVIEW is the right call, not BLOCK.
    ("1b phantom exchange position (protected)",
     intended(), view(xpos(), [stop_order("alien")]),
     Disposition.REQUIRE_HUMAN_REVIEW, F.PHANTOM_POSITION),

    ("2  local position missing on exchange, unexplained",
     intended(ipos()), view(), Disposition.REQUIRE_HUMAN_REVIEW,
     F.POSITION_MISSING_ON_EXCHANGE),
    ("2b local position missing, explained by a protective fill",
     intended(ipos(), [SubmittedOrder("stop1", D("2.38"), D("2.38"),
                                      OrderStatus.FILLED, NOW, True)]),
     view(fills=[Fill("f1", "stop1", D("2.38"))]),
     Disposition.SAFE_TO_RECONCILE, F.POSITION_CLOSED_EXPLAINED),

    ("3  position with no protective stop (can place)",
     held(ipos()), view(xpos()), Disposition.BLOCK_NEW_ENTRIES,
     F.POSITION_UNPROTECTED),
    ("3b position with no protective stop (cannot place)",
     held(ipos()), view(xpos(), can_place=False),
     Disposition.EMERGENCY_CLOSE, F.POSITION_UNPROTECTED),

    ("4  wrong stop price — WIDER than intended",
     held(ipos()), view(xpos(), [stop_order(price="29500")]),
     Disposition.BLOCK_NEW_ENTRIES, F.STOP_PRICE_WIDER_THAN_INTENDED),
    ("4b wrong stop price — tighter than intended",
     held(ipos()), view(xpos(), [stop_order(price="29800")]),
     Disposition.SAFE_TO_RECONCILE, F.STOP_PRICE_TIGHTER_THAN_INTENDED),

    ("5  wrong position size — LARGER than intended",
     held(ipos()), view(xpos(contracts="5.00"), [stop_order(contracts="5.00")]),
     Disposition.EMERGENCY_CLOSE, F.POSITION_LARGER_THAN_INTENDED),
    # EXPECTATION CORRECTED (safety closure, blocker D): adopting the smaller
    # position is safe, but it leaves protection to be RESIZED, and that work
    # has not been done when reconcile() returns. Reporting SAFE_TO_RECONCILE
    # here let the system open a SECOND position alongside one whose stop still
    # covered the wrong size. Outstanding remediation blocks new entries.
    ("5b wrong position size — smaller than intended",
     held(ipos()), view(xpos(contracts="1.00"), [stop_order(contracts="1.00")]),
     Disposition.BLOCK_NEW_ENTRIES, F.POSITION_SMALLER_THAN_INTENDED),

    ("6  partial fill",
     held(ipos(contracts="2.38"),
          [SubmittedOrder("e1b", D("2.38"), D("1.00"), OrderStatus.ACK, NOW)]),
     view(xpos(contracts="1.00"), [stop_order(contracts="1.00")]),
     Disposition.BLOCK_NEW_ENTRIES, F.PARTIAL_FILL),

    ("7  unknown fill / outcome not established",
     intended(None, [SubmittedOrder("e9", D("2.38"), D("0"),
                                    OrderStatus.UNKNOWN, NOW)]),
     view(), Disposition.BLOCK_NEW_ENTRIES, F.UNKNOWN_ORDER_STATUS),
    ("7b unknown fill still unresolved after 3 attempts",
     intended(None, [SubmittedOrder("e9", D("2.38"), D("0"),
                                    OrderStatus.UNKNOWN, NOW, False, 3)]),
     view(), Disposition.REQUIRE_HUMAN_REVIEW, F.UNKNOWN_ORDER_UNRESOLVED),

    ("8  duplicate fill event (same fill_id twice)",
     held(ipos()), view(xpos(), [stop_order()],
          fills=[Fill("f1", "e1", D("2.38")), Fill("f1", "e1", D("2.38"))]),
     Disposition.SAFE_TO_RECONCILE, F.DUPLICATE_FILL_EVENT),
    ("8b genuine double execution (two distinct fills, one intent)",
     held(ipos()), view(xpos(contracts="4.76"), [stop_order(contracts="4.76")],
          fills=[Fill("f1", "e1", D("2.38")), Fill("f2", "e1", D("2.38"))]),
     Disposition.EMERGENCY_CLOSE, F.DOUBLE_EXECUTION),

    ("9  order accepted but response lost -> resolved by client id",
     intended(None, [SubmittedOrder("e9", D("2.38"), D("0"),
                                    OrderStatus.UNKNOWN, NOW)]),
     view(orders=[ExchangeOrder("e9", D("2.38"), False)]),
     Disposition.SAFE_TO_RECONCILE, F.UNKNOWN_RESOLVED_BY_CLIENT_ID),

    ("10 connection loss immediately after submission",
     intended(None, [SubmittedOrder("e9", D("2.38"), D("0"),
                                    OrderStatus.UNKNOWN, NOW)]),
     view(reachable=False), Disposition.BLOCK_NEW_ENTRIES, F.EXCHANGE_UNREACHABLE),
    ("10b connection loss, persistent",
     intended(), view(reachable=False, fails=3),
     Disposition.REQUIRE_HUMAN_REVIEW, F.EXCHANGE_UNREACHABLE_PERSISTENT),

    ("11 stale exchange state",
     intended(), view(age_s=600), Disposition.BLOCK_NEW_ENTRIES,
     F.STALE_EXCHANGE_VIEW),

    ("12 contradictory exchange responses",
     intended(), view(consistent=False), Disposition.REQUIRE_HUMAN_REVIEW,
     F.EXCHANGE_INCONSISTENT),

    ("13 orphaned open order (not ours)",
     intended(), view(orders=[ExchangeOrder("someone-else", D("1"), False)]),
     Disposition.BLOCK_NEW_ENTRIES, F.ORPHANED_ORDER),

    ("14 orphaned protective order (no position behind it)",
     intended(None, [SubmittedOrder("stop1", D("2.38"), D("0"),
                                    OrderStatus.ACK, NOW, True)]),
     view(orders=[stop_order()]), Disposition.BLOCK_NEW_ENTRIES,
     F.ORPHANED_PROTECTIVE_ORDER),

    ("15 clock skew within severity",
     intended(), view(skew_s=30), Disposition.BLOCK_NEW_ENTRIES, F.CLOCK_SKEW),
    ("15b clock skew severe",
     intended(), view(skew_s=300), Disposition.REQUIRE_HUMAN_REVIEW,
     F.CLOCK_SKEW_SEVERE),

    ("16 restart with an existing exchange position, unprotected",
     intended(journal=False), view(xpos()), Disposition.EMERGENCY_CLOSE,
     F.COLD_START_WITH_POSITION),
    ("16b restart with an existing exchange position, protected",
     intended(journal=False), view(xpos(), [stop_order()]),
     Disposition.REQUIRE_HUMAN_REVIEW, F.COLD_START_WITH_POSITION),
    ("16c restart with no journal and no position",
     intended(journal=False), view(), Disposition.BLOCK_NEW_ENTRIES,
     F.JOURNAL_UNAVAILABLE),

    ("17 duplicate submission after timeout, exchange shows one order",
     intended(None, [SubmittedOrder("e9", D("2.38"), D("0"),
                                    OrderStatus.UNKNOWN, NOW)]),
     view(orders=[ExchangeOrder("e9", D("2.38"), False)]),
     Disposition.SAFE_TO_RECONCILE, F.UNKNOWN_RESOLVED_BY_CLIENT_ID),

    ("18 exchange reports CLOSED while local says open",
     intended(ipos()), view(), Disposition.REQUIRE_HUMAN_REVIEW,
     F.POSITION_MISSING_ON_EXCHANGE),

    ("19 exchange reports OPEN while local says closed",
     intended(), view(xpos()), Disposition.EMERGENCY_CLOSE, F.PHANTOM_POSITION),

    ("20 side disagreement (exchange short, ORBIT intended long)",
     held(ipos("long")), view(xpos("short"), [stop_order()]),
     Disposition.EMERGENCY_CLOSE, F.EXCHANGE_INCONSISTENT),

    ("21 protective order covers only part of the position",
     held(ipos()), view(xpos(), [stop_order(contracts="1.00")]),
     Disposition.BLOCK_NEW_ENTRIES, F.STOP_SIZE_MISMATCH),
]

banner("SCENARIO DISPOSITIONS")
results = []
for name, i, v, want_disp, want_code in SCENARIOS:
    r = reconcile(i, v, NOW)
    results.append((name, r, want_disp))
    ok_disp = r.worst is want_disp
    ok_code = want_code is None or want_code in r.codes()
    check(f"{name}", ok_disp and ok_code,
          f"{r.worst.name} {[c.value for c in r.codes()]}")

# ======================================================================
banner("THE INVARIANT — no trustworthy view, no new position")
# ======================================================================
approved_on, violations = [], []
for name, r, _ in results:
    st = r.to_system_state()
    act = ProposedAction("inv-" + name[:6], Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                         stop=D("29700"))
    v = GW.evaluate(act, st)
    if v.approved:
        approved_on.append(name)
        if not r.clean:
            violations.append((name, r.worst.name, r.reconciled))

check("I1. an OPEN is approved ONLY on a clean reconciliation",
      not violations, str(violations))
check("I2. every non-clean scenario blocked the OPEN",
      all(not GW.evaluate(ProposedAction("i2-" + n[:6], Kind.OPEN,
                                         "BTC-USDT-SWAP", "long",
                                         entry_type="market",
                                         stop=D("29700")),
                          r.to_system_state()).approved
          for n, r, _ in results if not r.clean))
check("I3. the invariant test is NOT vacuous — the clean flat case does open",
      len(approved_on) >= 1, f"opened on: {approved_on}")
check("I4. reconciled is False whenever any finding is untrustworthy",
      all(r.reconciled == (all(f.view_trustworthy for f in r.findings)
                           and r.worst <= Disposition.BLOCK_NEW_ENTRIES)
          for _, r, _ in results))
check("I5. every REQUIRE_HUMAN_REVIEW or EMERGENCY_CLOSE lands in HALTED",
      all(r.run_state is RunState.HALTED for _, r, _ in results
          if r.worst >= Disposition.REQUIRE_HUMAN_REVIEW))
check("I6. no scenario yields RUNNING unless it is fully clean",
      all(r.clean for _, r, _ in results if r.run_state is RunState.RUNNING))
check("I7. every EMERGENCY_CLOSE emits a flatten or escalate remedy",
      all(Remedy.FLATTEN_POSITION in r.remedies or Remedy.ESCALATE_TO_HUMAN in r.remedies
          for _, r, _ in results if r.worst is Disposition.EMERGENCY_CLOSE))
check("I8. a position that is open but unprotected NEVER reconciles clean",
      all(not r.clean for _, r, _ in results
          if F.POSITION_UNPROTECTED in r.codes()))

# ======================================================================
banner("RESTART / RECOVERY — tested as aggressively as first start")
# ======================================================================
# SEMANTICS CORRECTED at step-5 approval: `reconciled` reports whether the
# EXCHANGE view is trustworthy; a missing local journal does not make the
# exchange invisible. So this is reconciled=True with local state untrusted and
# run_state=NO_NEW_ENTRY -- "we can see, and we are choosing not to open".
r = reconcile(intended(journal=False), view(), NOW)
_open = GW.evaluate(ProposedAction("r1", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                                   stop=D("29700")), r.to_system_state())
check("R1. cold start with no journal: exchange view IS trustworthy, local state "
      "is NOT, and the OPEN is refused as NO_NEW_ENTRY",
      not r.clean and r.reconciled and not r.local_state_trusted
      and r.run_state is RunState.NO_NEW_ENTRY
      and _open.code is Code.NO_NEW_ENTRY, r.run_state.value)

r = reconcile(intended(journal=False), view(xpos()), NOW)
check("R2. cold start with an unprotected exchange position -> EMERGENCY_CLOSE + HALTED",
      r.worst is Disposition.EMERGENCY_CLOSE and r.run_state is RunState.HALTED
      and Remedy.FLATTEN_POSITION in r.remedies)

r = reconcile(intended(journal=False), view(xpos(), [stop_order()]), NOW)
check("R3. cold start with a PROTECTED exchange position still requires a human",
      r.run_state is RunState.HALTED and not r.reconciled)

r = reconcile(held(ipos()), view(xpos(), [stop_order()]), NOW)
check("R4. warm restart with a journal that matches the exchange reconciles clean",
      r.clean and r.run_state is RunState.RUNNING)
check("R5. the adopted position carries the VERIFIED exchange stop, not the intended one",
      r.position is not None and r.position.stop_price == D("29700")
      and r.position.stop_order_id == "stop1")

# ======================================================================
banner("PLANNED RISK vs WORST-CASE PROTECTED LOSS")
# ======================================================================
a = assess(D("8"), True, MarginMode.UNKNOWN, None, D("1000"))
check("P1. unknown margin mode establishes NO worst-case bound",
      a.worst_case_protected_loss is None and not a.is_guaranteed)
check("P2. and says why, citing the unverified margin mode",
      "unverified" in a.guarantee_basis)

a = assess(D("8"), True, MarginMode.CROSS, None, D("1000"))
check("P3. cross margin bounds loss only at total equity, and is not a guarantee",
      a.worst_case_protected_loss == D("1000") and not a.is_guaranteed)

a = assess(D("8"), True, MarginMode.ISOLATED, D("150"), D("1000"))
check("P4. isolated margin gives a real structural bound at the margin posted",
      a.worst_case_protected_loss == D("150") and a.is_guaranteed)

txt = a.describe()
check("P5. the sanctioned wording never calls planned risk a maximum",
      "planned risk is NOT a guaranteed maximum loss" in txt
      and "maximum loss" not in txt.split("NOT a guaranteed")[0])
check("P6. planned risk and worst-case bound are reported as separate numbers",
      "$8" in txt and "$150" in txt)

r = reconcile(held(ipos()), view(xpos(), [stop_order()], margin=MarginMode.UNKNOWN),
              NOW)
check("P7. the reconciler attaches a protection assessment to a live position",
      r.protection is not None and r.protection.worst_case_protected_loss is None
      and r.protection.protective_order_verified)

# ======================================================================
banner("DEFAULT BEHAVIOUR — nothing unrecognised continues by default")
# ======================================================================
non_safe = [(n, r) for n, r, _ in results if r.worst > Disposition.SAFE_TO_RECONCILE]
check("Dflt1. every non-SAFE scenario leaves RUNNING",
      all(r.run_state is not RunState.RUNNING for _, r in non_safe),
      f"{len(non_safe)} non-safe scenarios")
check("Dflt2. no scenario in the table silently reconciled clean while carrying "
      "an untrustworthy finding",
      all(all(f.view_trustworthy for f in r.findings)
          for _, r, _ in results if r.clean))
check("Dflt3. HALTED blocks even risk-reducing agent actions (Python protects)",
      all(GW.evaluate(ProposedAction("h-" + n[:6], Kind.CLOSE, "BTC-USDT-SWAP"),
                      r.to_system_state()).code is Code.HALTED
          for n, r, _ in results if r.run_state is RunState.HALTED))

# ======================================================================
banner("C — CRASH AFTER FILL, BEFORE THE FILL WAS RECORDED")
# ======================================================================
# The process died between OKX filling the entry and Python persisting it.
# The journal is READABLE and says position = NONE. The exchange says LONG.
# The rule under test: a missing local record is never evidence that nothing
# happened, and ORBIT must reconstruct and protect rather than destroy a
# position it probably opened itself.

crash_local = intended(
    position=None, clean=False, entries=0,
    orders=[SubmittedOrder("e1", D("2.38"), D("0"), OrderStatus.SUBMITTED, NOW)])
crash_exch = view(xpos("long", "2.38"), fills=[Fill("f1", "e1", D("2.38"))])

r = reconcile(crash_local, crash_exch, NOW)

check("C1. the unrecorded position is identified as OUR OWN fill, not a phantom",
      F.UNRECORDED_OWN_FILL in r.codes() and F.PHANTOM_POSITION not in r.codes(),
      str([c.value for c in r.codes()]))
check("C2. authorship is proved from our deterministic client order id, not inferred",
      "STRONG" in [f.detail for f in r.findings if f.code is F.UNRECORDED_OWN_FILL][0])
check("C3. the dirty shutdown is itself recorded as a finding",
      F.DIRTY_SHUTDOWN in r.codes())
check("C4. ORBIT does NOT flatten a position it probably opened",
      Remedy.FLATTEN_POSITION not in r.remedies, str([x.value for x in r.remedies]))
check("C5. remediation order is reconstruct -> protect -> restore counters",
      (r.remedies.index(Remedy.RECONSTRUCT_POSITION_FROM_EXCHANGE)
       < r.remedies.index(Remedy.PLACE_PROTECTIVE_STOP)
       < r.remedies.index(Remedy.RESTORE_DAY_COUNTERS)),
      " -> ".join(x.value for x in r.remedies))
# The exchange is perfectly visible here -- it is OUR RECORD that is wrong.
# reconciled=True, local state untrusted, no new entries.
check("C6. the exchange view is trustworthy but LOCAL state is not, so trading "
      "does not resume in this cycle",
      r.reconciled and not r.local_state_trusted
      and r.run_state is RunState.NO_NEW_ENTRY and not r.clean, r.run_state.value)
_v = GW.evaluate(ProposedAction("c6", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                                stop=D("29700")), r.to_system_state())
check("C7. an OPEN in the crash cycle is refused as NO_NEW_ENTRY",
      _v.code is Code.NO_NEW_ENTRY, _v.code.value)

r_noplace = reconcile(crash_local, view(xpos("long", "2.38"),
                                        fills=[Fill("f1", "e1", D("2.38"))],
                                        can_place=False), NOW)
check("C8. if protection CANNOT be established, the position is closed instead "
      "of carried unprotected",
      r_noplace.worst is Disposition.EMERGENCY_CLOSE
      and Remedy.FLATTEN_POSITION in r_noplace.remedies)

# --- weaker evidence: no fill record, only an in-flight order --------------
r_weak = reconcile(
    intended(position=None, clean=False, entries=0,
             # SAFETY CLOSURE, blocker C: the fixture now states the side and
             # instrument of the in-flight order. WEAK authorship used to match
             # on SIZE ALONE, so this fixture passed while an in-flight SHORT
             # would have "authorised" adopting a LONG exchange position.
             orders=[SubmittedOrder("e1", D("2.38"), D("0"),
                                    OrderStatus.UNKNOWN, NOW,
                                    instrument="BTC-USDT-SWAP", side="long",
                                    kind="OPEN", role="ENTRY",
                                    reduce_only=False)]),
    view(xpos("long", "2.38")), NOW)
check("C9. an in-flight order matching the exchange position is WEAK evidence "
      "of authorship and still reconstructs rather than flattens",
      F.UNRECORDED_OWN_FILL in r_weak.codes()
      and Remedy.FLATTEN_POSITION not in r_weak.remedies
      and "WEAK" in [f.detail for f in r_weak.findings
                     if f.code is F.UNRECORDED_OWN_FILL][0])

# --- a dirty shutdown alone is enough, even with no evidence at all --------
r_dirty = reconcile(intended(position=None, clean=False), view(xpos()), NOW)
check("C10. after a dirty shutdown, an unexplained position is still "
      "reconstructed, not treated as an intruder",
      F.UNRECORDED_OWN_FILL in r_dirty.codes())

# --- but a CLEAN shutdown with no evidence is a genuine phantom ------------
r_clean_phantom = reconcile(intended(position=None, clean=True), view(xpos()), NOW)
check("C11. after a CLEAN shutdown with no evidence, an exchange position IS "
      "treated as a phantom and flattened",
      F.PHANTOM_POSITION in r_clean_phantom.codes()
      and r_clean_phantom.worst is Disposition.EMERGENCY_CLOSE)

# --- dirty shutdown with nothing open anywhere still blocks ---------------
r_sweep = reconcile(intended(position=None, clean=False), view(), NOW)
check("C12. a dirty shutdown blocks new entries until exchange history is swept, "
      "even when nothing appears to be open",
      not r_sweep.clean and F.DIRTY_SHUTDOWN in r_sweep.codes()
      and Remedy.SWEEP_EXCHANGE_HISTORY in r_sweep.remedies)

# ======================================================================
banner("SEP — reconciled AND run_state ARE SEPARATE CONCEPTS")
# ======================================================================
# 1. reconciled=True  => Python has a trustworthy view of the exchange.
# 2. run_state=RUNNING => new entries are permitted.
# 3. They are different questions and must not be conflated.
# 4. A trustworthy-but-blocked state has reconciled=True and run_state != RUNNING.

blind = reconcile(intended(), view(reachable=False), NOW)
check("SEP1. BLIND: exchange unreachable -> reconciled False, RECONCILING",
      not blind.reconciled and blind.run_state is RunState.RECONCILING)

seeing_blocked = reconcile(
    intended(None, [SubmittedOrder("stop1", D("2.38"), D("0"),
                                   OrderStatus.ACK, NOW, True)]),
    view(orders=[stop_order()]), NOW)
check("SEP2. VISIBLE BUT BLOCKED: an orphaned protective order gives "
      "reconciled=True with run_state=NO_NEW_ENTRY",
      seeing_blocked.reconciled
      and seeing_blocked.run_state is RunState.NO_NEW_ENTRY
      and not seeing_blocked.clean)
_v = GW.evaluate(ProposedAction("sep2", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                                stop=D("29700")), seeing_blocked.to_system_state())
check("SEP3. and the OPEN is refused for the RIGHT reason — NO_NEW_ENTRY, not "
      "NOT_RECONCILED", _v.code is Code.NO_NEW_ENTRY, _v.code.value)

check("SEP4. reconciled=True never on its own implies RUNNING",
      any(r.reconciled and r.run_state is not RunState.RUNNING
          for _, r, _ in results))
check("SEP5. RUNNING always implies reconciled",
      all(r.reconciled for _, r, _ in results
          if r.run_state is RunState.RUNNING))

# ======================================================================
banner("C2 — RECOVERY COMPLETES: the second pass after remediation")
# ======================================================================
# Remedies applied: the position was reconstructed from the exchange, a
# protective stop was placed, day counters were rebuilt, and the journal is
# once again known-good.
recovered_local = intended(
    position=ipos("long", "2.38", "30000", "29700", "stop1"),
    orders=[SubmittedOrder("e1", D("2.38"), D("2.38"), OrderStatus.FILLED, NOW),
            SubmittedOrder("stop1", D("2.38"), D("0"), OrderStatus.ACK, NOW, True)],
    entries=1, clean=True)
r2 = reconcile(recovered_local, view(xpos(), [stop_order()]), NOW)

check("C13. after remediation the state reconciles clean and RUNNING",
      r2.clean and r2.run_state is RunState.RUNNING, r2.run_state.value)
check("C14. the recovered position carries the VERIFIED exchange stop",
      r2.position is not None and r2.position.stop_price == D("29700")
      and r2.position.stop_order_id == "stop1")
_v = GW.evaluate(ProposedAction("c14", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                                stop=D("29700")), r2.to_system_state())
check("C15. trading has resumed, but the one-position rule now binds — the OPEN "
      "is refused as ADD_TO_POSITION, not as NOT_RECONCILED",
      _v.code is Code.ADD_TO_POSITION, _v.code.value)
_v = GW.evaluate(ProposedAction("c15", Kind.MODIFY_STOP, "BTC-USDT-SWAP",
                                new_stop=D("29800")), r2.to_system_state())
check("C16. the recovered position can be managed (stop tightened)", _v.approved)

# --- counters NOT restored: recovery is incomplete and must not resume -----
r3 = reconcile(intended(position=ipos(), orders=recovered_local.submitted_orders,
                        entries=0, clean=True),
               view(xpos(), [stop_order()]), NOW)
check("C17. a recovered position without rebuilt day counters does NOT resume — "
      "the entry limit would be unenforceable",
      not r3.clean and F.DAY_COUNTERS_UNRELIABLE in r3.codes(), r3.run_state.value)

# ======================================================================
banner("C3 — THE RULE, STATED AS A PROPERTY OVER EVERY COMBINATION")
# ======================================================================
bad = []
for clean_sd in (True, False):
    for has_fill in (True, False):
        for in_flight in (True, False):
            for protected in (True, False):
                orders = ([SubmittedOrder("e1", D("2.38"), D("0"),
                                          OrderStatus.UNKNOWN, NOW)]
                          if in_flight else [])
                fills = [Fill("f1", "e1", D("2.38"))] if has_fill else []
                rr = reconcile(
                    intended(position=None, orders=orders, clean=clean_sd),
                    view(xpos(), [stop_order()] if protected else [], fills=fills),
                    NOW)
                st = rr.to_system_state()
                opened = GW.evaluate(
                    ProposedAction("prop", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                                   stop=D("29700")), st).approved
                if rr.clean or rr.run_state is RunState.RUNNING or opened:
                    bad.append((clean_sd, has_fill, in_flight, protected,
                                rr.run_state.value))
check("C18. across all 16 combinations of shutdown/evidence/protection, an "
      "exchange position with no local record NEVER reconciles clean, NEVER "
      "reaches RUNNING, and NEVER permits an OPEN",
      not bad, str(bad))

# ======================================================================
print("\n" + "=" * 74)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 74)
if FAIL:
    for x in FAIL:
        print("  FAILED:", x)
    print("\nGATE CLOSED.")
    sys.exit(1)
print("Reconciliation invariant holds across every injected discrepancy.")
