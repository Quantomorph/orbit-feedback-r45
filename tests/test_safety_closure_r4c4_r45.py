"""
tests/test_safety_closure_r4c4_r45.py — SAFETY CLOSURE R4-5.

THE DEFECT THIS SUITE EXISTS FOR.

    Freshness was decided by a ONE-SIDED comparison, in two independent places:

        orbit/exec/recon.py   age = (now - view.fetched_at).total_seconds()
                              if age > limits.max_data_age_seconds: ...

        orbit/risk/gateway.py age = s.data_age_seconds
                              if age > self.limits.max_data_age_seconds: ...

    Both ask only whether an observation is too OLD. Neither asked whether it
    could exist at all. A view stamped in the FUTURE yields a NEGATIVE age,
    which is not greater than any positive limit, so BOTH gates passed it.

    Reproduced on the accepted baseline 45c0081, exactly as filed:

        fetched_at = NOW + 600s, server_time = None
          -> age = -600.0
          -> findings = []
          -> run_state = RUNNING
          -> Gateway APPROVES the OPEN

    DIRECTION: fail-open, and monotonically worse — the further into the future
    the timestamp, the fresher the data looked. A venue (or an adapter, or a
    clock) that reported tomorrow's time would have been believed absolutely.

    A SECOND, INDEPENDENT ROUTE TO THE SAME CLAIM. The venue-clock comparison
    ran only `if view.server_time is not None`. An observation carrying NO
    server_time skipped the check entirely and was treated as fresh BECAUSE a
    timestamp was missing. Absence of evidence was read as evidence of
    soundness.

WHAT THE REPAIR IS.

    `age < 0` is refused in its own right, under its OWN finding code, at the
    reconciler AND independently at the gateway. `server_time is None` is
    refused under its own code. Neither is clamped: `max(age, 0)` would turn an
    impossible timestamp into maximally fresh data and erase the evidence.

    NO TOLERANCE IS INTRODUCED. Both sides of `now - fetched_at` are the LOCAL
    clock, so no venue skew enters this comparison and there is nothing to
    forgive. The condition is exactly `age < 0`; `age == 0` is a legitimate
    instantaneous read and is NOT refused.

WHAT IS ASSERTED HERE.

    A  the filed fail-open shape is refused, with a dedicated finding
    B  future fetched_at WITH server_time present is still refused
    C  missing server_time yields no positive freshness claim
    D  valid observations are unchanged — the repair does not reject everything
    E  age == 0 is NOT rejected by the future-time rule
    F  the smallest constructible negative age (1 microsecond) IS refused
    G  existing stale behaviour is intact, and impossible-time is at least as
       restrictive as it
    H  no unrelated gateway permission changed
    I  the gateway refuses independently of the reconciler
    J  nothing is clamped, and the existing server-clock semantic is preserved

    R4-5 IS NOT CLOSED BY THIS SUITE. It is a candidate awaiting independent
    adversarial review and owner acceptance. Trigger gamma remains blocked.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import sys
from datetime import timedelta
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, flat, held, pos, stop_order
from orbit.exec.protection import MarginMode
from orbit.exec.recon import F, Disposition, ExchangeView, RunState, reconcile
from orbit.exec.resolver import is_eligible_evidence
from orbit.risk.gateway import Code, Gateway, Kind, ProposedAction
from orbit.risk.limits import A1
from orbit.risk.state import SystemState

PASS, FAIL = [], []
GW = Gateway()

# The smallest age below zero this implementation can construct: `datetime`
# resolves to one microsecond, so one microsecond into the future is the first
# value the rule must refuse. Anything smaller is not representable.
ONE_TICK = timedelta(microseconds=1)


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def banner(t):
    print("\n" + "-" * 78)
    print(t)
    print("-" * 78)


def view(fetched_delta, server_time, position=None, orders=()):
    """An otherwise entirely healthy observation. Every field but the two under
    test is the clean case, so a refusal can only come from the clocks."""
    return ExchangeView(
        fetched_at=NOW + fetched_delta, reachable=True, consistent=True,
        server_time=server_time, equity=D("1000"), mark_price=D("30000"),
        margin_mode=MarginMode.UNKNOWN, position=position,
        open_orders=tuple(orders), fills=(), can_place_orders=True)


def opened(r, decision="r45"):
    return GW.evaluate(ProposedAction(decision, Kind.OPEN, "BTC-USDT-SWAP",
                                      "long", entry_type="market",
                                      stop=D("29700")), r.to_system_state())


print("=" * 78)
print("ORBIT — SAFETY CLOSURE R4-5: future-dated observations (CANDIDATE)")
print("=" * 78)

# ======================================================================
banner("R45.A  THE FILED FAIL-OPEN SHAPE — future fetched_at, no server_time")
# ======================================================================
# The exact shape recorded in the master context at 8.4.3 and reproduced on the
# untouched baseline before any production edit.
vA = view(timedelta(seconds=600), None)
rA = reconcile(flat(), vA, NOW)
gA = opened(rA, "r45a")
ageA = (NOW - vA.fetched_at).total_seconds()

check("R45.A.1 the filed shape still computes a negative age — the defect is "
      "not hidden by rewriting the arithmetic",
      ageA == -600.0, f"age={ageA}")
check("R45.A.2 it raises the DEDICATED impossible-time finding",
      F.FUTURE_DATED_EXCHANGE_VIEW in rA.codes(), str(rA.codes()))
check("R45.A.3 that finding is NOT the stale-data finding: 'old' and "
      "'impossible' are different diagnoses",
      F.STALE_EXCHANGE_VIEW not in rA.codes(), str(rA.codes()))
check("R45.A.4 findings are no longer empty",
      len(rA.findings) > 0, str(rA.codes()))
check("R45.A.5 run_state is no longer RUNNING",
      rA.run_state is not RunState.RUNNING, rA.run_state.value)
check("R45.A.6 run_state is RECONCILING — we cannot place the observation in "
      "time, so we are blind, not merely cautious",
      rA.run_state is RunState.RECONCILING, rA.run_state.value)
check("R45.A.7 the view is not reconciled",
      not rA.reconciled)
check("R45.A.8 THE GATEWAY REFUSES THE OPEN — the fail-open is closed",
      not gA.approved, f"{gA.code.value}")
# Written to be TOTAL: under a mutant that removes the finding entirely this
# must report a clean failure, not raise. A suite that crashes tells a reviewer
# only that something broke.
_fd = [f.detail for f in rA.findings
       if f.code is F.FUTURE_DATED_EXCHANGE_VIEW]
check("R45.A.9 the refusal detail preserves the evidence: it states how far "
      "into the future the observation claimed to be",
      len(_fd) == 1 and "600" in _fd[0] and "FUTURE" in _fd[0],
      _fd[0] if _fd else "no FUTURE_DATED_EXCHANGE_VIEW finding")
check("R45.A.10 the missing venue clock is ALSO reported, as its own finding — "
      "the shape has two independent defects and names both",
      F.SERVER_TIME_UNAVAILABLE in rA.codes(), str(rA.codes()))

# ======================================================================
banner("R45.B  FUTURE fetched_at WITH server_time PRESENT")
# ======================================================================
# Supplying a venue clock must not buy the observation a pass: the age is still
# negative, and that is the condition being refused.
vB = view(timedelta(seconds=600), NOW)
rB = reconcile(flat(), vB, NOW)
gB = opened(rB, "r45b")

check("R45.B.1 a present, correct server_time does not excuse a future "
      "fetched_at",
      F.FUTURE_DATED_EXCHANGE_VIEW in rB.codes(), str(rB.codes()))
check("R45.B.2 and no missing-server_time finding is raised, so the refusal is "
      "attributable to the future timestamp alone",
      F.SERVER_TIME_UNAVAILABLE not in rB.codes(), str(rB.codes()))
check("R45.B.3 exactly one finding — the diagnosis is specific",
      len(rB.findings) == 1, str(rB.codes()))
check("R45.B.4 the OPEN is refused",
      not gB.approved, gB.code.value)

# ======================================================================
banner("R45.C  MISSING server_time WITH AN OTHERWISE VALID fetched_at")
# ======================================================================
# Invariant 2: server_time presence is REQUIRED for a positive freshness claim.
# A missing timestamp must not be the reason an observation looks fresh.
vC = view(-timedelta(seconds=5), None)
rC = reconcile(flat(), vC, NOW)
gC = opened(rC, "r45c")

check("R45.C.1 a missing venue clock raises its own finding",
      F.SERVER_TIME_UNAVAILABLE in rC.codes(), str(rC.codes()))
check("R45.C.2 it is not reported as a future-dated view — the fetched_at is "
      "perfectly ordinary",
      F.FUTURE_DATED_EXCHANGE_VIEW not in rC.codes(), str(rC.codes()))
check("R45.C.3 no positive freshness claim survives: the state is not "
      "reconciled",
      not rC.reconciled)
check("R45.C.4 run_state is blocking",
      rC.run_state is RunState.RECONCILING, rC.run_state.value)
check("R45.C.5 the OPEN is refused — absence of a timestamp is not freshness",
      not gC.approved, gC.code.value)

# ======================================================================
banner("R45.D  VALID CONTROL — the repair must not simply reject everything")
# ======================================================================
vD = view(-timedelta(seconds=5), NOW)
rD = reconcile(flat(), vD, NOW)
gD = opened(rD, "r45d")

check("R45.D.1 an ordinary healthy observation raises NO finding",
      list(rD.codes()) == [], str(rD.codes()))
check("R45.D.2 it reconciles",
      rD.reconciled)
check("R45.D.3 run_state is RUNNING",
      rD.run_state is RunState.RUNNING, rD.run_state.value)
check("R45.D.4 and the gateway still APPROVES a well-formed OPEN — the system "
      "can still trade",
      gD.approved, gD.code.value)

# ======================================================================
banner("R45.E  EXACT ZERO BOUNDARY — age == 0 is NOT rejected")
# ======================================================================
# An instantaneous read is legal. The rule is `age < 0`, not `age <= 0`.
vE = view(timedelta(0), NOW)
rE = reconcile(flat(), vE, NOW)
gE = opened(rE, "r45e")

check("R45.E.1 age is exactly 0.0",
      (NOW - vE.fetched_at).total_seconds() == 0.0)
check("R45.E.2 age == 0 raises NO future-dated finding",
      F.FUTURE_DATED_EXCHANGE_VIEW not in rE.codes(), str(rE.codes()))
check("R45.E.3 age == 0 raises no finding at all",
      list(rE.codes()) == [], str(rE.codes()))
check("R45.E.4 age == 0 still RUNNING",
      rE.run_state is RunState.RUNNING, rE.run_state.value)
check("R45.E.5 and the OPEN is still approved at the boundary",
      gE.approved, gE.code.value)

# ======================================================================
banner("R45.F  FIRST NEGATIVE BOUNDARY — one microsecond into the future")
# ======================================================================
# The smallest negative age the implementation can represent must already be
# refused. A rule that only catches large excursions is a tolerance by
# accident, and no tolerance is authorised here.
vF = view(ONE_TICK, NOW)
rF = reconcile(flat(), vF, NOW)
gF = opened(rF, "r45f")
ageF = (NOW - vF.fetched_at).total_seconds()

check("R45.F.1 one microsecond ahead is a representable negative age",
      ageF < 0 and ageF == -1e-06, f"age={ageF!r}")
check("R45.F.2 the SMALLEST constructible negative age is refused — there is "
      "no epsilon, grace period or tolerance",
      F.FUTURE_DATED_EXCHANGE_VIEW in rF.codes(), str(rF.codes()))
check("R45.F.3 it is blocking, not advisory",
      rF.run_state is RunState.RECONCILING and not rF.reconciled,
      rF.run_state.value)
check("R45.F.4 and the OPEN is refused at the first tick below zero",
      not gF.approved, gF.code.value)

# ======================================================================
banner("R45.G  EXISTING STALE BEHAVIOUR — intact, and not weakened")
# ======================================================================
vG = view(-timedelta(seconds=720), NOW)
rG = reconcile(flat(), vG, NOW)
gG = opened(rG, "r45g")

check("R45.G.1 a genuinely old view still raises STALE_EXCHANGE_VIEW",
      F.STALE_EXCHANGE_VIEW in rG.codes(), str(rG.codes()))
check("R45.G.2 and is not mislabelled as future-dated",
      F.FUTURE_DATED_EXCHANGE_VIEW not in rG.codes(), str(rG.codes()))
check("R45.G.3 stale is still refused",
      not gG.approved, gG.code.value)
check("R45.G.4 THE IMPOSSIBLE-TIME REFUSAL IS AT LEAST AS RESTRICTIVE AS THE "
      "STALE REFUSAL — same disposition, same run_state, both refused",
      rA.worst >= rG.worst and rA.run_state is rG.run_state
      and rA.reconciled == rG.reconciled and not gA.approved,
      f"future={rA.worst.name}/{rA.run_state.value} "
      f"stale={rG.worst.name}/{rG.run_state.value}")
check("R45.G.5 the stale boundary itself did not move: one second inside the "
      "limit is still accepted",
      list(reconcile(flat(), view(-timedelta(seconds=A1.max_data_age_seconds),
                                  NOW), NOW).codes()) == [])
check("R45.G.6 and one second outside it is still stale",
      F.STALE_EXCHANGE_VIEW in reconcile(
          flat(), view(-timedelta(seconds=A1.max_data_age_seconds + 1), NOW),
          NOW).codes())

# ======================================================================
banner("R45.H  NO UNRELATED GATEWAY PERMISSION CHANGED")
# ======================================================================
# The repair touched ONE clause of the gateway. Every neighbouring refusal must
# still refuse for its ORIGINAL reason, and the healthy path must still pass.
check("R45.H.1 a healthy OPEN is still approved (see D.4)",
      gD.approved, gD.code.value)
check("R45.H.2 a stale snapshot is still refused as STALE_DATA when it reaches "
      "the gateway directly",
      GW.evaluate(
          ProposedAction("r45h2", Kind.OPEN, "BTC-USDT-SWAP", "long",
                         entry_type="market", stop=D("29700")),
          SystemState(now=NOW, data_as_of=NOW - timedelta(seconds=720),
                      mark_price=D("30000"), equity=D("1000"), position=None,
                      realized_pnl_utc_day=D("0"), entries_utc_day=0,
                      run_state=RunState.RUNNING, environment="DEMO",
                      reconciled=True)).code is Code.STALE_DATA)
check("R45.H.3 the wrong instrument is still WRONG_INSTRUMENT",
      GW.evaluate(ProposedAction("r45h3", Kind.OPEN, "ETH-USDT-SWAP", "long",
                                 entry_type="market", stop=D("29700")),
                  rD.to_system_state()).code is Code.WRONG_INSTRUMENT)
check("R45.H.4 a missing stop is still refused for its own reason",
      GW.evaluate(ProposedAction("r45h4", Kind.OPEN, "BTC-USDT-SWAP", "long",
                                 entry_type="market"),
                  rD.to_system_state()).code is Code.STOP_MISSING)
check("R45.H.5 a non-acting decision is still always valid",
      GW.evaluate(ProposedAction("r45h5", Kind.NO_TRADE, "BTC-USDT-SWAP"),
                  rA.to_system_state()).approved)
check("R45.H.6 HALTED still outranks the freshness clause: a halted state is "
      "reported as HALTED, not re-diagnosed",
      GW.evaluate(
          ProposedAction("r45h6", Kind.OPEN, "BTC-USDT-SWAP", "long",
                         entry_type="market", stop=D("29700")),
          SystemState(now=NOW, data_as_of=NOW + timedelta(seconds=600),
                      mark_price=D("30000"), equity=D("1000"), position=None,
                      realized_pnl_utc_day=D("0"), entries_utc_day=0,
                      run_state=RunState.HALTED, environment="DEMO",
                      reconciled=True)).code is Code.HALTED)

# ======================================================================
banner("R45.I  THE GATEWAY REFUSES INDEPENDENTLY OF THE RECONCILER")
# ======================================================================
# The gateway owns its own freshness decision. If some future producer of
# SystemState ever hands it a future-dated snapshot that claims to be
# reconciled and RUNNING, the gateway must still refuse — and under its own
# diagnosis, not as ordinary staleness.
future_state = SystemState(
    now=NOW, data_as_of=NOW + timedelta(seconds=600), mark_price=D("30000"),
    equity=D("1000"), position=None, realized_pnl_utc_day=D("0"),
    entries_utc_day=0, run_state=RunState.RUNNING, environment="DEMO",
    reconciled=True)
gI = GW.evaluate(ProposedAction("r45i", Kind.OPEN, "BTC-USDT-SWAP", "long",
                                entry_type="market", stop=D("29700")),
                 future_state)

check("R45.I.1 SystemState.data_age_seconds is negative",
      future_state.data_age_seconds == -600.0,
      str(future_state.data_age_seconds))
check("R45.I.2 the gateway refuses a future-dated snapshot even when the state "
      "claims RUNNING and reconciled",
      not gI.approved, gI.code.value)
check("R45.I.3 under its OWN code, not STALE_DATA",
      gI.code is Code.FUTURE_DATED_DATA, gI.code.value)
check("R45.I.4 and the refusal carries the age as evidence, unclamped",
      "future" in gI.reason.lower()
      and gI.computed.get("data_age_seconds") == -600.0,
      f"{gI.reason} / {gI.computed}")
check("R45.I.5 the gateway's own zero boundary is unchanged: age == 0 passes",
      GW.evaluate(
          ProposedAction("r45i5", Kind.OPEN, "BTC-USDT-SWAP", "long",
                         entry_type="market", stop=D("29700")),
          SystemState(now=NOW, data_as_of=NOW, mark_price=D("30000"),
                      equity=D("1000"), position=None,
                      realized_pnl_utc_day=D("0"), entries_utc_day=0,
                      run_state=RunState.RUNNING, environment="DEMO",
                      reconciled=True)).approved)
check("R45.I.6 and one microsecond into the future is refused there too",
      GW.evaluate(
          ProposedAction("r45i6", Kind.OPEN, "BTC-USDT-SWAP", "long",
                         entry_type="market", stop=D("29700")),
          SystemState(now=NOW, data_as_of=NOW + ONE_TICK,
                      mark_price=D("30000"), equity=D("1000"), position=None,
                      realized_pnl_utc_day=D("0"), entries_utc_day=0,
                      run_state=RunState.RUNNING, environment="DEMO",
                      reconciled=True)).code is Code.FUTURE_DATED_DATA)

# ======================================================================
banner("R45.J  NOTHING IS CLAMPED, AND THE SERVER-CLOCK SEMANTIC IS PRESERVED")
# ======================================================================
# If the negative age were clamped to zero the observation would be reported as
# maximally FRESH, the finding would disappear, and the evidence of the defect
# would be gone. The age reported must stay negative.
check("R45.J.1 the age carried into SystemState is still negative — it is "
      "refused, not clamped to zero",
      rA.to_system_state().data_age_seconds == -600.0,
      str(rA.to_system_state().data_age_seconds))
check("R45.J.2 a clamped implementation would have reported 0.0 and approved; "
      "this one reports the real number and refuses",
      rA.to_system_state().data_age_seconds < 0 and not gA.approved)

# The existing venue-clock comparison (recon.py, `abs(server_time - now)`) is a
# DIFFERENT clock pair with its own filed thresholds. R4-5 does not touch it,
# and these assertions exist so that a later change cannot quietly remove it.
vJ_severe = view(-timedelta(seconds=5), NOW + timedelta(seconds=600))
rJ_severe = reconcile(flat(), vJ_severe, NOW)
vJ_mild = view(-timedelta(seconds=5), NOW + timedelta(seconds=30))
rJ_mild = reconcile(flat(), vJ_mild, NOW)

check("R45.J.3 a future SERVER_TIME is still CLOCK_SKEW_SEVERE — a production "
      "path does compare the venue clock to ours, and R4-5 did not disturb it",
      F.CLOCK_SKEW_SEVERE in rJ_severe.codes(), str(rJ_severe.codes()))
check("R45.J.4 and it still HALTS, which is stricter than the R4-5 refusal",
      rJ_severe.run_state is RunState.HALTED, rJ_severe.run_state.value)
check("R45.J.5 a future server_time is NOT re-diagnosed as a future-dated view: "
      "the two clock pairs keep separate vocabularies",
      F.FUTURE_DATED_EXCHANGE_VIEW not in rJ_severe.codes(),
      str(rJ_severe.codes()))
check("R45.J.6 the moderate skew band is unchanged",
      F.CLOCK_SKEW in rJ_mild.codes(), str(rJ_mild.codes()))
check("R45.J.7 skew is measured with abs(), so a BEHIND venue clock is caught "
      "identically — unchanged by this repair",
      F.CLOCK_SKEW_SEVERE in reconcile(
          flat(), view(-timedelta(seconds=5), NOW - timedelta(seconds=600)),
          NOW).codes())

# The evidence-eligibility path consumes the ReconResult rather than the raw
# view. It is NOT modified by this repair; this records that it is closed
# transitively, so a reviewer can see the claim was checked and not assumed.
check("R45.J.8 the evidence-eligibility path is transitively closed: the filed "
      "shape no longer qualifies as evidence for terminalising an operation",
      not is_eligible_evidence(rA).eligible, is_eligible_evidence(rA).reason)
check("R45.J.9 and a missing server_time likewise no longer qualifies",
      not is_eligible_evidence(rC).eligible, is_eligible_evidence(rC).reason)
check("R45.J.10 while a healthy observation still does — not everything was "
      "refused",
      is_eligible_evidence(rD).eligible, is_eligible_evidence(rD).reason)

# The refusal must not depend on the account being flat: a future-dated view
# while holding a position is refused the same way.
rJ_pos = reconcile(held(), view(timedelta(seconds=600), NOW,
                                position=pos(), orders=(stop_order(),)), NOW)
check("R45.J.11 the refusal does not depend on being flat — a held position "
      "observed from the future is refused too",
      F.FUTURE_DATED_EXCHANGE_VIEW in rJ_pos.codes()
      and rJ_pos.run_state is not RunState.RUNNING, str(rJ_pos.codes()))

# ======================================================================
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
for f in FAIL:
    print(f"  FAILED: {f}")
sys.exit(1 if FAIL else 0)
