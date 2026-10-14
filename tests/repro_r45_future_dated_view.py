"""
tests/repro_r45_future_dated_view.py — R4-5 STANDALONE DETERMINISTIC REPRODUCER.

WHAT THIS SCRIPT IS FOR.

    An observation that cannot be placed in time is not evidence of anything,
    and must never authorise an action.

    R4-5 was a violation of that. Freshness was decided by a ONE-SIDED
    comparison, independently in two places:

        orbit/exec/recon.py     if age > limits.max_data_age_seconds
        orbit/risk/gateway.py   if age > self.limits.max_data_age_seconds

    Both ask only whether an observation is too OLD. A view stamped in the
    FUTURE produces a NEGATIVE age, which is not greater than any positive
    limit, so BOTH gates passed it — and the further into the future the
    timestamp, the fresher the data looked.

    A second route reached the same false claim: the venue-clock comparison
    ran only `if view.server_time is not None`, so an observation carrying NO
    server_time skipped it and was treated as fresh BECAUSE a timestamp was
    missing.

HOW THIS SCRIPT IS USED AS EVIDENCE.

    It asserts the REPAIRED property. It is not parameterised by tree, it
    contains no copy of the old behaviour, and it is not told which tree it is
    running on.

        against the repaired tree      -> impossible times are refused, exit 0
        against 45c0081 (pre-R4-5)     -> the fail-open stands, exit 1

    The same bytes run against both trees. The pre-repair evidence is this
    script FAILING, with the approvals it printed — not a second script that
    imitates the defect.

    It uses only API present on BOTH trees. Finding codes are compared as
    STRINGS and the gateway verdict by its boolean, so no enum member added by
    the repair is referenced and no adaptation is needed to run it against
    45c0081.

WHAT IT IS GIVEN.

    Nothing a genuine runtime would not have: an `ExchangeView` of the shape an
    adapter would return, a durable-intent state, and a wall-clock instant. No
    private attribute, no internal of the repair, and no hint of which
    behaviour is expected. Scenario [S1] is additionally re-run in a GENUINE
    SUBPROCESS — a new interpreter given only the repository path — so the
    refusal is shown to be a property of the code on disk rather than of
    anything this process arranged.

THE BOUNDARY THIS PINS.

    age  <  0   is refused, with no tolerance, no grace period and no epsilon
    age ==  0   is a legitimate instantaneous read and is NOT refused
    age  >  0   keeps its existing staleness behaviour, unchanged

    The smallest negative age the implementation can represent is one
    microsecond, and that first tick below zero must already be refused:
    a rule that only catches large excursions is a tolerance by accident.

    Nothing is clamped. A clamped implementation would report age 0.0 and
    approve; the age printed below stays negative while the action is refused.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from orbit.exec.protection import MarginMode
from orbit.exec.recon import (ExchangeView, IntendedState, reconcile)
from orbit.risk.gateway import Gateway, Kind, ProposedAction
from orbit.risk.limits import A1, RunState

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
ONE_TICK = timedelta(microseconds=1)

PASS, FAIL = [], []
GW = Gateway()


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def rule(t=""):
    print("\n" + "=" * 78)
    if t:
        print(t)
        print("=" * 78)


def observe(fetched_delta, server_delta):
    """An observation of the shape a venue adapter would return. Every field
    but the two clocks is the healthy case, so any refusal is attributable to
    the timestamps alone."""
    return ExchangeView(
        fetched_at=NOW + fetched_delta, reachable=True, consistent=True,
        server_time=None if server_delta is None else NOW + server_delta,
        equity=D("1000"), mark_price=D("30000"),
        margin_mode=MarginMode.UNKNOWN, position=None, open_orders=(),
        fills=(), can_place_orders=True)


def flat_intent():
    return IntendedState(journal_loaded=True, clean_shutdown=True,
                         entries_utc_day=0)


def run(fetched_delta, server_delta):
    """The production path, end to end: observation -> reconcile -> system
    state -> gateway authorization of an OPEN."""
    v = observe(fetched_delta, server_delta)
    r = reconcile(flat_intent(), v, NOW)
    st = r.to_system_state()
    verdict = GW.evaluate(
        ProposedAction("r45repro", Kind.OPEN, "BTC-USDT-SWAP", "long",
                       entry_type="market", stop=D("29700")), st)
    return {
        "age": (NOW - v.fetched_at).total_seconds(),
        "state_age": st.data_age_seconds,
        "codes": [f.code.value for f in r.findings],
        "run_state": r.run_state.value,
        "reconciled": r.reconciled,
        "approved": verdict.approved,
        "verdict_code": verdict.code.value,
    }


print("=" * 78)
print("ORBIT — R4-5 STANDALONE REPRODUCER: observations that cannot be placed")
print("           in time must never authorise an action")
print("=" * 78)
print(f"evaluation instant NOW = {NOW}")
print(f"max_data_age_seconds   = {A1.max_data_age_seconds}")

SCENARIOS = [
    ("S1 filed fail-open",   timedelta(seconds=600),  None,                    False),
    ("S2 future + srv time", timedelta(seconds=600),  timedelta(0),            False),
    ("S3 no server_time",    -timedelta(seconds=5),   None,                    False),
    ("S4 first tick < 0",    ONE_TICK,                timedelta(0),            False),
    ("S5 valid control",     -timedelta(seconds=5),   timedelta(0),            True),
    ("S6 zero boundary",     timedelta(0),            timedelta(0),            True),
    ("S7 stale control",     -timedelta(seconds=720), timedelta(0),            False),
    ("S8 future srv clock",  -timedelta(seconds=5),   timedelta(seconds=600),  False),
]

rule("PER-SCENARIO RESULT")
rows = []
results = {}
for name, fd, sd, want_open in SCENARIOS:
    out = run(fd, sd)
    results[name[:2]] = out
    rows.append((name, out, want_open))
    print(f"\n{name}")
    print(f"    fetched_at offset : {fd}")
    print(f"    server_time       : {'ABSENT' if sd is None else NOW + sd}")
    print(f"    computed age (s)  : {out['age']!r}")
    print(f"    findings          : {out['codes']}")
    print(f"    run_state         : {out['run_state']}")
    print(f"    reconciled        : {out['reconciled']}")
    print(f"    GATEWAY OPEN      : {'APPROVED' if out['approved'] else 'REFUSED'}"
          f"  ({out['verdict_code']})")

# ======================================================================
rule("1. AN IMPOSSIBLE OBSERVATION AUTHORISES NOTHING")
# ======================================================================
for name, out, want_open in rows:
    if want_open:
        continue
    check(f"{name}: the OPEN is REFUSED", not out["approved"],
          f"verdict={out['verdict_code']} age={out['age']}")

check("S1: the filed shape reports the negative age it actually computed",
      results["S1"]["age"] == -600.0, repr(results["S1"]["age"]))
check("S1: it is no longer finding-free — the defect is diagnosed, not merely "
      "suppressed",
      len(results["S1"]["codes"]) > 0, str(results["S1"]["codes"]))
check("S1: run_state is no longer RUNNING",
      results["S1"]["run_state"] != RunState.RUNNING.value,
      results["S1"]["run_state"])
check("S2: supplying a correct venue clock does not excuse a future fetch",
      not results["S2"]["approved"] and len(results["S2"]["codes"]) > 0,
      str(results["S2"]["codes"]))
check("S3: a MISSING server_time yields no positive freshness claim",
      not results["S3"]["approved"] and not results["S3"]["reconciled"],
      str(results["S3"]["codes"]))

# ======================================================================
rule("2. THE BOUNDARY IS EXACTLY ZERO — NO TOLERANCE WAS INTRODUCED")
# ======================================================================
check("S4: the SMALLEST representable negative age (1 microsecond) is already "
      "refused — no epsilon, no grace period",
      results["S4"]["age"] == -1e-06 and not results["S4"]["approved"],
      f"age={results['S4']['age']!r}")
check("S6: age == 0 is NOT refused — an instantaneous read is legal",
      results["S6"]["age"] == 0.0 and results["S6"]["approved"],
      f"age={results['S6']['age']!r} verdict={results['S6']['verdict_code']}")
check("S6: and it raises no finding at all",
      results["S6"]["codes"] == [], str(results["S6"]["codes"]))

# ======================================================================
rule("3. NOTHING WAS CLAMPED")
# ======================================================================
# `age = max(age, 0)` would report 0.0 and approve. The real number survives
# into the state the gateway reads, and the action is refused anyway.
for k in ("S1", "S2", "S4"):
    check(f"{k}: the age carried into SystemState is still NEGATIVE — refused, "
          f"not re-labelled as maximally fresh",
          results[k]["state_age"] < 0 and not results[k]["approved"],
          f"state_age={results[k]['state_age']!r}")

# ======================================================================
rule("4. THE REPAIR DID NOT SIMPLY REFUSE EVERYTHING")
# ======================================================================
check("S5: an ordinary healthy observation is still APPROVED",
      results["S5"]["approved"], results["S5"]["verdict_code"])
check("S5: and raises no finding",
      results["S5"]["codes"] == [], str(results["S5"]["codes"]))
check("S5: run_state is RUNNING",
      results["S5"]["run_state"] == RunState.RUNNING.value,
      results["S5"]["run_state"])

# ======================================================================
rule("5. PRE-EXISTING REFUSALS ARE INTACT AND NOT WEAKENED")
# ======================================================================
check("S7: a genuinely stale view is still refused",
      not results["S7"]["approved"] and "STALE_EXCHANGE_VIEW" in results["S7"]["codes"],
      str(results["S7"]["codes"]))
check("S7: and is NOT re-diagnosed as an impossible timestamp",
      "FUTURE_DATED_EXCHANGE_VIEW" not in results["S7"]["codes"],
      str(results["S7"]["codes"]))
check("S1 vs S7: the impossible-time refusal is AT LEAST AS RESTRICTIVE as the "
      "existing stale refusal",
      (not results["S1"]["approved"])
      and results["S1"]["reconciled"] == results["S7"]["reconciled"]
      and results["S1"]["run_state"] == results["S7"]["run_state"],
      f"future={results['S1']['run_state']}/{results['S1']['reconciled']} "
      f"stale={results['S7']['run_state']}/{results['S7']['reconciled']}")
check("S8: a FUTURE venue clock is still caught by the existing skew rule and "
      "still HALTS — a different clock pair, untouched by R4-5",
      "CLOCK_SKEW_SEVERE" in results["S8"]["codes"]
      and results["S8"]["run_state"] == RunState.HALTED.value,
      str(results["S8"]["codes"]))

# ======================================================================
rule("6. A GENUINE PROCESS — THE REFUSAL IS IN THE CODE, NOT IN THIS PROCESS")
# ======================================================================
# A new interpreter, given only the repository path. Module state, import
# caches and anything this process arranged cannot follow it across.
PROBE = (
    "import sys;sys.path.insert(0,%r)\n"
    "from datetime import datetime,timedelta,timezone\n"
    "from decimal import Decimal as D\n"
    "from orbit.exec.protection import MarginMode\n"
    "from orbit.exec.recon import ExchangeView,IntendedState,reconcile\n"
    "from orbit.risk.gateway import Gateway,Kind,ProposedAction\n"
    "N=datetime(2026,9,8,12,0,0,tzinfo=timezone.utc)\n"
    "v=ExchangeView(fetched_at=N+timedelta(seconds=600),reachable=True,\n"
    "  consistent=True,server_time=None,equity=D('1000'),mark_price=D('30000'),\n"
    "  margin_mode=MarginMode.UNKNOWN,position=None,open_orders=(),fills=(),\n"
    "  can_place_orders=True)\n"
    "i=IntendedState(journal_loaded=True,clean_shutdown=True,entries_utc_day=0)\n"
    "r=reconcile(i,v,N)\n"
    "verdict=Gateway().evaluate(ProposedAction('p',Kind.OPEN,'BTC-USDT-SWAP',\n"
    "  'long',entry_type='market',stop=D('29700')),r.to_system_state())\n"
    "print('APPROVED' if verdict.approved else 'REFUSED',verdict.code.value)\n"
) % (ROOT,)

proc = subprocess.run([sys.executable, "-c", PROBE], capture_output=True,
                      text=True, cwd=ROOT,
                      env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
fresh = (proc.stdout or "").strip()
print(f"    fresh interpreter says: {fresh!r}")
if proc.returncode != 0:
    print(proc.stderr)
check("S1 in a GENUINE separate process: the filed fail-open shape is REFUSED "
      "there too",
      proc.returncode == 0 and fresh.startswith("REFUSED"),
      f"rc={proc.returncode} out={fresh!r}")

# ======================================================================
rule("SUMMARY")
print(f"{'scenario':<22} {'age (s)':>14}  {'run_state':<13} {'OPEN':<9} findings")
print("-" * 78)
for name, out, want_open in rows:
    print(f"{name:<22} {out['age']!r:>14}  {out['run_state']:<13} "
          f"{'APPROVED' if out['approved'] else 'REFUSED':<9} "
          f"{','.join(out['codes']) or '-'}")

rule()
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("\nAN OBSERVATION THAT COULD NOT BE PLACED IN TIME WAS TREATED AS")
    print("EVIDENCE OF CURRENT STATE. The fail-open stands on this tree:")
    for f_ in FAIL:
        print("  FAILED:", f_)
print("=" * 78)
sys.exit(1 if FAIL else 0)
