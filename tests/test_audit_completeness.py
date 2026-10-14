"""
tests/test_audit_completeness.py — DOES ANYTHING ACTUALLY WRITE THE SCHEMA?

Added 2026-09-08. A schema-vs-system audit found that five declared event types
had no producer anywhere in the library: RUN_STATE_TRANSITION, CYCLE_OPEN,
DECISION_PROPOSED, GATEWAY_VERDICT and RECOVERY_BEGIN. The step-5 report claimed
every required field was carried; that was true of the schema and false of the
system.

A declared record type that nothing writes is not a harmless placeholder. It is
a promise in a design document that the running system does not keep, and it is
invisible until someone goes looking for the data and finds an empty column.

This suite makes that class of gap a test failure.

Run:  python tests/test_audit_completeness.py
"""

from __future__ import annotations

import inspect
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

sys.path.insert(0, ".")

from orbit.audit import cycle as cycle_mod
from orbit.audit import recovery as recovery_mod
from orbit.audit.cycle import (EMITTED_BY, CycleRecorder,
                               verify_information_from_journal)
from orbit.audit.information import DecisionContext, SeriesRef
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.audit.recovery import recover, write_clean_shutdown
from orbit.exec.protection import MarginMode
from orbit.exec.recon import (ExchangeOrder, ExchangePosition, ExchangeView,
                              F, OrderStatus, reconcile)
from orbit.risk.limits import RunState

PASS, FAIL = [], []
NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
TMP = tempfile.mkdtemp(prefix="orbit_a1_audit_")


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))
    return ok


def banner(t):
    print("\n" + "-" * 76)
    print(t)


print("=" * 76)
print("ORBIT A1 — AUDIT SCHEMA COMPLETENESS")
print("=" * 76)

# ======================================================================
banner("S — EVERY DECLARED EVENT TYPE HAS A REAL PRODUCER")
# ======================================================================
missing = sorted(set(E) - set(EMITTED_BY))
check("S1. the producer registry covers every event type in the schema",
      not missing, str([m.value for m in missing]))

from orbit.audit import decision_input as decision_input_mod
from orbit.audit.blobstore import BlobStore
from orbit.audit.decision_input import DecisionInput, record_decision_input
from orbit.exec import resolver as resolver_mod

NS = {"CycleRecorder": CycleRecorder, "Journal": Journal,
      "recovery": recovery_mod, "decision_input": decision_input_mod,
      "resolver": resolver_mod}


def resolve(dotted):
    head, _, attr = dotted.partition(".")
    obj = NS[head]
    return getattr(obj, attr, None)


unresolved = [f"{k.value} -> {v}" for k, v in EMITTED_BY.items()
              if resolve(v) is None]
check("S2. every named producer exists", not unresolved, str(unresolved))

not_emitting = []
for kind, dotted in EMITTED_BY.items():
    fn = resolve(dotted)
    try:
        src = inspect.getsource(fn)
    except Exception:
        not_emitting.append(f"{kind.value}: source unavailable")
        continue
    if f"E.{kind.name}" not in src:
        not_emitting.append(f"{kind.value} -> {dotted} does not mention it")
check("S3. every producer's SOURCE actually emits the type it claims — a "
      "registry entry pointing at the wrong function is caught",
      not not_emitting, str(not_emitting))

# ======================================================================
banner("C — A FULL CYCLE WRITES WHAT THE SCHEMA PROMISES")
# ======================================================================
path = os.path.join(TMP, "cycle.jsonl")
j = Journal(path, clock=lambda: NOW)
rec = CycleRecorder(j, policy_version="A1", model_id="none")

ex_view = ExchangeView(
    fetched_at=NOW - timedelta(seconds=5), reachable=True, consistent=True,
    server_time=NOW, equity=D("1000"), mark_price=D("30000"),
    margin_mode=MarginMode.UNKNOWN)

rec.run_start()
rep0 = recover(path)
rec.recovery_begin(rep0.journal_trusted, rep0.clean_marker,
                   [u.client_order_id for u in rep0.unresolved],
                   list(rep0.notes))
rec.open_cycle("cyc1", NOW.isoformat())

ctx = DecisionContext(
    cycle_id="cyc1", decision_id="d1", market_snapshot_as_of=NOW.isoformat(),
    series=(SeriesRef("candles:5m", "h5m", NOW.isoformat(), 300),),
    account_state_id="acct1", position_state_id="none", open_orders_id="none",
    run_state="RUNNING", reconciled=True, local_state_trusted=True,
    policy_version="A1", model_id="none", prompt_hash="ph1")
rec.record_information(ctx)
# SAFETY CLOSURE ROUND 2, N4: the exact bytes the model was given are part of a
# cycle, not an optional extra, so the completeness test exercises them.
record_decision_input(
    j, BlobStore(os.path.join(TMP, "blobs")), "d1",
    DecisionInput(system_prompt="You are ORBIT A1.",
                  user_prompt="Assess BTC-USDT-SWAP.",
                  messages=({"role": "user", "content": "Assess."},),
                  tool_schema={"get_market_state": {"params": {}}},
                  tool_results=({"tool": "get_market_state", "ref": "h5m"},),
                  account_state={"equity": "1000"},
                  position_state=None, open_orders=(), memory=(),
                  policy_version="A1", model_id="none"))
rec.record_decision("d1", {"decision": "LONG", "stop": "29700.1"},
                    ("candles:5m@h5m", "account@acct1"))
rec.record_gateway_verdict("d1", True, "OK", "approved",
                           computed={"planned_risk_usdt": "7.99"},
                           order={"contracts": "2.38"})
j.record_intent("d1", client_order_id="e1", instrument="BTC-USDT-SWAP",
                side="long", intended_contracts="2.4003", contracts="2.38",
                intended_stop="29700.07", stop="29700.1")
rec.record_submit_attempted("d1", "e1")
rec.record_submit_ack("d1", "e1", "X1", server_ts=NOW.isoformat())
rec.record_fill_group("d1", "e1", "f1", "2.38", "30000",
                      position={"side": "long", "contracts": "2.38",
                                "entry_price": "30000", "stop_price": None,
                                "stop_client_id": None,
                                "opened_at": NOW.isoformat()},
                      entries_utc_day=1, realized_pnl_utc_day="0",
                      server_ts=NOW.isoformat(), cumulative="2.38",
                      executed_at=NOW)
rec.record_protective_intent("stop1", "2.38", "29700.1")
rec.record_protective_ack("stop1", position={
    "side": "long", "contracts": "2.38", "entry_price": "30000",
    "stop_price": "29700.1", "stop_client_id": "stop1",
    "opened_at": NOW.isoformat()})
rec.record_order_status("d1", "e1", OrderStatus.FILLED.value)
rec.record_reconstruction("d1", "n/a", ["fill:f1->e1"], ["e1"], ["f1"],
                          {"side": "long"}, "SAFE", [])
rec.record_remediation("d1", "none required")

exv = ExchangeView(
    fetched_at=NOW - timedelta(seconds=5), reachable=True, consistent=True,
    server_time=NOW, equity=D("1000"), mark_price=D("30000"),
    margin_mode=MarginMode.UNKNOWN,
    position=ExchangePosition("long", D("2.38"), D("30000")),
    open_orders=(ExchangeOrder("stop1", D("2.38"), True, D("29700.1")),))
# R4C4 DF-R4. The session clock is passed EXPLICITLY. This cycle is the
# HAPPY one, and a happy cycle knows what day it is: without the clock the
# day figures are underivable, reconciliation adds DAY_COUNTERS_UNRELIABLE,
# and the "full cycle" the fixture depicts quietly stops being the clean
# cycle it is named for.
r = reconcile(recover(path, now=NOW).rebuilt, exv, NOW)
rec.record_recon(r)
rec.record_submit_failed("dx", "ex", "simulated rejection")
rec.record_submit_unknown("dy", "ey", 1)
write_clean_shutdown(j, 0, r)

seen = {ev["e"] for rr in Journal.load(path).records for ev in rr["events"]}
# An event type may be excepted from the happy-path cycle ONLY with a written
# reason and a named suite that does cover it. The reason is required so that
# excepting a type is a decision someone made, not a literal quietly added to a
# set expression.
NOT_IN_A_HAPPY_CYCLE = {
    E.RECOVERY_COMPLETE.value:
        "belongs to restart, not to a cycle — covered by test_journal_crash.py",
    E.DECISION_INPUT_CONFLICT.value:
        "an exceptional event by construction: a happy cycle binds each "
        "decision id once — covered by test_safety_closure_r3.py R3.5.2/R3.5.8",
}
absent = sorted(set(k.value for k in EMITTED_BY) - seen
                - set(NOT_IN_A_HAPPY_CYCLE))
check("C1. a full cycle emits every declared event type, except those with a "
      "written reason and a named suite that covers them",
      not absent, str(absent))
check("C1b. every exception carries a reason and names where it IS covered",
      all(len(v) > 30 and (".py" in v) for v in NOT_IN_A_HAPPY_CYCLE.values()),
      str(sorted(NOT_IN_A_HAPPY_CYCLE)))
# R4C4 DF-R4. Declared, so that a later change to what this cycle derives
# cannot drift the fixture again without a test saying so. DIRTY_SHUTDOWN is
# expected and intended: `recover` runs before `write_clean_shutdown`, so
# there is no marker yet. DAY_COUNTERS_UNRELIABLE must NOT be present --
# the journal is valid, the clock was given, and the figures are therefore
# derived rather than unknown.
check("C1c. the happy cycle reconciles with its day figures DERIVED — the "
      "only finding is the expected missing shutdown marker",
      [f.code for f in r.findings] == [F.DIRTY_SHUTDOWN]
      and r.reconciled is True,
      f"findings={[f.code.value for f in r.findings]} "
      f"reconciled={r.reconciled}")
check("C2. the journal survives the whole cycle with an intact hash chain",
      Journal.load(path).trusted)

# ======================================================================
banner("RS — RUN-STATE TRANSITIONS ARE RECORDED, AND ONLY ON CHANGE")
# ======================================================================
p2 = os.path.join(TMP, "rs.jsonl")
j2 = Journal(p2, clock=lambda: NOW)
r2 = CycleRecorder(j2)
a = r2.record_run_state(RunState.RUNNING, "start")
b = r2.record_run_state(RunState.RUNNING, "unchanged")
c = r2.record_run_state(RunState.NO_NEW_ENTRY, "orphaned order", ("ORPHANED_ORDER",))
d = r2.record_run_state(RunState.HALTED, "phantom position", ("PHANTOM_POSITION",))
check("RS1. a transition is written on change", a is not None and c is not None)
check("RS2. no record is written when the state is unchanged", b is None)
evs = [ev for rr in Journal.load(p2).records for ev in rr["events"]
       if ev["e"] == E.RUN_STATE_TRANSITION.value]
check("RS3. exactly three transitions recorded", len(evs) == 3, str(len(evs)))
check("RS4. each records previous, new, reason and the findings that caused it",
      evs[1]["previous"] == "RUNNING" and evs[1]["new"] == "NO_NEW_ENTRY"
      and evs[1]["reason"] == "orphaned order"
      and evs[1]["findings"] == ["ORPHANED_ORDER"])
check("RS5. engaging protection (HALTED) is visible in the record",
      evs[2]["new"] == "HALTED" and evs[2]["findings"] == ["PHANTOM_POSITION"])

# ======================================================================
banner("GV — EVERY GATEWAY VERDICT IS RECORDED, NOT ONLY APPROVALS")
# ======================================================================
p3 = os.path.join(TMP, "gv.jsonl")
j3 = Journal(p3, clock=lambda: NOW)
r3 = CycleRecorder(j3)
r3.open_cycle("c1", NOW.isoformat())
r3.record_gateway_verdict("d1", False, "STOP_MISSING", "no stop supplied")
r3.record_gateway_verdict("d2", False, "RISK_EXCEEDED", "over cap",
                          computed={"planned_risk_usdt": "12.0"})
r3.record_gateway_verdict("d3", True, "OK", "approved")
gv = [ev for rr in Journal.load(p3).records for ev in rr["events"]
      if ev["e"] == E.GATEWAY_VERDICT.value]
check("GV1. rejections are journalled as first-class records",
      len(gv) == 3 and sum(1 for x in gv if not x["approved"]) == 2)
check("GV2. the rejection CODE is preserved, so 'rejections by reason' is "
      "computable from the journal",
      {x["code"] for x in gv} == {"STOP_MISSING", "RISK_EXCEEDED", "OK"})
check("GV3. the gateway's own computed figures travel with the verdict",
      gv[1]["computed"]["planned_risk_usdt"] == "12.0")

# ======================================================================
banner("IJ — information_used VERIFIED FROM THE DURABLE RECORD")
# ======================================================================
v = verify_information_from_journal(path, "d1")
check("IJ1. a decision citing only what its own cycle recorded is accepted",
      v.ok, v.reason)

p4 = os.path.join(TMP, "info_bad.jsonl")
j4 = Journal(p4, clock=lambda: NOW)
r4 = CycleRecorder(j4)
r4.open_cycle("cyc1", NOW.isoformat())          # same cycle as ctx
r4.record_information(ctx)
r4.record_decision("d1", {"decision": "LONG"},
                   ("candles:5m@h5m", "orderbook@L2-that-never-existed"))
v = verify_information_from_journal(p4, "d1")
check("IJ2. a decision citing data its tools never provided is rejected FROM "
      "THE JOURNAL, after the process that claimed it is gone",
      not v.ok and "orderbook@L2-that-never-existed" in v.unknown_refs,
      v.reason[:64])

p5 = os.path.join(TMP, "info_missing.jsonl")
j5 = Journal(p5, clock=lambda: NOW)
r5 = CycleRecorder(j5)
r5.open_cycle("c1", NOW.isoformat())
r5.record_decision("d9", {"decision": "LONG"}, ("candles:5m@h5m",))
v = verify_information_from_journal(p5, "d9")
check("IJ3. a decision with NO information record at all is rejected — silence "
      "is not evidence that it knew what it claims", not v.ok, v.reason[:64])

p5b = os.path.join(TMP, "info_xcycle.jsonl")
j5b = Journal(p5b, clock=lambda: NOW)
r5b = CycleRecorder(j5b)
r5b.open_cycle("cycle-B", NOW.isoformat())
r5b.record_information(ctx)                      # ctx belongs to cycle "cyc1"
r5b.record_decision("d1", {"decision": "LONG"}, ("candles:5m@h5m",))
v = verify_information_from_journal(p5b, "d1")
check("IJ4. a decision whose information record belongs to a DIFFERENT cycle is "
      "rejected — context cannot be borrowed from another cycle",
      not v.ok and "different cycles" in v.reason, v.reason[:64])

# ======================================================================
banner("WA — REGRESSION: THE WRITE-AHEAD INTENT MUST NOT BE SWALLOWED")
# ======================================================================
# Defect found 2026-09-08 by C1. record_information / record_decision /
# record_gateway_verdict all pass the decision_id as action_id. Before the fix,
# that made has_action(decision_id) true, so the WRITE-AHEAD INTENT for the same
# decision was suppressed as a duplicate -- and the order would then have gone to
# the exchange with no write-ahead record at all, silently voiding guarantee W1.
pwa = os.path.join(TMP, "wa.jsonl")
jwa = Journal(pwa, clock=lambda: NOW)
rwa = CycleRecorder(jwa)
rwa.open_cycle("cyc1", NOW.isoformat())
rwa.record_information(ctx)                       # action_id = "d1"
rwa.record_decision("d1", {"decision": "LONG"}, ("candles:5m@h5m",))
rwa.record_gateway_verdict("d1", True, "OK", "approved")
intent = jwa.record_intent("d1", client_order_id="e1", contracts="2.38")
check("WA1. informational records for a decision do NOT claim its action id, so "
      "the write-ahead INTENT is still written", intent is not None)
ints = [ev for rr in Journal.load(pwa).records for ev in rr["events"]
        if ev["e"] == E.INTENT.value]
check("WA2. exactly one INTENT exists and it reached the journal before any "
      "exchange call could occur", len(ints) == 1)
check("WA3. a genuine duplicate INTENT for the same action id is still refused",
      jwa.record_intent("d1", client_order_id="e1", contracts="2.38") is None)
check("WA4. only INTENT and PROTECTIVE_INTENT claim an action id",
      __import__("orbit.audit.journal", fromlist=["x"]).ACTION_CLAIMING
      == {E.INTENT.value, E.PROTECTIVE_INTENT.value})

# ======================================================================
banner("ID — THE NEW RECORDER IS STILL IDEMPOTENT")
# ======================================================================
p6 = os.path.join(TMP, "idem.jsonl")
j6 = Journal(p6, clock=lambda: NOW)
r6 = CycleRecorder(j6)
r6.record_protective_intent("stop1", "2.38", "29700.1")
dup = r6.record_protective_intent("stop1", "2.38", "29500.0")
pi = [ev for rr in Journal.load(p6).records for ev in rr["events"]
      if ev["e"] == E.PROTECTIVE_INTENT.value]
check("ID1. a replayed protective intent does not create a second stop order",
      len(pi) == 1 and pi[0]["stop"] == "29700.1")
check("ID2. and the suppression is itself journalled",
      any(ev["e"] == E.REMEDIATION.value
          for rr in Journal.load(p6).records for ev in rr["events"]))

st = recover(p6).rebuilt
check("ID3. rebuild classifies a PROTECTIVE_INTENT as protective, not as an "
      "entry order",
      len(st.submitted_orders) == 1 and st.submitted_orders[0].is_protective)

r6.record_fill_group("a1", "e1", "f1", "1.0", "30000", position=None,
                     entries_utc_day=1, realized_pnl_utc_day="0",
                     executed_at=NOW)
r6.record_fill_group("a1", "e1", "f1", "1.0", "30000", position=None,
                     entries_utc_day=2, realized_pnl_utc_day="99",
                     executed_at=NOW)
evs = [ev for rr in Journal.load(p6).records for ev in rr["events"]]
fills = [ev for ev in evs if ev["e"] == E.FILL.value]
counters = [ev for ev in evs if ev["e"] == E.COUNTERS.value]
positions = [ev for ev in evs if ev["e"] == E.POSITION_STATE.value]
# R4C4 DAYFIG-1. This asserts suppression of the REPLAYED GROUP, which is what
# ID4 is about, by counting the durable records the group writes. It used to
# assert it through `recover().rebuilt.entries_utc_day == 1`, which read the
# COUNTERS aggregate -- and this fixture's history is a FILL against an order
# with no INTENT, which the authoritative derivation refuses to account at all.
# Recovery reporting `1` for it was reporting a number nobody could derive, so
# that clause was asserting the DAYFIG-1 defect. The second group's
# `entries_utc_day=2, realized_pnl_utc_day="99"` is still the thing being
# suppressed: it must not appear in the journal.
check("ID4. a replayed fill group is suppressed whole — no duplicate fill, no "
      "duplicate counters, no duplicate P&L",
      len(fills) == 1 and len(counters) == 1 and len(positions) == 1
      and counters[0]["entries_utc_day"] == 1
      and counters[0]["realized_pnl_utc_day"] == "0")

# ======================================================================
shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 76)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 76)
if FAIL:
    for x in FAIL:
        print("  FAILED:", x)
    sys.exit(1)
print("Every declared record type has a producer, and the producer emits it.")
