"""
tests/test_journal_crash.py — DURABLE JOURNAL: CRASH WINDOWS AND REPLAY.

ORBIT-AGENT-ARCH-001, build step 5 verification.

These are not unit tests of functions. Each case runs the REAL sequence

    action -> journal -> exchange -> exchange result -> journal result
           -> reconciliation -> restart -> recovery -> reconciliation again

against a simulated exchange, kills the process at a chosen point, reopens the
journal FROM DISK, and asserts what recovery may and may not conclude.

The two invariants under test:

    NO TRUSTED DURABLE STATE   = NO NEW ENTRY
    NO TRUSTWORTHY EXCHANGE STATE = NO NEW ENTRY   (step 4, still enforced)

No model. No credentials. No network.

Run:  python tests/test_journal_crash.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

sys.path.insert(0, ".")

from orbit.audit.information import (DecisionContext, SeriesRef,
                                     verify_information_used)
from orbit.audit.journal import CrashPoint, Fault, Journal, SimulatedCrash
from orbit.audit.records import E, event
from orbit.audit.recovery import (can_complete_recovery, complete_recovery,
                                  outstanding_operations, recover,
                                  write_clean_shutdown)
from orbit.exec.protection import MarginMode
from orbit.exec.recon import (Disposition, ExchangeOrder, ExchangePosition,
                              ExchangeView, F, Fill, OrderStatus, Remedy,
                              reconcile)
from orbit.risk.gateway import Code, Gateway, Kind, ProposedAction
from orbit.risk.limits import RunState

PASS, FAIL = [], []
GW = Gateway()
NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)
TMP = tempfile.mkdtemp(prefix="orbit_a1_")


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))
    return ok


def banner(t):
    print("\n" + "-" * 76)
    print(t)


# ======================================================================
# A SIMULATED EXCHANGE. It records what really happened out there, which is
# exactly what the journal may fail to know.
# ======================================================================
class FakeExchange:
    def __init__(self):
        self.orders = {}
        self.fills = []
        self.position = None
        self.stops = {}

    def submit(self, cid, contracts):
        self.orders[cid] = {"contracts": contracts, "filled": D("0")}

    def fill(self, cid, fill_id, contracts, side="long", entry="30000"):
        self.orders[cid]["filled"] += contracts
        self.fills.append((fill_id, cid, contracts))
        cur = self.position["contracts"] if self.position else D("0")
        self.position = {"side": side, "contracts": cur + contracts,
                         "entry": D(entry)}

    def place_stop(self, cid, contracts, price):
        self.stops[cid] = {"contracts": contracts, "price": D(price)}

    def view(self, age_s=5, reachable=True, can_place=True):
        pos = (ExchangePosition(self.position["side"], self.position["contracts"],
                                self.position["entry"]) if self.position else None)
        orders = tuple(ExchangeOrder(cid, s["contracts"], True, s["price"])
                       for cid, s in self.stops.items())
        return ExchangeView(
            fetched_at=NOW - timedelta(seconds=age_s), reachable=reachable,
            consistent=True, server_time=NOW, equity=D("1000"),
            mark_price=D("30000"), margin_mode=MarginMode.UNKNOWN,
            position=pos, open_orders=orders,
            fills=tuple(Fill(f, c, n) for f, c, n in self.fills),
            can_place_orders=can_place)


POS_PAYLOAD = {"side": "long", "contracts": "2.38", "entry_price": "30000",
               "stop_price": "29700.1", "stop_client_id": "stop1",
               "opened_at": NOW.isoformat()}


def run_sequence(path, fault=None, *, partial=False, multi_fill=False,
                 unknown=False, exch=None):
    """The full happy path, interrupted wherever the fault is armed."""
    ex = exch or FakeExchange()
    j = Journal(path, fault=fault, clock=lambda: NOW)
    try:
        j.append_one(E.RUN_START, None, policy_version="A1", model_id="none")

        # 1. WRITE-AHEAD: committed before the exchange is touched at all.
        j.record_intent("a1", client_order_id="e1", instrument="BTC-USDT-SWAP",
                        side="long", intended_contracts="2.4003",
                        contracts="2.38", intended_stop="29700.07",
                        stop="29700.1", order_type="market",
                        planned_risk_usdt="7.9918")

        j.append_one(E.SUBMIT_ATTEMPTED, "a1", client_order_id="e1")
        ex.submit("e1", D("2.38"))                      # <- exchange touched here

        if unknown:
            j.append_one(E.SUBMIT_UNKNOWN, "a1", client_order_id="e1", attempts=1)
            return ex, j
        j.append_one(E.SUBMIT_ACK, "a1", client_order_id="e1",
                     exchange_order_id="X1", server_ts=NOW.isoformat())

        n1 = D("1.00") if (partial or multi_fill) else D("2.38")
        ex.fill("e1", "f1", n1)
        # ATOMIC GROUP: fill + position + counters commit together or not at all
        j.append([
            # R4C4 DAYFIG-1. `executed_at` is what a fill IS: checkpoint A.1
            # made the venue's execution time the accounting day, and
            # `CycleRecorder.record_fill_group` REFUSES to write a fill
            # without one. This fixture hand-builds the atomic group to arm a
            # crash inside it, and had kept writing the pre-A.1 shape -- a
            # history production cannot produce. Now it writes what production
            # writes; the crash windows it exists to test are unchanged.
            event(E.FILL, "a1", client_order_id="e1", fill_id="f1",
                  contracts=str(n1), price="30000", server_ts=NOW.isoformat(),
                  executed_at=NOW.isoformat()),
            event(E.POSITION_STATE, "a1",
                  position={**POS_PAYLOAD, "contracts": str(n1),
                            "stop_price": None, "stop_client_id": None}),
            event(E.COUNTERS, "a1", entries_utc_day=1, realized_pnl_utc_day="0"),
        ])
        if multi_fill:
            ex.fill("e1", "f2", D("1.38"))
            j.append([
                event(E.FILL, "a1", client_order_id="e1", fill_id="f2",
                      contracts="1.38", price="30001",
                      executed_at=NOW.isoformat()),
                event(E.POSITION_STATE, "a1",
                      position={**POS_PAYLOAD, "stop_price": None,
                                "stop_client_id": None}),
                event(E.COUNTERS, "a1", entries_utc_day=1, realized_pnl_utc_day="0"),
            ])
        if partial:
            return ex, j

        j.append_one(E.PROTECTIVE_INTENT, "stop1", client_order_id="stop1",
                     contracts="2.38", stop="29700.1")
        ex.place_stop("stop1", D("2.38"), "29700.1")
        j.append([
            event(E.PROTECTIVE_ACK, "stop1", client_order_id="stop1"),
            event(E.POSITION_STATE, "a1", position=POS_PAYLOAD),
        ])

        r = reconcile(recover(path, now=NOW).rebuilt, ex.view(), NOW)
        j.append_one(E.RECON_RESULT, None, reconciled=r.reconciled,
                     run_state=r.run_state.value,
                     findings=[f.code.value for f in r.findings])
        # SAFETY CLOSURE, blocker E: the fixture no longer hardcodes "nothing
        # is outstanding". It asks, so that a regression in terminality would
        # change what this sequence does rather than being papered over here.
        write_clean_shutdown(j, outstanding_operations(recover(path, now=NOW), r), r)
    except SimulatedCrash:
        pass
    return ex, j


def first_pass(path, ex, **vkw):
    rep = recover(path, now=NOW)
    r = reconcile(rep.rebuilt, ex.view(**vkw), NOW)
    opened = GW.evaluate(ProposedAction("probe", Kind.OPEN, "BTC-USDT-SWAP",
                                        "long", entry_type="market",
                                        stop=D("29700")),
                         r.to_system_state())
    return rep, r, opened


def fresh(name):
    return os.path.join(TMP, name + ".jsonl")


print("=" * 76)
print("ORBIT A1 — DURABLE JOURNAL, CRASH WINDOWS AND REPLAY")
print("=" * 76)

# ======================================================================
banner("W — THE SIXTEEN CRASH WINDOWS")
# ======================================================================
WINDOWS = [
    ("W1  journal write succeeds, exchange submission never happens",
     dict(fault=Fault(at_event=E.SUBMIT_ATTEMPTED.value)), {}),
    ("W2  exchange submission happens, journal ACK write fails",
     dict(fault=Fault(at_event=E.SUBMIT_ACK.value)), {}),
    ("W3  order fills, fill persistence fails",
     dict(fault=Fault(at_event=E.FILL.value)), {}),
    ("W4  order fills, position persistence fails (same atomic group)",
     dict(fault=Fault(at_event=E.POSITION_STATE.value)), {}),
    ("W5  protective stop submitted, stop persistence fails",
     dict(fault=Fault(at_event=E.PROTECTIVE_INTENT.value)), {}),
    ("W6  stop accepted, confirmation lost",
     dict(fault=Fault(at_event=E.PROTECTIVE_ACK.value)), {}),
    ("W7  partial fill before death",
     dict(partial=True), {}),
    ("W8  multiple fills before death",
     dict(multi_fill=True, fault=Fault(at_event=E.PROTECTIVE_INTENT.value)), {}),
    ("W9  process dies DURING a journal transaction (torn record)",
     dict(fault=Fault(at_event=E.FILL.value, point=CrashPoint.TORN)), {}),
    ("W10 dies immediately BEFORE the clean-shutdown marker",
     dict(fault=Fault(at_event=E.CLEAN_SHUTDOWN.value)), {}),
    ("W12 killed while an order is UNKNOWN",
     dict(unknown=True), {}),
]

for label, kw, vkw in WINDOWS:
    p = fresh(label.split()[0])
    ex, _ = run_sequence(p, **kw)
    rep, r, opened = first_pass(p, ex, **vkw)
    ok = (not rep.durable_state_trusted) and (not opened.approved)
    check(label, ok,
          f"trusted={rep.durable_state_trusted} clean_marker={rep.clean_marker} "
          f"unresolved={len(rep.unresolved)} open={opened.code.value}")

# W11 — the one window that ends with a valid marker
p = fresh("W11")
ex, _ = run_sequence(p, fault=Fault(at_event=E.CLEAN_SHUTDOWN.value,
                                    point=CrashPoint.AFTER_FSYNC))
rep, r, opened = first_pass(p, ex)
check("W11 dies immediately AFTER the clean-shutdown marker: the marker is "
      "durable, yet the first pass after restart still refuses to open",
      rep.clean_marker and rep.durable_state_trusted and not opened.approved,
      f"marker={rep.clean_marker} open={opened.code.value}")

# W11b — R4C4 DF-R1. JOURNAL TRUST IS AN INDEPENDENT CONJUNCT.
#
# `rep` above is the one report in this repository that is genuinely
# TRUSTED: valid chain, durable clean marker, day figures derived from a
# real session clock, nothing outstanding. That makes it the only state in
# which the conjuncts of `durable_state_trusted` can be told APART, and the
# only place this property can be asserted as a behaviour rather than read
# off the source.
#
# Why it must be asserted here. `_daily_figures` refuses an untrusted
# journal (UNDERIVABLE:JOURNAL_UNTRUSTED) BEFORE it ever consults the
# clock, so today `daily_figures_derivable` already implies
# `journal_trusted` and no end-to-end fixture — clocked or not — can
# produce a report that separates them. The `journal_trusted` conjunct is
# therefore currently carried by its neighbour, and a change that stopped
# the neighbour carrying it (deriving figures before the trust gate, or a
# report built from a partially trusted load) would silently turn
# NO TRUSTED DURABLE STATE = NO NEW ENTRY into a fail-OPEN. Withdrawing
# journal trust ALONE, holding every other conjunct at its trusting value,
# is the one perturbation that states the conjunct on its own.
rep_untrusted = replace(rep, journal_trusted=False)
check("W11b withdrawing journal trust ALONE — every other conjunct held at "
      "its trusting value — still refuses durable state",
      rep.durable_state_trusted is True
      and rep_untrusted.clean_marker is True
      and rep_untrusted.daily_figures_derivable is True
      and not rep_untrusted.journal_outstanding
      and rep_untrusted.durable_state_trusted is False,
      f"trusted={rep.durable_state_trusted} "
      f"perturbed={rep_untrusted.durable_state_trusted} "
      f"marker={rep_untrusted.clean_marker} "
      f"derivable={rep_untrusted.daily_figures_derivable} "
      f"outstanding={len(rep_untrusted.journal_outstanding)}")

# W13 — stale journal, newer exchange state
p = fresh("W13")
j = Journal(p, clock=lambda: NOW)
j.append_one(E.RUN_START, None)
j.append_one(E.COUNTERS, None, entries_utc_day=0, realized_pnl_utc_day="0")
write_clean_shutdown(j, 0, reconcile(recover(p, now=NOW).rebuilt, FakeExchange().view(), NOW))
stale_ex = FakeExchange()
stale_ex.submit("zz", D("2.38")); stale_ex.fill("zz", "fz", D("2.38"))
rep, r, opened = first_pass(p, stale_ex)
check("W13 stale journal (clean, flat) but the exchange holds a position: "
      "recovery must not believe the journal",
      not opened.approved and F.UNRECORDED_OWN_FILL in r.codes(),
      f"{[c.value for c in r.codes()]} open={opened.code.value}")

# ======================================================================
banner("ATOMICITY — a fill can never be observed without its position")
# ======================================================================
bad = []
for ev in (E.FILL.value, E.POSITION_STATE.value, E.COUNTERS.value):
    p = fresh("atom_" + ev)
    ex, _ = run_sequence(p, fault=Fault(at_event=ev))
    st = recover(p, now=NOW)
    orders = {o.client_order_id: o for o in st.rebuilt.submitted_orders}
    filled = orders.get("e1").filled_contracts if "e1" in orders else D("0")
    if (filled > 0) != (st.rebuilt.position is not None):
        bad.append((ev, str(filled), st.rebuilt.position))
check("A1. crashing on ANY member of the fill/position/counters group loses the "
      "whole group — never a fill without a position", not bad, str(bad))

# ======================================================================
banner("T — TAMPER EVIDENCE vs A TORN TAIL")
# ======================================================================
p = fresh("torn")
run_sequence(p, fault=Fault(at_event=E.FILL.value, point=CrashPoint.TORN))
lr = Journal.load(p)
check("T1. a torn FINAL record is discarded as uncommitted and the prefix stays "
      "trusted", lr.trusted and lr.discarded_tail == 1, lr.reason)

p = fresh("tamper")
run_sequence(p)
with open(p) as fh:
    lines = [x for x in fh.read().split("\n") if x]
idx = next(i for i, x in enumerate(lines) if '"INTENT"' in x)
tampered = lines[idx].replace('"contracts":"2.38"', '"contracts":"9.99"')
assert tampered != lines[idx], "the tamper edit did not land -- test is vacuous"
assert idx < len(lines) - 1, "tamper must be in the MIDDLE, not the tail"
lines[idx] = tampered
with open(p, "w") as fh:
    fh.write("\n".join(lines) + "\n")
lr = Journal.load(p)
check("T2. rewriting a record in the MIDDLE breaks the chain and is detected as "
      "tampering, not as a crash", lr.tamper_detected and not lr.trusted, lr.reason)
rep = recover(p, now=NOW)
r = reconcile(rep.rebuilt, FakeExchange().view(), NOW)
opened = GW.evaluate(ProposedAction("t2", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                                    stop=D("29700")), r.to_system_state())
check("T3. a tampered journal can never open a position",
      not rep.journal_trusted and not opened.approved, opened.code.value)

# ======================================================================
banner("I — IDEMPOTENCY: replay changes nothing")
# ======================================================================
p = fresh("idem")
ex, j = run_sequence(p)
before = recover(p, now=NOW).rebuilt

j2 = Journal(p, clock=lambda: NOW)
dup_intent = j2.record_intent("a1", client_order_id="e1", contracts="2.38")
check("W14/I1. a replayed journal INTENT with a known action_id is suppressed",
      dup_intent is None)
dup_fill = j2.record_fill("a1", "f1", client_order_id="e1", contracts="2.38")
check("W15/I2. a replayed exchange FILL with a known fill_id is suppressed",
      dup_fill is None)

after = recover(p, now=NOW).rebuilt
o_b = {o.client_order_id: o for o in before.submitted_orders}
o_a = {o.client_order_id: o for o in after.submitted_orders}
check("I3. replay did not duplicate the position",
      (before.position is None) == (after.position is None)
      and (before.position is None
           or before.position.contracts == after.position.contracts))
check("I4. replay did not double-count fills",
      o_b["e1"].filled_contracts == o_a["e1"].filled_contracts,
      f"{o_b['e1'].filled_contracts} -> {o_a['e1'].filled_contracts}")
check("I5. replay did not double-count the daily entry counter",
      before.entries_utc_day == after.entries_utc_day == 1)
check("I6. replay did not duplicate realized P&L",
      before.realized_pnl_utc_day == after.realized_pnl_utc_day)
check("I7. replay did not create a second protective order",
      len([o for o in after.submitted_orders if o.is_protective]) == 1)

p2 = fresh("idem2")
ex2, _ = run_sequence(p2)
j3 = Journal(p2, clock=lambda: NOW)
check("W16/I8. the SAME client order id replayed after restart is refused by the "
      "journal, so a retry cannot create a second order",
      j3.has_action("a1") and j3.record_intent("a1", client_order_id="e1") is None)

check("I9. rebuilding the same journal twice is deterministic",
      recover(p, now=NOW).rebuilt == recover(p, now=NOW).rebuilt)

# ======================================================================
banner("S — CLEAN SHUTDOWN IS NOT 'main() RETURNED'")
# ======================================================================
p = fresh("cs1")
j = Journal(p, clock=lambda: NOW)
j.append_one(E.RUN_START, None)
ok = write_clean_shutdown(j, report_unresolved=2, recon=None)
check("S1. clean shutdown is REFUSED while exchange operations are unresolved",
      not ok and not recover(p, now=NOW).clean_marker)

p = fresh("cs2")
j = Journal(p, clock=lambda: NOW)
j.append_one(E.RUN_START, None)
ok = write_clean_shutdown(j, report_unresolved=0, recon=None)
check("S2. clean shutdown is REFUSED without a completed reconciliation",
      not ok and not recover(p, now=NOW).clean_marker)

p = fresh("cs3")
ex, _ = run_sequence(p)
check("S3. clean shutdown IS written when every condition holds",
      recover(p, now=NOW).clean_marker and recover(p, now=NOW).durable_state_trusted)

check("S4. even then, the rebuilt state presented to the first reconcile has "
      "clean_shutdown=False — the marker is not believed on sight",
      recover(p, now=NOW).rebuilt.clean_shutdown is False)

# ======================================================================
banner("SEQ — THE COMPLETE SEQUENCE, END TO END")
# ======================================================================
p = fresh("seq")
ex, _ = run_sequence(p)                       # action->journal->exchange->...->clean
# R4C4 DAYFIG-1. The session clock is what the UTC day is taken from, and a
# restarting process has one. Without it the day's entry count and realized
# P&L are UNDERIVABLE -- not zero -- and recovery deliberately will not clear
# such a state to trade. Production passes it here; so does this sequence.
rep = recover(p, now=NOW)                     # restart -> recovery
r1 = reconcile(rep.rebuilt, ex.view(), NOW)   # reconciliation #1
o1 = GW.evaluate(ProposedAction("s1", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                                stop=D("29700")), r1.to_system_state())
check("SEQ1. after restart, reconciliation #1 sees the exchange clearly but "
      "refuses a new entry because durable state is not yet re-trusted",
      r1.reconciled and not r1.clean and not o1.approved
      and o1.code is Code.NO_NEW_ENTRY, o1.code.value)

ok, why = can_complete_recovery(rep, r1)
check("SEQ2. recovery may complete: journal trusted, nothing unresolved, "
      "exchange view trustworthy", ok, why)

j = Journal(p, clock=lambda: NOW)
state2 = complete_recovery(j, rep, r1)
check("SEQ3. RECOVERY_COMPLETE is appended and a trusted state is returned",
      state2 is not None and state2.clean_shutdown is True)

r2 = reconcile(state2, ex.view(), NOW)        # reconciliation #2
o2 = GW.evaluate(ProposedAction("s2", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               entry_type="market",
                                stop=D("29700")), r2.to_system_state())
check("SEQ4. reconciliation #2 reaches RUNNING",
      r2.run_state is RunState.RUNNING and r2.clean, r2.run_state.value)
check("SEQ5. the OPEN is now refused only by the one-position rule, not by "
      "trust", o2.code is Code.ADD_TO_POSITION, o2.code.value)

p = fresh("seq_unres")
ex, _ = run_sequence(p, unknown=True)
rep = recover(p, now=NOW)
r = reconcile(rep.rebuilt, ex.view(), NOW)
ok, why = can_complete_recovery(rep, r)
check("SEQ6. recovery CANNOT complete while an operation is unresolved",
      not ok and "unresolved" in why, why)
check("SEQ7. and complete_recovery returns None rather than a trusted state",
      complete_recovery(Journal(p, clock=lambda: NOW), rep, r) is None)

# ======================================================================
banner("INFO — WHAT DID CLAUDE KNOW?")
# ======================================================================
ctx = DecisionContext(
    cycle_id="c1", decision_id="d1", market_snapshot_as_of=NOW.isoformat(),
    series=(SeriesRef("candles:5m", "h5m", NOW.isoformat(), 300),
            SeriesRef("funding", "hfund", NOW.isoformat())),
    account_state_id="acct1", position_state_id="pos1", open_orders_id="oo1",
    run_state="RUNNING", reconciled=True, local_state_trusted=True,
    memory_refs=("journal:last10",), policy_version="A1",
    model_id="none", prompt_hash="ph1")

v = verify_information_used(("candles:5m@h5m", "account@acct1"), ctx)
check("INFO1. a decision citing only provided references is accepted", v.ok)
v = verify_information_used(("candles:5m@h5m", "orderbook@L2"), ctx)
check("INFO2. a decision citing something its tools NEVER provided is rejected",
      not v.ok and "orderbook@L2" in v.unknown_refs, v.reason[:70])
v = verify_information_used((), ctx)
check("INFO3. a decision citing nothing at all is rejected", not v.ok)
check("INFO4. the context hash is stable and covers model and policy version",
      ctx.context_hash() == ctx.context_hash()
      and ctx.context_hash() != DecisionContext(
          **{**ctx.__dict__, "model_id": "other"}).context_hash())

p = fresh("info")
j = Journal(p, clock=lambda: NOW)
j.append_one(E.INFORMATION_USED, "d1", **ctx.as_event_payload())
rec = Journal.load(p).records[0]["events"][0]
check("INFO5. the context is journalled with its available reference set, so "
      "'what did Claude know' is answerable from the journal alone",
      set(rec["available_refs"]) == ctx.refs()
      and rec["context_hash"] == ctx.context_hash())

# ======================================================================
banner("R — RECONSTRUCTION IS APPENDED, NEVER SUBSTITUTED")
# ======================================================================
p = fresh("recon_evid")
ex = FakeExchange(); ex.submit("e1", D("2.38")); ex.fill("e1", "f1", D("2.38"))
j = Journal(p, clock=lambda: NOW)
j.append_one(E.RUN_START, None)
j.record_intent("a1", client_order_id="e1", contracts="2.38")
before_len = len(Journal.load(p).records)
j.append_one(E.RECONSTRUCTION, "a1", reason="UNRECORDED_OWN_FILL",
             evidence=["fill:f1->e1"], client_ids=["e1"], fill_ids=["f1"],
             reconstructed={"side": "long", "contracts": "2.38"},
             recon_result="BLOCK_NEW_ENTRIES", remediation=["PLACE_PROTECTIVE_STOP"])
after = Journal.load(p)
check("R1. reconstruction is an APPENDED record; nothing earlier is altered",
      len(after.records) == before_len + 1 and after.trusted
      and after.records[before_len - 1]["hash"]
      == Journal.load(p).records[before_len - 1]["hash"])
ev = after.records[-1]["events"][0]
check("R2. it records why, the supporting observations, the ids used, the "
      "result and the remediation",
      all(k in ev for k in ("reason", "evidence", "client_ids", "fill_ids",
                            "reconstructed", "recon_result", "remediation")))

# ======================================================================
shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 76)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 76)
if FAIL:
    for x in FAIL:
        print("  FAILED:", x)
    print("\nGATE CLOSED.")
    sys.exit(1)
print("No crash window permits a new entry from an untrusted journal.")
