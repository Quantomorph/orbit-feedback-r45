"""
tests/test_safety_closure_r2.py — ORBIT A1 SAFETY CLOSURE, ROUND 2.

The round-1 suite was independently rerun at 441/441 and NEW adversarial probes
still found defects. That is the second time a green suite has agreed with the
implementation about what could go wrong, and it is the reason every test below
was written to FAIL against the archive that scored 441/441.

    N1  the idempotency decision was not atomic with the durable append
    N2  the adapter did not bind the outgoing payload to the durable INTENT
    N3  the gateway and the reconciler used different definitions of $8 risk
    N4  a prompt HASH does not reconstruct what the model was actually given
    N5  the append lock is POSIX-only and the runtime contract was implicit
    N6  admin mutations (CANCEL / MODIFY_STOP) had no terminalisation path

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import timedelta
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, owning, pos, stop_order
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.audit.recovery import outstanding_operations, recover
from orbit.core.precision import BTC_USDT_SWAP as SPEC
from orbit.exec.operations import OperationLedger, OpStatus, Role
from orbit.exec.recon import (IntendedPosition, IntendedState, OrderStatus,
                              SubmittedOrder, reconcile)
from orbit.risk.gateway import Code, Gateway, Kind, ProposedAction
from orbit.risk.limits import A1, RunState
from orbit.tools.session import ActionStatus

PASS, FAIL = [], []
TMP = tempfile.mkdtemp(prefix="orbit_r2_")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def banner(t):
    print("\n" + "-" * 78)
    print(t)


def attempt(name, fn):
    """A missing capability is a FAILING test, never an aborted suite."""
    try:
        ok, detail = fn()
    except Exception as e:                                # noqa: BLE001
        check(name, False, f"{type(e).__name__}: {e}"[:120])
        return False
    check(name, ok, detail)
    return bool(ok)


def count_events(path, kind, **match):
    n = 0
    for rec in Journal.load(path).records:
        for ev in rec["events"]:
            if ev["e"] != kind:
                continue
            if all(ev.get(k) == v for k, v in match.items()):
                n += 1
    return n


def race(path, mode, n=8, lead=1.2):
    """n REAL processes, released in the same tick, all claiming one id."""
    barrier = time.time() + lead
    ps = [subprocess.Popen(
        [sys.executable, os.path.join(HERE, "_unique_worker.py"),
         path, mode, str(barrier)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(n)]
    return [p.communicate()[0].strip() for p in ps]


print("=" * 78)
print("ORBIT A1 — SAFETY CLOSURE ROUND 2")
print("=" * 78)


# ======================================================================
banner("N1 — THE IDEMPOTENCY DECISION MUST BE ATOMIC WITH THE APPEND")
# DEFECT: record_intent() asked has_action(), which read an IN-MEMORY set, and
# THEN called append(), which took the lock. Two critical sections. The lock
# protected sequence numbers and the hash chain; it did not protect uniqueness.
# Eight processes each held their own empty cache, each saw "not present", and
# each committed. Eight durable INTENTs for one action, and the journal reported
# itself trusted — because it WAS internally consistent. It was just wrong.
# ======================================================================
def _n1(mode, kind, n=8, **match):
    p = os.path.join(TMP, f"n1_{mode}.jsonl")
    j = Journal(p, clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    if mode in ("fill", "fillgroup"):
        j.append_one(E.INTENT, "a1", client_order_id="same-cid",
                     contracts="0.01", instrument=A1.instrument,
                     order_kind="OPEN", side="long", role="ENTRY",
                     reduce_only=False)
    outs = race(p, mode, n)
    return p, outs, count_events(p, kind, **match)


p1, outs1, n_intent = _n1("intent", E.INTENT.value, action_id="same-action")
check("N1.1  eight processes claiming ONE action_id produce exactly ONE INTENT",
      n_intent == 1, f"{n_intent} durable INTENT records; workers={outs1}")

p2, outs2, n_fill = _n1("fill", E.FILL.value, fill_id="fill-1")
check("N1.2  eight processes claiming ONE fill_id produce exactly ONE FILL",
      n_fill == 1, f"{n_fill} durable FILL records; workers={outs2}")

check("N1.3  the journal is TRUSTED after both races",
      Journal.load(p1).trusted and Journal.load(p2).trusted)

check("N1.4a every process gets a deterministic answer — no errors",
      all(o in ("WROTE", "SUPPRESSED") for o in outs1 + outs2),
      str([o for o in outs1 + outs2 if o not in ("WROTE", "SUPPRESSED")]))
check("N1.4b exactly one process is told it WROTE; the rest are told SUPPRESSED",
      outs1.count("WROTE") == 1 and outs2.count("WROTE") == 1,
      f"intent={outs1.count('WROTE')} fill={outs2.count('WROTE')}")


def _n1_5():
    """A Journal object built BEFORE the record exists holds a cache that says
    the id is free. It must still not be able to write a second one."""
    p = os.path.join(TMP, "n1_stale.jsonl")
    j_stale = Journal(p, clock=lambda: NOW)      # cache built now: empty
    j_stale.append_one(E.RUN_START, None)
    j_other = Journal(p, clock=lambda: NOW)
    j_other.record_intent("A", client_order_id="cid-A", contracts="0.01")
    out = j_stale.record_intent("A", client_order_id="cid-A", contracts="0.01")
    return (out is None and count_events(p, E.INTENT.value, action_id="A") == 1,
            f"{count_events(p, E.INTENT.value, action_id='A')} INTENT(s)")


attempt("N1.5  a STALE Journal object cannot defeat uniqueness — the decision "
        "is made against fresh durable state, never a cache", _n1_5)


def _n1_6():
    """A writer that dies BEFORE committing must leave the id claimable."""
    from orbit.audit.journal import CrashPoint, Fault, SimulatedCrash
    p = os.path.join(TMP, "n1_crash_before.jsonl")
    Journal(p, clock=lambda: NOW).append_one(E.RUN_START, None)
    dying = Journal(p, fault=Fault(at_event=E.INTENT.value,
                                   point=CrashPoint.BEFORE_WRITE),
                    clock=lambda: NOW)
    try:
        dying.record_intent("B", client_order_id="cid-B", contracts="0.01")
    except SimulatedCrash:
        pass
    survivor = Journal(p, clock=lambda: NOW)
    out = survivor.record_intent("B", client_order_id="cid-B", contracts="0.01")
    return (out is not None
            and count_events(p, E.INTENT.value, action_id="B") == 1,
            f"{count_events(p, E.INTENT.value, action_id='B')} INTENT(s)")


attempt("N1.6  a writer that crashes BEFORE commit does not consume the id, "
        "and a later legitimate writer succeeds", _n1_6)


def _n1_7():
    """A writer that dies AFTER committing must have consumed it for everyone."""
    from orbit.audit.journal import CrashPoint, Fault, SimulatedCrash
    p = os.path.join(TMP, "n1_crash_after.jsonl")
    Journal(p, clock=lambda: NOW).append_one(E.RUN_START, None)
    dying = Journal(p, fault=Fault(at_event=E.INTENT.value,
                                   point=CrashPoint.AFTER_FSYNC),
                    clock=lambda: NOW)
    try:
        dying.record_intent("C", client_order_id="cid-C", contracts="0.01")
    except SimulatedCrash:
        pass
    later = Journal(p, clock=lambda: NOW)
    out = later.record_intent("C", client_order_id="cid-C", contracts="0.01")
    return (out is None
            and count_events(p, E.INTENT.value, action_id="C") == 1,
            f"{count_events(p, E.INTENT.value, action_id='C')} INTENT(s)")


attempt("N1.7  a writer that crashes AFTER commit has consumed the id: every "
        "later writer suppresses", _n1_7)


def _n1_8():
    """The rule must not serialise DIFFERENT work into a single writer."""
    p = os.path.join(TMP, "n1_distinct.jsonl")
    j = Journal(p, clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    wrote = [Journal(p, clock=lambda: NOW).record_intent(
        f"act-{i}", client_order_id=f"cid-{i}", contracts="0.01")
        for i in range(8)]
    return (all(w is not None for w in wrote)
            and count_events(p, E.INTENT.value) == 8
            and Journal.load(p).trusted,
            f"{count_events(p, E.INTENT.value)} INTENTs")


attempt("N1.8  eight DISTINCT action ids remain concurrently appendable", _n1_8)


def _n1_9():
    p = os.path.join(TMP, "n1_distinct_fills.jsonl")
    j = Journal(p, clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    j.append_one(E.INTENT, "a1", client_order_id="cid", contracts="1")
    wrote = [Journal(p, clock=lambda: NOW).record_fill(
        "a1", f"f{i}", client_order_id="cid", contracts="0.01")
        for i in range(8)]
    return (all(w is not None for w in wrote)
            and count_events(p, E.FILL.value) == 8,
            f"{count_events(p, E.FILL.value)} FILLs")


attempt("N1.9  eight DISTINCT fill ids remain concurrently appendable", _n1_9)

p3, outs3, n_fg = _n1("fillgroup", E.FILL.value, fill_id="fill-1")
n_pos = count_events(p3, E.POSITION_STATE.value)
n_ctr = count_events(p3, E.COUNTERS.value)
check("N1.10 a duplicated fill produces no duplicate POSITION_STATE or "
      "COUNTERS either — the whole atomic group is suppressed, not just the "
      "FILL", n_fg == 1 and n_pos == 1 and n_ctr == 1,
      f"FILL={n_fg} POSITION_STATE={n_pos} COUNTERS={n_ctr}; workers={outs3}")

p4, outs4, n_prot = _n1("protective", E.PROTECTIVE_INTENT.value,
                        action_id="stop-1")
check("N1.11 the protective-intent path has the same guarantee",
      n_prot == 1, f"{n_prot} PROTECTIVE_INTENTs; workers={outs4}")
check("N1.12 and its journal is trusted too", Journal.load(p4).trusted)


# ======================================================================
banner("N2 — THE ADAPTER MUST BIND THE PAYLOAD TO THE DURABLE INTENT")
# DEFECT: the boundary proved that A durable INTENT existed for the client order
# id, that we still held authority, and that role and reduce_only agreed with
# each other. It never proved that the mutation about to reach the exchange was
# the mutation that had been approved and journalled. A valid INTENT for payload
# A therefore acted as permission for a completely different payload B:
#
#   INTENT: long 0.01 contracts.  Sent: SHORT 99.99 contracts.  Accepted.
# ======================================================================
BOUND = dict(instrument=A1.instrument, order_kind="OPEN", side="long",
             contracts=D("0.01"), role=Role.ENTRY.value, reduce_only=False,
             order_type="market", price=None, stop=None,
             target_client_order_id=None, logical_operation_id="k:g0")


def _bind_probe(cid="cid1", **override):
    """Journal an INTENT, then call the adapter with a payload that differs in
    exactly the fields named in `override`. Everything else is identical."""
    from orbit.exec.adapter import DurableIntentMismatch
    rg = Rig(TMP, "n2_" + cid, intended=flat())
    lz = rg.acquire()
    rg.journal.record_intent(
        "a-" + cid, client_order_id=cid,
        instrument=BOUND["instrument"], order_kind=BOUND["order_kind"],
        side=BOUND["side"], contracts=str(BOUND["contracts"]),
        role=BOUND["role"], reduce_only=BOUND["reduce_only"],
        order_type=BOUND["order_type"],
        logical_operation_id=BOUND["logical_operation_id"],
        operation_id=BOUND["logical_operation_id"],
        target_client_order_id=BOUND["target_client_order_id"],
        stop=BOUND["stop"], price=BOUND["price"])
    sent = dict(BOUND)
    sent.update(override)
    try:
        rg.adapter.submit_order(
            lz, cid, sent["side"], sent["contracts"], sent["order_type"],
            sent["price"], reduce_only=sent["reduce_only"], role=sent["role"],
            instrument=sent["instrument"], order_kind=sent["order_kind"],
            logical_operation_id=sent["logical_operation_id"])
    except DurableIntentMismatch as e:
        return True, f"refused ({len(rg.adapter.calls)} calls): {str(e)[:52]}"
    return False, f"ACCEPTED — {len(rg.adapter.calls)} exchange call(s) made"


N2_FIELDS = [
    ("side", dict(side="short")),
    ("contracts", dict(contracts=D("99.99"))),
    ("instrument", dict(instrument="ETH-USDT-SWAP")),
    ("order_kind", dict(order_kind="CLOSE")),
    ("role", dict(role=Role.EXIT.value, reduce_only=True)),
    ("reduce_only", dict(reduce_only=True, role=Role.EXIT.value)),
    ("order_type", dict(order_type="limit", price=D("29900.0"))),
    ("price", dict(price=D("29900.0"))),
    ("logical_operation_id", dict(logical_operation_id="other:g0")),
]
for i, (field, override) in enumerate(N2_FIELDS, start=1):
    attempt(f"N2.{i}  a mutation whose {field} differs from the durable INTENT "
            f"is REFUSED, with zero exchange mutations",
            lambda o=override, f=field: _bind_probe("cid-" + f, **o))

attempt("N2.10 an identical payload is ACCEPTED — the binding must not block "
        "legitimate work",
        lambda: (lambda r: (not r[0], r[1]))(_bind_probe("cid-identical")))


def _n2_amend():
    from orbit.exec.adapter import DurableIntentMismatch
    rg = Rig(TMP, "n2_amend", intended=flat())
    lz = rg.acquire()
    rg.journal.record_intent(
        "a-am", client_order_id="mut1", instrument=A1.instrument,
        order_kind="MODIFY_STOP", role=Role.ADMIN.value, reduce_only=True,
        target_client_order_id="stop1", stop="29800.1", order_type="stop",
        logical_operation_id="k:g0", operation_id="k:g0")
    try:
        rg.adapter.amend_stop(lz, "mut1", D("29800.1"),
                              target_client_order_id="OTHER-ORDER")
    except DurableIntentMismatch as e:
        return True, str(e)[:60]
    return False, "an amend was redirected to a different resting order"


attempt("N2.11 an amend redirected to a DIFFERENT target order is refused",
        _n2_amend)


def _n2_stop():
    from orbit.exec.adapter import DurableIntentMismatch
    rg = Rig(TMP, "n2_stop", intended=flat())
    lz = rg.acquire()
    rg.journal.record_intent(
        "a-st", client_order_id="mut2", instrument=A1.instrument,
        order_kind="MODIFY_STOP", role=Role.ADMIN.value, reduce_only=True,
        target_client_order_id="stop1", stop="29800.1", order_type="stop",
        logical_operation_id="k:g0", operation_id="k:g0")
    try:
        rg.adapter.amend_stop(lz, "mut2", D("29500.0"),
                              target_client_order_id="stop1")
    except DurableIntentMismatch as e:
        return True, str(e)[:60]
    return False, "a stop was amended to a price that was never approved"


attempt("N2.12 an amend to a stop price that was never approved is refused — "
        "this is the stop-widening rule's last line of defence", _n2_stop)


def _n2_endtoend():
    """The real path must still work, and must exercise the binding."""
    ex = Exch(position=pos(), orders=[stop_order(cid="stop1")])
    rg = Rig(TMP, "n2_e2e", intended=held(cid="stop1"), exch=ex)
    rg.acquire()
    out = rg.session("c1").close_position()
    return (out.reached_exchange and len(rg.adapter.calls) == 1,
            f"{out.status.value}/{out.code} calls={len(rg.adapter.calls)}")


attempt("N2.13 the ordinary session path satisfies the binding end to end",
        _n2_endtoend)


# ======================================================================
banner("N3 — ONE CANONICAL MODELLED-LOSS FUNCTION, USED BY BOTH SIDES")
# DEFECT: the gateway sized a position against stop distance + entry fee + exit
# fee + modelled stop slippage. The reconciler's post-fill overrun check used
# price distance ALONE. The two answered different questions and were compared
# to the same $8 cap, so a fill whose modelled loss was 8.108483166 under the
# gateway's own definition reported 7.25662 and stayed RUNNING.
#
# Worked example, frozen here so a drift in either side fails this test:
#   reference 30000, stop 29700.1, size 0.0238 BTC -> gateway 7.989423666
#   actual fill 30005 -> price-only 7.25662, canonical 8.108483166 > 8 cap
# ======================================================================
def _canon(entry, stop, size_btc):
    from orbit.risk.modeled_loss import modeled_loss
    return modeled_loss(D(entry), D(stop), D(size_btc), SPEC, A1)


attempt("N3.1  a single canonical modelled-loss function exists",
        lambda: (_canon("30000", "29700.1", "0.0238").total_usdt is not None,
                 str(_canon("30000", "29700.1", "0.0238").total_usdt)))

attempt("N3.2  it reproduces the GATEWAY's frozen pre-entry number exactly",
        lambda: (_canon("30000", "29700.1", "0.0238").total_usdt
                 == D("7.989423666"),
                 str(_canon("30000", "29700.1", "0.0238").total_usdt)))

attempt("N3.3  and the worked post-fill number the audit computed by hand",
        lambda: (_canon("30005", "29700.1", "0.0238").total_usdt
                 == D("8.108483166"),
                 str(_canon("30005", "29700.1", "0.0238").total_usdt)))


def _n3_components():
    m = _canon("30005", "29700.1", "0.0238")
    return ((m.price_risk_usdt == D("7.25662")
             and m.total_usdt == m.price_risk_usdt + m.entry_fee_usdt
             + m.exit_fee_usdt + m.slippage_usdt),
            f"price={m.price_risk_usdt} entry_fee={m.entry_fee_usdt} "
            f"exit_fee={m.exit_fee_usdt} slip={m.slippage_usdt}")


attempt("N3.4  the components are named separately and sum to the total — "
        "price risk, entry fee, modelled exit fee, modelled stop slippage",
        _n3_components)


GW = Gateway()


def _n3_gateway_uses_it():
    """The gateway must not carry its own copy of the formula."""
    src = open(os.path.join(ROOT, "orbit", "risk", "gateway.py")).read()
    uses = "modeled_loss" in src or "risk_per_unit_usdt" in src
    dup = "taker_fee *" in src or "slippage_bps /" in src
    return uses and not dup, f"uses_shared={uses} duplicates_formula={dup}"


attempt("N3.5  the gateway uses the shared function and no longer carries a "
        "duplicate of the formula", _n3_gateway_uses_it)


def _n3_recon_uses_it():
    src = open(os.path.join(ROOT, "orbit", "exec", "recon.py")).read()
    uses = "modeled_loss" in src
    dup = "abs(adopted.entry_price - ref_stop) * adopted.size_btc" in src
    return uses and not dup, f"uses_shared={uses} price_only_left={dup}"


attempt("N3.6  the reconciler uses the shared function and the price-only "
        "expression is gone", _n3_recon_uses_it)


def _n3_state(entry, stop="29700.1", contracts="2.38"):
    ex = Exch(position=pos(entry=entry, contracts=contracts),
              orders=[stop_order(cid="stop1", contracts=contracts, price=stop)])
    st = IntendedState(
        journal_loaded=True, clean_shutdown=True, entries_utc_day=1,
        position=IntendedPosition("long", D(contracts), D(entry), D(stop),
                                  "stop1", NOW - timedelta(minutes=30)),
        submitted_orders=(
            SubmittedOrder("e1", D(contracts), D(contracts), OrderStatus.FILLED,
                           NOW, instrument=A1.instrument, side="long",
                           kind="OPEN", role="ENTRY", reduce_only=False),
            SubmittedOrder("stop1", D(contracts), D("0"), OrderStatus.ACK, NOW,
                           True, instrument=A1.instrument, side="short",
                           kind="PROTECTIVE", role="PROTECTIVE",
                           reduce_only=True)))
    return reconcile(st, ex.view(), NOW)


r_over = _n3_state("30005")
check("N3.7  the worked overrun fill is now reported as a budget breach",
      any("BUDGET" in f.code.value for f in r_over.findings),
      f"{[f.code.value for f in r_over.findings]} "
      f"planned={r_over.protection.planned_risk_usdt if r_over.protection else None}")
check("N3.8  and it does not remain RUNNING",
      r_over.run_state is not RunState.RUNNING, r_over.run_state.value)

r_under = _n3_state("30000")
check("N3.9  the same fill at the reference price is within budget and RUNNING",
      not any("BUDGET" in f.code.value for f in r_under.findings)
      and r_under.run_state is RunState.RUNNING,
      f"{r_under.run_state.value} "
      f"planned={r_under.protection.planned_risk_usdt if r_under.protection else None}")


def _n3_boundary():
    """Walk the fill price across the exact cap and prove the flip happens at
    the boundary, not near it."""
    below = above = None
    e = D("30000.0")
    while e <= D("30010.0"):
        m = _canon(str(e), "29700.1", "0.0238")
        if m.total_usdt <= A1.planned_risk_usdt:
            below = (e, m.total_usdt)
        elif above is None:
            above = (e, m.total_usdt)
        e += D("0.1")
    r_b = _n3_state(str(below[0]))
    r_a = _n3_state(str(above[0]))
    ok = (not any("BUDGET" in f.code.value for f in r_b.findings)
          and any("BUDGET" in f.code.value for f in r_a.findings))
    return ok, (f"last within budget {below[0]}->{below[1]}; "
                f"first over {above[0]}->{above[1]}")


attempt("N3.10 the RUNNING/NOT-RUNNING flip lands exactly on the $8 boundary",
        _n3_boundary)


def _n3_known_costs():
    """The contract must distinguish a modelled entry cost from a known one."""
    from orbit.risk.modeled_loss import modeled_loss
    m = modeled_loss(D("30005"), D("29700.1"), D("0.0238"), SPEC, A1,
                     actual_entry_fee_usdt=D("0.5"))
    return (m.entry_fee_usdt == D("0.5") and m.entry_fee_is_actual
            and not m.exit_fee_is_actual,
            f"entry_fee={m.entry_fee_usdt} actual={m.entry_fee_is_actual}")


attempt("N3.11 a KNOWN realised entry cost replaces the modelled one, and the "
        "future stop execution cost stays explicitly modelled", _n3_known_costs)


# ======================================================================
banner("N4 — A DURABLE DecisionInput, NOT JUST A PROMPT HASH")
# DEFECT: the round-1 fix stored sha256(prompt_text). A hash proves EQUALITY if
# the original is available somewhere else. It reconstructs nothing. The
# requirement was "what exactly did Claude know when it made this decision?",
# and after a restart the answer was still unavailable.
# ======================================================================
def _build_input(store_dir, prompt="decide now", tools=None):
    from orbit.audit.decision_input import DecisionInput
    return DecisionInput(
        system_prompt="You are ORBIT A1. You may not execute anything.",
        user_prompt=prompt,
        messages=({"role": "user", "content": prompt},),
        tool_schema=tools or {"get_market_state": {"params": {}},
                              "propose_order": {"params": {"side": "str"}}},
        tool_results=({"tool": "get_market_state", "ref": "r1",
                       "data": {"mark_price": "30000"}},),
        account_state={"equity": "1000"},
        position_state={"side": "long", "contracts": "2.38"},
        open_orders=({"client_order_id": "stop1"},),
        memory=(),
        policy_version="A1", model_id="none")


def _n4_1():
    di = _build_input(TMP)
    h = di.hashes()
    need = ("system_prompt_hash", "user_prompt_hash", "tool_schema_hash",
            "model_input_hash")
    return (all(k in h and len(h[k]) == 64 for k in need),
            str(sorted(h))[:100])


attempt("N4.1  every required hash is recorded separately", _n4_1)


def _n4_2():
    a = _build_input(TMP, prompt="one")
    b = _build_input(TMP, prompt="two")
    return (a.hashes()["model_input_hash"] != b.hashes()["model_input_hash"]
            and a.hashes()["system_prompt_hash"]
            == b.hashes()["system_prompt_hash"],
            "prompt change moves the input hash, not the system-prompt hash")


attempt("N4.2  a changed user prompt changes the model input hash and nothing "
        "it should not", _n4_2)


def _n4_3():
    a = _build_input(TMP)
    b = _build_input(TMP, tools={"propose_order": {"params": {"side": "str"}},
                                 "get_market_state": {"params": {}}})
    return (a.hashes()["tool_schema_hash"] == b.hashes()["tool_schema_hash"],
            "the serialisation is canonical: key order does not change a hash")


attempt("N4.3  serialisation is canonical — reordering does not change a hash",
        _n4_3)


def _n4_4():
    a = _build_input(TMP)
    b = _build_input(TMP, tools={"propose_order": {"params": {"side": "str"}}})
    return (a.hashes()["tool_schema_hash"] != b.hashes()["tool_schema_hash"]
            and a.hashes()["model_input_hash"] != b.hashes()["model_input_hash"],
            "a removed tool is a different input")


attempt("N4.4  a changed TOOL SCHEMA is a different decision input", _n4_4)


def _n4_5():
    from orbit.audit.blobstore import BlobStore
    st = BlobStore(os.path.join(TMP, "blobs_5"))
    di = _build_input(TMP)
    cid = st.put(di.serialize())
    return (os.path.exists(st.path_for(cid)) and st.get(cid) == di.serialize(),
            f"content id {cid[:16]}…")


attempt("N4.5  the exact serialised bytes are stored durably, content-addressed",
        _n4_5)


def _n4_6():
    """THE TEST THAT MATTERS: a genuinely separate process, with nothing but the
    journal and the blob store on disk, reconstructs the exact bytes and
    reproduces the same model_input_hash."""
    d = os.path.join(TMP, "n4_restart")
    os.makedirs(d, exist_ok=True)
    jpath = os.path.join(d, "journal.jsonl")
    blobs = os.path.join(d, "blobs")
    from orbit.audit.blobstore import BlobStore
    from orbit.audit.decision_input import record_decision_input
    j = Journal(jpath, clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    di = _build_input(TMP, prompt="reconstruct me exactly")
    ref = record_decision_input(j, BlobStore(blobs), "d1", di)
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "_reconstruct_worker.py"),
         jpath, blobs, "d1"],
        cwd=ROOT, capture_output=True, text=True)
    got = json.loads(out.stdout or "{}")
    return (got.get("model_input_hash") == ref["model_input_hash"]
            and got.get("bytes_identical") is True,
            f"{out.stderr[-90:] if out.returncode else got}")


attempt("N4.6  a SEPARATE PROCESS reconstructs the exact input bytes from disk "
        "alone and reproduces the same model_input_hash", _n4_6)


def _n4_7():
    from orbit.audit.blobstore import BlobStore
    st = BlobStore(os.path.join(TMP, "blobs_7"))
    di = _build_input(TMP)
    cid = st.put(di.serialize())
    with open(st.path_for(cid), "ab") as fh:
        fh.write(b" ")
    try:
        st.get(cid)
    except Exception as e:                                # noqa: BLE001
        return True, f"{type(e).__name__}: {str(e)[:50]}"
    return False, "a corrupted blob was returned as though it were intact"


attempt("N4.7  a corrupted blob is detected, not silently returned", _n4_7)


def _n4_8():
    di = _build_input(TMP)
    return (di.serialize() == di.serialize()
            and _build_input(TMP).serialize() == di.serialize(),
            "serialisation is deterministic across construction")


attempt("N4.8  serialisation is deterministic", _n4_8)


def _n4_9():
    di = _build_input(TMP)
    blob = json.loads(di.serialize().decode())
    need = ("system_prompt", "user_prompt", "messages", "tool_schema",
            "tool_results", "account_state", "position_state", "open_orders",
            "memory", "policy_version", "model_id", "serialization_version")
    missing = [k for k in need if k not in blob]
    return not missing, f"missing {missing}"


attempt("N4.9  the artifact carries every field the requirement names", _n4_9)


def _n4_10():
    d = os.path.join(TMP, "n4_journal")
    os.makedirs(d, exist_ok=True)
    from orbit.audit.blobstore import BlobStore
    from orbit.audit.decision_input import record_decision_input
    j = Journal(os.path.join(d, "j.jsonl"), clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    di = _build_input(TMP)
    ref = record_decision_input(j, BlobStore(os.path.join(d, "b")), "d9", di)
    evs = [ev for rec in Journal.load(os.path.join(d, "j.jsonl")).records
           for ev in rec["events"] if ev["e"] == E.DECISION_INPUT.value]
    return (len(evs) == 1
            and evs[0]["model_input_hash"] == ref["model_input_hash"]
            and evs[0]["content_id"] == ref["content_id"],
            f"{len(evs)} DECISION_INPUT record(s)")


attempt("N4.10 the reference is written durably into the journal as its own "
        "record type", _n4_10)


# ======================================================================
banner("N5 — THE RUNTIME CONTRACT IS EXPLICIT, NOT IMPLIED")
# DEFECT: `import fcntl` at module scope. On native Windows the journal module
# cannot import at all, so the failure would arrive as an ImportError deep in a
# traceback rather than as a stated deployment contract. Nothing in the code or
# the tests said which platforms and filesystems ORBIT supports.
#
# DECISION TAKEN: option A. ORBIT A1 runs on POSIX (Linux / WSL2 / container)
# on a LOCAL filesystem. It is declared, checked at startup, and stated in the
# report. A cross-platform lock is NOT claimed, because it could not be tested
# here and an untested lock is worse than a refused start.
# ======================================================================
def _n5_1():
    from orbit.runtime import RUNTIME_CONTRACT, UnsupportedPlatform
    return (bool(RUNTIME_CONTRACT.get("platforms"))
            and bool(RUNTIME_CONTRACT.get("filesystems"))
            and bool(RUNTIME_CONTRACT.get("reason")),
            str(RUNTIME_CONTRACT.get("platforms")))


attempt("N5.1  a runtime contract is declared in code", _n5_1)


def _n5_2():
    from orbit.runtime import check_platform
    ok, why = check_platform("linux")
    return ok, why[:60]


attempt("N5.2  the supported platform passes the check", _n5_2)


def _n5_3():
    from orbit.runtime import check_platform
    ok, why = check_platform("win32")
    return (not ok and "fcntl" in why.lower() or "posix" in why.lower(),
            why[:80])


attempt("N5.3  an unsupported platform is refused with a message that names "
        "the reason", _n5_3)


def _n5_4():
    from orbit.runtime import UnsupportedPlatform, require_supported_platform
    try:
        require_supported_platform("win32")
    except UnsupportedPlatform as e:
        return True, str(e)[:70]
    return False, "startup accepted an unsupported platform"


attempt("N5.4  startup REFUSES an unsupported platform rather than failing "
        "later inside a traceback", _n5_4)


def _n5_5():
    from orbit import runtime
    return (runtime.require_supported_platform() is None,
            "the current platform is supported, so the suite may run")


attempt("N5.5  the current platform satisfies the contract", _n5_5)


def _n5_6():
    src = open(os.path.join(ROOT, "orbit", "audit", "journal.py")).read()
    return ("require_supported_platform" in src,
            "the journal asserts the contract where the lock is defined")


attempt("N5.6  the journal states the contract at the point of the dependency",
        _n5_6)


def _n5_7():
    from orbit.runtime import RUNTIME_CONTRACT
    fs = " ".join(RUNTIME_CONTRACT["filesystems"]).lower()
    return ("nfs" in fs, "the filesystem limit is stated, NFS included")


attempt("N5.7  the filesystem limit is stated explicitly, NFS named", _n5_7)


# ======================================================================
banner("N6 — ADMIN MUTATIONS MUST TERMINALISE")
# DEFECT: a CANCEL and a MODIFY_STOP each carry their OWN operation identity
# while targeting an EXISTING order's identity. An ORDER_STATUS about the TARGET
# says nothing about the MUTATION. So an acknowledged, fully successful stop
# amendment stayed nonterminal for ever:
#
#   after ACK and the target confirmed at the new stop:
#   unresolved = [('MODIFY_STOP', 'ACK')]
#
# which blocks the next amendment and makes a clean shutdown impossible.
# ======================================================================
def _trusted(rg, ex, intended=None):
    """SAFETY CLOSURE ROUND 3, R3-3: the resolver no longer accepts a raw
    ExchangeView, because "we cannot see the exchange" was being converted into
    "positive evidence the operation finished". These fixtures now hand it a
    reconciliation result, and assert the evidence really was eligible — so a
    test can never pass merely because the trust gate refused."""
    from orbit.exec.resolver import is_eligible_evidence
    r = reconcile(intended if intended is not None else rg.intended,
                  ex.view(), NOW)
    v = is_eligible_evidence(r)
    assert v.eligible, f"fixture evidence is not eligible: {v.reason}"
    return r


def _admin_rig(name, orders, intended=None, cid="stop1"):
    ex = Exch(position=pos(), orders=orders)
    rg = Rig(TMP, name, intended=intended or held(cid=cid), exch=ex)
    rg.acquire()
    # SAFETY CLOSURE ROUND 4B, R4-1. A stop ORBIT placed has a durable record
    # behind it; the amendment path now proves ownership of its target, as the
    # cancellation path already did.
    owning(rg, cid)
    return rg, ex


def _n6_1():
    from orbit.exec.resolver import resolve_operations
    rg, ex = _admin_rig("n6_1", [stop_order(cid="stop1")])
    rg.session("c1").modify_stop("29800.1")
    ex.orders = [stop_order(cid="stop1", price="29800.1")]   # target confirmed
    res = resolve_operations(rg.journal, _trusted(rg, ex), NOW)
    led = OperationLedger(rg.path)
    admin = [o for o in led.unresolved() if o.kind == "MODIFY_STOP"]
    return (not admin,
            f"{[(o.kind, o.status.value) for o in led.unresolved()]} "
            f"resolutions={[r.outcome for r in res]}")


attempt("N6.1  a stop amendment ACKed and CONFIRMED at the new stop becomes "
        "terminal", _n6_1)


def _n6_2():
    from orbit.exec.resolver import resolve_operations
    rg, ex = _admin_rig("n6_2", [stop_order(cid="stop1")])
    rg.session("c1").modify_stop("29800.1")
    resolve_operations(rg.journal, _trusted(rg, ex), NOW)  # still the OLD stop
    led = OperationLedger(rg.path)
    admin = [o for o in led.unresolved() if o.kind == "MODIFY_STOP"]
    return (len(admin) == 1,
            f"{[(o.kind, o.status.value) for o in led.unresolved()]}")


attempt("N6.2  an amendment the exchange has NOT applied stays unresolved — "
        "acknowledgement is not application", _n6_2)


def _n6_3():
    from orbit.exec.resolver import resolve_operations
    ex = Exch(position=None, orders=[stop_order(cid="own1", contracts="2.38")])
    rg = Rig(TMP, "n6_3", intended=flat(), exch=ex)
    rg.acquire()
    owning(rg, "own1")
    rg.session("c1").cancel_order("own1")
    ex.orders = []                                     # the order is gone
    resolve_operations(rg.journal, _trusted(rg, ex), NOW)
    led = OperationLedger(rg.path)
    return ([o for o in led.unresolved() if o.kind == "CANCEL"] == [],
            f"{[(o.kind, o.status.value) for o in led.unresolved()]}")


attempt("N6.3  a cancel ACKed and CONFIRMED gone becomes terminal", _n6_3)


def _n6_4():
    from orbit.exec.resolver import resolve_operations
    ex = Exch(position=None, orders=[stop_order(cid="own2", contracts="2.38")])
    rg = Rig(TMP, "n6_4", intended=flat(), exch=ex)
    rg.acquire()
    owning(rg, "own2")
    rg.session("c1").cancel_order("own2")
    resolve_operations(rg.journal, _trusted(rg, ex), NOW)   # still resting
    led = OperationLedger(rg.path)
    return (len([o for o in led.unresolved() if o.kind == "CANCEL"]) == 1,
            f"{[(o.kind, o.status.value) for o in led.unresolved()]}")


attempt("N6.4  a cancel whose target is still resting stays unresolved", _n6_4)


def _n6_5():
    from orbit.exec.resolver import resolve_operations
    rg, ex = _admin_rig("n6_5", [stop_order(cid="stop1")])
    rg.adapter.timeout_next = True
    out = rg.session("c1").modify_stop("29800.1")
    ex.orders = [stop_order(cid="stop1", price="29800.1")]   # it DID land
    resolve_operations(rg.journal, _trusted(rg, ex), NOW)
    led = OperationLedger(rg.path)
    admin = [o for o in led.unresolved() if o.kind == "MODIFY_STOP"]
    return (out.status is ActionStatus.UNKNOWN and not admin,
            f"{out.status.value} -> "
            f"{[(o.kind, o.status.value) for o in led.unresolved()]}")


attempt("N6.5  a TIMEOUT that later state proves succeeded resolves to "
        "terminal", _n6_5)


def _n6_6():
    from orbit.exec.resolver import resolve_operations
    ex = Exch(position=None, orders=[stop_order(cid="own3", contracts="2.38")])
    rg = Rig(TMP, "n6_6", intended=flat(), exch=ex)
    rg.acquire()
    owning(rg, "own3")
    rg.adapter.timeout_next = True
    rg.session("c1").cancel_order("own3")
    for _ in range(4):                     # the target never goes away
        resolve_operations(rg.journal, _trusted(rg, ex), NOW)
    led = OperationLedger(rg.path)
    op = next((o for o in led.all() if o.kind == "CANCEL"), None)
    return (op is not None and op.unresolved,
            f"{op.status.value if op else None} — ambiguity is not resolved by "
            f"repetition")


attempt("N6.6  an AMBIGUOUS outcome stays unresolved however many times the "
        "resolver runs", _n6_6)


def _n6_7():
    from orbit.exec.resolver import resolve_operations
    rg, ex = _admin_rig("n6_7", [stop_order(cid="stop1")])
    rg.session("c1").modify_stop("29800.1")
    rep = recover(rg.path)
    r = reconcile(rep.rebuilt, ex.view(), NOW)
    from orbit.audit.recovery import write_clean_shutdown
    wrote = write_clean_shutdown(
        rg.journal, len(outstanding_operations(rep, r)), r)
    return (not wrote,
            "a clean shutdown is impossible while an admin mutation is "
            "genuinely unresolved")


attempt("N6.7  a clean shutdown is refused while an admin mutation is "
        "unresolved", _n6_7)


def _n6_8():
    from orbit.exec.resolver import resolve_operations
    rg, ex = _admin_rig("n6_8", [stop_order(cid="stop1")])
    rg.session("c1").modify_stop("29800.1")
    ex.orders = [stop_order(cid="stop1", price="29800.1")]
    resolve_operations(rg.journal, _trusted(rg, ex), NOW)
    rg.intended = held(cid="stop1", stop="29800.1")
    out = rg.session("c2").modify_stop("29900.1")
    return (out.reached_exchange,
            f"{out.status.value}/{out.code} — a resolved admin operation must "
            f"not deadlock the next generation")


attempt("N6.8  once resolved, the SAME admin operation may be performed again "
        "at the next generation", _n6_8)


def _n6_9():
    from orbit.exec.resolver import resolve_operations
    rg, ex = _admin_rig("n6_9", [stop_order(cid="stop1")])
    rg.session("c1").modify_stop("29800.1")
    ex.orders = [stop_order(cid="stop1", price="29800.1")]
    res = resolve_operations(rg.journal, _trusted(rg, ex), NOW)
    evs = [ev for rec in Journal.load(rg.path).records for ev in rec["events"]
           if ev["e"] == E.ORDER_STATUS.value]
    return (bool(res) and bool(evs)
            and all(r.evidence for r in res),
            f"{[(r.outcome, r.evidence[:34]) for r in res]}")


attempt("N6.9  every resolution is recorded durably, with its evidence", _n6_9)


def _n6_10():
    """The resolver is deterministic: running it twice changes nothing."""
    from orbit.exec.resolver import resolve_operations
    rg, ex = _admin_rig("n6_10", [stop_order(cid="stop1")])
    rg.session("c1").modify_stop("29800.1")
    ex.orders = [stop_order(cid="stop1", price="29800.1")]
    first = resolve_operations(rg.journal, _trusted(rg, ex), NOW)
    n1 = len(Journal.load(rg.path).records)
    second = resolve_operations(rg.journal, _trusted(rg, ex), NOW)
    n2 = len(Journal.load(rg.path).records)
    return (len(first) == 1 and second == [] and n1 == n2,
            f"first={len(first)} second={len(second)} records {n1}->{n2}")


attempt("N6.10 the resolver is idempotent: a second run resolves nothing and "
        "writes nothing", _n6_10)


def _n6_11():
    """The model must not be able to reach the resolver."""
    ex = Exch(position=pos(), orders=[stop_order(cid="stop1")])
    rg = Rig(TMP, "n6_11", intended=held(cid="stop1"), exch=ex)
    rg.acquire()
    s = rg.session("c1")
    public = [a for a in dir(s) if not a.startswith("_")]
    leaked = [a for a in public if "resolve" in a.lower()]
    return not leaked, str(leaked)


attempt("N6.11 the resolver is NOT a capability the model is granted", _n6_11)


def _n6_12():
    from orbit.exec.operations import TERMINAL, NONTERMINAL
    return (OpStatus.EFFECTIVE in TERMINAL
            and OpStatus.ACK in NONTERMINAL,
            f"terminal={sorted(s.value for s in TERMINAL)}")


attempt("N6.12 an applied admin mutation has its own TERMINAL status, distinct "
        "from a fill", _n6_12)


shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("Round-2 findings closed. No model. No credentials. No network. "
      "No live capital.")
