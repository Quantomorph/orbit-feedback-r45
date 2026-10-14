"""
tests/test_safety_closure.py — ORBIT A1 SAFETY CLOSURE, S4/S5/S6.

Every test in this file was written to FAIL against the repository as it stood
on 2026-09-08, before any fix. Each one is the smallest concrete scenario that
exhibits a defect found by the independent GPT-5.6 Sol reassessment.

The 302 assertions of the existing suites all passed while every one of these
failed. That is the point: they encode assumptions the earlier tests shared with
the implementation.

    A  logical operation identity across cycles and restarts
    B  reduce_only end to end
    C  durable order schema and authorship
    D  outstanding remediation must prevent RUNNING
    E  ACK is not terminal
    F  torn-tail repair
    G  cross-process append serialisation
    H  in-flight mutation versus lease expiry
    I  the model may cancel only ORBIT-owned orders
    J  MODIFY_STOP needs two identities
    K  gateway-independent enum and geometry validation
    L  actual-fill risk beyond the planned budget
    M  one frozen decision snapshot, real prompt hash

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from datetime import timedelta
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, owning, pos, stop_order
from orbit.audit.journal import Journal, TamperedJournalError
from orbit.audit.records import E, GENESIS, event, make_record
from orbit.audit.recovery import (recover, write_clean_shutdown)
from orbit.exec.adapter import NullAdapter, WriteAheadViolation
from orbit.exec.recon import (ExchangeOrder, IntendedPosition, IntendedState,
                              OrderStatus, SubmittedOrder, reconcile)
from orbit.exec.writer import StaleWriterError, WriterAuthority
from orbit.risk.gateway import Code, Gateway, Kind, ProposedAction
from orbit.risk.limits import A1, RunState
from orbit.tools.session import ActionStatus, ToolSession

PASS, FAIL = [], []
TMP = tempfile.mkdtemp(prefix="orbit_sc_")


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
    except Exception as e:
        check(name, False, f"{type(e).__name__}: {e}"[:110])
        return False
    check(name, ok, detail)
    return bool(ok)


print("=" * 78)
print("ORBIT A1 — SAFETY CLOSURE REGRESSION SUITE (S4/S5/S6)")
print("=" * 78)


# ======================================================================
banner("A — LOGICAL OPERATION IDENTITY ACROSS CYCLES AND RESTARTS")
# DEFECT: identity was hash(cycle_id, tool, params). A CLOSE whose outcome was
# never established was re-proposed in the next cycle under a NEW identity, and
# a SECOND external mutation was sent for one logical intent.
# ======================================================================
from orbit.exec.operations import (NONTERMINAL, TERMINAL, OperationLedger,
                                   OpStatus, Role, client_order_id_for,
                                   logical_key)

ex_a = Exch(position=pos(), orders=[stop_order()])
rig_a = Rig(TMP, "A", intended=held(), exch=ex_a)
rig_a.acquire()

rig_a.adapter.timeout_next = True
r1 = rig_a.session("cycA").close_position()
check("A1. cycle A: the CLOSE times out and the outcome is UNKNOWN",
      r1.status is ActionStatus.UNKNOWN, r1.code)
check("A2. exactly one exchange mutation was made",
      len(rig_a.adapter.calls) == 1, f"{len(rig_a.adapter.calls)} calls")

r2 = rig_a.session("cycB").close_position()
check("A3. cycle B: the same CLOSE is REFUSED while the first is unresolved",
      not r2.reached_exchange, f"{r2.status.value}/{r2.code}")
check("A4. SECOND EXCHANGE MUTATION COUNT IS ZERO",
      len(rig_a.adapter.calls) == 1, f"{len(rig_a.adapter.calls)} calls")
check("A5. the refusal names the unresolved operation, not a new one",
      r2.client_order_id == r1.client_order_id,
      f"{r2.client_order_id} vs {r1.client_order_id}")

led_a = OperationLedger(rig_a.path)
# SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 8. These two asserted a
# GLOBAL count: `len(unresolved()) == 1`. The rig now seeds the position's
# resting protective stop as the durable PROTECTIVE_INTENT + ACK production
# would have written, and a resting stop is genuinely nonterminal, so the
# ledger truthfully reports two unresolved operations. The count was never the
# invariant; the CLOSE's own lifecycle is. Asserted against THAT operation.
_close_a = led_a.open_for(logical_key(A1.instrument, "CLOSE"))
check("A6. the ledger reconstructs the unresolved CLOSE from the journal alone, "
      "under the identity the action was given",
      _close_a is not None
      and _close_a.client_order_id == r1.client_order_id
      and _close_a.unresolved,
      str([(o.kind, o.status.value) for o in led_a.unresolved()]))
check("A7. and it is nonterminal because UNKNOWN is not an outcome",
      _close_a is not None and _close_a.status is OpStatus.UNKNOWN)

# resolve it the only legitimate way: positive evidence
rig_a.rec.record_order_status(r1.action_id, r1.client_order_id, "CANCELLED")
r3 = rig_a.session("cycC").close_position()
check("A8. once the operation is genuinely terminal a later CLOSE is permitted "
      "again — a terminal operation must not block forever",
      r3.reached_exchange, f"{r3.status.value}/{r3.code}")
check("A9. and it carries a NEW identity (generation advanced)",
      r3.client_order_id != r1.client_order_id)
check("A10. one exchange mutation per logical operation, never per cycle",
      len(rig_a.adapter.calls) == 2, f"{len(rig_a.adapter.calls)} calls")

k1 = logical_key("BTC-USDT-SWAP", "CLOSE")
k2 = logical_key("BTC-USDT-SWAP", "CLOSE")
check("A11. the logical key is independent of cycle, epoch, session and clock",
      k1 == k2 and k1 != logical_key("BTC-USDT-SWAP", "MODIFY_STOP"))

# SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 7. THIS ASSERTION IS
# REVERSED, DELIBERATELY, AND THE REVERSAL IS THE FINDING.
#
# It used to demand that an unresolved CLOSE "does not block an unrelated
# MODIFY_STOP", and it held because the tree at the time did not stop it. But a
# stop amendment is NOT unrelated to a CLOSE whose outcome is unknown: it is a
# mutation of the protection of a position that may no longer exist - and if
# the CLOSE did NOT execute, of the only thing protecting a position that does.
# ONE UNRESOLVED ECONOMIC EXIT BLOCKS EVERY FURTHER MODEL-DRIVEN POSITION/STOP
# MUTATION, with its own code, decided from durable state. The old expectation
# encoded an unsafe permission; it is not preserved.
ex_a2 = Exch(position=pos(), orders=[stop_order()])
rig_a2 = Rig(TMP, "A2", intended=held(), exch=ex_a2)
rig_a2.acquire()
owning(rig_a2, "stop1")
rig_a2.adapter.timeout_next = True
r_close = rig_a2.session("c1").close_position()
r4 = rig_a2.session("c2").modify_stop("29800.1")
check("A12. an unresolved CLOSE BLOCKS a subsequent MODIFY_STOP with the "
      "dedicated EXIT_UNRESOLVED code, naming the exit, with no second mutation",
      r4.status is ActionStatus.OPERATION_UNRESOLVED
      and r4.code == "EXIT_UNRESOLVED"
      and r4.client_order_id == r_close.client_order_id
      and len(rig_a2.adapter.calls) == 1,
      f"{r4.status.value}/{r4.code} calls={len(rig_a2.adapter.calls)}")

# every nonterminal status must block a second mutation
blocked_all = True
detail = []
for st in ("SUBMITTED", "ACK", "PARTIALLY_FILLED", "UNKNOWN"):
    e = Exch(position=pos(), orders=[stop_order()])
    rg = Rig(TMP, f"A_{st}", intended=held(), exch=e)
    rg.acquire()
    if st == "UNKNOWN":
        rg.adapter.timeout_next = True
    first = rg.session("x1").close_position()
    if st == "SUBMITTED":
        pass                      # ACK already written; downgrade below
    if st == "PARTIALLY_FILLED":
        rg.rec.record_order_status(first.action_id, first.client_order_id,
                                   "PARTIALLY_FILLED")
    n_before = len(rg.adapter.calls)
    second = rg.session("x2").close_position()
    if len(rg.adapter.calls) != n_before:
        blocked_all = False
        detail.append(st)
check("A13. for EVERY nonterminal status the second exchange mutation count "
      "remains zero", blocked_all, str(detail))

# restart: a brand-new process object, same journal file
ex_a3 = Exch(position=pos(), orders=[stop_order()])
rig_a3 = Rig(TMP, "A3", intended=held(), exch=ex_a3)
rig_a3.acquire()
rig_a3.adapter.timeout_next = True
r5 = rig_a3.session("c1").close_position()
rig_a3b = Rig(TMP, "A3", intended=held(), exch=ex_a3)     # same path, new objects
rig_a3b.authority = rig_a3.authority
rig_a3b.lease = rig_a3.lease
rig_a3b.adapter = NullAdapter(rig_a3.authority, rig_a3b.journal)
r6 = rig_a3b.session("c2").close_position()
check("A14. identity survives a restart: the rebuilt process still refuses the "
      "duplicate", not r6.reached_exchange, f"{r6.status.value}/{r6.code}")
check("A15. and the restarted process made no exchange mutation at all",
      len(rig_a3b.adapter.calls) == 0, f"{len(rig_a3b.adapter.calls)}")


# ======================================================================
banner("B — reduce_only END TO END")
# DEFECT: the gateway computed reduce_only and nothing carried it. It never
# reached the INTENT record, the adapter, or the exchange call, so a CLOSE could
# in principle open an opposite position on a hedge-mode account.
# ======================================================================
gw = Gateway()
ex_b = Exch(position=pos(), orders=[stop_order()])
rig_b = Rig(TMP, "B", intended=held(), exch=ex_b)
rig_b.acquire()
rb = rig_b.session("b1").close_position()
check("B1. the CLOSE reached the exchange boundary", rb.reached_exchange, rb.code)
call_b = rig_b.adapter.calls[-1] if rig_b.adapter.calls else None
check("B2. the exchange call record carries reduce_only=True",
      call_b is not None and call_b.args.get("reduce_only") is True,
      str(call_b.args if call_b else None)[:90])


def _intent_of(path, cid):
    for rec in Journal.load(path).records:
        for ev in rec["events"]:
            if ev["e"] in (E.INTENT.value, E.PROTECTIVE_INTENT.value) \
                    and ev.get("client_order_id") == cid:
                return ev
    return None


iv_b = _intent_of(rig_b.path, rb.client_order_id)
check("B3. the durable INTENT carries reduce_only=True",
      iv_b is not None and iv_b.get("reduce_only") is True,
      str(sorted(iv_b))[:90] if iv_b else "no intent")
check("B4. the durable INTENT names the role of the order",
      iv_b is not None and iv_b.get("role") == Role.EXIT.value,
      str(iv_b.get("role") if iv_b else None))

ex_b2 = Exch()
rig_b2 = Rig(TMP, "B2", intended=flat(), exch=ex_b2)
rig_b2.acquire()
rb2 = rig_b2.session("b2").propose_order("long", stop="29700.1")
call_b2 = rig_b2.adapter.calls[-1] if rig_b2.adapter.calls else None
check("B5. an ENTRY reaches the exchange with reduce_only=False",
      call_b2 is not None and call_b2.args.get("reduce_only") is False,
      str(call_b2.args if call_b2 else None)[:90])
iv_b2 = _intent_of(rig_b2.path, rb2.client_order_id)
check("B6. and its INTENT records role ENTRY",
      iv_b2 is not None and iv_b2.get("role") == Role.ENTRY.value,
      str(iv_b2.get("role") if iv_b2 else None))

def _semantics_probe(reduce_only, role):
    """Call the adapter directly with a valid lease and a durable intent, so
    the ONLY thing that can refuse the call is the semantics check."""
    from orbit.exec.adapter import InconsistentOrderSemantics
    rg = Rig(TMP, f"Bsem{reduce_only}{role}", intended=flat())
    lz = rg.acquire()
    cid = f"cid-{reduce_only}-{role}"
    rg.journal.record_intent("a-" + cid, client_order_id=cid, contracts="1")
    try:
        rg.adapter.submit_order(lz, cid, "long", D("1"), "market",
                                reduce_only=reduce_only, role=role,
                                instrument=A1.instrument)
    except InconsistentOrderSemantics as e:
        return True, f"refused: {str(e)[:60]}"
    return False, f"accepted, {len(rg.adapter.calls)} call(s) recorded"


attempt("B7. the adapter itself REFUSES role=ENTRY with reduce_only=True",
        lambda: _semantics_probe(True, Role.ENTRY.value))
attempt("B8. the adapter itself REFUSES role=EXIT that is not reduce_only",
        lambda: _semantics_probe(False, Role.EXIT.value))


# ======================================================================
banner("C — DURABLE ORDER SCHEMA AND AUTHORSHIP GRADING")
# DEFECT 1: SubmittedOrder carried only (cid, intended, filled, status, ts,
#           protective, attempts). Instrument, kind, side, reduce_only, role,
#           logical operation and epoch were all absent from the durable record,
#           so nothing downstream could reason about WHAT an in-flight order was.
# DEFECT 2: WEAK authorship claimed to match "side and size" and matched on SIZE
#           ALONE. An in-flight SHORT of matching size would have authorised
#           adopting a LONG exchange position as ORBIT's own.
# ======================================================================
REQUIRED_C = ("instrument", "kind", "side", "reduce_only", "role",
              "logical_operation_id", "epoch", "created_at")
have_c = [f for f in REQUIRED_C if f in SubmittedOrder.__dataclass_fields__]
check("C1. the durable order record carries instrument, kind, side, "
      "reduce_only, role, logical operation, epoch and creation time",
      len(have_c) == len(REQUIRED_C),
      f"missing {sorted(set(REQUIRED_C) - set(have_c))}")

ex_c = Exch()
rig_c = Rig(TMP, "C", intended=flat(), exch=ex_c)
rig_c.acquire()
rc = rig_c.session("c1").propose_order("long", stop="29700.1")
rep_c = recover(rig_c.path)
so_c = next((o for o in rep_c.rebuilt.submitted_orders
             if o.client_order_id == rc.client_order_id), None)
check("C2. recovery rebuilds those fields from the journal alone",
      so_c is not None and getattr(so_c, "instrument", None) == A1.instrument
      and getattr(so_c, "side", None) == "long",
      str(so_c)[:100] if so_c else "no rebuilt order")
check("C3. and the rebuilt order is not reduce_only, because it is an ENTRY",
      so_c is not None and getattr(so_c, "reduce_only", None) is False)
check("C4. and it names the logical operation it belongs to",
      so_c is not None and getattr(so_c, "logical_operation_id", None),
      str(getattr(so_c, "logical_operation_id", None)))
check("C5. and the writer epoch under which it was created",
      so_c is not None and getattr(so_c, "epoch", None) is not None,
      str(getattr(so_c, "epoch", None)))


def _authorship(entry_side, exch_side, contracts="2.38", instrument=None):
    from orbit.exec.recon import _own_fill_evidence
    kw = {}
    if "instrument" in SubmittedOrder.__dataclass_fields__:
        kw["instrument"] = instrument or A1.instrument
    if "side" in SubmittedOrder.__dataclass_fields__:
        kw["side"] = entry_side
    o = SubmittedOrder("e-inflight", D(contracts), D("0"), OrderStatus.ACK,
                       NOW, False, 0, **kw)
    st = IntendedState(journal_loaded=True, clean_shutdown=True,
                       submitted_orders=(o,))
    view = Exch(position=pos(side=exch_side, contracts=contracts)).view()
    return _own_fill_evidence(st, view)


attempt("C6. WEAK authorship requires the SIDE to match, not only the size",
        lambda: (_authorship("short", "long") is None,
                 str(_authorship("short", "long"))))
attempt("C7. WEAK authorship still recognises a genuine side+size match",
        lambda: ((_authorship("long", "long") or ("", ""))[0] == "WEAK",
                 str(_authorship("long", "long"))[:70]))
attempt("C8. WEAK authorship requires the INSTRUMENT to match",
        lambda: (_authorship("long", "long", instrument="ETH-USDT-SWAP") is None,
                 str(_authorship("long", "long", instrument="ETH-USDT-SWAP"))))

ex_c9 = Exch(position=pos(), orders=[stop_order()])
r_c9 = reconcile(IntendedState(journal_loaded=True, clean_shutdown=True),
                 ex_c9.view(), NOW)
check("C9. NO authorship after a CLEAN shutdown is PHANTOM_POSITION, never "
      "adopted", "PHANTOM_POSITION" in [f.code.value for f in r_c9.findings],
      str([f.code.value for f in r_c9.findings]))
check("C10. and it never reaches RUNNING", r_c9.run_state is not RunState.RUNNING,
      r_c9.run_state.value)


# ======================================================================
banner("D — OUTSTANDING REMEDIATION MUST PREVENT RUNNING")
# DEFECT 1: a finding could carry an EXECUTABLE remedy (RESIZE_STOP_TO_POSITION)
#           that nothing had executed, and run_state was still RUNNING.
# DEFECT 2: protective coverage was checked only for UNDER-coverage. A stop for
#           MORE contracts than the position would, on trigger, open an opposite
#           position — and was reported clean.
# ======================================================================
ex_d = Exch(position=pos(contracts="2.00"), orders=[stop_order(contracts="2.00")])
int_d = held(contracts="2.38")
r_d = reconcile(int_d, ex_d.view(), NOW)
check("D1. a smaller-than-intended position is seen",
      "POSITION_SMALLER_THAN_INTENDED" in [f.code.value for f in r_d.findings],
      str([f.code.value for f in r_d.findings]))
check("D2. an OUTSTANDING remedy prevents RUNNING",
      r_d.run_state is not RunState.RUNNING,
      f"{r_d.run_state.value} remedies={[x.value for x in r_d.remedies]}")
check("D3. the state is still reported as reconciled — we can SEE, we are "
      "choosing not to open", r_d.reconciled)
check("D4. and it is not reported clean", not r_d.clean)

ex_d5 = Exch(position=pos(contracts="2.38"),
             orders=[stop_order(contracts="4.00")])
r_d5 = reconcile(held(contracts="2.38"), ex_d5.view(), NOW)
check("D5. OVER-coverage is a finding: a stop for more contracts than the "
      "position would reverse it on trigger",
      any("STOP_SIZE" in f.code.value or "OVER" in f.code.value
          for f in r_d5.findings),
      str([f.code.value for f in r_d5.findings]))
check("D6. and over-coverage prevents RUNNING",
      r_d5.run_state is not RunState.RUNNING, r_d5.run_state.value)

ex_d7 = Exch(position=pos(), orders=[stop_order()])
r_d7 = reconcile(held(), ex_d7.view(), NOW)
check("D7. a fully consistent state is still RUNNING — the rule must not "
      "block everything", r_d7.run_state is RunState.RUNNING,
      f"{r_d7.run_state.value} {[f.code.value for f in r_d7.findings]}")


# ======================================================================
banner("E — ACK IS NOT A TERMINAL OUTCOME")
# DEFECT: recover() treated SUBMITTED and UNKNOWN as unresolved and everything
# else as settled. An order the exchange had ACCEPTED but not filled counted as
# resolved, so write_clean_shutdown wrote a CLEAN marker while a live order sat
# on the exchange — and the next start then believed absence proved absence.
# ======================================================================
def _journal_with(status_events, name):
    p = os.path.join(TMP, name + ".jsonl")
    j = Journal(p, clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    j.append_one(E.INTENT, "a1", client_order_id="c1", contracts="2.38",
                 instrument=A1.instrument, side="long", order_kind="OPEN",
                 role=Role.ENTRY.value, reduce_only=False,
                 logical_operation_id="k:g0", epoch=1)
    for kind, payload in status_events:
        j.append_one(kind, "a1", client_order_id="c1", **payload)
    return j, p


j_e, p_e = _journal_with([(E.SUBMIT_ATTEMPTED, {}),
                          (E.SUBMIT_ACK, {"exchange_order_id": "X1"})], "E_ack")
# R4C4 DF-R1. The session clock is passed EXPLICITLY. Without it the day
# figures are underivable, so E2 below would hold for a report that is
# untrusted merely because nobody said what "today" was. With it the day
# figures ARE derivable and E2 is carried by the outstanding ACK — the
# property E2 names.
rep_e = recover(p_e, now=NOW)
check("E1. an ACKNOWLEDGED-but-unfilled order is UNRESOLVED",
      len(rep_e.unresolved) == 1,
      str([(u.client_order_id, u.status) for u in rep_e.unresolved]))
check("E2. so durable state is NOT trusted", not rep_e.durable_state_trusted)

ex_e = Exch(position=None, orders=[ExchangeOrder("c1", D("2.38"), False)])
r_e = reconcile(rep_e.rebuilt, ex_e.view(), NOW)
wrote_e = write_clean_shutdown(j_e, len(rep_e.unresolved), r_e)
check("E3. write_clean_shutdown REFUSES while an ACK is outstanding", not wrote_e)
check("E4. and no CLEAN_SHUTDOWN event was written",
      not any(ev["e"] == E.CLEAN_SHUTDOWN.value
              for rec in Journal.load(p_e).records for ev in rec["events"]))

def _e5():
    nt_bad = []
    for st in ("SUBMITTED", "ACK", "PARTIALLY_FILLED", "UNKNOWN"):
        evs = [(E.SUBMIT_ATTEMPTED, {})]
        if st == "ACK":
            evs.append((E.SUBMIT_ACK, {"exchange_order_id": "X"}))
        elif st == "UNKNOWN":
            evs.append((E.SUBMIT_UNKNOWN, {"attempts": 1}))
        elif st == "PARTIALLY_FILLED":
            evs.append((E.ORDER_STATUS, {"status": "PARTIALLY_FILLED"}))
        jj, pp = _journal_with(evs, "E_nt_" + st)
        if not recover(pp).unresolved:
            nt_bad.append(st)
    return not nt_bad, str(nt_bad)


attempt("E5. EVERY nonterminal status leaves the operation unresolved", _e5)


def _e6():
    t_bad = []
    for st, evs in (("FILLED", [(E.SUBMIT_ACK, {"exchange_order_id": "X"}),
                                (E.FILL, {"fill_id": "f1", "contracts": "2.38"}),
                                (E.ORDER_STATUS, {"status": "FILLED"})]),
                    ("CANCELLED", [(E.ORDER_STATUS, {"status": "CANCELLED"})]),
                    ("REJECTED", [(E.SUBMIT_FAILED, {"error": "no"})])):
        jj, pp = _journal_with([(E.SUBMIT_ATTEMPTED, {})] + evs, "E_t_" + st)
        rp = recover(pp)
        if rp.unresolved:
            t_bad.append((st, [u.status for u in rp.unresolved]))
    return not t_bad, str(t_bad)


attempt("E6. a genuinely TERMINAL outcome resolves the operation — the rule "
        "must not make shutdown impossible", _e6)


def _e11():
    """Found while building this suite: an ORDER_STATUS the enum does not know
    raised ValueError out of rebuild(), so ONE unrecognised exchange status
    made recovery impossible. Recovery must fail CLOSED, never crash."""
    jj, pp = _journal_with([(E.SUBMIT_ATTEMPTED, {}),
                            (E.ORDER_STATUS, {"status": "SOMETHING_NEW"})],
                           "E_unknown_status")
    # R4C4 DF-R1. Explicit clock: the refusal below must come from the
    # unresolved operation, not from an unstated evaluation time.
    rp = recover(pp, now=NOW)
    return (bool(rp.unresolved) and not rp.durable_state_trusted,
            f"unresolved={[u.status for u in rp.unresolved]}")


attempt("E11. an UNRECOGNISED exchange status leaves the operation unresolved "
        "instead of crashing recovery", _e11)

j_e7, p_e7 = _journal_with([(E.SUBMIT_ATTEMPTED, {}),
                            (E.SUBMIT_ACK, {"exchange_order_id": "X"}),
                            (E.FILL, {"fill_id": "f1", "contracts": "2.38"}),
                            (E.ORDER_STATUS, {"status": "FILLED"})], "E_clean")
rep_e7 = recover(p_e7)
ex_e7 = Exch(position=pos(), orders=[stop_order()])
r_e7 = reconcile(held(), ex_e7.view(), NOW)
check("E7. with everything terminal a clean shutdown IS written",
      write_clean_shutdown(j_e7, len(rep_e7.unresolved), r_e7))

check("E8. ACK is classified nonterminal in the operation model",
      OpStatus.ACK in NONTERMINAL and OpStatus.ACK not in TERMINAL)
check("E9. PARTIALLY_FILLED is nonterminal",
      OpStatus.PARTIALLY_FILLED in NONTERMINAL)
# EXPECTATION EXTENDED (round 2, finding N6): EFFECTIVE was added as the
# terminal outcome of an ADMIN mutation whose effect has been positively
# confirmed against the exchange. It is an ADDITION to the terminal set and
# changes nothing about the nonterminal one — which is what blocker E was
# about — so the assertion below now pins BOTH halves rather than only the
# terminal list, and would fail if a nonterminal status were ever quietly
# promoted.
check("E10. the terminal set is exactly FILLED / CANCELLED / REJECTED / "
      "EXPIRED / EFFECTIVE, and no acknowledgement-like status is in it",
      {s.value for s in TERMINAL} == {"FILLED", "CANCELLED", "REJECTED",
                                      "EXPIRED", "EFFECTIVE"}
      and {s.value for s in NONTERMINAL} == {"PENDING", "SUBMITTED", "ACK",
                                             "PARTIALLY_FILLED", "UNKNOWN"},
      f"terminal={sorted(s.value for s in TERMINAL)} "
      f"nonterminal={sorted(s.value for s in NONTERMINAL)}")


# ======================================================================
banner("F — TORN TAIL REPAIR (append after a crash mid-write)")
# DEFECT: load() discarded a torn final record but append() wrote AFTER it. The
# file then held 'partial JSON + valid JSON', which load() classified as tamper.
# One ordinary crash made the journal permanently untrusted, and an untrusted
# journal means ORBIT can never open a position again.
# ======================================================================
p_f = os.path.join(TMP, "F.jsonl")
jf = Journal(p_f, clock=lambda: NOW)
jf.append_one(E.RUN_START, None)
with open(p_f, "a") as fh:
    fh.write('{"seq": 2, "ts": "2026')          # torn: no newline, no close
before_f = Journal.load(p_f)
check("F1. the torn tail is recognised as an uncommitted record, not tamper",
      before_f.discarded_tail == 1 and not before_f.tamper_detected,
      before_f.reason)

jf2 = Journal(p_f, clock=lambda: NOW)
jf2.append_one(E.REMEDIATION, None, note="after the crash")
after_f = Journal.load(p_f)
check("F2. appending after a torn tail keeps the journal TRUSTED",
      after_f.trusted and not after_f.tamper_detected, after_f.reason)
check("F3. the chain is intact and continuous",
      [r["seq"] for r in after_f.records] == list(
          range(1, len(after_f.records) + 1)),
      str([r["seq"] for r in after_f.records]))
check("F4. the repair itself is recorded durably",
      any(ev.get("note") == "TORN_TAIL_REPAIRED"
          for rec in after_f.records for ev in rec["events"]))
check("F5. no committed record was lost",
      any(ev["e"] == E.RUN_START.value
          for rec in after_f.records for ev in rec["events"]))

jf3 = Journal(p_f, clock=lambda: NOW)
jf3.append_one(E.REMEDIATION, None, note="second append")
after_f2 = Journal.load(p_f)
check("F6. repair is idempotent: a second append repairs nothing again",
      after_f2.trusted and sum(
          1 for rec in after_f2.records for ev in rec["events"]
          if ev.get("note") == "TORN_TAIL_REPAIRED") == 1)

# a BROKEN MIDDLE is corruption and must still fail closed
p_f7 = os.path.join(TMP, "F7.jsonl")
jf7 = Journal(p_f7, clock=lambda: NOW)
jf7.append_one(E.RUN_START, None)
jf7.append_one(E.REMEDIATION, None, note="two")
jf7.append_one(E.REMEDIATION, None, note="three")
lines_f7 = open(p_f7).read().rstrip("\n").split("\n")
rec2 = json.loads(lines_f7[1])
rec2["events"][0]["note"] = "REWRITTEN"
lines_f7[1] = json.dumps(rec2, sort_keys=True, separators=(",", ":"))
open(p_f7, "w").write("\n".join(lines_f7) + "\n")
load_f7 = Journal.load(p_f7)
check("F7. a rewritten MIDDLE record is tamper, not a torn tail",
      load_f7.tamper_detected, load_f7.reason[:60])
size_f7 = os.path.getsize(p_f7)
jf7b = Journal(p_f7, clock=lambda: NOW)
try:
    jf7b.append_one(E.REMEDIATION, None, note="should never be written")
    check("F8. appending to a tampered journal FAILS CLOSED", False,
          "the append succeeded")
except TamperedJournalError as e:
    check("F8. appending to a tampered journal FAILS CLOSED", True, str(e)[:60])
check("F9. and nothing was appended to it", os.path.getsize(p_f7) == size_f7)
# R4C4 DF-R1. Explicit clock, so the refusal is attributable to the tamper
# (UNDERIVABLE:JOURNAL_UNTRUSTED) rather than to a missing clock.
rep_f10 = recover(p_f7, now=NOW)
check("F10. recovery from a tampered journal refuses to trust durable state",
      not rep_f10.durable_state_trusted and not rep_f10.journal_trusted)


# ======================================================================
banner("G — CROSS-PROCESS APPEND SERIALISATION (real subprocesses)")
# DEFECT: append() cached _seq/_prev in memory. Two Journal objects over one
# file each believed they held the head, wrote the same seq with the same
# prev_hash, and the second record broke the chain the first had extended.
# The audit trail was silently destroyed by ordinary concurrency.
#
# Threads would not have proved this: the shared state is the FILE. These are
# real OS processes.
# ======================================================================
G_WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "_append_worker.py")
p_g = os.path.join(TMP, "G.jsonl")
Journal(p_g, clock=lambda: NOW).append_one(E.RUN_START, None)

N_PROC, N_EACH = 6, 8
procs = [subprocess.Popen([sys.executable, G_WORKER, p_g, str(i), str(N_EACH)],
                          cwd=os.path.dirname(os.path.dirname(
                              os.path.abspath(__file__))),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
         for i in range(N_PROC)]
outs = [p.communicate() for p in procs]
rcs = [p.returncode for p in procs]
load_g = Journal.load(p_g)
seqs_g = [r["seq"] for r in load_g.records]
notes_g = [ev.get("note") for rec in load_g.records for ev in rec["events"]
           if ev.get("note", "").startswith("w")]

check("G1. every worker process exited cleanly", all(rc == 0 for rc in rcs),
      str([(rc, o[1].decode()[-90:]) for rc, o in zip(rcs, outs) if rc != 0]))
check("G2. the journal is TRUSTED after concurrent appends from 6 processes",
      load_g.trusted and not load_g.tamper_detected, load_g.reason)
check("G3. sequence numbers are unique",
      len(set(seqs_g)) == len(seqs_g),
      f"{len(seqs_g)} records, {len(set(seqs_g))} distinct")
check("G4. sequence numbers are contiguous from 1",
      seqs_g == list(range(1, len(seqs_g) + 1)), str(seqs_g[:12]))
check("G5. NOT ONE record was lost: every write is present",
      len(notes_g) == N_PROC * N_EACH,
      f"{len(notes_g)} of {N_PROC * N_EACH}")
check("G6. every note is distinct — no write overwrote another",
      len(set(notes_g)) == len(notes_g))
prev_ok = True
prev_h = GENESIS
for rec in load_g.records:
    if rec["prev_hash"] != prev_h:
        prev_ok = False
        break
    prev_h = rec["hash"]
check("G7. the hash chain links every record to its predecessor", prev_ok)
check("G8. and recovery can rebuild from it",
      recover(p_g).journal_trusted)

# the lock must be released even when the body raises
p_g9 = os.path.join(TMP, "G9.jsonl")
jg9 = Journal(p_g9, clock=lambda: NOW)
jg9.append_one(E.RUN_START, None)
try:
    jg9.append([{"e": E.REMEDIATION.value, "action_id": None,
                 "bad": object()}])            # not serialisable
except Exception:
    pass
try:
    jg9.append_one(E.REMEDIATION, None, note="after the failure")
    check("G9. a failed append does not leave the append lock held", True)
except Exception as e:
    check("G9. a failed append does not leave the append lock held", False,
          f"{type(e).__name__}: {e}"[:70])
check("G10. and the journal survived the failed append",
      Journal.load(p_g9).trusted)


# ======================================================================
banner("H — IN-FLIGHT MUTATION VERSUS LEASE EXPIRY")
# DEFECT: authority was fenced BEFORE the call and never afterwards. A worker
# whose lease expired while a submission was in flight recorded the outcome as
# its own, and the SUCCESSOR had no way to learn that a mutation from the
# previous epoch might still be live. Fencing protected the decision to act; it
# did not protect the interval during which the action was outstanding.
# ======================================================================
ex_h = Exch(position=pos(), orders=[stop_order()])
rig_h = Rig(TMP, "H", intended=held(), exch=ex_h)
lease_h1 = rig_h.acquire()
rig_h.adapter.timeout_next = True
r_h1 = rig_h.session("h1").close_position()
check("H1. epoch 1 leaves a CLOSE outstanding", r_h1.status is ActionStatus.UNKNOWN)

other_h = WriterAuthority(rig_h.wdir, owner_id="SUCCESSOR")
rig_h.authority.release(lease_h1)
lease_h2 = other_h.acquire()
check("H2. a successor takes a strictly higher epoch",
      lease_h2.epoch > lease_h1.epoch, f"{lease_h1.epoch} -> {lease_h2.epoch}")

rig_h.authority = other_h
rig_h.lease = lease_h2
rig_h.adapter = NullAdapter(other_h, rig_h.journal)
r_h3 = rig_h.session("h3").close_position()
check("H3. the SUCCESSOR refuses to repeat a mutation left outstanding by the "
      "previous epoch", not r_h3.reached_exchange, f"{r_h3.status.value}/{r_h3.code}")
check("H4. and the successor made no exchange mutation",
      len(rig_h.adapter.calls) == 0, str(len(rig_h.adapter.calls)))

led_h = OperationLedger(rig_h.path)
un_h = led_h.unresolved()
# SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 8. `un_h[0]` was whichever
# unresolved operation the ledger listed first; with the resting stop now
# durably seeded that is the stop, whose epoch is None. The invariant is about
# the CLOSE left outstanding by epoch 1. Asserted against that operation.
_close_h = led_h.open_for(logical_key(A1.instrument, "CLOSE"))
check("H5. the outstanding CLOSE records the epoch that created it",
      _close_h is not None and _close_h.epoch == lease_h1.epoch,
      str([(o.kind, o.operation_id[:12], o.epoch) for o in un_h]))


def _h6():
    """A lease that goes stale DURING the call must not be reported as a clean
    outcome: the response may have been produced under superseded authority."""
    from orbit.exec.adapter import AdapterResult
    ex = Exch(position=pos(), orders=[stop_order()])
    rg = Rig(TMP, "H6", intended=held(), exch=ex)
    lz = rg.acquire()
    steal = WriterAuthority(rg.wdir, owner_id="THIEF")

    class Racing(NullAdapter):
        def _do_submit(self, cid, side, contracts, order_type, price):
            rg.authority.release(lz)     # the lease dies mid-flight
            steal.acquire()
            return AdapterResult(True, f"X-{cid}", "accepted")

    rg.adapter = Racing(rg.authority, rg.journal)
    res = rg.session("h6").close_position()
    return (res.status is ActionStatus.UNKNOWN,
            f"{res.status.value}/{res.code}")


attempt("H6. an outcome returned after the lease was superseded is recorded as "
        "UNKNOWN, never as an accepted result", _h6)


def _h7():
    from orbit.exec.adapter import AdapterResult
    ex = Exch(position=pos(), orders=[stop_order()])
    rg = Rig(TMP, "H7", intended=held(), exch=ex)
    lz = rg.acquire()
    steal = WriterAuthority(rg.wdir, owner_id="THIEF7")

    class Racing(NullAdapter):
        def _do_submit(self, cid, side, contracts, order_type, price):
            rg.authority.release(lz)
            steal.acquire()
            return AdapterResult(True, f"X-{cid}", "accepted")

    rg.adapter = Racing(rg.authority, rg.journal)
    res = rg.session("h7").close_position()
    # SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 8: the CLOSE's own
    # lifecycle, not a global count (the seeded resting stop is unresolved too).
    op = OperationLedger(rg.path).open_for(logical_key(A1.instrument, "CLOSE"))
    return (op is not None and op.unresolved
            and op.client_order_id == res.client_order_id,
            str([(o.kind, o.status.value)
                 for o in OperationLedger(rg.path).unresolved()]))


attempt("H7. and the operation stays UNRESOLVED for the successor to settle",
        _h7)

check("H8. an unresolved operation is visible across epochs because the ledger "
      "is derived from the journal, not from the lease",
      OperationLedger(rig_h.path).open_for(
          logical_key(A1.instrument, "CLOSE")) is not None)


# ======================================================================
banner("I — THE MODEL MAY CANCEL ONLY ORBIT-OWNED ORDERS")
# DEFECT: cancel_order checked only that the order EXISTED on the exchange. Any
# order in the account — a manual order the operator placed, another system's
# order — could be cancelled by the model. Ownership was never established.
# ======================================================================
alien = ExchangeOrder("someone-elses-order", D("1.00"), False)
ex_i = Exch(position=None, orders=[alien])
rig_i = Rig(TMP, "I", intended=flat(), exch=ex_i)
rig_i.acquire()
r_i1 = rig_i.session("i1").cancel_order("someone-elses-order")
check("I1. cancelling an order ORBIT did not create is REFUSED on OWNERSHIP",
      not r_i1.reached_exchange and r_i1.code == "NOT_OUR_ORDER",
      f"{r_i1.status.value}/{r_i1.code}")
check("I2. and no exchange mutation was made",
      len(rig_i.adapter.calls) == 0, str(len(rig_i.adapter.calls)))

# a plausible-looking id is not ownership either
spoof = ExchangeOrder("orbitA1" + "f" * 24, D("1.00"), False)
ex_i3 = Exch(position=None, orders=[spoof])
rig_i3 = Rig(TMP, "I3", intended=flat(), exch=ex_i3)
rig_i3.acquire()
r_i3 = rig_i3.session("i3").cancel_order(spoof.client_order_id)
check("I3. an id merely SHAPED like ours is not ownership",
      not r_i3.reached_exchange and r_i3.code == "NOT_OUR_ORDER",
      f"{r_i3.status.value}/{r_i3.code}")
check("I4. and that refusal made no exchange mutation",
      len(rig_i3.adapter.calls) == 0)

# an order ORBIT really did create, still resting, may be cancelled
ex_i5 = Exch()
rig_i5 = Rig(TMP, "I5", intended=flat(), exch=ex_i5)
rig_i5.acquire()
mine = rig_i5.session("i5a").propose_order("long", stop="29700.1",
                                           entry_type="limit",
                                           entry_price="29900.0")
ex_i5.orders = [ExchangeOrder(mine.client_order_id, D("2.38"), False)]
r_i5 = rig_i5.session("i5b").cancel_order(mine.client_order_id)
check("I5. an order ORBIT DID create may be cancelled — the rule must not "
      "disable cancelling", r_i5.reached_exchange,
      f"{r_i5.status.value}/{r_i5.code}")

# ownership is durable: it survives a restart with no in-memory state
led_i = OperationLedger(rig_i5.path)
check("I6. ownership is read from the durable journal, not from memory",
      led_i.owns(mine.client_order_id))
check("I7. and an alien id is not owned", not led_i.owns("someone-elses-order"))

ex_i8 = Exch(position=pos(),
             orders=[stop_order(), ExchangeOrder("alien-stop", D("2.38"),
                                                 True, D("29500.0"))])
rig_i8 = Rig(TMP, "I8", intended=held(), exch=ex_i8)
rig_i8.acquire()
r_i8 = rig_i8.session("i8").cancel_order("alien-stop")
check("I8. an alien PROTECTIVE order is not ORBIT's to cancel either, and it "
      "is refused on ownership before any other rule is consulted",
      not r_i8.reached_exchange and r_i8.code == "NOT_OUR_ORDER",
      f"{r_i8.status.value}/{r_i8.code}")


# ======================================================================
banner("J — MODIFY_STOP NEEDS TWO IDENTITIES")
# DEFECT: the gateway minted a NEW client order id for the stop modification and
# the session sent an amend addressed to that new id. Nothing on the exchange
# has that id. The mutation identity (for idempotency and audit) and the TARGET
# identity (the resting order to change) are different things and only one
# existed.
# ======================================================================
ex_j = Exch(position=pos(), orders=[stop_order(cid="stop1")])
rig_j = Rig(TMP, "J", intended=held(cid="stop1"), exch=ex_j)
rig_j.acquire()
owning(rig_j, "stop1")
r_j = rig_j.session("j1").modify_stop("29800.1")
call_j = rig_j.adapter.calls[-1] if rig_j.adapter.calls else None
check("J1. the amend is ADDRESSED TO THE RESTING STOP that exists on the "
      "exchange", call_j is not None
      and call_j.args.get("target_client_order_id") == "stop1",
      str(call_j.args if call_j else None)[:100])
check("J2. the mutation carries its own identity, distinct from the target",
      r_j.client_order_id is not None and r_j.client_order_id != "stop1",
      str(r_j.client_order_id))
iv_j = _intent_of(rig_j.path, r_j.client_order_id)
check("J3. the durable INTENT records BOTH identities",
      iv_j is not None and iv_j.get("target_client_order_id") == "stop1"
      and iv_j.get("client_order_id") == r_j.client_order_id,
      str({k: iv_j.get(k) for k in ("client_order_id",
                                    "target_client_order_id")} if iv_j else None))
check("J4. and names the role ADMIN, not ENTRY",
      iv_j is not None and iv_j.get("role") in (Role.ADMIN.value,
                                                Role.PROTECTIVE.value),
      str(iv_j.get("role") if iv_j else None))


def _j5():
    """The target must come from RECONCILED state, never from the model."""
    ex = Exch(position=pos(), orders=[stop_order(cid="real-stop")])
    rg = Rig(TMP, "J5", intended=held(cid="real-stop"), exch=ex)
    rg.acquire()
    owning(rg, "real-stop")
    res = rg.session("j5").modify_stop("29800.1")
    c = rg.adapter.calls[-1] if rg.adapter.calls else None
    return (c is not None and c.args.get("target_client_order_id") == "real-stop",
            str(c.args if c else None)[:80])


attempt("J5. the target is taken from reconciled exchange state", _j5)


def _j6():
    """No verified resting stop => nothing to amend => refuse, do not invent."""
    ex = Exch(position=pos(), orders=[])
    st = IntendedState(
        journal_loaded=True, clean_shutdown=True, entries_utc_day=1,
        position=IntendedPosition("long", D("2.38"), D("30000"), None, None,
                                  NOW - timedelta(minutes=30)))
    rg = Rig(TMP, "J6", intended=st, exch=ex)
    rg.acquire()
    res = rg.session("j6").modify_stop("29800.1")
    return (not res.reached_exchange and len(rg.adapter.calls) == 0,
            f"{res.status.value}/{res.code} calls={len(rg.adapter.calls)}")


attempt("J6. with no verified resting stop the amend is refused, not invented",
        _j6)


def _j7():
    """The adapter refuses an amend with no target."""
    rg = Rig(TMP, "J7", intended=flat())
    lz = rg.acquire()
    rg.journal.record_intent("a-j7", client_order_id="cid-j7", contracts="1")
    try:
        rg.adapter.amend_stop(lz, "cid-j7", D("29800.1"))
    except TypeError as e:
        return True, f"target is a required argument: {str(e)[:50]}"
    except Exception as e:
        return True, f"{type(e).__name__}: {str(e)[:50]}"
    return False, "the adapter accepted an amend with no target order"


attempt("J7. the adapter itself will not amend without a target order id", _j7)

r_j8 = rig_j.session("j1").modify_stop("29800.1")
check("J8. re-proposing the same stop move in the same cycle makes no second "
      "exchange mutation",
      len([c for c in rig_j.adapter.calls if c.method == "amend_stop"]) == 1,
      str([c.method for c in rig_j.adapter.calls]))

cancel_j = None
ex_j9 = Exch()
rig_j9 = Rig(TMP, "J9", intended=flat(), exch=ex_j9)
rig_j9.acquire()
mine_j9 = rig_j9.session("j9a").propose_order("long", stop="29700.1",
                                              entry_type="limit",
                                              entry_price="29900.0")
ex_j9.orders = [ExchangeOrder(mine_j9.client_order_id, D("2.38"), False)]
r_j9 = rig_j9.session("j9b").cancel_order(mine_j9.client_order_id)
cancel_j = next((c for c in rig_j9.adapter.calls
                 if c.method == "cancel_order"), None)
check("J9. a cancel likewise carries the target it is addressed to",
      cancel_j is not None
      and cancel_j.args.get("target_client_order_id") == mine_j9.client_order_id,
      str(cancel_j.args if cancel_j else None)[:90])
check("J10. and the cancel mutation is itself write-ahead journalled",
      _intent_of(rig_j9.path, r_j9.client_order_id) is not None
      and r_j9.client_order_id != mine_j9.client_order_id,
      str(r_j9.client_order_id))


# ======================================================================
banner("K — THE GATEWAY VALIDATES ENUMS AND GEOMETRY INDEPENDENTLY")
# DEFECT: entry_type was validated only in the session's schema check. Called
# directly, the gateway treated ANY unrecognised entry_type as "market". And a
# target on the wrong side of entry was silently DISCARDED rather than rejected,
# so a decision whose take-profit was nonsense executed as if it had none.
# The gateway is the last deterministic authority; it may not delegate its
# validation to the layer above it.
# ======================================================================
sys_k = reconcile(flat(), Exch().view(), NOW).to_system_state()


def _gw(**kw):
    base = dict(decision_id="k", kind=Kind.OPEN, symbol=A1.instrument,
                side="long", entry_type="market", stop=D("29700.1"))
    base.update(kw)
    return gw.evaluate(ProposedAction(**base), sys_k)


v_k1 = _gw(entry_type="banana")
check("K1. an unrecognised entry_type is REJECTED, not silently treated as a "
      "market order", not v_k1.approved, f"{v_k1.code.value}: {v_k1.reason[:50]}")
v_k2 = _gw(entry_type=None)
check("K2. a missing entry_type is rejected", not v_k2.approved, v_k2.code.value)
v_k3 = _gw(entry_type="MARKET")
check("K3. the enum is exact — case is not silently normalised",
      not v_k3.approved, v_k3.code.value)
v_k4 = _gw(entry_type="market")
check("K4. a valid market entry is still approved — the rule must not block "
      "everything", v_k4.approved, v_k4.code.value)

v_k5 = _gw(target=D("29000.0"))
check("K5. a LONG target BELOW entry is rejected, not discarded",
      not v_k5.approved, f"{v_k5.code.value}: {v_k5.reason[:50]}")
v_k6 = gw.evaluate(ProposedAction(
    decision_id="k6", kind=Kind.OPEN, symbol=A1.instrument, side="short",
    entry_type="market", stop=D("30300.0"), target=D("31000.0")), sys_k)
check("K6. a SHORT target ABOVE entry is rejected", not v_k6.approved,
      f"{v_k6.code.value}: {v_k6.reason[:50]}")
v_k7 = _gw(target=D("30000.0"))
check("K7. a target AT the entry price is rejected", not v_k7.approved,
      v_k7.code.value)
v_k8 = _gw(target=D("31000.0"))
check("K8. a correctly placed target is approved and CARRIED",
      v_k8.approved and v_k8.order.target_price is not None,
      f"{v_k8.code.value} target={v_k8.order.target_price if v_k8.order else None}")
v_k9 = _gw(target=D("30000.05"))
check("K9. a target that quantises onto the entry price is rejected rather "
      "than silently dropped", not v_k9.approved, v_k9.code.value)
v_k10 = _gw(side="up")
check("K10. an invalid side is rejected at the gateway too, independently of "
      "the session's schema check", not v_k10.approved, v_k10.code.value)


# ======================================================================
banner("L — ACTUAL-FILL RISK BEYOND THE PLANNED BUDGET")
# GAP: planned_risk_usdt was computed from a REFERENCE price (the mark, or the
# limit price) before execution. A market entry can fill worse than that. There
# was no contract at all for what happens when the risk implied by the ACTUAL
# fill and the verified stop exceeds the $8 budget: the system simply carried on.
#
# THE CONTRACT, now enforced: Python recomputes planned risk from the ACTUAL
# entry price and the VERIFIED resting stop at every reconciliation. If it
# exceeds the cap, that is a finding. New entries stop. The stop is NEVER
# widened to bring the number back under the cap — widening would increase the
# real maximum loss in order to improve a report. Reducing the position is the
# only risk-reducing correction, and it is Python's to make, not the model's.
# ======================================================================
ex_l = Exch(position=pos(entry="30100"), orders=[stop_order(price="29700.1")])
int_l = held()
int_l = IntendedState(
    journal_loaded=True, clean_shutdown=True, entries_utc_day=1,
    position=IntendedPosition("long", D("2.38"), D("30100"), D("29700.1"),
                              "stop1", NOW - timedelta(minutes=30)),
    submitted_orders=int_l.submitted_orders)
r_l = reconcile(int_l, ex_l.view(), NOW)
over = (r_l.protection is not None
        and r_l.protection.planned_risk_usdt > A1.planned_risk_usdt)
check("L1. the fill was worse than planned and the implied risk exceeds the "
      "budget", over,
      f"planned={r_l.protection.planned_risk_usdt if r_l.protection else None} "
      f"cap={A1.planned_risk_usdt}")
codes_l = [f.code.value for f in r_l.findings]
check("L2. that overrun is an explicit FINDING, not an unremarked number",
      any("RISK" in c and "BUDGET" in c for c in codes_l), str(codes_l))
check("L3. and it prevents RUNNING", r_l.run_state is not RunState.RUNNING,
      r_l.run_state.value)
check("L4. while the exchange view remains trustworthy — this is a risk "
      "decision, not blindness", r_l.reconciled)
rem_l = [x.value for x in r_l.remedies]
check("L5. the remedy is never to widen the stop",
      not any("WIDEN" in x for x in rem_l), str(rem_l))
check("L6. and the finding carries the numbers an auditor needs",
      any(("RISK" in f.code.value and "BUDGET" in f.code.value)
          and str(A1.planned_risk_usdt) in f.detail for f in r_l.findings),
      str([f.detail[:60] for f in r_l.findings if "RISK" in f.code.value]))

ex_l7 = Exch(position=pos(), orders=[stop_order()])
r_l7 = reconcile(held(), ex_l7.view(), NOW)
check("L7. a fill within budget produces no such finding and stays RUNNING",
      not any("BUDGET" in f.code.value for f in r_l7.findings)
      and r_l7.run_state is RunState.RUNNING,
      f"{r_l7.run_state.value} {[f.code.value for f in r_l7.findings]}")
s_l8 = r_l.to_system_state()
check("L8. the system state handed to the gateway is not RUNNING while the "
      "overrun stands", s_l8.run_state is not RunState.RUNNING,
      s_l8.run_state.value)
v_l9 = gw.evaluate(
    ProposedAction(decision_id="l9", kind=Kind.CLOSE, symbol=A1.instrument),
    s_l8)
check("L9. and risk-REDUCING actions remain available: an overrun must not "
      "trap the position", v_l9.approved, v_l9.code.value)


# ======================================================================
banner("M — ONE FROZEN DECISION SNAPSHOT, WITH A REAL PROMPT HASH")
# DEFECT 1: prompt_hash was hash({"cycle": cycle_id}). It recorded the cycle id
#           twice and said NOTHING about what the model was actually asked. An
#           audit could not tell whether the prompt had changed between cycles.
# DEFECT 2: the information context was rebuilt on demand from a MUTABLE list of
#           references. A read performed after the decision was made would still
#           appear in the context the decision was verified against, so the
#           check "a decision may cite only what its cycle provided" could be
#           satisfied retroactively.
# ======================================================================
def _snap_session(name):
    ex = Exch(position=pos(), orders=[stop_order()])
    rg = Rig(TMP, name, intended=held(), exch=ex)
    rg.acquire()
    return rg, rg.session(name)


def _m1():
    rg, s = _snap_session("M1")
    s.get_market_state()
    snap = s._freeze_decision_snapshot("d1", prompt_text="PROMPT ONE")
    other = s.__class__  # noqa
    rg2, s2 = _snap_session("M1b")
    s2.get_market_state()
    snap2 = s2._freeze_decision_snapshot("d1", prompt_text="PROMPT TWO")
    return (snap.context.prompt_hash != snap2.context.prompt_hash,
            f"{snap.context.prompt_hash[:12]} vs {snap2.context.prompt_hash[:12]}")


attempt("M1. the prompt hash is derived from the PROMPT, so two different "
        "prompts in the same cycle hash differently", _m1)


def _m2():
    rg, s = _snap_session("M2")
    s.get_market_state()
    a = s._freeze_decision_snapshot("d1", prompt_text="IDENTICAL")
    rg2, s2 = _snap_session("M2b")
    s2.get_market_state()
    b = s2._freeze_decision_snapshot("d1", prompt_text="IDENTICAL")
    return (a.context.prompt_hash == b.context.prompt_hash,
            "identical prompts hash identically")


attempt("M2. and the same prompt hashes identically — it is a real digest of "
        "real text", _m2)


def _m3():
    rg, s = _snap_session("M3")
    s.get_market_state()
    snap = s._freeze_decision_snapshot("d1", prompt_text="P")
    before = set(snap.context.refs())
    s.get_orderbook()                    # a read AFTER the snapshot
    return (set(snap.context.refs()) == before,
            f"{len(before)} refs before, {len(snap.context.refs())} after")


attempt("M3. the snapshot is FROZEN: a later read cannot enter the context the "
        "decision is judged against", _m3)


def _m4():
    from orbit.audit.information import verify_information_used
    rg, s = _snap_session("M4")
    s.get_market_state()
    snap = s._freeze_decision_snapshot("d1", prompt_text="P")
    late = s.get_orderbook()
    v = verify_information_used((late.token,), snap.context)
    return (not v.ok, v.reason[:70])


attempt("M4. citing a reference produced after the freeze is a mechanical "
        "error", _m4)


def _m5():
    rg, s = _snap_session("M5")
    s.get_market_state()
    s._freeze_decision_snapshot("d1", prompt_text="P")
    try:
        s._freeze_decision_snapshot("d1", prompt_text="P AGAIN")
    except Exception as e:
        return True, f"{type(e).__name__}: {str(e)[:50]}"
    return False, "a second snapshot was permitted for the same decision"


attempt("M5. exactly ONE snapshot per decision: re-freezing is refused", _m5)


def _m6():
    rg, s = _snap_session("M6")
    s.get_market_state()
    fn = s._freeze_decision_snapshot         # must EXIST before it can refuse
    try:
        fn("d1", prompt_text="")
    except ValueError as e:
        return True, f"ValueError: {str(e)[:50]}"
    return False, "an empty prompt was accepted as a prompt"


attempt("M6. a decision cannot be frozen with no prompt at all", _m6)


def _m7():
    rg, s = _snap_session("M7")
    s.get_market_state()
    snap = s._freeze_decision_snapshot("d1", prompt_text="P")
    found = [ev for rec in Journal.load(rg.path).records
             for ev in rec["events"]
             if ev["e"] == E.INFORMATION_USED.value]
    return (len(found) == 1 and found[0].get("prompt_hash")
            == snap.context.prompt_hash,
            f"{len(found)} INFORMATION_USED record(s)")


attempt("M7. the frozen snapshot is written durably, with its prompt hash", _m7)


def _m8():
    rg, s = _snap_session("M8")
    s.get_market_state()
    a = s._freeze_decision_snapshot("d1", prompt_text="ONE")
    rg2, s2 = _snap_session("M8b")
    s2.get_market_state()
    b = s2._freeze_decision_snapshot("d1", prompt_text="TWO")
    return (a.context.context_hash() != b.context.context_hash(),
            "the context hash covers the prompt hash")


attempt("M8. the context hash covers the prompt, so a changed prompt changes "
        "the recorded context", _m8)


def _m9():
    rg, s = _snap_session("M9")
    s.get_market_state()
    snap = s._freeze_decision_snapshot("d1", prompt_text="P")
    return (snap.context.model_id == "none"
            and snap.context.policy_version == "A1",
            f"{snap.context.model_id}/{snap.context.policy_version}")


attempt("M9. the snapshot carries the model id and the policy version", _m9)


def _m10():
    rg, s = _snap_session("M10")
    s.get_market_state()
    snap = s._freeze_decision_snapshot("d1", prompt_text="P")
    try:
        snap.context.series = ()          # frozen dataclass
    except Exception:
        return True, "the recorded context is immutable"
    return False, "the recorded context could be mutated after the fact"


attempt("M10. and the recorded context cannot be edited afterwards", _m10)


# ======================================================================
banner("§15 — CROSS-LAYER: TIMEOUT ON EVERY MUTATING ACTION")
# One scenario per action shape. In every case the outcome is UNKNOWN, the
# operation stays unresolved, and NO second exchange mutation is ever made for
# the same logical intent — across cycles, and after a restart.
# ======================================================================
def _timeout_scenario(label, drive):
    # SAFETY CLOSURE ROUND 4B2, finding I3: a partial reduction is only
    # available where protection already fits the remainder, so REDUCE gets a
    # stop sized to what would be left. Every other shape is unchanged.
    ex = Exch(position=pos(), orders=[
        stop_order(cid="stop1",
                   contracts="1.19" if label == "REDUCE" else "2.38")])
    rg = Rig(TMP, "X15_" + label, intended=held(cid="stop1"), exch=ex)
    rg.acquire()
    owning(rg, "stop1")
    rg.adapter.timeout_next = True
    first = drive(rg.session("c1"))
    n1 = len(rg.adapter.calls)
    second = drive(rg.session("c2"))
    n2 = len(rg.adapter.calls)
    led = OperationLedger(rg.path)
    return first, second, n1, n2, led


for label, drive in (
        ("CLOSE", lambda s: s.close_position()),
        ("REDUCE", lambda s: s.reduce_position("0.5")),
        ("MODIFY_STOP", lambda s: s.modify_stop("29800.1")),
):
    f1, f2, n1, n2, led = _timeout_scenario(label, drive)
    check(f"X15-{label}. the first attempt times out to UNKNOWN",
          f1.status is ActionStatus.UNKNOWN, f"{f1.status.value}/{f1.code}")
    check(f"X15-{label}. the retry in the next cycle makes NO second exchange "
          f"mutation", n2 == n1, f"{n1} -> {n2}")
    check(f"X15-{label}. and the operation is still unresolved for a human or "
          f"a resolver to settle", len(led.unresolved()) >= 1,
          str([o.status.value for o in led.unresolved()]))

# OPEN, from flat
ex_x = Exch()
rig_x = Rig(TMP, "X15_OPEN", intended=flat(), exch=ex_x)
rig_x.acquire()
rig_x.adapter.timeout_next = True
x1 = rig_x.session("c1").propose_order("long", stop="29700.1")
n_x1 = len(rig_x.adapter.calls)
x2 = rig_x.session("c2").propose_order("long", stop="29700.1")
check("X15-OPEN. the first entry times out to UNKNOWN",
      x1.status is ActionStatus.UNKNOWN, f"{x1.status.value}/{x1.code}")
check("X15-OPEN. the retry makes NO second exchange mutation",
      len(rig_x.adapter.calls) == n_x1, f"{n_x1} -> {len(rig_x.adapter.calls)}")

# CANCEL of an order ORBIT owns
ex_xc = Exch()
rig_xc = Rig(TMP, "X15_CANCEL", intended=flat(), exch=ex_xc)
rig_xc.acquire()
own_xc = rig_xc.session("c0").propose_order("long", stop="29700.1",
                                            entry_type="limit",
                                            entry_price="29900.0")
ex_xc.orders = [ExchangeOrder(own_xc.client_order_id, D("2.38"), False)]
rig_xc.adapter.timeout_next = True
c1 = rig_xc.session("c1").cancel_order(own_xc.client_order_id)
n_xc = len(rig_xc.adapter.calls)
c2 = rig_xc.session("c2").cancel_order(own_xc.client_order_id)
check("X15-CANCEL. the first cancel times out to UNKNOWN",
      c1.status is ActionStatus.UNKNOWN, f"{c1.status.value}/{c1.code}")
check("X15-CANCEL. the retry makes NO second exchange mutation",
      len(rig_xc.adapter.calls) == n_xc,
      f"{n_xc} -> {len(rig_xc.adapter.calls)}")


shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("Every reassessment finding has a permanent regression test, and it "
      "passes.")
print("No model. No credentials. No network. No live capital.")
