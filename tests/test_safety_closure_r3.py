"""
tests/test_safety_closure_r3.py — ORBIT A1 SAFETY CLOSURE, ROUND 3.

Third independent adversarial pass against a green suite; third time it found
real defects. 302 -> 13 blockers. 441 -> 6 findings. 507 -> 6 more. The count of
assertions has never been the thing that was missing.

    R3-1  multiple protective orders could hide a wider stop
    R3-2  reduce_only vanished before the real subclass I/O hook
    R3-3  the admin resolver terminalised from untrustworthy views
    R3-4  the operation ledger accumulated fills in binary floats
    R3-5  the decision_id -> input mapping was mutable
    R3-6  the hash chain cannot detect loss of a COMMITTED suffix

Every test here was written to FAIL against the 507/507 archive.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import itertools
import json
import os
import random
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
from orbit.audit.blobstore import BlobStore
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.core.precision import BTC_USDT_SWAP as SPEC
from orbit.exec.operations import OperationLedger, OpStatus
from orbit.exec.recon import (ExchangeOrder, IntendedPosition, IntendedState,
                              OrderStatus, SubmittedOrder, reconcile)
from orbit.risk.limits import A1, RunState

PASS, FAIL = [], []
TMP = tempfile.mkdtemp(prefix="orbit_r3_")
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
    try:
        ok, detail = fn()
    except Exception as e:                                    # noqa: BLE001
        check(name, False, f"{type(e).__name__}: {e}"[:120])
        return False
    check(name, ok, detail)
    return bool(ok)


print("=" * 78)
print("ORBIT A1 — SAFETY CLOSURE ROUND 3")
print("=" * 78)


# ======================================================================
banner("R3-1 — A WIDER STOP MUST NOT HIDE BEHIND AGGREGATE COVERAGE")
# DEFECT: _protection_findings() checked the stop PRICE of prot[0] and the stop
# SIZE as sum(o.contracts for o in prot). Two disconnected analyses. Half a
# position resting at 29000 while the other half rests at the authorised
# 29700.1 summed to full coverage and reported:
#
#   run=RUNNING clean=True findings=[] adopted_stop=29700.1
#
# and — worse than reported — REVERSING THE ORDER LIST changed the verdict to
# NO_NEW_ENTRY. The same account state, two different answers, decided by which
# order the exchange happened to list first.
# ======================================================================
def ladder_state(slices, *, intended_stop="29700.1", contracts="2.38",
                 entry="30000", shuffle=False, seed=0):
    """`slices` is [(cid, contracts, stop_price_or_None), ...]. Every one is a
    durably known ORBIT protective order."""
    orders = [ExchangeOrder(cid, D(c), True,
                            None if p is None else D(p)) for cid, c, p in slices]
    if shuffle:
        random.Random(seed).shuffle(orders)
    subs = [SubmittedOrder("e1", D(contracts), D(contracts), OrderStatus.FILLED,
                           NOW, instrument=A1.instrument, side="long",
                           kind="OPEN", role="ENTRY", reduce_only=False)]
    subs += [SubmittedOrder(cid, D(c), D("0"), OrderStatus.ACK, NOW, True,
                            instrument=A1.instrument, side="short",
                            kind="PROTECTIVE", role="PROTECTIVE",
                            reduce_only=True) for cid, c, p in slices]
    st = IntendedState(
        journal_loaded=True, clean_shutdown=True, entries_utc_day=1,
        position=IntendedPosition("long", D(contracts), D(entry),
                                  D(intended_stop), slices[0][0],
                                  NOW - timedelta(minutes=30)),
        submitted_orders=tuple(subs))
    return reconcile(st, Exch(position=pos(contracts=contracts, entry=entry),
                              orders=orders).view(), NOW)


AT = "29700.1"
WIDE = "29000"
TIGHT = "29800"

r_full = ladder_state([("s1", "2.38", AT)])
check("R3.1.1  one exact full-size stop at the intended price may RUN",
      r_full.run_state is RunState.RUNNING and r_full.clean,
      f"{r_full.run_state.value} {[f.code.value for f in r_full.findings]}")

r_two_ok = ladder_state([("s1", "1.19", AT), ("s2", "1.19", AT)])
check("R3.1.2  two partial stops BOTH at the intended price may RUN",
      r_two_ok.run_state is RunState.RUNNING and r_two_ok.clean,
      f"{r_two_ok.run_state.value} {[f.code.value for f in r_two_ok.findings]}")

r_one_wide = ladder_state([("s1", "1.19", AT), ("s2", "1.19", WIDE)])
check("R3.1.3  two partial stops, ONE WIDER, must not RUN",
      r_one_wide.run_state is not RunState.RUNNING,
      f"{r_one_wide.run_state.value} {[f.code.value for f in r_one_wide.findings]}")

r_both_wide = ladder_state([("s1", "1.19", WIDE), ("s2", "1.19", "28500")])
check("R3.1.4  two partial stops, BOTH wider, must not RUN",
      r_both_wide.run_state is not RunState.RUNNING,
      f"{r_both_wide.run_state.value} "
      f"{[f.code.value for f in r_both_wide.findings]}")

r_mixed = ladder_state([("s1", "1.19", TIGHT), ("s2", "1.19", WIDE)])
check("R3.1.5  a TIGHTER slice cannot hide a WIDER one",
      r_mixed.run_state is not RunState.RUNNING
      and any("WIDER" in f.code.value for f in r_mixed.findings),
      f"{r_mixed.run_state.value} {[f.code.value for f in r_mixed.findings]}")


def _r316():
    """The conclusion must not depend on the order the exchange lists orders in.
    Every permutation, and shuffled orderings, must agree."""
    slices = [("s1", "1.19", AT), ("s2", "1.19", WIDE)]
    verdicts = set()
    for perm in itertools.permutations(slices):
        r = ladder_state(list(perm))
        verdicts.add((r.run_state.value,
                      tuple(sorted(f.code.value for f in r.findings))))
    for seed in range(6):
        r = ladder_state(slices, shuffle=True, seed=seed)
        verdicts.add((r.run_state.value,
                      tuple(sorted(f.code.value for f in r.findings))))
    return len(verdicts) == 1, f"{len(verdicts)} distinct verdicts: {verdicts}"


attempt("R3.1.6  the verdict is IDENTICAL under every ordering of the "
        "protective orders — no prot[0] dependence", _r316)

r_three = ladder_state([("s1", "0.80", AT), ("s2", "0.80", AT),
                        ("s3", "0.78", WIDE)])
check("R3.1.7  three or more protective slices are each evaluated",
      r_three.run_state is not RunState.RUNNING
      and any("WIDER" in f.code.value for f in r_three.findings),
      f"{r_three.run_state.value} {[f.code.value for f in r_three.findings]}")


def _r318():
    """Exact aggregate size, heterogeneous prices, all at-or-tighter than the
    intent. Every contract IS protected at least as well as authorised, so this
    must not be over-blocked — but the ladder must be VISIBLE in the record
    rather than collapsed to one number."""
    r = ladder_state([("s1", "1.19", AT), ("s2", "1.19", TIGHT)])
    visible = any("LADDER" in f.code.value or "SLICE" in f.code.value
                  for f in r.findings)
    return (visible and r.reconciled,
            f"{r.run_state.value} {[f.code.value for f in r.findings]}")


attempt("R3.1.8  exact aggregate size with heterogeneous but authorised prices "
        "is reported as a ladder, not silently collapsed", _r318)


def _r319():
    """Risk must be computed from ALL slices, not from one of them."""
    from orbit.risk.modeled_loss import modeled_loss
    r = ladder_state([("s1", "1.19", AT), ("s2", "1.19", WIDE)])
    half = D("1.19") * SPEC.contract_size_btc
    expect = (modeled_loss(D("30000"), D(AT), half, SPEC, A1).total_usdt
              + modeled_loss(D("30000"), D(WIDE), half, SPEC, A1).total_usdt)
    got = r.protection.planned_risk_usdt if r.protection else None
    return got == expect, f"got {got}, all-slices {expect}"


attempt("R3.1.9  modelled risk is the sum over EVERY slice at ITS OWN stop",
        _r319)


def _r3110():
    r = ladder_state([("s1", "1.19", AT), ("s2", "1.19", WIDE)])
    over = any("BUDGET" in f.code.value for f in r.findings)
    return (over and r.run_state is not RunState.RUNNING,
            f"planned={r.protection.planned_risk_usdt if r.protection else None} "
            f"cap={A1.planned_risk_usdt} "
            f"{[f.code.value for f in r.findings]}")


attempt("R3.1.10 an aggregate modelled loss above the $8 cap is a budget "
        "overrun", _r3110)

r_unknown = ladder_state([("s1", "1.19", AT), ("s2", "1.19", None)])
check("R3.1.11 a slice with an UNKNOWN stop price cannot be claimed as "
      "protection", r_unknown.run_state is not RunState.RUNNING
      and any("UNKNOWN" in f.code.value for f in r_unknown.findings),
      f"{r_unknown.run_state.value} "
      f"{[f.code.value for f in r_unknown.findings]}")


def _r3112():
    src = open(os.path.join(ROOT, "orbit", "exec", "recon.py")).read()
    return ("prot[0]" not in src, "recon.py still indexes prot[0]"
            if "prot[0]" in src else "no positional dependence remains")


attempt("R3.1.12 the reconciler no longer reasons from prot[0]", _r3112)


# ======================================================================
banner("R3-2 — THE VALIDATED MUTATION IS THE OBJECT THAT IS SENT")
# DEFECT: the base adapter validated and bound role / reduce_only / instrument /
# order_kind / logical_operation_id, and then called
#
#   _do_submit(cid, side, contracts, order_type, price)
#
# The real OKX subclass API therefore did not contain the safety property the
# boundary claims to enforce. A subclass would have had to RECONSTRUCT
# reduce_only from something — which is the one thing it must never do.
# ======================================================================
CAPTURED = {}


def capture_adapter(rig):
    """A subclass that records what the ACTUAL I/O hook receives. The base
    adapter's own call log is not evidence about the subclass API."""
    from orbit.exec.adapter import AdapterResult, NullAdapter

    class Capturing(NullAdapter):
        def _do_mutation(self, mutation):
            CAPTURED["mutation"] = mutation
            CAPTURED["call"] = self.calls[-1]
            return AdapterResult(True, f"X-{mutation.client_order_id}", "ok")

    rig.adapter = Capturing(rig.authority, rig.journal)
    return rig


N_HOOK = itertools.count()


def _hook(kind, **kw):
    CAPTURED.clear()
    tag = f"r32_{kind}_{next(N_HOOK)}"
    if kind == "OPEN":
        ex = Exch()
        rg = capture_adapter(Rig(TMP, tag, intended=flat(), exch=ex))
        rg.acquire()
        rg.session("c1").propose_order("long", stop="29700.1")
    elif kind == "CLOSE":
        ex = Exch(position=pos(), orders=[stop_order(cid="stop1")])
        rg = capture_adapter(Rig(TMP, tag, intended=held(cid="stop1"),
                                 exch=ex))
        rg.acquire()
        rg.session("c1").close_position()
    elif kind == "REDUCE":
        # SAFETY CLOSURE ROUND 4B2, finding I3. A 2.38 position behind a
        # 2.38 stop cannot be halved: the remainder would rest behind an
        # oversized stop, which on trigger reverses the position. The
        # fixture uses protection already sized to the remainder, which
        # is the state in which a partial reduction IS safe. What this
        # test asserts is unchanged.
        ex = Exch(position=pos(),
                  orders=[stop_order(cid="stop1", contracts="1.19")])
        rg = capture_adapter(Rig(TMP, tag, intended=held(cid="stop1"),
                                 exch=ex))
        rg.acquire()
        rg.session("c1").reduce_position("0.5")
    elif kind == "STOP":
        rg = capture_adapter(Rig(TMP, tag, intended=flat()))
        lz = rg.acquire()
        rg.journal.record_intent(
            "a-p", client_order_id="p1", instrument=A1.instrument,
            order_kind="PROTECTIVE", role="PROTECTIVE", reduce_only=True,
            contracts="2.38", stop="29700.1", side="short",
            logical_operation_id="k:g0", operation_id="k:g0")
        rg.adapter.place_protective_stop(
            lz, "p1", D("2.38"), D("29700.1"), reduce_only=True,
            role="PROTECTIVE", instrument=A1.instrument, side="short",
            logical_operation_id="k:g0")
    return CAPTURED.get("mutation")


for i, (kind, field, want) in enumerate([
        ("CLOSE", "reduce_only", True),
        ("REDUCE", "reduce_only", True),
        ("OPEN", "reduce_only", False),
        ("STOP", "reduce_only", True),
], start=1):
    attempt(f"R3.2.{i}  the {kind} I/O hook receives {field}={want}",
            lambda k=kind, f=field, w=want: (
                (lambda m: (m is not None and getattr(m, f) is w,
                            f"{f}={getattr(m, f, None)!r}"))(_hook(k))))

attempt("R3.2.5  instrument survives to the hook",
        lambda: (lambda m: (m is not None and m.instrument == A1.instrument,
                            str(getattr(m, "instrument", None))))(_hook("CLOSE")))
attempt("R3.2.6  role survives to the hook",
        lambda: (lambda m: (m is not None and m.role == "EXIT",
                            str(getattr(m, "role", None))))(_hook("CLOSE")))
attempt("R3.2.7  the logical operation id survives to the hook",
        lambda: (lambda m: (bool(getattr(m, "logical_operation_id", None)),
                            str(getattr(m, "logical_operation_id", None))))(
            _hook("CLOSE")))
attempt("R3.2.8  order kind survives to the hook",
        lambda: (lambda m: (getattr(m, "order_kind", None) == "CLOSE",
                            str(getattr(m, "order_kind", None))))(_hook("CLOSE")))
attempt("R3.2.9  exact contracts and side survive to the hook",
        lambda: (lambda m: (m is not None and m.side == "short"
                            and m.contracts == D("2.38"),
                            f"{getattr(m, 'side', None)} "
                            f"{getattr(m, 'contracts', None)}"))(_hook("CLOSE")))


def _r3210():
    """The object the subclass receives must BE the object that was validated,
    not a reconstruction that happens to look similar."""
    m = _hook("CLOSE")
    call = CAPTURED.get("call")
    return (m is not None and call is not None
            and call.mutation_fingerprint == m.fingerprint(),
            f"validated={call.mutation_fingerprint[:16] if call else None} "
            f"sent={m.fingerprint()[:16] if m else None}")


attempt("R3.2.10 the mutation the hook receives hashes identically to the one "
        "the guard validated", _r3210)


def _r3211():
    """A subclass must not be able to reach the exchange without the guard."""
    from orbit.exec.adapter import ExchangeAdapter, GuardBypassed
    import inspect
    src = inspect.getsource(ExchangeAdapter)
    sealed = "__init_subclass__" in src
    from orbit.exec.adapter import NullAdapter
    try:
        class Sneaky(NullAdapter):
            def submit_order(self, *a, **k):      # override the guarded surface
                return None
        return False, "a subclass overrode the guarded public surface"
    except (GuardBypassed, TypeError) as e:
        return sealed, f"{type(e).__name__}: {str(e)[:60]}"


attempt("R3.2.11 the guarded public surface is SEALED: a subclass that tries "
        "to override it fails at class-definition time, not in a comment",
        _r3211)


# ======================================================================
banner("R3-3 — THE RESOLVER MUST CONSUME TRUSTED RECONCILIATION")
# DEFECT: resolve_operations() took a raw ExchangeView and never asked whether
# it was reachable, consistent, fresh, clock-sane or reconciled. With an
# unresolved ACKed CANCEL and the target simply absent from a BROKEN view:
#
#   unreachable  -> CANCEL EFFECTIVE
#   inconsistent -> CANCEL EFFECTIVE
#   999s stale   -> CANCEL EFFECTIVE
#
# "we cannot see the exchange" was being converted into "positive evidence the
# cancellation succeeded".
# ======================================================================
def cancel_rig(name):
    ex = Exch(position=None, orders=[stop_order(cid="own1", contracts="2.38")])
    rg = Rig(TMP, name, intended=flat(), exch=ex)
    rg.acquire()
    owning(rg, "own1")
    rg.session("c1").cancel_order("own1")          # ACK under a GOOD view
    return rg


def _resolve_with(name, **exch_kw):
    """Feed a view that fails exactly ONE trust dimension, with the target
    absent so the only thing standing between it and a false EFFECTIVE is the
    trust check."""
    from orbit.exec.resolver import resolve_operations
    rg = cancel_rig(name)
    bad = Exch(position=None, orders=[], **exch_kw)
    r = reconcile(rg.intended, bad.view(), NOW)
    acted = resolve_operations(rg.journal, r, NOW)
    still = [o.kind for o in OperationLedger(rg.path).unresolved()]
    return acted, still


for i, (label, kw) in enumerate([
        ("an UNREACHABLE view", dict(reachable=False)),
        ("an INCONSISTENT view", dict(consistent=False)),
        ("a STALE view", dict(age_s=999)),
], start=1):
    attempt(f"R3.3.{i}  {label} terminalises nothing",
            lambda k=kw, n=label: (
                (lambda t: (not t[0] and "CANCEL" in t[1],
                            f"acted={[x.outcome for x in t[0]]} still={t[1]}"))(
                    _resolve_with("r33_" + str(abs(hash(n)) % 9999), **k))))


def _r334():
    from orbit.exec.resolver import resolve_operations
    rg = cancel_rig("r33_skew")
    bad = Exch(position=None, orders=[])
    v = bad.view()
    from dataclasses import replace as dc_replace
    v = dc_replace(v, server_time=NOW + timedelta(seconds=600))
    r = reconcile(rg.intended, v, NOW)
    acted = resolve_operations(rg.journal, r, NOW)
    still = [o.kind for o in OperationLedger(rg.path).unresolved()]
    return (not acted and "CANCEL" in still,
            f"acted={[x.outcome for x in acted]} still={still}")


attempt("R3.3.4  SEVERE CLOCK SKEW terminalises nothing", _r334)


def _r335():
    """An unreconciled state — a phantom position the view cannot explain."""
    from orbit.exec.resolver import resolve_operations
    rg = cancel_rig("r33_unrec")
    bad = Exch(position=pos(), orders=[])          # phantom, unprotected
    r = reconcile(flat(), bad.view(), NOW)
    acted = resolve_operations(rg.journal, r, NOW)
    still = [o.kind for o in OperationLedger(rg.path).unresolved()]
    return (not acted and "CANCEL" in still,
            f"reconciled={r.reconciled} run={r.run_state.value} "
            f"acted={[x.outcome for x in acted]}")


attempt("R3.3.5  an UNRECONCILED state terminalises nothing", _r335)


def _r336():
    from orbit.exec.resolver import resolve_operations
    rg = cancel_rig("r33_halt")
    bad = Exch(position=pos(), orders=[stop_order(cid="alien")])
    r = reconcile(flat(), bad.view(), NOW)         # phantom + alien stop: HALTED
    acted = resolve_operations(rg.journal, r, NOW)
    return (not acted,
            f"run={r.run_state.value} acted={[x.outcome for x in acted]}")


attempt("R3.3.6  a HALTED or ambiguous state produces no positive conclusion",
        _r336)


def _r337():
    from orbit.exec.resolver import resolve_operations
    rg = cancel_rig("r33_good")
    good = Exch(position=None, orders=[])          # clean, fresh, target gone
    r = reconcile(rg.intended, good.view(), NOW)
    acted = resolve_operations(rg.journal, r, NOW)
    return ([a.outcome for a in acted] == [OpStatus.EFFECTIVE.value],
            f"reconciled={r.reconciled} acted={[a.outcome for a in acted]}")


attempt("R3.3.7  a CLEAN, RECONCILED, FRESH view with the target gone DOES "
        "terminalise the cancel — the rule must not block everything", _r337)


def _r338():
    from orbit.exec.resolver import resolve_operations
    ex = Exch(position=pos(), orders=[stop_order(cid="stop1")])
    rg = Rig(TMP, "r33_amend", intended=held(cid="stop1"), exch=ex)
    rg.acquire()
    owning(rg, "stop1")   # R4B: the amendment target must be durably ours
    rg.session("c1").modify_stop("29800.1")
    ex.orders = [stop_order(cid="stop1", price="29800.1")]
    rg.intended = held(cid="stop1", stop="29800.1")
    r = reconcile(rg.intended, ex.view(), NOW)
    acted = resolve_operations(rg.journal, r, NOW)
    return ([a.outcome for a in acted] == [OpStatus.EFFECTIVE.value],
            f"reconciled={r.reconciled} acted={[a.outcome for a in acted]}")


attempt("R3.3.8  and a clean amend confirmed at the approved stop terminalises",
        _r338)


def _r339():
    from orbit.exec.resolver import resolve_operations
    rg = cancel_rig("r33_ev")
    good = Exch(position=None, orders=[])
    r = reconcile(rg.intended, good.view(), NOW)
    resolve_operations(rg.journal, r, NOW)
    evs = [ev for rec in Journal.load(rg.path).records for ev in rec["events"]
           if ev["e"] == E.ORDER_STATUS.value and ev.get("resolver")]
    ok = bool(evs) and all(ev.get("evidence_id") and ev.get("view_fetched_at")
                           for ev in evs)
    return ok, str([{k: ev.get(k) for k in ("evidence_id", "view_fetched_at")}
                    for ev in evs])[:110]


attempt("R3.3.9  the resolution records the exact TRUSTED evidence it used",
        _r339)


def _r3310():
    """A raw ExchangeView must not even be accepted — the trust check cannot be
    forgotten if the untrusted type cannot be passed."""
    from orbit.exec.resolver import resolve_operations
    rg = cancel_rig("r33_type")
    try:
        resolve_operations(rg.journal, Exch(position=None, orders=[]).view(), NOW)
    except TypeError as e:
        return True, f"TypeError: {str(e)[:60]}"
    return False, "a raw ExchangeView was accepted by the resolver"


attempt("R3.3.10 a raw ExchangeView is STRUCTURALLY rejected: the resolver "
        "takes a reconciliation result or nothing", _r3310)


# ======================================================================
banner("R3-4 — NO BINARY FLOATS IN FINANCIAL STATE")
# DEFECT: OperationLedger accumulated fills with float():
#   fills[oid] += float(contracts);  want = float(o["contracts"])
# 0.01 + 0.06 == 0.06999999999999999, which is < 0.07, so a fully filled
# operation reported PARTIALLY_FILLED and stayed unresolved for ever — blocking
# the next operation on that key and any clean shutdown.
# ======================================================================
def fill_ledger(name, intended, fills):
    p = os.path.join(TMP, name + ".jsonl")
    j = Journal(p, clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    j.append_one(E.INTENT, "a1", client_order_id="c1", contracts=intended,
                 instrument=A1.instrument, order_kind="OPEN", side="long",
                 role="ENTRY", reduce_only=False, logical_operation_id="k:g0",
                 operation_id="k:g0")
    for i, c in enumerate(fills):
        j.append_one(E.FILL, "a1", client_order_id="c1", fill_id=f"f{i}",
                     contracts=c)
    return OperationLedger(p).all()[0]


op = fill_ledger("r34_a", "0.07", ["0.01", "0.06"])
check("R3.4.1  0.01 + 0.06 fills a 0.07 intent",
      op.status is OpStatus.FILLED,
      f"{op.status.value} (binary float sum is {0.01 + 0.06})")


def _r342():
    bad = []
    for intended, parts in (("0.03", ["0.01", "0.01", "0.01"]),
                            ("0.29", ["0.07", "0.07", "0.07", "0.08"]),
                            ("1.00", ["0.10"] * 10),
                            ("2.38", ["1.19", "1.19"])):
        o = fill_ledger("r34_" + intended.replace(".", "_"), intended, parts)
        if o.status is not OpStatus.FILLED:
            bad.append((intended, parts, o.status.value))
    return not bad, str(bad)


attempt("R3.4.2  every lot-step combination that sums exactly reaches FILLED",
        _r342)

op3 = fill_ledger("r34_partial", "0.07", ["0.01", "0.05"])
check("R3.4.3  a fill genuinely short of the intent stays PARTIALLY_FILLED",
      op3.status is OpStatus.PARTIALLY_FILLED, op3.status.value)

op4 = fill_ledger("r34_exact", "0.07", ["0.07"])
check("R3.4.4  an exact single fill terminalises", op4.status is OpStatus.FILLED,
      op4.status.value)


def _r345():
    o = fill_ledger("r34_over", "0.07", ["0.05", "0.05"])
    return (o.status is OpStatus.FILLED and o.overfilled,
            f"{o.status.value} overfilled={getattr(o, 'overfilled', None)}")


attempt("R3.4.5  an OVERFILL is separately detectable, not hidden by rounding",
        _r345)


def _r346():
    """Static assertion. A float() on a money quantity is not a style problem:
    it is the defect above, waiting."""
    import re
    offenders = []
    for mod in ("orbit/exec/operations.py", "orbit/exec/recon.py",
                "orbit/risk/gateway.py", "orbit/risk/modeled_loss.py",
                "orbit/audit/recovery.py", "orbit/core/precision.py",
                "orbit/exec/protection.py", "orbit/exec/resolver.py",
                "orbit/tools/session.py"):
        for n, line in enumerate(open(os.path.join(ROOT, mod)), 1):
            if re.search(r"\bfloat\(", line) and "# non-financial:" not in line:
                offenders.append(f"{mod}:{n}: {line.strip()[:60]}")
    return not offenders, str(offenders)[:200]


attempt("R3.4.6  no unjustified float() anywhere in the execution, state or "
        "risk modules", _r346)


# ======================================================================
banner("R3-5 — THE decision_id -> INPUT MAPPING MUST BE IMMUTABLE")
# DEFECT: the blob was immutable; the MAPPING was an ordinary journal append.
# Recording "decision-1 -> FIRST" then "decision-1 -> SECOND" was accepted, and
# load_decision_input("decision-1") returned SECOND, because it took the last
# matching record. The audit answer to "what did Claude know for decision-1?"
# could be changed after the fact — which is the one thing an audit record
# exists to prevent.
# ======================================================================
def di(prompt="FIRST"):
    from orbit.audit.decision_input import DecisionInput
    return DecisionInput(system_prompt="You are ORBIT A1.", user_prompt=prompt,
                         tool_schema={"get_market_state": {"params": {}}})


def fresh_store(name):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    j = Journal(os.path.join(d, "j.jsonl"), clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    return j, BlobStore(os.path.join(d, "blobs")), os.path.join(d, "j.jsonl")


def _r351():
    from orbit.audit.decision_input import record_decision_input
    j, st, p = fresh_store("r35_same")
    a = record_decision_input(j, st, "d1", di("FIRST"))
    b = record_decision_input(j, st, "d1", di("FIRST"))
    return (b.get("duplicate") is True
            and b["content_id"] == a["content_id"],
            f"second={('duplicate' if b.get('duplicate') else 'recorded')}")


attempt("R3.5.1  an IDENTICAL second mapping is idempotently suppressed", _r351)


def _r352():
    from orbit.audit.decision_input import (DecisionInputConflict,
                                            record_decision_input)
    j, st, p = fresh_store("r35_diff")
    record_decision_input(j, st, "d1", di("FIRST"))
    try:
        record_decision_input(j, st, "d1", di("SECOND"))
    except DecisionInputConflict as e:
        return True, str(e)[:70]
    return False, "a DIFFERENT input was accepted for an existing decision id"


attempt("R3.5.2  a DIFFERENT second mapping is a CONFLICT, not an update",
        _r352)


def _r353():
    from orbit.audit.decision_input import (DecisionInputConflict,
                                            load_decision_input,
                                            record_decision_input)
    j, st, p = fresh_store("r35_load")
    record_decision_input(j, st, "d1", di("FIRST"))
    try:
        record_decision_input(j, st, "d1", di("SECOND"))
    except DecisionInputConflict:
        pass
    got, ref = load_decision_input(p, st, "d1")
    return got.user_prompt == "FIRST", f"load returned {got.user_prompt!r}"


attempt("R3.5.3  load always returns the FIRST committed mapping", _r353)


def mapping_race(name, prompts, n=8):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    jpath = os.path.join(d, "j.jsonl")
    blobs = os.path.join(d, "blobs")
    j = Journal(jpath, clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    barrier = time.time() + 1.2
    ps = [subprocess.Popen(
        [sys.executable, os.path.join(HERE, "_mapping_worker.py"),
         jpath, blobs, "d1", prompts[i % len(prompts)], str(barrier)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for i in range(n)]
    outs = [p.communicate()[0].strip() for p in ps]
    return outs, jpath, BlobStore(blobs)


def _r354():
    outs, p, st = mapping_race("r35_race_same", ["SAME"])
    ids = {ev["content_id"] for rec in Journal.load(p).records
           for ev in rec["events"] if ev["e"] == E.DECISION_INPUT.value}
    return (outs.count("RECORDED") == 1 and len(ids) == 1
            and outs.count("CONFLICT") == 0,
            f"{outs} distinct_content_ids={len(ids)}")


attempt("R3.5.4  eight processes, same decision id and same input -> ONE "
        "mapping, no conflicts", _r354)


def _r355():
    outs, p, st = mapping_race("r35_race_diff",
                               [f"PROMPT-{i}" for i in range(8)])
    return (outs.count("RECORDED") == 1
            and outs.count("CONFLICT") == 7,
            str(outs))


attempt("R3.5.5  eight processes, same decision id and DIFFERENT inputs -> "
        "exactly one winner, seven conflicts", _r355)


def _r356():
    from orbit.audit.decision_input import load_decision_input
    outs, p, st = mapping_race("r35_restart", ["ONLY-ONE"])
    got, ref = load_decision_input(p, st, "d1")      # fresh objects, from disk
    return got.user_prompt == "ONLY-ONE", got.user_prompt


attempt("R3.5.6  the mapping survives a restart, read from disk alone", _r356)


def _r357():
    outs, p, st = mapping_race("r35_chain", [f"P{i}" for i in range(8)])
    load = Journal.load(p)
    return load.trusted, load.reason or "chain intact"


attempt("R3.5.7  the hash chain survives the race", _r357)


def _r358():
    from orbit.audit.decision_input import (DecisionInputConflict,
                                            load_decision_input,
                                            record_decision_input)
    j, st, p = fresh_store("r35_audit")
    record_decision_input(j, st, "d1", di("FIRST"))
    try:
        record_decision_input(j, st, "d1", di("SECOND"))
    except DecisionInputConflict:
        pass
    conflicts = [ev for rec in Journal.load(p).records for ev in rec["events"]
                 if ev["e"] == E.DECISION_INPUT_CONFLICT.value]
    got, ref = load_decision_input(p, st, "d1")
    return (len(conflicts) == 1 and got.user_prompt == "FIRST"
            and conflicts[0].get("attempted_model_input_hash"),
            f"{len(conflicts)} conflict record(s); load still FIRST")


attempt("R3.5.8  the conflict is durably auditable WITHOUT replacing the "
        "original meaning", _r358)


# ======================================================================
banner("R3-6 — A HASH CHAIN CANNOT DETECT LOSS OF ITS OWN SUFFIX")
# THE LIMITATION, STATED FIRST: a forward hash chain proves that the records it
# still holds have not been altered. It cannot prove how many there were. Every
# record's hash depends on its predecessors and on nothing that comes after, so
# deleting a suffix leaves a perfectly valid shorter chain.
#
# Observed on the 507/507 archive:
#   half of a COMMITTED final record removed -> trusted=True discarded_tail=1
#   the whole COMMITTED final record removed -> trusted=True discarded_tail=0
#
# The round-1 F7 test asserted a REWRITTEN MIDDLE record is detected. That is a
# different failure and does not cover this one.
#
# THE DESIGN TAKEN: an independently durable monotonic committed-head
# checkpoint, written after each commit, outside the file whose truncation we
# are trying to detect. The checkpoint says what the last committed sequence and
# hash were. The journal cannot argue with it.
# ======================================================================
def committed(name, n=3):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "j.jsonl")
    j = Journal(p, clock=lambda: NOW)
    j.append_one(E.RUN_START, None)
    for i in range(n - 1):
        j.append_one(E.REMEDIATION, None, note=f"committed-{i}")
    return p, d


def _r361():
    """A genuine pre-commit torn write must still recover — the checkpoint must
    not turn ordinary crash semantics into a permanent halt."""
    p, d = committed("r36_torn", 2)
    with open(p, "a") as fh:
        fh.write('{"seq": 3, "ts": "2026')        # never committed
    load = Journal.load(p)
    j = Journal(p, clock=lambda: NOW)
    j.append_one(E.REMEDIATION, None, note="after the crash")
    after = Journal.load(p)
    return (load.discarded_tail == 1 and not load.tamper_detected
            and after.trusted,
            f"pre: discarded={load.discarded_tail} tamper={load.tamper_detected}; "
            f"post: trusted={after.trusted} {after.reason[:40]}")


attempt("R3.6.1  a genuine torn PRE-COMMIT final write still recovers", _r361)


def _truncate_committed(name, keep_records=None, half=False):
    p, d = committed(name, 3)
    lines = open(p).read().rstrip("\n").split("\n")
    if half:
        body = "\n".join(lines[:-1]) + "\n" + lines[-1][: len(lines[-1]) // 2]
    else:
        keep = keep_records if keep_records is not None else len(lines) - 1
        body = "\n".join(lines[:keep]) + "\n"
    open(p, "w").write(body)
    return Journal.load(p)


def _r362():
    load = _truncate_committed("r36_half", half=True)
    return (not load.trusted and load.tamper_detected,
            f"trusted={load.trusted} tamper={load.tamper_detected} "
            f"{load.reason[:60]}")


attempt("R3.6.2  half of a previously COMMITTED final record removed is "
        "DETECTED, not mistaken for a crash-torn write", _r362)


def _r363():
    load = _truncate_committed("r36_one")
    return (not load.trusted and load.tamper_detected,
            f"trusted={load.trusted} tamper={load.tamper_detected} "
            f"{load.reason[:60]}")


attempt("R3.6.3  a whole COMMITTED final record removed is DETECTED", _r363)


def _r364():
    load = _truncate_committed("r36_many", keep_records=1)
    return (not load.trusted and load.tamper_detected,
            f"trusted={load.trusted} tamper={load.tamper_detected} "
            f"{load.reason[:60]}")


attempt("R3.6.4  SEVERAL committed suffix records removed is DETECTED", _r364)


def _r365():
    p, d = committed("r36_mid", 3)
    lines = open(p).read().rstrip("\n").split("\n")
    rec = json.loads(lines[1])
    rec["events"][0]["note"] = "REWRITTEN"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    open(p, "w").write("\n".join(lines) + "\n")
    load = Journal.load(p)
    return (not load.trusted and load.tamper_detected, load.reason[:60])


attempt("R3.6.5  a rewritten MIDDLE record is still detected", _r365)


def _r366():
    """A checkpoint AHEAD of the journal means records are missing. Fail closed;
    never quietly adopt the shorter history."""
    from orbit.audit.checkpoint import HeadCheckpoint
    p, d = committed("r36_ahead", 3)
    cp = HeadCheckpoint(p)
    cur = cp.read()
    cp._write_unchecked(cur.seq + 5, "f" * 64)
    load = Journal.load(p)
    return (not load.trusted and load.tamper_detected,
            f"trusted={load.trusted} {load.reason[:70]}")


attempt("R3.6.6  a checkpoint NEWER than the journal fails closed", _r366)


def _r367():
    """The one legitimate divergence: a crash between the fsync of the record
    and the fsync of the checkpoint. The journal is exactly ONE record ahead and
    that record is committed. The protocol rolls the checkpoint forward — it
    does not guess, and it does not accept two."""
    from orbit.audit.checkpoint import HeadCheckpoint
    p, d = committed("r36_behind", 3)
    load_before = Journal.load(p)
    cp = HeadCheckpoint(p)
    head = load_before.records[-2]
    cp._write_unchecked(head["seq"], head["hash"])       # one behind
    ok_one = Journal.load(p).trusted
    two = load_before.records[-3] if len(load_before.records) >= 3 else None
    cp._write_unchecked(two["seq"], two["hash"])         # two behind
    ok_two = Journal.load(p).trusted
    return (ok_one and not ok_two,
            f"one-behind trusted={ok_one}; two-behind trusted={ok_two}")


attempt("R3.6.7  a checkpoint exactly ONE committed record behind is the "
        "defined crash window and recovers; further behind is not", _r367)


def _r368():
    """Tail repair must never be able to erase a record the external head says
    was committed."""
    from orbit.audit.checkpoint import HeadCheckpoint
    p, d = committed("r36_repair", 3)
    lines = open(p).read().rstrip("\n").split("\n")
    open(p, "w").write("\n".join(lines[:-1]) + "\n" + lines[-1][:20])
    j = Journal(p, clock=lambda: NOW)
    try:
        j.append_one(E.REMEDIATION, None, note="must not be written")
        return False, "the append succeeded over a lost committed record"
    except Exception as e:                                # noqa: BLE001
        return (type(e).__name__ == "TamperedJournalError",
                f"{type(e).__name__}: {str(e)[:60]}")


attempt("R3.6.8  repair cannot erase evidence the external head says was "
        "committed", _r368)


def _r369():
    """The threat model must be written down, not implied."""
    from orbit.audit import checkpoint as cp_mod
    doc = (cp_mod.__doc__ or "") + (cp_mod.THREAT_MODEL or "")
    for word in ("cannot", "suffix", "checkpoint"):
        if word not in doc.lower():
            return False, f"the stated threat model does not mention {word!r}"
    return True, "the limitation and the narrowed guarantee are both stated"


attempt("R3.6.9  the limitation a hash chain CANNOT provide is stated in the "
        "code, not merely worked around", _r369)


def _r3610():
    """The whole thing must still work end to end after the change."""
    p, d = committed("r36_e2e", 4)
    j = Journal(p, clock=lambda: NOW)
    for i in range(5):
        j.append_one(E.REMEDIATION, None, note=f"more-{i}")
    load = Journal.load(p)
    return (load.trusted and len(load.records) == 9,
            f"trusted={load.trusted} records={len(load.records)}")


attempt("R3.6.10 ordinary appending continues to work with the checkpoint in "
        "place", _r3610)


shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("Round-3 findings closed. No model. No credentials. No network. "
      "No live capital.")
