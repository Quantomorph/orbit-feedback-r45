"""
tests/test_tools_adversarial.py — THE CAPABILITY BOUNDARY, ADVERSARIALLY.

ORBIT-AGENT-ARCH-001, steps 6A/6B/6E/6F/6G/6H/6I/6J/6K/6M.

No model is connected. Every "request" below is a hostile stub standing in for
one. The suite's job is to get an unsafe exchange action out of the tool layer
and fail to.

Where a rejection is asserted, the rig uses `ForbiddenAdapter`, which RAISES on
any call. "Never reached the exchange" is then enforced by the object rather
than by counting calls afterwards.
"""
from __future__ import annotations

import inspect
import random
import shutil
import sys
import tempfile
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from orbit.exec.operations import logical_key
from harness import owning, NOW, Exch, Rig, flat, held, pos, stop_order
from orbit.audit.information import verify_information_used
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.exec.adapter import AdapterRefused
from orbit.exec.recon import ExchangeOrder
from orbit.risk.limits import A1, RunState
from orbit.tools.registry import (ACTION_TOOLS, ALL_TOOLS, FORBIDDEN_SHAPES,
                                  READ_TOOLS, Capability, capability_of)
from orbit.tools.session import ActionStatus, ToolSession

PASS, FAIL = [], []
TMP = tempfile.mkdtemp(prefix="orbit_t6_")
N = [0]


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def banner(t):
    print("\n" + "-" * 76)
    print(t)


def rig(**kw):
    N[0] += 1
    r = Rig(TMP, f"r{N[0]}", **kw)
    r.acquire()
    return r


print("=" * 76)
print("ORBIT A1 — TOOL CAPABILITY BOUNDARY")
print("=" * 76)

# ======================================================================
banner("CAP — THE CAPABILITY MODEL IS THE WHOLE SURFACE")
# ======================================================================
public = {n for n in dir(ToolSession)
          if not n.startswith("_") and callable(getattr(ToolSession, n))}
extra = public - ALL_TOOLS
check("CAP1. the session exposes NOTHING beyond the declared capabilities",
      not extra, str(sorted(extra)))
check("CAP2. every declared capability exists on the session",
      not (ALL_TOOLS - public), str(sorted(ALL_TOOLS - public)))

bad_shape = [n for n in dir(ToolSession) if not n.startswith("_")
             and any(s in n.lower() for s in FORBIDDEN_SHAPES)]
check("CAP3. no attribute has the shape of an unrestricted primitive",
      not bad_shape, str(bad_shape))

leaky = []
for name in ALL_TOOLS:
    sig = inspect.signature(getattr(ToolSession, name))
    for p in sig.parameters:
        if p in ("lease", "epoch", "authority", "adapter", "journal", "gateway",
                 "approved", "reconciled", "run_state", "risk", "size",
                 "contracts", "leverage", "equity", "position"):
            leaky.append(f"{name}({p})")
check("CAP4. no tool accepts authority, approval, reconciliation, size, risk or "
      "leverage as an argument — those are Python's to compute", not leaky,
      str(leaky))
check("CAP5. read and action capabilities are distinguished",
      capability_of("get_candles") is Capability.READ
      and capability_of("propose_order") is Capability.ACTION)

# ======================================================================
banner("PROV — READ RESULTS ARE CITABLE; CLAIMS ARE CHECKED")
# ======================================================================
r0 = rig(intended=flat())
s0 = r0.session()
t_c = s0.get_candles("5m", 300)
t_m = s0.get_market_state()
t_r = s0.get_current_risk_state()
# SAFETY CLOSURE ROUND 4C2, C2-I3. `get_candles` is a PLACEHOLDER: it observes
# no exchange state. Its freshness used to be derived from a view it never
# read, which was a number with no referent. A result that observed nothing now
# reports `freshness_seconds is None`, which is the honest answer, and a result
# that DID observe reports the freshness of the observation its data came from.
check("PROV1. a read result carries a reference id, hashes, source and cycle",
      all([t_c.ref_id, t_c.data_hash, t_c.snapshot_id, t_c.source,
           t_c.cycle_id == "cyc1"]))
check("PROV1b. freshness belongs to results that actually observed the exchange",
      t_c.freshness_seconds is None and t_m.freshness_seconds >= 0,
      f"candles={t_c.freshness_seconds} market={t_m.freshness_seconds}")
ctx = s0._freeze_decision_snapshot("d1", prompt_text="ORBIT A1 cycle prompt").context
check("PROV2. every read performed is present in the decision context",
      {t_c.token, t_m.token, t_r.token} <= ctx.refs(),
      f"{len(ctx.refs())} refs")
v = verify_information_used((t_c.token,), ctx)
check("PROV3. citing a tool result that was actually returned is accepted", v.ok)
v = verify_information_used(("get_orderbook@fabricated",), ctx)
check("PROV4. citing a snapshot that was never returned is rejected",
      not v.ok and "get_orderbook@fabricated" in v.unknown_refs)
s_other = r0.session(cycle_id="cyc2")
c2 = s_other.get_candles("5m", 300)
check("PROV5. the same read in a different cycle gets a DIFFERENT reference, so "
      "information cannot be carried across cycles", c2.ref_id != t_c.ref_id)
check("PROV6. the risk read states plainly that planned risk is not a guarantee",
      "NOT a guaranteed maximum loss" in t_r.data["note"])

# ======================================================================
banner("ORD — NO EXCHANGE MUTATION BEFORE DURABLE INTENT (from real data)")
# ======================================================================
r1 = rig(intended=flat())
s1 = r1.session()
res = s1.propose_order(side="long", stop="29700.1")
check("ORD1. a valid entry is ACKNOWLEDGED, not reported as filled",
      res.status is ActionStatus.ACKNOWLEDGED and "NOT a fill" in res.reason,
      res.status.value)
call = r1.adapter.calls[0]
iseq = r1.adapter.intent_seq(res.client_order_id)
check("ORD2. the INTENT record precedes the adapter call, verified by journal "
      "sequence numbers rather than by narrative",
      iseq is not None and call.journal_seq_at_call >= iseq,
      f"intent seq {iseq} <= call seq {call.journal_seq_at_call}")
check("ORD3. the adapter call carries the writer epoch that authorised it",
      call.epoch == r1.lease.epoch)

evs = [ev["e"] for rr in Journal.load(r1.path).records for ev in rr["events"]]
check("ORD4. the journal shows INTENT before SUBMIT_ATTEMPTED before SUBMIT_ACK",
      evs.index(E.INTENT.value) < evs.index(E.SUBMIT_ATTEMPTED.value)
      < evs.index(E.SUBMIT_ACK.value))

# ======================================================================
banner("LIFE — LIFECYCLE GATES (6J 25-27)")
# ======================================================================
r = rig(intended=flat(), exch=Exch(position=pos()), forbidden=True)
out = r.session().propose_order(side="long", stop="29700.1")
check("LIFE1. a phantom position (EMERGENCY) refuses agent actions entirely",
      out.status is ActionStatus.EMERGENCY_STATE, out.status.value)

r = rig(intended=flat(), exch=Exch(orders=[ExchangeOrder("alien", D("1"), False)]),
        forbidden=True)
out = r.session().propose_order(side="long", stop="29700.1")
check("LIFE2. an orphaned order (NO_NEW_ENTRY) BLOCKS a new entry",
      out.status is ActionStatus.BLOCKED, out.status.value)

r = rig(intended=held(), exch=Exch(position=pos(), orders=[stop_order()],
                                   reachable=False), forbidden=True)
out = r.session().close_position()
check("LIFE3. an unreachable exchange returns REQUIRES_RECONCILIATION, not a "
      "guess", out.status is ActionStatus.REQUIRES_RECONCILIATION, out.status.value)

r = rig(intended=held(), exch=Exch(position=pos(), orders=[stop_order()],
                                   consistent=False), forbidden=True)
out = r.session().close_position()
check("LIFE4. contradictory exchange responses require a human",
      out.status is ActionStatus.REQUIRES_HUMAN_REVIEW, out.status.value)

r = rig(intended=held(), exch=Exch(position=pos(), orders=[stop_order()],
                                   age_s=999), forbidden=True)
out = r.session().close_position()
check("LIFE5. a stale snapshot blocks action",
      out.status in (ActionStatus.REQUIRES_RECONCILIATION, ActionStatus.BLOCKED),
      out.status.value)

# NO_NEW_ENTRY must still permit risk reduction.
ex = Exch(position=pos(), orders=[stop_order(), ExchangeOrder("alien", D("1"), False)])
r = rig(intended=held(), exch=ex)
out = r.session().close_position()
check("LIFE6. NO_NEW_ENTRY still permits a risk-reducing CLOSE",
      out.status is ActionStatus.ACKNOWLEDGED, out.status.value)

# ======================================================================
banner("PROT — PROTECTION IS NOT NEGOTIABLE (6G, 6J 20-22)")
# ======================================================================
ex = Exch(position=pos(), orders=[stop_order()])
r = owning(rig(intended=held(), exch=ex, forbidden=True), "stop1")
out = r.session().cancel_order("stop1")
check("PROT1. cancelling the only protective order is refused",
      out.code == "PROTECTION_WOULD_BE_REMOVED", out.code)

ex = Exch(position=pos(), orders=[stop_order(), stop_order("rep", "1.00", "29800")])
r = owning(rig(intended=held(), exch=ex, forbidden=True), "stop1", "rep")
out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
check("PROT2. a replacement that under-covers the position is refused",
      out.code == "REPLACEMENT_UNDER_COVERS", out.code)

ex = Exch(position=pos(), orders=[stop_order(), stop_order("rep", "2.38", "29500")])
r = owning(rig(intended=held(), exch=ex, forbidden=True), "stop1", "rep")
out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
check("PROT3. a replacement further from entry is refused — widening by another "
      "route is still widening", out.code == "REPLACEMENT_LESS_PROTECTIVE", out.code)

ex = Exch(position=pos(), orders=[stop_order(), stop_order("rep", "2.38", "29800")])
r = owning(rig(intended=held(), exch=ex), "stop1", "rep")
out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
check("PROT4. cancelling IS permitted once a durable, equal-or-better "
      "replacement is already resting", out.status is ActionStatus.ACKNOWLEDGED,
      out.status.value)

ex = Exch(position=pos(), orders=[stop_order("stop1", "1.00", "29700.1")])
r = rig(intended=held(), exch=ex, forbidden=True)
out = r.session().reduce_position("0.1")
check("PROT5. a reduction leaving protection short of the remainder is refused",
      out.code == "PROTECTION_WOULD_NOT_COVER_REMAINDER", out.code)

ex = Exch(position=pos(), orders=[stop_order()])
r = rig(intended=held(), exch=ex, forbidden=True)
out = r.session().modify_stop("29500")
check("PROT6. widening a stop is refused by the gateway",
      out.code == "STOP_WIDENED", out.code)

r = owning(rig(intended=held(),
               exch=Exch(position=pos(), orders=[stop_order()])), "stop1")
out = r.session().modify_stop("29800")
check("PROT7. tightening a stop is permitted",
      out.status is ActionStatus.ACKNOWLEDGED, out.status.value)

# ======================================================================
banner("RISK — PYTHON RECOMPUTES; THE REQUEST IS NEVER TRUSTED (6E)")
# ======================================================================
r = rig(intended=held(), exch=Exch(position=pos(), orders=[stop_order()]),
        forbidden=True)
out = r.session().propose_order(side="long", stop="29700.1")
check("RISK1. adding to an existing position is refused",
      out.code == "ADD_TO_POSITION", out.code)
out = r.session(cycle_id="c9").propose_order(side="short", stop="30300")
check("RISK2. a second, opposite position is refused as a reversal",
      out.code == "REVERSAL_IN_ONE_ACTION", out.code)

r = rig(intended=flat(), forbidden=True)
out = r.session().propose_order(side="long", stop="29994")
check("RISK3. a stop tight enough to demand more than 5x is refused on leverage",
      out.code == "LEVERAGE_EXCEEDED", out.code)

worst, approvals, order_viol = D("0"), 0, []
for i in range(1, 200):
    stop = (D("30000") * (1 - D(i) / D("10000"))).quantize(D("0.1"))
    rr = rig(intended=flat())
    o = rr.session(cycle_id=f"c{i}").propose_order(side="long", stop=str(stop))
    if o.status is ActionStatus.ACKNOWLEDGED:
        approvals += 1
        worst = max(worst, D(o.computed["planned_risk_usdt"]))
        c = rr.adapter.calls[0]
        iseq = rr.adapter.intent_seq(o.client_order_id)
        if iseq is None or c.journal_seq_at_call < iseq or c.epoch != rr.lease.epoch:
            order_viol.append(str(stop))
check("RISK4. across 199 stop distances the planned risk NEVER exceeds the $8 "
      "cap AT THE TOOL LEVEL", worst <= A1.planned_risk_usdt,
      f"worst ${worst}, {approvals} approved")
check("RISK5. that sweep is not vacuous", approvals > 50, f"{approvals}")
check("RISK6. and in every one of those real orders the durable INTENT preceded "
      "the exchange call under the live epoch", not order_viol, str(order_viol[:3]))

# ======================================================================
banner("CONC — CONCURRENCY AND CROSS-CYCLE (6J)")
# ======================================================================
# Two OPENs in one cycle with DIFFERENT parameters. Neither has filled yet, so
# the exchange still shows flat and the day counter is still zero.
rc = rig(intended=flat())
sc = rc.session()
o1 = sc.propose_order(side="long", stop="29700.1")
o2 = sc.propose_order(side="long", stop="29650.0")
check("CONC1. a second entry while the first is still in flight is refused",
      o2.status is not ActionStatus.ACKNOWLEDGED,
      f"{o2.status.value}/{o2.code}")
check("CONC2. and exactly one order reached the exchange",
      len(rc.adapter.calls) == 1, f"{len(rc.adapter.calls)} calls")

rc = rig(intended=flat())
o1 = rc.session(cycle_id="cA").propose_order(side="long", stop="29700.1")
o2 = rc.session(cycle_id="cB").propose_order(side="long", stop="29650.0")
check("CONC3. and the same holds across two different cycles sharing the journal",
      o2.status is not ActionStatus.ACKNOWLEDGED and len(rc.adapter.calls) == 1,
      f"{o2.status.value}/{o2.code}, {len(rc.adapter.calls)} calls")

# Two CLOSEs, two MODIFY_STOPs: identical requests must collapse to one action.
rc = owning(rig(intended=held(),
                exch=Exch(position=pos(), orders=[stop_order()])), "stop1")
s = rc.session()
c1, c2 = s.close_position(), s.close_position()
check("CONC4. two simultaneous CLOSE requests produce ONE exchange action",
      c2.status is ActionStatus.DUPLICATE_SUPPRESSED and len(rc.adapter.calls) == 1)

rc = owning(rig(intended=held(),
                exch=Exch(position=pos(), orders=[stop_order()])), "stop1")
s = rc.session()
m1, m2 = s.modify_stop("29800"), s.modify_stop("29800")
check("CONC5. two simultaneous identical MODIFY_STOPs produce ONE exchange action",
      m2.status is ActionStatus.DUPLICATE_SUPPRESSED and len(rc.adapter.calls) == 1)

# OPEN and CLOSE racing: with no position, CLOSE has nothing to close.
rc = rig(intended=flat())
s = rc.session()
oo = s.propose_order(side="long", stop="29700.1")
cc = s.close_position()
check("CONC6. a CLOSE racing an unfilled OPEN is refused — an acknowledged "
      "entry is not a position", cc.status is ActionStatus.REJECTED
      and cc.code == "NO_POSITION", cc.code)

# Two workers, one stale.
rc = owning(rig(intended=held(),
                exch=Exch(position=pos(), orders=[stop_order()])), "stop1")
old = rc.lease
from orbit.exec.writer import WriterAuthority as WA
rc.authority.release(old)
new_owner = WA(rc.wdir, owner_id="WORKER2")
new_lease = new_owner.acquire()
stale = rc.session(lease=old)
fresh = rc.session(cycle_id="cF", lease=new_lease)
a_stale = stale.modify_stop("29800")
check("CONC7. the superseded worker is BLOCKED as STALE_WRITER",
      a_stale.code == "STALE_WRITER", a_stale.code)
check("CONC8. and the current worker still acts normally",
      fresh.modify_stop("29810").status is ActionStatus.ACKNOWLEDGED)
check("CONC9. exactly one exchange action came from the two workers",
      len(rc.adapter.calls) == 1, f"{len(rc.adapter.calls)}")

# Information from another cycle.
rc = rig(intended=flat())
sA = rc.session(cycle_id="cX")
tok = sA.get_candles("5m", 300).token
sB = rc.session(cycle_id="cY")
sB.get_market_state()
vv = verify_information_used(
    (tok,), sB._freeze_decision_snapshot("dY", prompt_text="p").context)
check("CONC10. a decision may not cite a snapshot taken in another cycle",
      not vv.ok and tok in vv.unknown_refs)

# ======================================================================
banner("IDEM — IDENTITY IS PYTHON'S, AND IT IS DURABLE (6I)")
# ======================================================================
r = rig(intended=flat())
s = r.session()
a1 = s.propose_order(side="long", stop="29700.1")
a2 = s.propose_order(side="long", stop="29700.1")
check("IDEM1. an identical repeated request is suppressed",
      a2.status is ActionStatus.DUPLICATE_SUPPRESSED, a2.status.value)
check("IDEM2. and produced exactly ONE exchange action",
      len(r.adapter.calls) == 1, f"{len(r.adapter.calls)} calls")
check("IDEM3. the duplicate returns the original client order id",
      a2.client_order_id == a1.client_order_id)

s2 = r.session()                      # a fresh session = a restarted process
a3 = s2.propose_order(side="long", stop="29700.1")
check("IDEM4. after restart the same request is still suppressed, from durable "
      "state rather than memory",
      a3.status is ActionStatus.DUPLICATE_SUPPRESSED and len(r.adapter.calls) == 1)

r = rig(intended=flat())
s = r.session()
# SAFETY CLOSURE, blocker A: identity is now the LOGICAL OPERATION id, derived
# from what the mutation is rather than from which cycle asked for it. The
# planted record claims that identity with different parameters and a client
# order id that is not this operation's.
aid = f"{logical_key(A1.instrument, 'OPEN', 'long', None)}:g0"
r.journal.record_intent(aid, client_order_id="planted", fingerprint="WRONG",
                        contracts="99")
out = s.propose_order(side="long", stop="29700.1")
check("IDEM5. the same action id carrying DIFFERENT parameters is an identity "
      "conflict, not a duplicate",
      out.status is ActionStatus.IDENTITY_CONFLICT, out.status.value)
check("IDEM6. and no exchange action followed it", len(r.adapter.calls) == 0)

r = rig(intended=flat())
r.adapter.timeout_next = True
s = r.session()
out = s.propose_order(side="long", stop="29700.1")
check("IDEM7. an exchange timeout is UNKNOWN, never a failure and never a "
      "success", out.status is ActionStatus.UNKNOWN, out.status.value)
again = s.propose_order(side="long", stop="29700.1")
check("IDEM8. retrying after a timeout does NOT resubmit — the durable intent "
      "already exists and the real state must be reconciled first",
      again.status is ActionStatus.DUPLICATE_SUPPRESSED
      and len(r.adapter.calls) == 1, f"{len(r.adapter.calls)} calls")

# ======================================================================
banner("STAT — ACCEPTANCE IS NOT EXECUTION (6H)")
# ======================================================================
r = rig(intended=flat())
r.adapter.fail_next = True
out = r.session().propose_order(side="long", stop="29700.1")
check("STAT1. an exchange rejection is REJECTED with its own code",
      out.status is ActionStatus.REJECTED and out.code == "EXCHANGE_REJECTED",
      out.code)
statuses = {s.value for s in ActionStatus}
check("STAT2. every status the brief requires exists",
      {"APPROVED", "REJECTED", "SUBMITTED", "ACKNOWLEDGED", "FILLED",
       "PARTIALLY_FILLED", "UNKNOWN", "BLOCKED", "REQUIRES_RECONCILIATION",
       "REQUIRES_HUMAN_REVIEW", "EMERGENCY_STATE"} <= statuses)

# ======================================================================
banner("HOSTILE — 6K")
# ======================================================================
HOSTILE = [
    ("arbitrary instrument", dict(side="long", stop="29700.1", instrument="ETH-USDT-SWAP")),
    ("invalid side", dict(side="sideways", stop="29700.1")),
    ("invalid order type", dict(side="long", stop="29700.1", entry_type="iceberg")),
    ("missing stop", dict(side="long", stop=None)),
    ("negative stop", dict(side="long", stop="-1")),
    ("zero stop", dict(side="long", stop="0")),
    ("NaN stop", dict(side="long", stop="NaN")),
    ("Infinity stop", dict(side="long", stop="Infinity")),
    ("-Infinity stop", dict(side="long", stop="-Infinity")),
    ("enormous stop", dict(side="long", stop="9" * 40)),
    ("stop above entry for a long (negative risk)", dict(side="long", stop="31000")),
    ("garbage stop", dict(side="long", stop="'; DROP TABLE")),
    ("stop as a dict", dict(side="long", stop={"a": 1})),
    ("stop as a list", dict(side="long", stop=[1, 2])),
    ("side as an int", dict(side=1, stop="29700.1")),
]
leaked = []
for label, kw in HOSTILE:
    rr = rig(intended=flat(), forbidden=True)
    try:
        o = rr.session().propose_order(**kw)
        if o.reached_exchange:
            leaked.append(label)
    except AdapterRefused:
        leaked.append(label + " (REACHED THE EXCHANGE)")
    except TypeError:
        pass
check("HOST1. none of 15 hostile order requests reaches the exchange",
      not leaked, str(leaked))

for label, kw in [("fake approval", dict(side="long", stop="29700.1", approved=True)),
                  ("fake reconciliation", dict(side="long", stop="29700.1", reconciled=True)),
                  ("injected size", dict(side="long", stop="29700.1", contracts="999")),
                  ("injected leverage", dict(side="long", stop="29700.1", leverage="100")),
                  ("injected epoch", dict(side="long", stop="29700.1", epoch=99))]:
    rr = rig(intended=flat(), forbidden=True)
    try:
        rr.session().propose_order(**kw)
        check(f"HOST2. injected field rejected: {label}", False)
    except TypeError:
        check(f"HOST2. injected field rejected: {label}", True)

rr = rig(intended=held(), exch=Exch(position=pos(), orders=[stop_order()]),
         forbidden=True)
for label, kw in [("fake exchange order id", dict(client_order_id="X-not-ours")),
                  ("empty client order id", dict(client_order_id="")),
                  ("non-string client order id", dict(client_order_id=7))]:
    o = rr.session().cancel_order(**kw)
    check(f"HOST3. {label} refused", o.status is ActionStatus.REJECTED, o.code)

rng = random.Random(20260908)
unsafe, reached, raised = [], 0, 0
for i in range(400):
    rr = rig(intended=rng.choice([flat(), held()]))          # NullAdapter
    kw = dict(side=rng.choice(["long", "short", None, 1, "up", ""]),
              stop=rng.choice([None, "29700.1", "-5", "NaN", "Infinity", 0,
                               {"x": 1}, "abc", "1e400", "30300"]),
              entry_type=rng.choice(["market", "limit", None, "twap"]),
              entry_price=rng.choice([None, "30000", "NaN", -1]),
              target=rng.choice([None, "30500", "NaN"]))
    try:
        o = rr.session().propose_order(**kw)
    except TypeError:
        continue
    except Exception as e:
        raised += 1
        unsafe.append(f"raised {type(e).__name__}: {e}")
        continue
    for c in rr.adapter.calls:
        reached += 1
        # INDEPENDENT CHECK, from the journal rather than from the object the
        # session returned: every call must be backed by a durable INTENT that
        # precedes it, carry the live epoch, and respect the risk cap.
        iseq = rr.adapter.intent_seq(c.client_order_id)
        intent = None
        for recd in Journal.load(rr.path).records:
            for ev in recd["events"]:
                if ev["e"] == E.INTENT.value and ev.get("client_order_id") == c.client_order_id:
                    intent = ev
        if iseq is None or c.journal_seq_at_call < iseq:
            unsafe.append(f"{kw}: adapter call preceded its INTENT")
        elif c.epoch != rr.lease.epoch:
            unsafe.append(f"{kw}: call carried a foreign epoch")
        elif intent is None or D(intent["planned_risk_usdt"]) > A1.planned_risk_usdt:
            unsafe.append(f"{kw}: planned risk {intent and intent.get('planned_risk_usdt')} > cap")
check("HOST4. 400 fuzzed requests: every action that DID reach the exchange was "
      "backed by a preceding durable intent, the live epoch, and a planned risk "
      "within the cap — checked from the journal, not from the return value",
      not unsafe, f"{reached} reached, {len(unsafe)} unsafe: {unsafe[:2]}")
check("HOST5. and no fuzzed request raised an unhandled exception", raised == 0)

shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 76)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 76)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("No hostile request produced an unsafe exchange action.")
