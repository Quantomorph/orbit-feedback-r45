"""
tests/test_gateway_adversarial.py — FAULT INJECTION AGAINST THE RISK GATEWAY.

ORBIT-AGENT-ARCH-001, build step 3. This suite is written as an ADVERSARY. Its
job is not to show the gateway works; it is to try to get an unsafe order
through and fail to.

No model is connected. Every "decision" here is a hostile stub. If a stub can
push a bad order past the gateway, no model should ever be attached to it.

Covers the eight classes named in the A1 approval:
  malformed decisions · excessive leverage/risk · missing or widened stops ·
  duplicate orders · contradictory exchange state · stale data ·
  connection loss · repeated unsafe requests
plus the quantization layer beneath them.

Run:  python tests/test_gateway_adversarial.py
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

sys.path.insert(0, ".")

from orbit.core.precision import (BTC_USDT_SWAP as SPEC, is_on_lot, is_on_tick,
                                  quantize_limit_entry, quantize_size,
                                  quantize_stop, quantize_target)
from orbit.risk.gateway import Code, Gateway, Kind, ProposedAction
from orbit.risk.limits import A1, RunState
from orbit.risk.state import Position, SystemState

PASS, FAIL = [], []
GW = Gateway()
NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)
D = Decimal


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))
    return ok


def banner(t):
    print("\n" + "-" * 72)
    print(t)


def state(position=None, equity="1000", mark="30000", age_s=5,
          run=RunState.RUNNING, reconciled=True, entries=0, pnl="0",
          env="DEMO", seen=frozenset(), revisions=0, in_flight=False):
    return SystemState(
        now=NOW, data_as_of=NOW - timedelta(seconds=age_s),
        mark_price=D(mark), equity=D(equity), position=position,
        realized_pnl_utc_day=D(pnl), entries_utc_day=entries,
        run_state=run, environment=env, reconciled=reconciled,
        seen_decision_ids=seen, revisions_this_cycle=revisions,
        entry_in_flight=in_flight)


def pos(side="long", contracts="2.38", entry="30000", stop="29700"):
    c = D(contracts)
    return Position(side=side, contracts=c, size_btc=c * SPEC.contract_size_btc,
                    entry_price=D(entry), stop_price=D(stop),
                    stop_order_id="x1", opened_at=NOW - timedelta(minutes=30))


def opening(did="d1", side="long", stop="29700", **kw):
    return ProposedAction(decision_id=did, kind=Kind.OPEN,
                          symbol="BTC-USDT-SWAP", side=side,
                          entry_type=kw.pop("entry_type", "market"),
                          stop=D(stop) if stop is not None else None, **kw)


print("=" * 72)
print("ORBIT A1 — RISK GATEWAY FAULT INJECTION")
print("=" * 72)

# ======================================================================
banner("P — QUANTIZATION: size never rounds up, prices never add risk")
# ======================================================================
rng = random.Random(20260907)
worst_up = None
for _ in range(4000):
    req = D(str(round(rng.uniform(0.00001, 5.0), 8)))
    q = quantize_size(req)
    if q.ok and q.btc > req:
        worst_up = (req, q.btc)
        break
check("P1. floored size never exceeds the request (4,000 random sizes)",
      worst_up is None, str(worst_up or ""))

check("P2. every accepted size sits exactly on the lot step",
      all(is_on_lot(quantize_size(D(str(round(rng.uniform(0.0001, 3), 8)))).contracts)
          for _ in range(500)))

tiny = quantize_size(D("0.00009"))
check("P3. sub-minimum size is REJECTED, never bumped up to the minimum",
      (not tiny.ok) and tiny.code_is_rejection if hasattr(tiny, "code_is_rejection")
      else (not tiny.ok and tiny.contracts < SPEC.min_contracts),
      tiny.reason)

check("P4. exactly-minimum size is accepted unchanged",
      quantize_size(D("0.0001")).contracts == D("0.01"))

sl = quantize_stop(D("29700.07"), "long")
ss = quantize_stop(D("30300.07"), "short")
check("P5. long stop rounds UP (toward entry, tighter)",
      sl.price == D("29700.1"), f"{sl.requested} -> {sl.price}")
check("P6. short stop rounds DOWN (toward entry, tighter)",
      ss.price == D("30300.0"), f"{ss.requested} -> {ss.price}")

entry = D("30000")
bad = 0
for _ in range(2000):
    raw = D(str(round(rng.uniform(28000, 29999.9), 4)))
    q = quantize_stop(raw, "long")
    if q.ok and abs(entry - q.price) > abs(entry - raw) + Decimal("1e-12"):
        bad += 1
check("P7. stop rounding NEVER increases the distance from entry (2,000 draws)",
      bad == 0, f"{bad} violations")

check("P8. limit entry rounds to the passive side (long down, short up)",
      quantize_limit_entry(D("30000.07"), "long").price == D("30000.0")
      and quantize_limit_entry(D("30000.03"), "short").price == D("30000.1"))

check("P9. target rounds toward entry (claims no extra reward)",
      quantize_target(D("30500.09"), "long").price == D("30500.0")
      and quantize_target(D("29500.01"), "short").price == D("29500.1"))

check("P10. Decimal arithmetic keeps 0.1 exact where binary float would not",
      is_on_tick(D("30000.1")) and is_on_tick(D("30000.3"))
      and not is_on_tick(D("30000.05")))

# ======================================================================
banner("M — MALFORMED DECISIONS: the gateway must reject, never raise")
# ======================================================================
s = state()
cases = [
    ("empty decision_id", ProposedAction("", Kind.OPEN, "BTC-USDT-SWAP", "long", entry_type="market", stop=D("29700")), Code.MALFORMED),
    ("non-string decision_id", ProposedAction(None, Kind.OPEN, "BTC-USDT-SWAP", "long", entry_type="market", stop=D("29700")), Code.MALFORMED),
    ("unknown kind", ProposedAction("m3", "YOLO", "BTC-USDT-SWAP", "long", stop=D("29700")), Code.UNKNOWN_KIND),
    ("bad side", opening("m4", side="sideways"), Code.MALFORMED),
    ("limit entry without a price", opening("m5", entry_type="limit"), Code.MALFORMED),
    ("wrong instrument", ProposedAction("m6", Kind.OPEN, "ETH-USDT-SWAP", "long", entry_type="market", stop=D("29700")), Code.WRONG_INSTRUMENT),
    ("MODIFY_STOP without new_stop", ProposedAction("m7", Kind.MODIFY_STOP, "BTC-USDT-SWAP"), Code.NO_POSITION),
    ("REDUCE fraction 0", ProposedAction("m8", Kind.REDUCE, "BTC-USDT-SWAP", reduce_fraction=D("0")), Code.NO_POSITION),
]
for label, act, want in cases:
    v = GW.evaluate(act, s)
    check(f"M. {label} -> rejected ({want.value})",
          v.rejected and v.code is want, f"got {v.code.value}")

v = GW.evaluate(ProposedAction("m9", Kind.OPEN, "BTC-USDT-SWAP", "long",
                               stop="not-a-number"), s)
check("M. garbage type in stop -> rejected without raising", v.rejected, v.code.value)

s_pos = state(position=pos())
for label, act, want in [
    ("REDUCE fraction 0 with a position", ProposedAction("m10", Kind.REDUCE, "BTC-USDT-SWAP", reduce_fraction=D("0")), Code.INVALID_FRACTION),
    ("REDUCE fraction 1 (must use CLOSE)", ProposedAction("m11", Kind.REDUCE, "BTC-USDT-SWAP", reduce_fraction=D("1")), Code.INVALID_FRACTION),
    ("REDUCE fraction negative", ProposedAction("m12", Kind.REDUCE, "BTC-USDT-SWAP", reduce_fraction=D("-0.5")), Code.INVALID_FRACTION),
    ("MODIFY_STOP with no new_stop", ProposedAction("m13", Kind.MODIFY_STOP, "BTC-USDT-SWAP"), Code.MALFORMED),
]:
    v = GW.evaluate(act, s_pos)
    check(f"M. {label} -> {want.value}", v.rejected and v.code is want, f"got {v.code.value}")

# ======================================================================
banner("S — STOPS: missing, wrong side, widened, degenerate")
# ======================================================================
v = GW.evaluate(opening("s1", stop=None), state())
check("S1. OPEN without a stop is refused", v.rejected and v.code is Code.STOP_MISSING)

v = GW.evaluate(opening("s2", side="long", stop="30500"), state())
check("S2. long stop ABOVE entry refused", v.rejected and v.code is Code.STOP_WRONG_SIDE)
v = GW.evaluate(opening("s3", side="short", stop="29500"), state())
check("S3. short stop BELOW entry refused", v.rejected and v.code is Code.STOP_WRONG_SIDE)

# S4 CORRECTION (2026-09-07): the original expectation here was MINE and it was
# wrong. With an on-tick mark, a stop inside one tick of entry quantizes UP onto
# the entry itself, so the gateway correctly reports STOP_WRONG_SIDE rather than
# STOP_DEGENERATE. That is the better behaviour, not a defect. The degenerate
# backstop is only reachable when the mark is OFF tick, which is itself a feed
# anomaly -- so both paths are now asserted explicitly.
v = GW.evaluate(opening("s4", stop="29999.95"), state())
check("S4a. a stop inside one tick of an on-tick entry quantizes onto entry "
      "and is refused as wrong-side",
      v.rejected and v.code is Code.STOP_WRONG_SIDE, v.code.value)

v = GW.evaluate(opening("s4b", stop="29999.98"), state(mark="30000.05"))
check("S4b. with an off-tick mark, a sub-tick stop distance hits the "
      "degenerate backstop",
      v.rejected and v.code is Code.STOP_DEGENERATE, v.code.value)

widen_long = ProposedAction("s5", Kind.MODIFY_STOP, "BTC-USDT-SWAP", new_stop=D("29500"))
v = GW.evaluate(widen_long, state(position=pos("long", stop="29700")))
check("S5. widening a LONG stop refused", v.rejected and v.code is Code.STOP_WIDENED,
      v.reason[:60])

widen_short = ProposedAction("s6", Kind.MODIFY_STOP, "BTC-USDT-SWAP", new_stop=D("30500"))
v = GW.evaluate(widen_short, state(position=pos("short", entry="30000", stop="30300"),
                                   mark="30000"))
check("S6. widening a SHORT stop refused", v.rejected and v.code is Code.STOP_WIDENED)

v = GW.evaluate(ProposedAction("s7", Kind.MODIFY_STOP, "BTC-USDT-SWAP", new_stop=D("29800")),
                state(position=pos("long", stop="29700")))
check("S7. tightening a LONG stop is approved", v.approved and v.order.stop_price == D("29800"))

v = GW.evaluate(ProposedAction("s8", Kind.MODIFY_STOP, "BTC-USDT-SWAP", new_stop=D("30100")),
                state(position=pos("long", stop="29700")))
check("S8. a 'stop' already through the mark is refused, not silently executed",
      v.rejected and v.code is Code.STOP_ALREADY_TRIGGERED)

v = GW.evaluate(ProposedAction("s9", Kind.MODIFY_STOP, "BTC-USDT-SWAP", new_stop=D("29800")),
                state(position=Position("long", D("2.38"), D("0.0238"), D("30000"),
                                        None, None, NOW)))
check("S9. cannot modify a stop that Python has not verified exists",
      v.rejected and v.code is Code.STOP_MISSING)

# ======================================================================
banner("R — RISK, LEVERAGE, MARGIN: recomputed here, never trusted")
# ======================================================================
worst_risk, worst_lev, approvals = D("0"), D("0"), 0
for i in range(1, 400):
    dist_pct = D(i) / D("10000")                      # 0.01% .. 3.99%
    stop = (D("30000") * (1 - dist_pct)).quantize(D("0.1"))
    v = GW.evaluate(opening(f"r{i}", stop=str(stop)), state())
    if v.approved:
        approvals += 1
        worst_risk = max(worst_risk, v.order.planned_risk_usdt)
        worst_lev = max(worst_lev, v.order.notional_usdt / D("1000"))
check("R1. planned risk NEVER exceeds $8 across 399 stop distances",
      worst_risk <= A1.planned_risk_usdt, f"worst ${worst_risk:.6f}, {approvals} approved")
check("R2. leverage NEVER exceeds 5x across the same sweep",
      worst_lev <= A1.max_leverage, f"worst {worst_lev:.4f}x")
check("R3. the sweep actually produced approvals (the test is not vacuous)",
      approvals > 100, f"{approvals} approved")

v = GW.evaluate(opening("r4", stop="29994"), state())
check("R4. a stop tight enough to demand >5x is refused on leverage",
      v.rejected and v.code is Code.LEVERAGE_EXCEEDED, v.code.value)

v = GW.evaluate(opening("r5", stop="29700"), state(equity="0"))
check("R5. zero equity refuses to open", v.rejected and v.code is Code.NO_EQUITY)

v = GW.evaluate(opening("r6", stop="29700"), state(equity="1"))
check("R6. equity too small to fund the minimum lot is refused",
      v.rejected and v.code in (Code.LEVERAGE_EXCEEDED, Code.INSUFFICIENT_MARGIN,
                                Code.SIZE_BELOW_MINIMUM), v.code.value)

v = GW.evaluate(opening("r7", stop="29700"), state())
check("R7. approved order is on-lot, on-tick, and carries its own risk figures",
      v.approved and is_on_lot(v.order.contracts) and is_on_tick(v.order.stop_price)
      and v.order.planned_risk_usdt <= D("8"),
      f"{v.order.contracts} contracts, risk ${v.order.planned_risk_usdt:.4f}")

# ======================================================================
banner("D — DUPLICATE ORDERS")
# ======================================================================
v1 = GW.evaluate(opening("dup1", stop="29700"), state())
v2 = GW.evaluate(opening("dup1", stop="29700"), state(seen=frozenset({"dup1"})))
check("D1. first submission approved", v1.approved)
check("D2. same decision_id again is refused", v2.rejected and v2.code is Code.DUPLICATE_DECISION)
a = GW.evaluate(opening("dupA", stop="29700"), state()).order.client_order_id
b = GW.evaluate(opening("dupB", stop="29700"), state()).order.client_order_id
a2 = GW.evaluate(opening("dupA", stop="29700"), state()).order.client_order_id
check("D3. client order id is deterministic per decision and distinct across them",
      a == a2 and a != b, f"{a} / {b}")

# ======================================================================
banner("X — CONTRADICTORY / DEGRADED EXCHANGE STATE, CONNECTION LOSS")
# ======================================================================
v = GW.evaluate(opening("x1", stop="29700"), state(reconciled=False))
check("X1. unreconciled state blocks all acting decisions",
      v.rejected and v.code is Code.NOT_RECONCILED)

v = GW.evaluate(opening("x2", stop="29700"), state(run=RunState.RECONCILING))
check("X2. RECONCILING blocks acting decisions", v.rejected and v.code is Code.NOT_RECONCILED)

v = GW.evaluate(opening("x3", stop="29700"), state(run=RunState.HALTED))
check("X3. HALTED blocks OPEN", v.rejected and v.code is Code.HALTED)
v = GW.evaluate(ProposedAction("x4", Kind.CLOSE, "BTC-USDT-SWAP"),
                state(position=pos(), run=RunState.HALTED))
check("X4. HALTED blocks agent CLOSE too — Python protects, not the model",
      v.rejected and v.code is Code.HALTED)

v = GW.evaluate(opening("x5", stop="29700"), state(run=RunState.NO_NEW_ENTRY))
check("X5. NO_NEW_ENTRY blocks OPEN", v.rejected and v.code is Code.NO_NEW_ENTRY)
v = GW.evaluate(ProposedAction("x6", Kind.CLOSE, "BTC-USDT-SWAP"),
                state(position=pos(), run=RunState.NO_NEW_ENTRY))
check("X6. NO_NEW_ENTRY still permits risk-reducing CLOSE", v.approved)
v = GW.evaluate(ProposedAction("x7", Kind.MODIFY_STOP, "BTC-USDT-SWAP", new_stop=D("29800")),
                state(position=pos(), run=RunState.NO_NEW_ENTRY))
check("X7. NO_NEW_ENTRY still permits tightening a stop", v.approved)

v = GW.evaluate(opening("x8", side="long", stop="29700"), state(position=pos("long")))
check("X8. OPEN while long -> ADD_TO_POSITION refused",
      v.rejected and v.code is Code.ADD_TO_POSITION)
v = GW.evaluate(opening("x9", side="short", stop="30300"), state(position=pos("long")))
check("X9. OPEN opposite while positioned -> REVERSAL refused",
      v.rejected and v.code is Code.REVERSAL_IN_ONE_ACTION)

v = GW.evaluate(opening("x10", stop="29700"), state(entries=2))
check("X10. third entry in a UTC day refused", v.rejected and v.code is Code.ENTRY_LIMIT_REACHED)
v = GW.evaluate(opening("x11", stop="29700"), state(pnl="-20"))
check("X11. daily loss limit blocks new entries", v.rejected and v.code is Code.DAILY_LOSS_REACHED)
v = GW.evaluate(opening("x12", stop="29700"), state(pnl="-19.99"))
check("X12. just inside the daily loss limit still trades", v.approved)

# REGRESSION (defect found 2026-09-08 by the step-6 concurrency suite): the
# one-position rule was evaluated against SETTLED state only, so a second entry
# could be approved in the window between acknowledgement and fill.
v = GW.evaluate(opening("x12b", stop="29700"), state(in_flight=True))
check("X12b. an entry already IN FLIGHT holds the single position slot — a "
      "second entry is refused even though the exchange still reports flat",
      v.rejected and v.code is Code.ENTRY_IN_FLIGHT, v.code.value)

v = GW.evaluate(opening("x13", stop="29700"), state(env="LIVE"))
check("X13. a non-DEMO environment is refused outright",
      v.rejected and v.code is Code.NOT_DEMO)

# ======================================================================
banner("T — STALE DATA AND SNAPSHOT MISMATCH")
# ======================================================================
v = GW.evaluate(opening("t1", stop="29700"), state(age_s=121))
check("T1. data older than 120s blocks action", v.rejected and v.code is Code.STALE_DATA)
v = GW.evaluate(opening("t2", stop="29700"), state(age_s=119))
check("T2. data inside the freshness window is allowed", v.approved)
s = state()
act = ProposedAction("t3", Kind.OPEN, "BTC-USDT-SWAP", "long", stop=D("29700"),
                     data_as_of=NOW - timedelta(seconds=999))
check("T3. a decision citing a different snapshot than Python holds is refused",
      GW.evaluate(act, s).code is Code.DATA_MISMATCH)

# ======================================================================
banner("U — REPEATED UNSAFE REQUESTS")
# ======================================================================
v = GW.evaluate(opening("u1", stop="29700"), state(revisions=3))
check("U1. exceeding the revision budget forces a stop to the dialogue",
      v.rejected and v.code is Code.REVISION_BUDGET_EXHAUSTED)

approved_any = False
for i in range(200):
    hostile = opening(f"u{i+10}", stop="30500")        # persistently wrong side
    if GW.evaluate(hostile, state()).approved:
        approved_any = True
check("U2. 200 consecutive unsafe proposals never yield an approval", not approved_any)

# ======================================================================
banner("F — FUZZ: never raise, never approve an unsafe acting order")
# ======================================================================
kinds = list(Kind) + ["", "OPEN ", None, 7]
raised = leaked = 0
for i in range(6000):
    a = ProposedAction(
        decision_id=rng.choice(["f%d" % i, "", None, "   "]),
        kind=rng.choice(kinds),
        symbol=rng.choice(["BTC-USDT-SWAP", "ETH-USDT-SWAP", "", None]),
        side=rng.choice(["long", "short", None, "up", 1]),
        entry_type=rng.choice(["market", "limit", None, "iceberg"]),
        entry_price=rng.choice([None, D("30000"), D("-5"), "abc"]),
        stop=rng.choice([None, D("29700"), D("30500"), D("-1"), "x", D("0")]),
        target=rng.choice([None, D("30500"), "y"]),
        reduce_fraction=rng.choice([None, D("0.5"), D("5"), D("-1"), "z"]),
        new_stop=rng.choice([None, D("29800"), "w"]),
    )
    st = state(position=rng.choice([None, pos("long"), pos("short", entry="30000", stop="30300")]),
               equity=rng.choice(["1000", "0", "50"]),
               age_s=rng.choice([5, 130]),
               run=rng.choice(list(RunState)),
               reconciled=rng.choice([True, False]),
               entries=rng.choice([0, 2]), pnl=rng.choice(["0", "-25"]))
    try:
        v = GW.evaluate(a, st)
    except Exception as e:
        raised += 1
        print("   raised:", type(e).__name__, e)
        continue
    if v.approved and v.order is not None and v.order.action is Kind.OPEN:
        o = v.order
        ok = (o.planned_risk_usdt <= A1.planned_risk_usdt
              and o.contracts >= SPEC.min_contracts
              and is_on_lot(o.contracts) and o.stop_price is not None
              and is_on_tick(o.stop_price)
              and o.notional_usdt <= D(st.equity) * A1.max_leverage)
        if not ok:
            leaked += 1
check("F1. 6,000 fuzzed proposals: the gateway never raised", raised == 0, f"{raised} raised")
check("F2. 6,000 fuzzed proposals: no unsafe OPEN was ever approved", leaked == 0,
      f"{leaked} leaked")

# ======================================================================
banner("A — RISK-REDUCING ACTIONS BEHAVE CONSERVATIVELY")
# ======================================================================
v = GW.evaluate(ProposedAction("a1", Kind.REDUCE, "BTC-USDT-SWAP", reduce_fraction=D("0.5")),
                state(position=pos("long", contracts="2.38")))
check("A1. a 50% reduce rounds the CLOSED amount UP (risk-reducing direction)",
      v.approved and v.order.contracts == D("1.19"), str(v.order.contracts))

v = GW.evaluate(ProposedAction("a2", Kind.REDUCE, "BTC-USDT-SWAP", reduce_fraction=D("0.999")),
                state(position=pos("long", contracts="0.02")))
check("A2. a reduction leaving un-closable dust becomes a full close",
      v.approved and v.order.action is Kind.CLOSE and v.order.contracts == D("0.02"),
      v.reason[:70])

v = GW.evaluate(ProposedAction("a3", Kind.CLOSE, "BTC-USDT-SWAP"), state(position=pos()))
check("A3. CLOSE is reduce_only and carries zero planned risk",
      v.approved and v.order.reduce_only and v.order.planned_risk_usdt == 0)

v = GW.evaluate(ProposedAction("a4", Kind.NO_TRADE, "BTC-USDT-SWAP"), state())
check("A4. NO_TRADE is an APPROVED decision, not a rejection",
      v.approved and v.order is None)

# ======================================================================
print("\n" + "=" * 72)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 72)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    print("\nGATE CLOSED — no model may be connected to this gateway.")
    sys.exit(1)
print("The gateway rejected every hostile proposal. No model is connected yet.")
