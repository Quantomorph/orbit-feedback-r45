"""
orbit/risk/gateway.py — THE RISK GATEWAY. THE ONLY PATH TO AN ORDER.

ORBIT-AGENT-ARCH-001, build step 2.

    CLAUDE DECIDES.  PYTHON ENFORCES.  OKX EXECUTES.

This module is the "ENFORCES". Nothing reaches the exchange except an
ExecutableOrder returned by `Gateway.evaluate()` with approved=True. The model
cannot import, configure, disable or bypass it, and it has no code path that
trusts a number the model supplied: every risk-relevant quantity is recomputed
here from exchange-verified state.

DESIGN RULE: a rounding or adjustment that would INCREASE maximum loss is a
REJECTION, never a silent fix. The gateway may make a proposal smaller, tighter
or safer; it may never make one larger, looser or riskier.

Rejections are first-class. Every rejection carries a stable machine code (for
the A1 operational metrics), a human reason, and the gateway's own computed
numbers so the agent can revise once within a bounded budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, ROUND_UP, localcontext
from enum import Enum
from typing import Any, Dict, Optional

from orbit.core.precision import (BTC_USDT_SWAP, InstrumentSpec, Side,
                                  quantize_limit_entry, quantize_size,
                                  quantize_stop, quantize_target)
from orbit.risk.modeled_loss import modeled_loss, risk_per_btc
from orbit.risk.limits import A1, A1Limits, RunState
from orbit.risk.state import Position, SystemState


# ======================================================================
# ACTIONS AND VERDICTS
# ======================================================================

class Kind(str, Enum):
    OPEN = "OPEN"
    CLOSE = "CLOSE"
    REDUCE = "REDUCE"
    MODIFY_STOP = "MODIFY_STOP"
    NO_TRADE = "NO_TRADE"
    HOLD = "HOLD"


class Code(str, Enum):
    """Stable rejection codes. A1 reports rejections grouped by these."""
    OK = "OK"
    # shape / protocol
    MALFORMED = "MALFORMED"
    UNKNOWN_KIND = "UNKNOWN_KIND"
    WRONG_INSTRUMENT = "WRONG_INSTRUMENT"
    DUPLICATE_DECISION = "DUPLICATE_DECISION"
    REVISION_BUDGET_EXHAUSTED = "REVISION_BUDGET_EXHAUSTED"
    # environment / lifecycle
    NOT_DEMO = "NOT_DEMO"
    HALTED = "HALTED"
    NO_NEW_ENTRY = "NO_NEW_ENTRY"
    NOT_RECONCILED = "NOT_RECONCILED"
    STALE_DATA = "STALE_DATA"
    # SAFETY CLOSURE ROUND 4-5, R4-5. A snapshot dated in the future is not
    # stale data; it is data that cannot be placed in time. Refusing it as
    # STALE_DATA would file the incident under the wrong diagnosis and hide a
    # broken clock or a broken adapter behind an ordinary staleness metric.
    FUTURE_DATED_DATA = "FUTURE_DATED_DATA"
    DATA_MISMATCH = "DATA_MISMATCH"
    # position / limits
    POSITION_ALREADY_OPEN = "POSITION_ALREADY_OPEN"
    ENTRY_IN_FLIGHT = "ENTRY_IN_FLIGHT"
    NO_POSITION = "NO_POSITION"
    ENTRY_LIMIT_REACHED = "ENTRY_LIMIT_REACHED"
    DAILY_LOSS_REACHED = "DAILY_LOSS_REACHED"
    # stop rules
    STOP_MISSING = "STOP_MISSING"
    STOP_WRONG_SIDE = "STOP_WRONG_SIDE"
    STOP_WIDENED = "STOP_WIDENED"
    STOP_ALREADY_TRIGGERED = "STOP_ALREADY_TRIGGERED"
    STOP_DEGENERATE = "STOP_DEGENERATE"
    # sizing / margin
    SIZE_BELOW_MINIMUM = "SIZE_BELOW_MINIMUM"
    RISK_EXCEEDED = "RISK_EXCEEDED"
    LEVERAGE_EXCEEDED = "LEVERAGE_EXCEEDED"
    INSUFFICIENT_MARGIN = "INSUFFICIENT_MARGIN"
    NO_EQUITY = "NO_EQUITY"
    # forbidden
    ADD_TO_POSITION = "ADD_TO_POSITION"
    REVERSAL_IN_ONE_ACTION = "REVERSAL_IN_ONE_ACTION"
    INVALID_FRACTION = "INVALID_FRACTION"
    # shape, validated HERE and not delegated upward (safety closure, K)
    INVALID_ENTRY_TYPE = "INVALID_ENTRY_TYPE"
    TARGET_WRONG_SIDE = "TARGET_WRONG_SIDE"
    NO_TARGET_ORDER = "NO_TARGET_ORDER"


@dataclass(frozen=True)
class ProposedAction:
    """What the model asked for. Every field is UNTRUSTED input."""
    decision_id: str
    kind: Kind
    symbol: str
    side: Optional[Side] = None
    entry_type: Optional[str] = None          # "market" | "limit"
    entry_price: Optional[Decimal] = None     # limit only
    stop: Optional[Decimal] = None
    target: Optional[Decimal] = None
    reduce_fraction: Optional[Decimal] = None
    new_stop: Optional[Decimal] = None
    data_as_of: Optional[datetime] = None


@dataclass(frozen=True)
class ExecutableOrder:
    """What Python will actually send. Every number computed here."""
    client_order_id: str
    decision_id: str
    inst_id: str
    action: Kind
    side: Optional[Side]
    contracts: Decimal
    size_btc: Decimal
    order_type: str                            # "market" | "limit"
    price: Optional[Decimal]
    stop_price: Optional[Decimal]
    target_price: Optional[Decimal]
    planned_risk_usdt: Decimal
    notional_usdt: Decimal
    required_margin_usdt: Decimal
    reduce_only: bool = False
    role: str = "ENTRY"
    """SAFETY CLOSURE, blocker B. ENTRY / EXIT / PROTECTIVE / ADMIN. Carried so
    the exchange boundary can check that the role and reduce_only agree instead
    of trusting whoever called it."""
    target_client_order_id: Optional[str] = None
    """SAFETY CLOSURE, blocker J. For a mutation ADDRESSED TO an order that
    already rests on the exchange, this is that order. `client_order_id` above
    is the identity of the mutation itself. They are never the same."""


@dataclass(frozen=True)
class Verdict:
    approved: bool
    code: Code
    reason: str
    order: Optional[ExecutableOrder] = None
    computed: Dict[str, Any] = field(default_factory=dict)

    @property
    def rejected(self) -> bool:
        return not self.approved


def _reject(code: Code, reason: str, **computed) -> Verdict:
    return Verdict(False, code, reason, None, computed)


def _d(x) -> Optional[Decimal]:
    if x is None:
        return None
    if isinstance(x, Decimal):
        return x
    if isinstance(x, float):
        return Decimal(repr(x))
    return Decimal(str(x))


# ======================================================================
# THE GATEWAY
# ======================================================================

class Gateway:
    def __init__(self, limits: A1Limits = A1,
                 spec: InstrumentSpec = BTC_USDT_SWAP):
        self.limits = limits
        self.spec = spec
        self.limits.assert_demo()

    # ------------------------------------------------------------------
    def evaluate(self, action: ProposedAction, state: SystemState) -> Verdict:
        """The single entry point. Order of checks is deliberate: cheapest and
        most categorical first, so a rejection reason is never ambiguous."""
        try:
            return self._evaluate(action, state)
        except Exception as e:                      # never leak an exception
            return _reject(Code.MALFORMED,
                           f"gateway could not interpret the proposal: "
                           f"{type(e).__name__}: {e}")

    # ------------------------------------------------------------------
    def _evaluate(self, a: ProposedAction, s: SystemState) -> Verdict:
        # ---- 0. protocol shape -------------------------------------
        if not isinstance(a.decision_id, str) or not a.decision_id.strip():
            return _reject(Code.MALFORMED, "decision_id is missing or empty")
        try:
            kind = Kind(a.kind)
        except ValueError:
            return _reject(Code.UNKNOWN_KIND, f"unknown decision kind {a.kind!r}")

        # ---- 1. environment ----------------------------------------
        if s.environment != self.limits.environment:
            return _reject(Code.NOT_DEMO,
                           f"environment is {s.environment!r}; A1 permits only "
                           f"{self.limits.environment!r}")

        # ---- 2. idempotency ----------------------------------------
        if a.decision_id in s.seen_decision_ids:
            return _reject(Code.DUPLICATE_DECISION,
                           f"decision_id {a.decision_id} has already been "
                           f"acted upon; refusing to double-submit")

        # ---- 3. non-acting decisions are always valid --------------
        if kind in (Kind.NO_TRADE, Kind.HOLD):
            return Verdict(True, Code.OK, f"{kind.value} recorded", None,
                           {"acting": False})

        # ---- 4. lifecycle ------------------------------------------
        if s.run_state is RunState.HALTED:
            return _reject(Code.HALTED,
                           "system is HALTED; Python protects existing "
                           "positions and a human must clear the halt")
        if s.run_state is RunState.RECONCILING or not s.reconciled:
            return _reject(Code.NOT_RECONCILED,
                           "state is not reconciled against the exchange; "
                           "no action may be taken on an unverified view")
        if s.run_state is RunState.NO_NEW_ENTRY and kind is Kind.OPEN:
            return _reject(Code.NO_NEW_ENTRY,
                           "degraded state permits only risk-reducing actions")

        # ---- 5. instrument -----------------------------------------
        if a.symbol != self.limits.instrument:
            return _reject(Code.WRONG_INSTRUMENT,
                           f"{a.symbol!r} is not the A1 instrument "
                           f"{self.limits.instrument!r}")

        # ---- 6. data freshness -------------------------------------
        # SAFETY CLOSURE ROUND 4-5, R4-5. The gateway owns this decision
        # INDEPENDENTLY of the reconciler — that redundancy is deliberate, and
        # it is why the one-sided comparison mattered here as well as there.
        # `age > max_data_age_seconds` is false for every negative age, so a
        # SystemState whose `data_as_of` lies in the future passed this gate
        # however absurd the timestamp was. The gateway now refuses it in its
        # own right, under its own code, and does NOT clamp: a snapshot from
        # the future is refused as impossible, not re-labelled as fresh.
        age = s.data_age_seconds
        if age < 0:
            return _reject(Code.FUTURE_DATED_DATA,
                           f"market snapshot is dated {-age:.6f}s in the "
                           f"future (data_as_of={s.data_as_of}, now={s.now}); "
                           f"an observation from a moment that has not "
                           f"occurred authorises nothing",
                           data_age_seconds=age)
        if age > self.limits.max_data_age_seconds:
            return _reject(Code.STALE_DATA,
                           f"market snapshot is {age:.0f}s old; limit is "
                           f"{self.limits.max_data_age_seconds}s",
                           data_age_seconds=age)
        if a.data_as_of is not None and a.data_as_of != s.data_as_of:
            return _reject(Code.DATA_MISMATCH,
                           "the decision cites a snapshot that is not the one "
                           "Python holds; the decision is not evaluable",
                           decision_as_of=str(a.data_as_of),
                           state_as_of=str(s.data_as_of))

        # ---- 7. revision budget ------------------------------------
        if s.revisions_this_cycle > self.limits.max_revisions_per_cycle:
            return _reject(Code.REVISION_BUDGET_EXHAUSTED,
                           f"more than {self.limits.max_revisions_per_cycle} "
                           f"revisions in one cycle; forcing NO_TRADE")

        # ---- 8. dispatch -------------------------------------------
        if kind is Kind.OPEN:
            return self._open(a, s)
        if kind is Kind.CLOSE:
            return self._close(a, s)
        if kind is Kind.REDUCE:
            return self._reduce(a, s)
        if kind is Kind.MODIFY_STOP:
            return self._modify_stop(a, s)
        return _reject(Code.UNKNOWN_KIND, f"unhandled kind {kind}")

    # ==================================================================
    # OPEN
    # ==================================================================
    def _open(self, a: ProposedAction, s: SystemState) -> Verdict:
        L, spec = self.limits, self.spec

        if a.side not in ("long", "short"):
            return _reject(Code.MALFORMED, f"side must be long or short, got {a.side!r}")

        # one position at a time; and an OPEN while positioned is either an
        # add or a reversal, both forbidden — distinguished for the metrics.
        if s.position is not None:
            if s.position.side == a.side:
                return _reject(Code.ADD_TO_POSITION,
                               "a position is already open in this direction; "
                               "adding is forbidden in A1")
            return _reject(Code.REVERSAL_IN_ONE_ACTION,
                           "reversing in one action is forbidden; CLOSE first, "
                           "then OPEN on a later cycle")

        if s.entry_in_flight:
            return _reject(Code.ENTRY_IN_FLIGHT,
                           "an entry order is already in flight and has not "
                           "reached a terminal outcome; it holds the single "
                           "position slot until it fills, fails or is cancelled")

        if s.entries_utc_day >= L.max_entries_per_utc_day:
            return _reject(Code.ENTRY_LIMIT_REACHED,
                           f"{s.entries_utc_day} entries already today; limit "
                           f"is {L.max_entries_per_utc_day} per UTC day",
                           entries_utc_day=s.entries_utc_day)

        if s.realized_pnl_utc_day <= -L.max_daily_loss_usdt:
            return _reject(Code.DAILY_LOSS_REACHED,
                           f"realized P&L today {s.realized_pnl_utc_day} has "
                           f"reached the {L.max_daily_loss_usdt} daily loss limit",
                           realized_pnl_utc_day=str(s.realized_pnl_utc_day))

        if s.equity <= 0:
            return _reject(Code.NO_EQUITY, "equity is not positive")

        # --- stop is mandatory and must be on the correct side ---------
        if a.stop is None:
            return _reject(Code.STOP_MISSING,
                           "every position must have a defined maximum-loss "
                           "boundary before execution")
        stop_q = quantize_stop(_d(a.stop), a.side, spec)
        if not stop_q.ok:
            return _reject(Code.STOP_DEGENERATE, stop_q.reason)

        # --- entry_type is an ENUM and this is where it is enforced --------
        # It was previously validated only in the session's schema check. The
        # gateway is the last deterministic authority before the exchange; it
        # does not delegate its own input validation to the layer above it.
        if a.entry_type not in ("market", "limit"):
            return _reject(Code.INVALID_ENTRY_TYPE,
                           f"entry_type must be exactly 'market' or 'limit'; "
                           f"got {a.entry_type!r}. An unrecognised value is "
                           f"never silently treated as a market order.")

        # reference entry price: the limit price if given, else the mark
        if a.entry_type == "limit":
            if a.entry_price is None:
                return _reject(Code.MALFORMED, "limit entry requires entry_price")
            ent_q = quantize_limit_entry(_d(a.entry_price), a.side, spec)
            if not ent_q.ok:
                return _reject(Code.MALFORMED, ent_q.reason)
            ref = ent_q.price
            order_type, price = "limit", ent_q.price
        else:
            ref = s.mark_price
            order_type, price = "market", None

        if a.side == "long" and stop_q.price >= ref:
            return _reject(Code.STOP_WRONG_SIDE,
                           f"long stop {stop_q.price} is not below entry {ref}")
        if a.side == "short" and stop_q.price <= ref:
            return _reject(Code.STOP_WRONG_SIDE,
                           f"short stop {stop_q.price} is not above entry {ref}")

        stop_distance = abs(ref - stop_q.price)
        if stop_distance < spec.tick_size:
            return _reject(Code.STOP_DEGENERATE,
                           f"stop distance {stop_distance} is below one tick "
                           f"{spec.tick_size}")

        # --- risk per unit, recomputed here, never taken from the model -
        # SAFETY CLOSURE ROUND 2, N3: the formula lives in exactly one place.
        # It used to be written out here and NOT written out in the reconciler,
        # so the two sides of the same $8 policy answered different questions.
        risk_per_unit = risk_per_btc(ref, stop_q.price, spec, self.limits)
        if risk_per_unit <= 0:
            return _reject(Code.STOP_DEGENERATE, "risk per unit is not positive")
        with localcontext() as ctx:
            ctx.prec = 40
            raw_btc = L.planned_risk_usdt / risk_per_unit

        size = quantize_size(raw_btc, spec)
        if not size.ok:
            return _reject(Code.SIZE_BELOW_MINIMUM, size.reason,
                           requested_btc=str(size.requested_btc),
                           executable_contracts=str(size.contracts),
                           risk_per_unit=str(risk_per_unit))

        modelled = modeled_loss(ref, stop_q.price, size.btc, spec, self.limits)
        planned_risk = modelled.total_usdt
        with localcontext() as ctx:
            ctx.prec = 40
            notional = size.btc * ref
            required_margin = notional / L.max_leverage

        # quantizing DOWN can only reduce planned risk; assert, do not trust
        if planned_risk > L.planned_risk_usdt:
            return _reject(Code.RISK_EXCEEDED,
                           f"planned risk {planned_risk} exceeds the "
                           f"{L.planned_risk_usdt} per-trade cap",
                           planned_risk=str(planned_risk))

        if notional > s.equity * L.max_leverage:
            return _reject(Code.LEVERAGE_EXCEEDED,
                           f"notional {notional} exceeds {L.max_leverage}x of "
                           f"equity {s.equity}",
                           notional=str(notional), equity=str(s.equity))
        if required_margin > s.equity:
            return _reject(Code.INSUFFICIENT_MARGIN,
                           f"required margin {required_margin} exceeds equity "
                           f"{s.equity}")

        # --- a target is either VALID or REJECTED, never silently discarded -
        # Dropping a nonsensical take-profit let a decision execute as though it
        # had none, which is not what the decision said.
        target_price = None
        if a.target is not None:
            tq = quantize_target(_d(a.target), a.side, spec)
            if not tq.ok:
                return _reject(Code.MALFORMED, tq.reason)
            wrong = ((tq.price <= ref) if a.side == "long"
                     else (tq.price >= ref))
            if wrong:
                return _reject(
                    Code.TARGET_WRONG_SIDE,
                    f"a {a.side} target must be beyond the entry: target "
                    f"{tq.price} against entry {ref}. It is rejected, not "
                    f"discarded — executing without the take-profit the "
                    f"decision named would not be the decision.",
                    target=str(tq.price), entry=str(ref))
            target_price = tq.price

        order = ExecutableOrder(
            client_order_id=client_id(a.decision_id),
            decision_id=a.decision_id,
            inst_id=spec.inst_id,
            action=Kind.OPEN,
            side=a.side,
            contracts=size.contracts,
            size_btc=size.btc,
            order_type=order_type,
            price=price,
            stop_price=stop_q.price,
            target_price=target_price,
            planned_risk_usdt=planned_risk,
            notional_usdt=notional,
            required_margin_usdt=required_margin,
            reduce_only=False,
            role="ENTRY",
        )
        return Verdict(True, Code.OK, "approved", order, {
            "risk_per_unit": str(risk_per_unit),
            "stop_distance": str(stop_distance),
            "requested_btc": str(size.requested_btc),
            "executable_btc": str(size.btc),
            "discarded_btc": str(size.discarded_btc),
            "stop_moved_by": str(stop_q.moved),
            "planned_risk_usdt": str(planned_risk),
            "modelled_price_risk": str(modelled.price_risk_usdt),
            "modelled_entry_fee": str(modelled.entry_fee_usdt),
            "modelled_exit_fee": str(modelled.exit_fee_usdt),
            "modelled_stop_slippage": str(modelled.slippage_usdt),
            "notional_usdt": str(notional),
            "leverage": str(notional / s.equity) if s.equity else None,
            "planned_risk_is_not_a_guaranteed_loss": True,
        })

    # ==================================================================
    # CLOSE / REDUCE / MODIFY_STOP  — risk-reducing actions
    # ==================================================================
    def _close(self, a: ProposedAction, s: SystemState) -> Verdict:
        if s.position is None:
            return _reject(Code.NO_POSITION, "no position to close")
        p = s.position
        order = ExecutableOrder(
            client_order_id=client_id(a.decision_id),
            decision_id=a.decision_id, inst_id=self.spec.inst_id,
            action=Kind.CLOSE,
            side="short" if p.side == "long" else "long",
            contracts=p.contracts, size_btc=p.size_btc,
            order_type="market", price=None,
            stop_price=None, target_price=None,
            planned_risk_usdt=Decimal("0"),
            notional_usdt=p.size_btc * s.mark_price,
            required_margin_usdt=Decimal("0"),
            reduce_only=True,
            role="EXIT",
        )
        return Verdict(True, Code.OK, "full close approved", order,
                       {"closing_contracts": str(p.contracts)})

    def _reduce(self, a: ProposedAction, s: SystemState) -> Verdict:
        if s.position is None:
            return _reject(Code.NO_POSITION, "no position to reduce")
        f = _d(a.reduce_fraction)
        if f is None or f <= 0 or f >= 1:
            return _reject(Code.INVALID_FRACTION,
                           "reduce_fraction must be strictly between 0 and 1; "
                           "use CLOSE for a full exit")
        p, spec = s.position, self.spec
        with localcontext() as ctx:
            ctx.prec = 40
            want = p.contracts * f
            steps = (want / spec.lot_step_contracts).to_integral_value(ROUND_UP)
            close_c = min(steps * spec.lot_step_contracts, p.contracts)
            remaining = p.contracts - close_c

        # Never leave dust that cannot itself be closed.
        if Decimal("0") < remaining < spec.min_contracts:
            close_c, remaining = p.contracts, Decimal("0")

        if close_c <= 0:
            return _reject(Code.SIZE_BELOW_MINIMUM,
                           "the reduction rounds to zero contracts")

        order = ExecutableOrder(
            client_order_id=client_id(a.decision_id),
            decision_id=a.decision_id, inst_id=spec.inst_id,
            action=Kind.CLOSE if remaining == 0 else Kind.REDUCE,
            side="short" if p.side == "long" else "long",
            contracts=close_c, size_btc=close_c * spec.contract_size_btc,
            order_type="market", price=None,
            stop_price=None, target_price=None,
            planned_risk_usdt=Decimal("0"),
            notional_usdt=close_c * spec.contract_size_btc * s.mark_price,
            required_margin_usdt=Decimal("0"),
            reduce_only=True,
            role="EXIT",
        )
        return Verdict(True, Code.OK,
                       "reduction approved" + (" (became a full close: the "
                       "remainder would be below the exchange minimum)"
                       if remaining == 0 and f < 1 else ""),
                       order,
                       {"requested_fraction": str(f),
                        "closing_contracts": str(close_c),
                        "remaining_contracts": str(remaining),
                        "rounded_up_to_reduce_risk": True})

    def _modify_stop(self, a: ProposedAction, s: SystemState) -> Verdict:
        if s.position is None:
            return _reject(Code.NO_POSITION, "no position whose stop could move")
        p = s.position
        if a.new_stop is None:
            return _reject(Code.MALFORMED, "MODIFY_STOP requires new_stop")
        if p.stop_price is None:
            return _reject(Code.STOP_MISSING,
                           "the open position has no verified stop; Python "
                           "must restore protection before any modification")
        if not p.stop_order_id:
            return _reject(Code.NO_TARGET_ORDER,
                           "the resting stop has no known client order id, so "
                           "there is no order this amendment could be "
                           "addressed to; protection must be re-established "
                           "rather than an identity invented")

        q = quantize_stop(_d(a.new_stop), p.side, self.spec)
        if not q.ok:
            return _reject(Code.STOP_DEGENERATE, q.reason)
        new = q.price

        tighter = (new > p.stop_price) if p.side == "long" else (new < p.stop_price)
        if not tighter:
            return _reject(Code.STOP_WIDENED,
                           f"{p.side} stop may only move closer to entry: "
                           f"current {p.stop_price}, requested {new}. Widening "
                           f"increases maximum loss and is forbidden in A1.",
                           current_stop=str(p.stop_price), requested=str(new))

        through = (new >= s.mark_price) if p.side == "long" else (new <= s.mark_price)
        if through:
            return _reject(Code.STOP_ALREADY_TRIGGERED,
                           f"the requested stop {new} is already through the "
                           f"mark {s.mark_price}; that is an exit, not a stop "
                           f"move — use CLOSE so the intent is explicit")

        order = ExecutableOrder(
            client_order_id=client_id(a.decision_id),
            decision_id=a.decision_id, inst_id=self.spec.inst_id,
            action=Kind.MODIFY_STOP, side=p.side,
            contracts=p.contracts, size_btc=p.size_btc,
            order_type="stop", price=None,
            stop_price=new, target_price=None,
            planned_risk_usdt=modeled_loss(p.entry_price, new, p.size_btc,
                                           self.spec, self.limits).total_usdt,
            notional_usdt=p.size_btc * s.mark_price,
            required_margin_usdt=Decimal("0"),
            reduce_only=True,
            role="ADMIN",
            target_client_order_id=p.stop_order_id,
        )
        return Verdict(True, Code.OK, "stop tightened", order,
                       {"old_stop": str(p.stop_price), "new_stop": str(new),
                        "moved_toward_entry_by": str(abs(new - p.stop_price))})


# ======================================================================
def client_id(decision_id: str) -> str:
    """Deterministic client order id => the exchange itself rejects a
    double-submission of the same decision, independently of our own
    idempotency check. Belt and braces, because these are different failures:
    ours catches a re-proposal, the exchange's catches a retry."""
    import hashlib
    h = hashlib.sha256(decision_id.encode()).hexdigest()[:24]
    return f"orbitA1{h}"
