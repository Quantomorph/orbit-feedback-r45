"""
orbit/risk/modeled_loss.py — THE ONE DEFINITION OF "WHAT THIS TRADE CAN COST".

ORBIT A1 SAFETY CLOSURE ROUND 2, finding N3.

THE DEFECT THIS EXISTS TO PREVENT.

The gateway sized every entry against

    stop distance + entry taker fee + exit taker fee + modelled stop slippage

and refused anything above the $8 cap. The reconciler's post-fill overrun check
then used

    abs(actual_entry - stop) * size_btc

— price distance alone. Two different economic definitions were compared to the
same number. A fill whose modelled loss was 8.108483166 under the gateway's own
definition reported 7.25662, cleared the cap, and stayed RUNNING.

That is not a rounding disagreement. It is the system holding two incompatible
opinions about the only quantity the whole risk policy is written in terms of,
and preferring whichever one happened to be in scope.

There is now ONE function. The gateway sizes with it; the reconciler re-checks
with it. Neither carries a copy.

WHAT THE NUMBER IS, AND IS NOT.

`total_usdt` is a MODELLED loss: what this position costs to close at its stop,
assuming the stop fills at the stop price plus the modelled slippage allowance.
It is NOT a guaranteed maximum. A gap fills at the next available price, and no
arithmetic here bounds that.

The components are kept separate on purpose, because they are known to different
degrees and at different times:

    price_risk_usdt   the distance to the stop. Known exactly once filled.
    entry_fee_usdt    modelled before the fill; REPLACED by the actual charge
                      once the exchange reports it.
    exit_fee_usdt     always modelled: the exit has not happened.
    slippage_usdt     always modelled: it is an allowance for a future
                      execution, never an observation.

`entry_fee_is_actual` / `exit_fee_is_actual` say which is which, so a report can
never present a modelled number as a realised one.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from typing import Optional

D = Decimal

# Every calculation here runs at this precision, in this order, in one place.
# When the gateway and the reconciler ask the same question they get the same
# digits — not merely the same formula written out twice.
PRECISION = 40


@dataclass(frozen=True)
class ModeledLoss:
    entry_price: Decimal
    stop_price: Decimal
    size_btc: Decimal

    price_risk_usdt: Decimal
    entry_fee_usdt: Decimal
    exit_fee_usdt: Decimal
    slippage_usdt: Decimal
    total_usdt: Decimal
    per_btc_usdt: Decimal

    entry_fee_is_actual: bool = False
    exit_fee_is_actual: bool = False

    @property
    def realised_usdt(self) -> Decimal:
        """The part of the number that is not a model."""
        out = self.price_risk_usdt
        if self.entry_fee_is_actual:
            out += self.entry_fee_usdt
        if self.exit_fee_is_actual:
            out += self.exit_fee_usdt
        return out

    @property
    def still_modelled_usdt(self) -> Decimal:
        return self.total_usdt - self.realised_usdt

    def describe(self) -> str:
        return (
            f"modelled loss at the stop: ${self.total_usdt}\n"
            f"  price risk        ${self.price_risk_usdt}\n"
            f"  entry fee         ${self.entry_fee_usdt}"
            f"{' (actual)' if self.entry_fee_is_actual else ' (modelled)'}\n"
            f"  exit fee          ${self.exit_fee_usdt}"
            f"{' (actual)' if self.exit_fee_is_actual else ' (modelled)'}\n"
            f"  stop slippage     ${self.slippage_usdt} (modelled allowance)\n"
            "this is a modelled figure, NOT a guaranteed maximum loss; a gap "
            "fills at the next available price."
        )


def risk_per_btc(entry_price: Decimal, stop_price: Decimal, spec,
                 limits) -> Decimal:
    """Modelled loss for ONE BTC of exposure.

    This is the sizing form: the gateway divides the risk budget by it to get
    the largest position the policy allows. `modeled_loss` below is the same
    quantity multiplied out, which is the checking form."""
    with localcontext() as ctx:
        ctx.prec = PRECISION
        distance = abs(entry_price - stop_price)
        entry_fee = spec.taker_fee * entry_price
        exit_fee = spec.taker_fee * stop_price
        slippage = limits.slippage_bps / D("10000") * stop_price
        return distance + entry_fee + exit_fee + slippage


def modeled_loss(entry_price: Decimal, stop_price: Decimal, size_btc: Decimal,
                 spec, limits, *,
                 actual_entry_fee_usdt: Optional[Decimal] = None,
                 actual_exit_fee_usdt: Optional[Decimal] = None) -> ModeledLoss:
    """The checking form, broken into its parts.

    Pass `actual_entry_fee_usdt` once the exchange has reported what the entry
    actually cost: the modelled estimate is then replaced rather than added to,
    and the result records that this component is no longer a model."""
    with localcontext() as ctx:
        ctx.prec = PRECISION
        price_risk = abs(entry_price - stop_price) * size_btc

        entry_fee_is_actual = actual_entry_fee_usdt is not None
        entry_fee = (actual_entry_fee_usdt if entry_fee_is_actual
                     else spec.taker_fee * entry_price * size_btc)

        exit_fee_is_actual = actual_exit_fee_usdt is not None
        exit_fee = (actual_exit_fee_usdt if exit_fee_is_actual
                    else spec.taker_fee * stop_price * size_btc)

        slippage = limits.slippage_bps / D("10000") * stop_price * size_btc

        total = price_risk + entry_fee + exit_fee + slippage
        per_btc = total / size_btc if size_btc else D("0")

    return ModeledLoss(
        entry_price=entry_price, stop_price=stop_price, size_btc=size_btc,
        price_risk_usdt=price_risk, entry_fee_usdt=entry_fee,
        exit_fee_usdt=exit_fee, slippage_usdt=slippage, total_usdt=total,
        per_btc_usdt=per_btc,
        entry_fee_is_actual=entry_fee_is_actual,
        exit_fee_is_actual=exit_fee_is_actual)
