"""
orbit/exec/fees.py — ONE DURABLE MEANING FOR A FILL'S FEE.

SAFETY CLOSURE ROUND 4C4, checkpoint A.1, review finding 1.

WHAT THIS EXISTS TO PREVENT.

Checkpoint A read a `fee` field off a FILL record and treated a NEGATIVE value
as a rebate, clamping it to zero. OKX documents the opposite convention:

    fee < 0   a transaction fee was CHARGED
    fee > 0   a REBATE was received

So a raw OKX fill written into the journal under Checkpoint A's semantics would
have had every charged fee read as a rebate and discarded — the realized daily
loss would have been UNDERSTATED by exactly the fees paid, and the daily-loss
limit would have been reached later than the policy says.

The defect is not the sign of one comparison. It is that a single signed number
named "fee" has NO fixed meaning: two venues, or two versions of one adapter,
can disagree about what the sign says, and nothing in the journal records which
convention was in force. A durable record must not carry a value whose meaning
depends on who wrote it.

THE DESIGN. Three things that were one number are now three fields, and the
fold that authorises mutations consumes exactly one of them:

    venue_fee_raw   the venue's exact string, sign and all, AUDIT ONLY. Never
                    read by any safety computation.
    fee_cost_usdt   the NORMALIZED economic cost of the fill: a NON-NEGATIVE
                    USDT amount that REDUCES realized P&L. This is the only
                    fee field `daily_accounting` reads.
    rebate_usdt     a NON-NEGATIVE USDT credit the venue paid. Recorded so
                    the audit is complete. NOT applied to the daily-loss
                    figure: a rebate ORBIT's policy has not modelled must not
                    make the loss limit less conservative. If a future policy
                    wants rebates counted, that is a change to `A1Limits` and
                    to this module, reviewed as such — not a sign flip.

The legacy field `fee` is REJECTED by the fold: its meaning was ambiguous, so
a record carrying it cannot be accounted (LocalStateUndecidable), and the
recorder refuses to write it.

WHERE FUTURE INGESTION MUST NORMALIZE. The OKX adapter does not exist yet.
When it does, the ONLY place a venue fee may enter the journal is
`CycleRecorder.record_fill_group(..., fee=FillFee)`, and the ONLY way to build
a `FillFee` from an OKX fill is `normalize_okx_fee(raw)` below, applied to the
`fee` field of the OKX fill (`/api/v5/trade/fills`, `fillFee` on the order
channel — verify against the live API before use; this is the DOCUMENTED
convention, not one ORBIT has observed). Fee CURRENCY (`feeCcy`) must be
USDT for a linear USDT swap; a fee denominated in anything else must be
converted by the adapter before it reaches here, or refused. This module does
not convert currencies and does not guess.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

# The durable field names, so nobody spells them twice.
FEE_COST_FIELD = "fee_cost_usdt"
REBATE_FIELD = "rebate_usdt"
VENUE_RAW_FIELD = "venue_fee_raw"
FEE_VENUE_FIELD = "fee_venue"
LEGACY_AMBIGUOUS_FEE_FIELD = "fee"


class FeeUnreadable(ValueError):
    """A venue fee that cannot be normalized. Fails closed at ingestion."""


@dataclass(frozen=True)
class FillFee:
    """The normalized economics of one fill. Both amounts are >= 0."""
    fee_cost_usdt: Decimal
    rebate_usdt: Decimal
    venue_fee_raw: Optional[str]
    fee_venue: str

    def __post_init__(self):
        for name in ("fee_cost_usdt", "rebate_usdt"):
            v = getattr(self, name)
            if not isinstance(v, Decimal) or not v.is_finite() or v < 0:
                raise FeeUnreadable(
                    f"{name} must be a finite non-negative Decimal, got {v!r}")
        if self.fee_cost_usdt > 0 and self.rebate_usdt > 0:
            raise FeeUnreadable(
                "a fill is either charged or rebated, not both; a venue that "
                "reports both must be normalized by its adapter first")

    def as_event_fields(self) -> dict:
        """Exactly the keys written into the FILL event."""
        return {FEE_COST_FIELD: str(self.fee_cost_usdt),
                REBATE_FIELD: str(self.rebate_usdt),
                VENUE_RAW_FIELD: self.venue_fee_raw,
                FEE_VENUE_FIELD: self.fee_venue}


def _dec(raw: Any) -> Decimal:
    try:
        v = Decimal(str(raw))
    except (InvalidOperation, ValueError, TypeError):
        raise FeeUnreadable(f"venue fee {raw!r} is not a number")
    if not v.is_finite():
        raise FeeUnreadable(f"venue fee {raw!r} is not finite")
    return v


def normalize_okx_fee(raw: Any) -> FillFee:
    """OKX convention: negative = charged, positive = rebate, zero = none.

    The raw string is preserved verbatim for audit. The sign is consumed HERE
    and nowhere else.
    """
    if raw is None:
        raise FeeUnreadable("OKX fill carries no fee field; a fill whose fee is "
                            "unknown is not a zero-fee fill")
    v = _dec(raw)
    if v < 0:
        return FillFee(-v, Decimal("0"), str(raw), "okx")
    if v > 0:
        return FillFee(Decimal("0"), v, str(raw), "okx")
    return FillFee(Decimal("0"), Decimal("0"), str(raw), "okx")


def zero_fee(venue: str = "none") -> FillFee:
    """An explicit, recorded zero. Used by fixtures; never a default."""
    return FillFee(Decimal("0"), Decimal("0"), "0", venue)
