"""
orbit/risk/state.py — the system state handed to the gateway.

The RECONCILER owns this. The exchange is truth; this is Python's verified view
of it. The model never constructs one of these and cannot write to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import FrozenSet, Optional

from orbit.core.precision import Side
from orbit.risk.limits import RunState


@dataclass(frozen=True)
class Position:
    side: Side
    contracts: Decimal
    size_btc: Decimal
    entry_price: Decimal
    stop_price: Optional[Decimal]          # exchange-resident stop, verified
    stop_order_id: Optional[str]
    opened_at: datetime
    unrealized_pnl: Decimal = Decimal("0")


@dataclass(frozen=True)
class SystemState:
    now: datetime
    data_as_of: datetime                   # timestamp of the market snapshot
    mark_price: Decimal
    equity: Decimal
    position: Optional[Position]
    realized_pnl_utc_day: Decimal
    entries_utc_day: int
    run_state: RunState
    environment: str
    reconciled: bool                       # False => state is not trustworthy
    open_order_ids: FrozenSet[str] = frozenset()
    seen_decision_ids: FrozenSet[str] = frozenset()
    revisions_this_cycle: int = 0
    entry_in_flight: bool = False
    """True when an entry order has been submitted and has NOT reached a
    terminal outcome. Such an order occupies the single position slot even
    though the exchange still reports flat: it is neither a position nor
    nothing. Without this, two entries could be approved in the window between
    acknowledgement and fill."""

    @property
    def data_age_seconds(self) -> float:
        return (self.now - self.data_as_of).total_seconds()

    @property
    def utc_day(self) -> str:
        return self.now.astimezone(timezone.utc).strftime("%Y-%m-%d")
