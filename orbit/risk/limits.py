"""
orbit/risk/limits.py — THE A1 HARD LIMIT SET. FROZEN.

Approved 2026-09-07 for experiment A1. These values are the boundary the model
cannot cross. They are configuration, not code the agent can reach, and they
are never modified by memory, by a losing streak, or by confidence.

Any change is a research proposal requiring explicit human approval, per the
approved decision list.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum


class RunState(str, Enum):
    RUNNING = "RUNNING"                 # normal operation
    NO_NEW_ENTRY = "NO_NEW_ENTRY"       # degraded: risk-reducing actions only
    RECONCILING = "RECONCILING"         # state unknown; nothing but verification
    HALTED = "HALTED"                   # human must clear; Python protects


@dataclass(frozen=True)
class A1Limits:
    """Frozen for ORBIT-AGENT-DEMO-001 (A1)."""

    experiment_id: str = "ORBIT-AGENT-A1"
    environment: str = "DEMO"                        # never "LIVE" in A1
    instrument: str = "BTC-USDT-SWAP"

    # risk
    planned_risk_usdt: Decimal = Decimal("8")
    max_leverage: Decimal = Decimal("5")
    max_concurrent_positions: int = 1
    max_entries_per_utc_day: int = 2
    max_daily_loss_usdt: Decimal = Decimal("20")     # realized, UTC calendar day

    # behaviour
    require_stop: bool = True
    allow_stop_widening: bool = False
    allow_add_to_position: bool = False
    allow_reversal_in_one_action: bool = False

    # execution model assumptions (declared, not measured — ledger §20)
    slippage_bps: Decimal = Decimal("2")
    slippage_is_calibrated: bool = False

    # data freshness. Cadence is 5 minutes; a decision may not act on data
    # older than this, and Python monitors between cycles.
    cadence_seconds: int = 300
    max_data_age_seconds: int = 120

    # bounded revision: how many times the agent may re-propose in one cycle
    max_revisions_per_cycle: int = 2

    def assert_demo(self) -> None:
        if self.environment != "DEMO":
            raise RuntimeError(
                "A1 is DEMO-ONLY. Environment is set outside the model's reach "
                "and may not be changed by any tool or decision.")


A1 = A1Limits()
