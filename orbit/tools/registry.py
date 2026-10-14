"""
orbit/tools/registry.py — THE CAPABILITY MODEL.

ORBIT-AGENT-ARCH-001, step 6A. The complete list of what the model may ever
ask for. Anything not named here does not exist as a capability.

The distinction that matters is not "safe vs dangerous tool" — it is that READ
tools observe and ACTION tools request. No tool executes. Every action is a
PROPOSAL that deterministic Python may refuse.

`FORBIDDEN_SHAPES` is not documentation. A test enumerates the live session's
public surface and fails if any attribute matches one of these shapes, so a
generic escape hatch cannot be added later without the suite going red.
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet


class Capability(str, Enum):
    READ = "READ"
    ACTION = "ACTION"


READ_TOOLS: FrozenSet[str] = frozenset({
    "get_market_state", "get_candles", "get_orderbook", "get_funding",
    "get_open_interest", "get_account_state", "get_positions",
    "get_open_orders", "get_recent_fills", "get_recent_trades",
    "get_system_state", "get_current_risk_state",
})

ACTION_TOOLS: FrozenSet[str] = frozenset({
    "propose_order", "cancel_order", "close_position", "reduce_position",
    "modify_stop",
})

ALL_TOOLS: FrozenSet[str] = READ_TOOLS | ACTION_TOOLS

# Substrings that must never appear in a public tool name. These are the shapes
# of an unrestricted primitive: a way to reach the exchange, the credentials,
# the writer, or the risk limits without passing the gateway.
FORBIDDEN_SHAPES = (
    "raw", "arbitrary", "execute_", "send_to_exchange", "place_any",
    "okx_request", "http", "request_url", "endpoint", "credential", "secret",
    "api_key", "passphrase", "set_limit", "override", "force_", "bypass",
    "acquire_writer", "release_writer", "set_run_state", "set_epoch",
    "sql", "eval", "exec_",
)


def capability_of(name: str) -> Capability:
    if name in READ_TOOLS:
        return Capability.READ
    if name in ACTION_TOOLS:
        return Capability.ACTION
    raise KeyError(f"{name!r} is not a capability ORBIT grants")
