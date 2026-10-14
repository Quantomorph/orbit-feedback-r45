"""
orbit/audit/information.py — WHAT DID CLAUDE KNOW WHEN IT DECIDED?

ORBIT-AGENT-ARCH-001, build step 5c. No model is connected; this is the
infrastructure that will make one auditable when it is.

The record must answer that question exactly, later, from the journal alone.
It is deliberately NOT a claim of reproducibility: it fixes the INPUTS, not the
output. Re-running the same context through the same model may produce a
different decision, and no report may say otherwise.

Every citable input becomes a REFERENCE TOKEN. A decision's `information_used`
field must contain only tokens that appear in the context recorded for its own
cycle. A claim to have seen something the tools did not provide is then a
mechanical error, not a matter of interpretation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple

from orbit.audit.records import canonical


@dataclass(frozen=True)
class SeriesRef:
    name: str                 # "candles:5m", "orderbook", "funding", "oi"
    identifier: str           # snapshot id or content hash
    as_of: str                # ISO timestamp of the newest datum
    rows: Optional[int] = None

    @property
    def token(self) -> str:
        return f"{self.name}@{self.identifier}"


@dataclass(frozen=True)
class DecisionContext:
    """Everything the model was given, and nothing it was not."""
    cycle_id: str
    decision_id: str
    market_snapshot_as_of: str
    series: Tuple[SeriesRef, ...] = ()
    account_state_id: str = ""
    position_state_id: str = ""
    open_orders_id: str = ""
    run_state: str = ""
    reconciled: bool = False
    local_state_trusted: bool = False
    memory_refs: Tuple[str, ...] = ()
    policy_version: str = ""
    model_id: str = ""
    prompt_hash: str = ""

    def refs(self) -> FrozenSet[str]:
        toks = {s.token for s in self.series}
        toks |= {f"account@{self.account_state_id}",
                 f"position@{self.position_state_id}",
                 f"open_orders@{self.open_orders_id}",
                 f"run_state@{self.run_state}",
                 f"snapshot@{self.market_snapshot_as_of}"}
        toks |= {f"memory@{m}" for m in self.memory_refs}
        return frozenset(toks)

    def context_hash(self) -> str:
        return hashlib.sha256(canonical({
            "cycle_id": self.cycle_id,
            "snapshot": self.market_snapshot_as_of,
            "series": [(s.name, s.identifier, s.as_of, s.rows) for s in self.series],
            "account": self.account_state_id,
            "position": self.position_state_id,
            "orders": self.open_orders_id,
            "run_state": self.run_state,
            "reconciled": self.reconciled,
            "local_state_trusted": self.local_state_trusted,
            "memory": list(self.memory_refs),
            "policy_version": self.policy_version,
            "model_id": self.model_id,
            "prompt_hash": self.prompt_hash,
        }).encode()).hexdigest()

    def as_event_payload(self) -> Dict:
        return {
            "cycle_id": self.cycle_id, "decision_id": self.decision_id,
            "market_snapshot_as_of": self.market_snapshot_as_of,
            "series": [{"name": s.name, "id": s.identifier,
                        "as_of": s.as_of, "rows": s.rows} for s in self.series],
            "account_state_id": self.account_state_id,
            "position_state_id": self.position_state_id,
            "open_orders_id": self.open_orders_id,
            "run_state": self.run_state, "reconciled": self.reconciled,
            "local_state_trusted": self.local_state_trusted,
            "memory_refs": list(self.memory_refs),
            "policy_version": self.policy_version,
            "model_id": self.model_id, "prompt_hash": self.prompt_hash,
            "context_hash": self.context_hash(),
            "available_refs": sorted(self.refs()),
        }


@dataclass(frozen=True)
class InformationVerdict:
    ok: bool
    unknown_refs: Tuple[str, ...]
    unused_refs: Tuple[str, ...]
    reason: str = ""


def verify_information_used(claimed: Tuple[str, ...],
                            ctx: DecisionContext) -> InformationVerdict:
    """A decision may cite only what its own cycle actually provided.

    An unknown reference is not a style problem. It means the decision claims
    to have seen something the tools did not supply — which, unchecked, is
    exactly how a confident narrative gets built on data that never existed."""
    available = ctx.refs()
    unknown = tuple(sorted(set(claimed) - available))
    unused = tuple(sorted(available - set(claimed)))
    if unknown:
        return InformationVerdict(
            False, unknown, unused,
            f"decision cites {len(unknown)} reference(s) not provided in its "
            f"own cycle: {unknown}")
    if not claimed:
        return InformationVerdict(
            False, (), unused,
            "decision cites no information at all; every decision must state "
            "what it was based on, including a decision not to trade")
    return InformationVerdict(True, (), unused)
