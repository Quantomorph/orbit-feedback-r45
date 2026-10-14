"""
orbit/audit/records.py — THE JOURNAL RECORD SCHEMA.

ORBIT-AGENT-ARCH-001, build step 5a.

One physical journal record may carry SEVERAL logical events. That is how
atomicity is achieved without a database: a group that must not be observed
half-applied (fill + position + counters) is written as one record, committed by
one append and one fsync. A crash either loses the whole group or none of it.

Every record is chained: hash = sha256(prev_hash || canonical(body)). A record
cannot be altered, and history cannot be silently rewritten, without breaking
every hash after it. This is tamper-EVIDENT, not tamper-proof: it detects
rewriting, it does not prevent it.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64


class E(str, Enum):
    """Logical event types."""
    # lifecycle
    RUN_START = "RUN_START"
    RUN_STATE_TRANSITION = "RUN_STATE_TRANSITION"
    SHUTDOWN_BEGIN = "SHUTDOWN_BEGIN"
    CLEAN_SHUTDOWN = "CLEAN_SHUTDOWN"
    RECOVERY_BEGIN = "RECOVERY_BEGIN"
    RECOVERY_COMPLETE = "RECOVERY_COMPLETE"

    # decision path
    CYCLE_OPEN = "CYCLE_OPEN"
    INFORMATION_USED = "INFORMATION_USED"
    DECISION_INPUT = "DECISION_INPUT"
    DECISION_INPUT_CONFLICT = "DECISION_INPUT_CONFLICT"
    DECISION_PROPOSED = "DECISION_PROPOSED"
    GATEWAY_VERDICT = "GATEWAY_VERDICT"

    # WRITE-AHEAD: this is committed BEFORE the exchange is touched
    INTENT = "INTENT"

    # exchange interaction
    SUBMIT_ATTEMPTED = "SUBMIT_ATTEMPTED"
    SUBMIT_ACK = "SUBMIT_ACK"
    SUBMIT_FAILED = "SUBMIT_FAILED"
    SUBMIT_UNKNOWN = "SUBMIT_UNKNOWN"
    FILL = "FILL"
    ORDER_STATUS = "ORDER_STATUS"
    PROTECTIVE_INTENT = "PROTECTIVE_INTENT"
    PROTECTIVE_ACK = "PROTECTIVE_ACK"

    # derived state
    POSITION_STATE = "POSITION_STATE"
    COUNTERS = "COUNTERS"

    # reconciliation
    RECON_RESULT = "RECON_RESULT"
    REMEDIATION = "REMEDIATION"
    RECONSTRUCTION = "RECONSTRUCTION"


TERMINAL_FOR_INTENT = {E.SUBMIT_ACK, E.SUBMIT_FAILED, E.ORDER_STATUS}


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(prev_hash: str, body: Dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical(body)).encode()).hexdigest()


def make_record(seq: int, ts: str, events: List[Dict[str, Any]],
                prev_hash: str) -> Dict[str, Any]:
    body = {"seq": seq, "ts": ts, "events": events, "prev_hash": prev_hash}
    body["hash"] = record_hash(prev_hash, body)
    return body


def verify_record(rec: Dict[str, Any]) -> bool:
    if not isinstance(rec, dict) or "hash" not in rec or "prev_hash" not in rec:
        return False
    body = {k: v for k, v in rec.items() if k != "hash"}
    return record_hash(rec["prev_hash"], body) == rec["hash"]


def event(kind: E, action_id: Optional[str] = None, **payload) -> Dict[str, Any]:
    return {"e": kind.value, "action_id": action_id, **payload}
