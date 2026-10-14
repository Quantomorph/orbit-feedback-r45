"""
orbit/audit/decision_input.py — WHAT EXACTLY DID CLAUDE RECEIVE?

ORBIT A1 SAFETY CLOSURE ROUND 2, finding N4.

THE DEFECT THIS EXISTS TO PREVENT.

Round 1 replaced `prompt_hash = hash({"cycle": cycle_id})` with a real SHA-256
of the prompt text. That was a genuine improvement and it was not the
requirement. A hash proves EQUALITY when you already hold the original. It
reconstructs nothing. After a restart the question

    what exactly did Claude know when it made this decision?

still had no answer, and "here is a digest of something you no longer have" is
not an audit trail — it is a receipt for one.

So the artifact is the INPUT ITSELF, serialised deterministically and stored
durably under its own content id, with the individual hashes recorded alongside
so a mismatch can be localised rather than merely detected:

    system_prompt_hash    did the operating instructions change?
    user_prompt_hash      did the question change?
    tool_schema_hash      did the model's available actions change?
    model_input_hash      did ANYTHING change?

A separate process, holding nothing but the journal and the blob store, must be
able to reproduce the exact bytes. `tests/_reconstruct_worker.py` is that
process, and it is a real one for exactly this reason: a test that reuses an
in-memory object proves nothing about a restart.

SERIALISATION. Canonical JSON — sorted keys, no insignificant whitespace, UTF-8.
Deterministic across processes and across runs, so key ordering can never change
a hash and two identical inputs can never be recorded as different ones.
`serialization_version` is part of the payload: if this format ever changes, the
change is visible in the record rather than silently altering every hash.

NOTHING HERE CALLS A MODEL. This is the shape of the record that will exist when
one is connected.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from orbit.audit.blobstore import BlobStore
from orbit.audit.journal import AppendLock, Journal
from orbit.audit.records import E, event

SERIALIZATION_VERSION = "orbit-decision-input/1"


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def _h(obj: Any) -> str:
    return hashlib.sha256(_canon(obj)).hexdigest()


@dataclass(frozen=True)
class DecisionInput:
    """Every byte the model was given, and nothing it was not."""
    system_prompt: str
    user_prompt: str
    messages: Tuple[Mapping[str, Any], ...] = ()
    tool_schema: Mapping[str, Any] = field(default_factory=dict)
    tool_results: Tuple[Mapping[str, Any], ...] = ()
    account_state: Mapping[str, Any] = field(default_factory=dict)
    position_state: Optional[Mapping[str, Any]] = None
    open_orders: Tuple[Mapping[str, Any], ...] = ()
    memory: Tuple[Mapping[str, Any], ...] = ()
    policy_version: str = "A1"
    model_id: str = "none"
    serialization_version: str = SERIALIZATION_VERSION

    # ------------------------------------------------------------------
    def as_payload(self) -> Dict[str, Any]:
        return {
            "serialization_version": self.serialization_version,
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "messages": [dict(m) for m in self.messages],
            "tool_schema": dict(self.tool_schema),
            "tool_results": [dict(t) for t in self.tool_results],
            "account_state": dict(self.account_state),
            "position_state": (dict(self.position_state)
                               if self.position_state is not None else None),
            "open_orders": [dict(o) for o in self.open_orders],
            "memory": [dict(m) for m in self.memory],
            "policy_version": self.policy_version,
            "model_id": self.model_id,
        }

    def serialize(self) -> bytes:
        """THE bytes. Deterministic, canonical, and the thing actually stored."""
        return _canon(self.as_payload())

    @staticmethod
    def deserialize(raw: bytes) -> "DecisionInput":
        d = json.loads(raw.decode("utf-8"))
        return DecisionInput(
            system_prompt=d["system_prompt"],
            user_prompt=d["user_prompt"],
            messages=tuple(d.get("messages", ())),
            tool_schema=d.get("tool_schema", {}),
            tool_results=tuple(d.get("tool_results", ())),
            account_state=d.get("account_state", {}),
            position_state=d.get("position_state"),
            open_orders=tuple(d.get("open_orders", ())),
            memory=tuple(d.get("memory", ())),
            policy_version=d.get("policy_version", "A1"),
            model_id=d.get("model_id", "none"),
            serialization_version=d.get("serialization_version",
                                        SERIALIZATION_VERSION))

    # ------------------------------------------------------------------
    def hashes(self) -> Dict[str, str]:
        """Separate hashes so a mismatch says WHICH part changed. A single
        aggregate hash tells an auditor only that something did."""
        return {
            "system_prompt_hash": hashlib.sha256(
                self.system_prompt.encode("utf-8")).hexdigest(),
            "user_prompt_hash": hashlib.sha256(
                self.user_prompt.encode("utf-8")).hexdigest(),
            "tool_schema_hash": _h(dict(self.tool_schema)),
            "messages_hash": _h([dict(m) for m in self.messages]),
            "tool_results_hash": _h([dict(t) for t in self.tool_results]),
            "state_hash": _h({"account": dict(self.account_state),
                              "position": (dict(self.position_state)
                                           if self.position_state else None),
                              "open_orders": [dict(o) for o in self.open_orders]}),
            "memory_hash": _h([dict(m) for m in self.memory]),
            "model_input_hash": hashlib.sha256(self.serialize()).hexdigest(),
        }

    @property
    def content_id(self) -> str:
        return BlobStore.content_id(self.serialize())


class DecisionInputConflict(RuntimeError):
    """A DIFFERENT input was offered for a decision id that already has one.

    Not an update. There is no such thing as updating what a decision was given:
    the decision was made from what it was given."""


def _existing_mapping(head, decision_id: str) -> Optional[Dict[str, Any]]:
    """The FIRST committed mapping, from fresh durable state."""
    for rec in head.records:
        for ev in rec["events"]:
            if ev["e"] == E.DECISION_INPUT.value \
                    and ev.get("decision_id") == decision_id:
                return ev
    return None


def record_decision_input(journal: Journal, store: BlobStore, decision_id: str,
                          decision_input: DecisionInput) -> Dict[str, Any]:
    """Store the bytes, then claim the mapping. In that order, atomically.

    The blob is durable before anything points at it, so a crash between the two
    leaves an unreferenced blob — harmless — rather than a journal record naming
    content that was never written.

    The mapping claim happens inside the journal's cross-process lock and is
    decided against freshly read durable state, for the same reason the INTENT
    and FILL claims are (round 2, N1): a check made outside the lock is right
    about this process and silent about every other one."""
    raw = decision_input.serialize()
    cid = store.put(raw)
    h = decision_input.hashes()
    payload = {
        "decision_id": decision_id,
        "content_id": cid,
        "bytes": len(raw),
        "blob_dir": store.dir,
        "serialization_version": decision_input.serialization_version,
        "policy_version": decision_input.policy_version,
        "model_id": decision_input.model_id,
        **h,
    }

    with AppendLock(journal.path):
        head = journal._prepare_locked()
        prior = _existing_mapping(head, decision_id)
        if prior is None:
            journal._write_locked([event(E.DECISION_INPUT, decision_id,
                                         **payload)])
            return dict(payload, duplicate=False)
        if prior.get("content_id") == cid:
            journal._write_locked([event(
                E.REMEDIATION, decision_id,
                note=f"duplicate DECISION_INPUT for {decision_id} suppressed "
                     f"(identical content {cid[:16]})")])
            return dict(prior, duplicate=True)
        journal._write_locked([event(
            E.DECISION_INPUT_CONFLICT, decision_id,
            decision_id=decision_id,
            committed_content_id=prior.get("content_id"),
            committed_model_input_hash=prior.get("model_input_hash"),
            attempted_content_id=cid,
            attempted_model_input_hash=h["model_input_hash"],
            note="a DIFFERENT decision input was offered for a decision id that "
                 "already has one; the committed mapping is unchanged")])
    raise DecisionInputConflict(
        f"decision {decision_id!r} is already bound to content "
        f"{prior.get('content_id', '')[:16]}… and cannot be rebound to "
        f"{cid[:16]}…. What a decision was given is not editable; the attempt "
        f"is recorded as DECISION_INPUT_CONFLICT.")


def load_decision_input(journal_path: str, store: BlobStore,
                        decision_id: str) -> Tuple[DecisionInput, Dict[str, Any]]:
    """Reconstruct from DISK ALONE. No in-memory object from the deciding
    process is involved, which is the whole point of the requirement."""
    # FIRST match, not last. Taking the last is what made the mapping mutable.
    ref = _existing_mapping(Journal.load(journal_path), decision_id)
    if ref is None:
        raise KeyError(f"no DECISION_INPUT record for {decision_id!r}")
    raw = store.get(ref["content_id"])          # verifies the bytes
    return DecisionInput.deserialize(raw), ref
