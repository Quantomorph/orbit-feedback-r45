"""
orbit/audit/cycle.py — THE LIBRARY-LEVEL RECORDER FOR ONE DECISION CYCLE.

ORBIT-AGENT-ARCH-001, build step 5e — added 2026-09-08 after a schema-vs-system
audit found that five declared event types had NO producer anywhere in the
library. The schema promised fields the system had no way to write, and the
step-5 report's claim that "every field the approval listed is carried" was true
of the schema and false of the system.

This module is the single place that writes a cycle to the journal, and
`EMITTED_BY` below is a registry that a test enforces: every event type in the
schema must name a real producer. A type with no producer is now a test failure,
not a silent hole.

Ordering discipline is the same as step 5: anything that must survive a crash is
fsynced BEFORE the external action it describes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from orbit.audit.information import (DecisionContext, InformationVerdict,
                                     verify_information_used)
from orbit.audit.journal import Journal
from orbit.audit.records import E, event
from orbit.risk.limits import RunState


# Every event type must name the function that produces it. Enforced by
# tests/test_audit_completeness.py. "reserved:" is permitted only with a reason.
EMITTED_BY: Dict[E, str] = {
    E.RUN_START:            "CycleRecorder.run_start",
    E.RUN_STATE_TRANSITION: "CycleRecorder.record_run_state",
    E.SHUTDOWN_BEGIN:       "recovery.write_clean_shutdown",
    E.CLEAN_SHUTDOWN:       "recovery.write_clean_shutdown",
    E.RECOVERY_BEGIN:       "CycleRecorder.recovery_begin",
    E.RECOVERY_COMPLETE:    "recovery.complete_recovery",
    E.CYCLE_OPEN:           "CycleRecorder.open_cycle",
    E.INFORMATION_USED:     "CycleRecorder.record_information",
    E.DECISION_INPUT:       "decision_input.record_decision_input",
    E.DECISION_INPUT_CONFLICT: "decision_input.record_decision_input",
    E.DECISION_PROPOSED:    "CycleRecorder.record_decision",
    E.GATEWAY_VERDICT:      "CycleRecorder.record_gateway_verdict",
    E.INTENT:               "Journal.record_intent",
    E.SUBMIT_ATTEMPTED:     "CycleRecorder.record_submit_attempted",
    E.SUBMIT_ACK:           "CycleRecorder.record_submit_ack",
    E.SUBMIT_FAILED:        "CycleRecorder.record_submit_failed",
    E.SUBMIT_UNKNOWN:       "CycleRecorder.record_submit_unknown",
    E.FILL:                 "CycleRecorder.record_fill_group",
    E.ORDER_STATUS:         "CycleRecorder.record_order_status",
    E.PROTECTIVE_INTENT:    "CycleRecorder.record_protective_intent",
    E.PROTECTIVE_ACK:       "CycleRecorder.record_protective_ack",
    E.POSITION_STATE:       "CycleRecorder.record_fill_group",
    E.COUNTERS:             "CycleRecorder.record_fill_group",
    E.RECON_RESULT:         "CycleRecorder.record_recon",
    E.REMEDIATION:          "CycleRecorder.record_remediation",
    E.RECONSTRUCTION:       "CycleRecorder.record_reconstruction",
}


@dataclass
class CycleRecorder:
    journal: Journal
    policy_version: str = "A1"
    model_id: str = "none"
    _last_run_state: Optional[RunState] = None
    _cycle_id: Optional[str] = None

    # -------------------------------------------------- lifecycle
    def run_start(self, **kw):
        return self.journal.append_one(
            E.RUN_START, None, policy_version=self.policy_version,
            model_id=self.model_id, **kw)

    def recovery_begin(self, journal_trusted: bool, clean_marker: bool,
                       unresolved: List[str], notes: List[str]):
        """Written BEFORE recovery does anything, so an interrupted recovery is
        itself visible in the record rather than invisible."""
        return self.journal.append_one(
            E.RECOVERY_BEGIN, None, journal_trusted=journal_trusted,
            clean_marker=clean_marker, unresolved=unresolved, notes=notes)

    def record_run_state(self, new_state: RunState, reason: str,
                         findings: Tuple[str, ...] = ()):
        """Emitted only on CHANGE. A run-state transition is a safety event:
        the record must show when protection was engaged and why, not merely
        what state the system happened to be in at the end."""
        if new_state is self._last_run_state:
            return None
        old = self._last_run_state
        self._last_run_state = new_state
        return self.journal.append_one(
            E.RUN_STATE_TRANSITION, None,
            previous=(old.value if old else None), new=new_state.value,
            reason=reason, findings=list(findings))

    # -------------------------------------------------- decision path
    def open_cycle(self, cycle_id: str, snapshot_as_of: str):
        self._cycle_id = cycle_id
        return self.journal.append_one(E.CYCLE_OPEN, None, cycle_id=cycle_id,
                                       snapshot_as_of=snapshot_as_of)

    def record_information(self, ctx: DecisionContext):
        return self.journal.append_one(E.INFORMATION_USED, ctx.decision_id,
                                       **ctx.as_event_payload())

    def record_decision(self, decision_id: str, decision: Dict[str, Any],
                        claimed_refs: Tuple[str, ...]):
        """The model's raw proposal, recorded VERBATIM before it is judged."""
        return self.journal.append_one(
            E.DECISION_PROPOSED, decision_id, cycle_id=self._cycle_id,
            decision=decision, information_used=list(claimed_refs))

    def record_gateway_verdict(self, decision_id: str, approved: bool,
                               code: str, reason: str,
                               computed: Optional[Dict[str, Any]] = None,
                               order: Optional[Dict[str, Any]] = None):
        """EVERY verdict, approval and rejection alike. The A1 metric
        'gateway rejections by reason code' is computed from these."""
        return self.journal.append_one(
            E.GATEWAY_VERDICT, decision_id, cycle_id=self._cycle_id,
            approved=approved, code=code, reason=reason,
            computed=computed or {}, order=order)

    # -------------------------------------------------- exchange path
    def record_submit_attempted(self, action_id, client_order_id):
        return self.journal.append_one(E.SUBMIT_ATTEMPTED, action_id,
                                       client_order_id=client_order_id)

    def record_submit_ack(self, action_id, client_order_id, exchange_order_id,
                          server_ts=None):
        return self.journal.append_one(
            E.SUBMIT_ACK, action_id, client_order_id=client_order_id,
            exchange_order_id=exchange_order_id, server_ts=server_ts)

    def record_submit_failed(self, action_id, client_order_id, error):
        return self.journal.append_one(E.SUBMIT_FAILED, action_id,
                                       client_order_id=client_order_id,
                                       error=error)

    def record_submit_unknown(self, action_id, client_order_id, attempts):
        return self.journal.append_one(E.SUBMIT_UNKNOWN, action_id,
                                       client_order_id=client_order_id,
                                       attempts=attempts)

    def record_fill_group(self, action_id, client_order_id, fill_id, contracts,
                          price, position: Optional[Dict[str, Any]],
                          entries_utc_day: int, realized_pnl_utc_day: str,
                          server_ts=None, cumulative=None, *,
                          executed_at, fee=None):
        """ONE atomic record: a fill can never be observed without the position
        and counters it produced.

        SAFETY CLOSURE ROUND 4C4, checkpoint A.1. Two fields are now part of
        what a FILL IS, because daily accounting is derived from fills:

        `executed_at` — REQUIRED. The moment the venue EXECUTED the fill
        (OKX `fillTime`), tz-aware, normalized to UTC here. NOT `server_ts`
        (the venue's data-generation time) and NOT the record's commit time.
        A fill is assigned to a UTC day by this field alone; a fill without
        it cannot be accounted and the fold refuses it, so the recorder
        refuses to write it. See `orbit/audit/derivation.py`.

        `fee` — a `FillFee` (see `orbit/exec/fees.py`), or None when the
        venue reported nothing, in which case the fold charges the modelled
        taker fee. The ambiguous legacy `fee` key is never written.
        """
        from orbit.exec.fees import FillFee
        if not isinstance(executed_at, datetime):
            try:
                executed_at = datetime.fromisoformat(str(executed_at))
            except (TypeError, ValueError):
                raise ValueError(
                    f"executed_at {executed_at!r} is not a timestamp; a fill "
                    f"with no execution time cannot be assigned to a UTC day")
        if executed_at.tzinfo is None:
            raise ValueError("executed_at must be timezone-aware; a naive "
                             "execution time cannot be assigned to a UTC day")
        executed_at = executed_at.astimezone(timezone.utc)
        fee_fields = {}
        if fee is not None:
            if not isinstance(fee, FillFee):
                raise ValueError("fee must be a normalized FillFee; a raw "
                                 "venue value has no fixed sign convention")
            fee_fields = fee.as_event_fields()
        # SAFETY CLOSURE ROUND 2, N1.10. The uniqueness claim governs the WHOLE
        # atomic group, inside one critical section. Asking `has_fill` first and
        # appending afterwards left a window in which a duplicated fill landed a
        # duplicate POSITION_STATE and a duplicate COUNTERS record — which is
        # worse than a duplicate FILL, because those two are what state is
        # rebuilt from.
        return self.journal.append_unique([
            event(E.FILL, action_id, client_order_id=client_order_id,
                  fill_id=fill_id, contracts=str(contracts), price=str(price),
                  server_ts=server_ts, cumulative=cumulative,
                  executed_at=executed_at.isoformat(), **fee_fields),
            event(E.POSITION_STATE, action_id, position=position),
            event(E.COUNTERS, action_id, entries_utc_day=entries_utc_day,
                  realized_pnl_utc_day=str(realized_pnl_utc_day)),
        ], fill_id=fill_id,
            note=f"duplicate FILL {fill_id} suppressed (idempotency)")

    def record_order_status(self, action_id, client_order_id, status: str):
        return self.journal.append_one(E.ORDER_STATUS, action_id,
                                       client_order_id=client_order_id,
                                       status=status)

    def record_protective_intent(self, client_order_id, contracts, stop,
                                 instrument: str = "BTC-USDT-SWAP",
                                 side: Optional[str] = None,
                                 logical_operation_id: Optional[str] = None):
        """WRITE-AHEAD for the protective order, with its own idempotency.
        (The first draft delegated to Journal.record_intent, which writes an
        INTENT event — the rebuild would then have classified the stop as an
        entry order. Caught while writing the completeness test.)"""
        return self.journal.append_unique(
            [event(E.PROTECTIVE_INTENT, client_order_id,
                   client_order_id=client_order_id, contracts=str(contracts),
                   stop=str(stop), instrument=instrument,
                   order_kind="PROTECTIVE", role="PROTECTIVE",
                   reduce_only=True, side=side,
                   target_client_order_id=None,
                   logical_operation_id=logical_operation_id,
                   operation_id=logical_operation_id)],
            action_id=client_order_id,
            note="duplicate PROTECTIVE_INTENT suppressed (idempotency)")

    def record_protective_ack(self, client_order_id,
                              position: Optional[Dict[str, Any]] = None):
        evs = [event(E.PROTECTIVE_ACK, client_order_id,
                     client_order_id=client_order_id)]
        if position is not None:
            evs.append(event(E.POSITION_STATE, client_order_id,
                             position=position))
        return self.journal.append(evs)

    # -------------------------------------------------- reconciliation
    def record_recon(self, recon) -> None:
        """Records the result AND emits a run-state transition when it changes."""
        self.journal.append_one(
            E.RECON_RESULT, None, cycle_id=self._cycle_id,
            reconciled=recon.reconciled,
            local_state_trusted=recon.local_state_trusted,
            run_state=recon.run_state.value, worst=recon.worst.name,
            findings=[{"code": f.code.value, "disposition": f.disposition.name,
                       "view_trustworthy": f.view_trustworthy,
                       "local_trustworthy": f.local_trustworthy,
                       "detail": f.detail} for f in recon.findings],
            remedies=[r.value for r in recon.remedies])
        self.record_run_state(
            recon.run_state,
            reason="reconciliation",
            findings=tuple(f.code.value for f in recon.findings))

    def record_remediation(self, action_id, note, **kw):
        return self.journal.append_one(E.REMEDIATION, action_id, note=note, **kw)

    def record_reconstruction(self, action_id, reason, evidence, client_ids,
                              fill_ids, reconstructed, recon_result,
                              remediation):
        return self.journal.append_one(
            E.RECONSTRUCTION, action_id, reason=reason, evidence=list(evidence),
            client_ids=list(client_ids), fill_ids=list(fill_ids),
            reconstructed=reconstructed, recon_result=recon_result,
            remediation=list(remediation))


# ======================================================================
def verify_information_from_journal(path: str, decision_id: str
                                    ) -> InformationVerdict:
    """Verify a decision's `information_used` against the DURABLE record of its
    own cycle, not against an in-memory object that could have been rebuilt to
    match. This is the version that survives the process that made the claim.
    """
    recs = Journal.load(path).records
    ctx_payload = None
    claimed: Tuple[str, ...] = ()
    cycle_of_decision = None

    for r in recs:
        for ev in r["events"]:
            if ev["e"] == E.INFORMATION_USED.value and ev.get("action_id") == decision_id:
                ctx_payload = ev
            if ev["e"] == E.DECISION_PROPOSED.value and ev.get("action_id") == decision_id:
                claimed = tuple(ev.get("information_used", ()))
                cycle_of_decision = ev.get("cycle_id")

    if ctx_payload is None:
        return InformationVerdict(
            False, (), (), f"no INFORMATION_USED record exists for decision "
                           f"{decision_id}: what it knew was never recorded")
    if cycle_of_decision is not None and ctx_payload.get("cycle_id") not in (
            None, cycle_of_decision):
        return InformationVerdict(
            False, (), (), "the decision and its information record belong to "
                           "different cycles")
    available = frozenset(ctx_payload.get("available_refs", ()))
    unknown = tuple(sorted(set(claimed) - available))
    unused = tuple(sorted(available - set(claimed)))
    if unknown:
        return InformationVerdict(
            False, unknown, unused,
            f"decision cites {len(unknown)} reference(s) absent from the "
            f"durable record of its own cycle: {unknown}")
    if not claimed:
        return InformationVerdict(False, (), unused,
                                  "decision cites no information at all")
    return InformationVerdict(True, (), unused)
