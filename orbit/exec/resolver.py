"""
orbit/exec/resolver.py — DETERMINISTIC RESOLUTION OF ADMIN MUTATIONS.

ORBIT A1 SAFETY CLOSURE ROUND 2, finding N6.

THE DEFECT THIS EXISTS TO PREVENT.

A CANCEL and a MODIFY_STOP each carry their OWN operation identity while acting
on an EXISTING order's identity. Round 1 made that separation explicit — which
was the fix for a real bug — and then had no path back. An ORDER_STATUS about
the TARGET order says nothing about the MUTATION, so an acknowledged, entirely
successful stop amendment stayed nonterminal for ever:

    after ACK, with the target confirmed resting at the new stop:
    unresolved = [('MODIFY_STOP', 'ACK')]

which blocks the next amendment (the operation ledger refuses to repeat an
unresolved mutation) and makes a clean shutdown impossible. A safety mechanism
that can never be discharged is a deadlock wearing a safety mechanism's clothes.

WHAT THIS MODULE WILL AND WILL NOT CONCLUDE.

It terminalises an admin mutation ONLY on positive evidence in the reconciled
exchange view:

    CANCEL       the target is GONE from open orders          -> EFFECTIVE
    MODIFY_STOP  the target is RESTING AT THE APPROVED PRICE  -> EFFECTIVE

Everything else stays unresolved, and repetition does not turn an ambiguity into
an answer:

    the target is still resting at the old price   the amend did not land
    the target is absent after an amend           it may have triggered, or
                                                  been cancelled by someone
                                                  else; absence is not proof
                                                  our amendment applied
    the outcome timed out and the view is unclear  unknown means unknown

Note the asymmetry, which is deliberate. For a CANCEL, absence is exactly the
outcome we asked for and is therefore evidence. For a MODIFY_STOP, absence is
the one thing we did NOT ask for, and reading it as success would let a stop
that had vanished be recorded as a stop that had moved.

WHAT IT WILL ACCEPT AS EVIDENCE (SAFETY CLOSURE ROUND 3, finding R3-3).

The first version took a raw `ExchangeView` and never asked whether it was
worth anything. With an unresolved acknowledged CANCEL and the target simply
absent from a BROKEN view:

    unreachable  -> CANCEL EFFECTIVE
    inconsistent -> CANCEL EFFECTIVE
    999s stale   -> CANCEL EFFECTIVE

"we cannot see the exchange" was being converted into "positive evidence the
cancellation succeeded" — the exact inversion this project keeps having to
refuse. Absence of a record is not a record of absence, and that is doubly true
of a view we already know we cannot trust.

The resolver now takes a `ReconResult` and nothing else. A raw view cannot be
passed at all: the trust check cannot be forgotten if the untrusted type is not
accepted. On top of that the result must clear `is_eligible_evidence` below —
reconciled, view-trustworthy, not HALTED, not blind, and fresh.

WHO RUNS IT. Python, between cycles, from reconciled state. It is not a tool,
it is not reachable from the session, and the model can neither invoke it nor
influence what it concludes. It writes ORDER_STATUS records through the ordinary
journal path, so every resolution is durable, hash-chained, and carries the
evidence it was based on.

This module is NOT the remediation executor (N7). It resolves what already
happened; it never sends anything to the exchange.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import List, Optional

from orbit.audit.journal import Journal
from orbit.audit.records import E, event
from orbit.exec.operations import LogicalOperation, OperationLedger, OpStatus, Role
from orbit.exec.recon import ReconResult
from orbit.risk.limits import RunState

# An admin resolution is a POSITIVE claim about the world, so the evidence
# behind it has to be better than "a snapshot arrived". This is the freshness
# ceiling for that claim; the reconciler's own staleness rule is separate and
# also applies.
MAX_EVIDENCE_AGE_S = 60

# Only these are resolved here. A position-changing operation is settled by
# fills and order status from the exchange, and guessing about one from an
# open-orders snapshot is precisely the reasoning this project keeps refusing.
ADMIN_KINDS = ("CANCEL", "MODIFY_STOP")


@dataclass(frozen=True)
class EvidenceVerdict:
    eligible: bool
    reason: str
    evidence_id: str = ""
    fetched_at: str = ""


def is_eligible_evidence(recon: ReconResult) -> EvidenceVerdict:
    """May this reconciliation be used to declare an admin mutation finished?

    Every clause is a way the view can be worthless while still LOOKING like a
    list of open orders — which is what made the original defect possible."""
    if not isinstance(recon, ReconResult):
        raise TypeError(
            "resolve_operations takes a ReconResult, not a raw ExchangeView. "
            "Terminalising an operation is a positive claim about the world and "
            "may only be made from reconciliation that has established the "
            "evidence as trustworthy.")
    v = recon.view
    fetched = str(v.fetched_at)
    ev_id = _evidence_id(recon)
    if not v.reachable:
        return EvidenceVerdict(False, "the exchange was not reachable", ev_id,
                               fetched)
    if not v.consistent:
        return EvidenceVerdict(False, "two reads of the exchange disagreed",
                               ev_id, fetched)
    age = (recon.now - v.fetched_at).total_seconds()
    if age > MAX_EVIDENCE_AGE_S:
        return EvidenceVerdict(
            False, f"the view is {age:.0f}s old; an operation is not declared "
                   f"finished on the strength of a stale snapshot", ev_id,
            fetched)
    if not recon.reconciled:
        return EvidenceVerdict(False, "reconciliation did not establish a "
                                      "trustworthy view", ev_id, fetched)
    if recon.run_state in (RunState.HALTED, RunState.RECONCILING):
        return EvidenceVerdict(
            False, f"run state is {recon.run_state.value}; the state is "
                   f"contested or blind and supports no positive conclusion",
            ev_id, fetched)
    if not recon.local_state_trusted:
        return EvidenceVerdict(False, "our own durable record is not trusted",
                               ev_id, fetched)
    return EvidenceVerdict(True, "reconciled, reachable, consistent and fresh",
                           ev_id, fetched)


def _evidence_id(recon: ReconResult) -> str:
    """Names the exact reconciliation a resolution was based on, so the record
    says WHICH observation was believed rather than merely that one was."""
    import hashlib
    from orbit.audit.records import canonical
    return hashlib.sha256(canonical({
        "fetched_at": str(recon.view.fetched_at),
        "now": str(recon.now),
        "run_state": recon.run_state.value,
        "reconciled": recon.reconciled,
        "orders": sorted(
            [(o.client_order_id, str(o.contracts), str(o.stop_price),
              o.is_protective) for o in recon.view.open_orders]),
        "position": str(recon.view.position),
        "findings": sorted(f.code.value for f in recon.findings),
    }).encode()).hexdigest()[:32]


@dataclass(frozen=True)
class Resolution:
    operation_id: str
    client_order_id: Optional[str]
    kind: str
    outcome: str                      # OpStatus value, or "UNRESOLVED"
    evidence: str
    evidence_id: str = ""
    view_fetched_at: str = ""

    @property
    def terminal(self) -> bool:
        return self.outcome != "UNRESOLVED"


def _dec(x) -> Optional[Decimal]:
    if x in (None, "", "None"):
        return None
    try:
        return Decimal(str(x))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _classify(op: LogicalOperation, view) -> Resolution:
    """Pure. Given one unresolved admin operation and an exchange view, say what
    the evidence supports — and nothing more."""
    target_id = op.target_client_order_id
    if not target_id:
        return Resolution(op.operation_id, op.client_order_id, op.kind,
                          "UNRESOLVED",
                          "the mutation names no target order, so nothing in "
                          "the view can confirm or deny it")

    resting = {o.client_order_id: o for o in view.open_orders
               if o.client_order_id}
    target = resting.get(target_id)

    if op.kind == "CANCEL":
        if target is None:
            return Resolution(
                op.operation_id, op.client_order_id, op.kind,
                OpStatus.EFFECTIVE.value,
                f"target {target_id} is absent from the reconciled open orders; "
                f"the cancellation we requested is the state we observe")
        return Resolution(
            op.operation_id, op.client_order_id, op.kind, "UNRESOLVED",
            f"target {target_id} is still resting: acknowledgement is not "
            f"application")

    if op.kind == "MODIFY_STOP":
        approved = _dec(op.stop)
        if approved is None:
            return Resolution(op.operation_id, op.client_order_id, op.kind,
                              "UNRESOLVED",
                              "no approved stop price was journalled for this "
                              "amendment, so nothing can be compared")
        if target is None:
            # Absence is NOT evidence that OUR amendment applied. The order may
            # have triggered, or been cancelled by something else entirely.
            return Resolution(
                op.operation_id, op.client_order_id, op.kind, "UNRESOLVED",
                f"target {target_id} is absent; for an amendment, absence is "
                f"not the outcome we asked for and does not prove it applied")
        actual = _dec(target.stop_price)
        if actual is not None and actual == approved:
            return Resolution(
                op.operation_id, op.client_order_id, op.kind,
                OpStatus.EFFECTIVE.value,
                f"target {target_id} is resting at {actual}, the approved stop; "
                f"the amendment is confirmed applied")
        return Resolution(
            op.operation_id, op.client_order_id, op.kind, "UNRESOLVED",
            f"target {target_id} rests at {target.stop_price}, not the approved "
            f"{approved}; the amendment has not taken effect")

    return Resolution(op.operation_id, op.client_order_id, op.kind,
                      "UNRESOLVED", "not an admin mutation")


def classify_operations(journal_path: str, recon: ReconResult) -> List[Resolution]:
    """Read-only. Every unresolved admin operation and what the evidence
    supports — which is NOTHING at all unless the evidence is eligible."""
    verdict = is_eligible_evidence(recon)
    led = OperationLedger(journal_path)
    out: List[Resolution] = []
    for op in led.unresolved():
        if op.kind not in ADMIN_KINDS:
            continue
        if not verdict.eligible:
            out.append(Resolution(
                op.operation_id, op.client_order_id, op.kind, "UNRESOLVED",
                f"no eligible evidence: {verdict.reason}",
                verdict.evidence_id, verdict.fetched_at))
            continue
        r = _classify(op, recon.view)
        out.append(Resolution(r.operation_id, r.client_order_id, r.kind,
                              r.outcome, r.evidence, verdict.evidence_id,
                              verdict.fetched_at))
    return out


def resolve_operations(journal: Journal, recon: ReconResult, now: datetime
                       ) -> List[Resolution]:
    """Terminalise every admin mutation the exchange confirms, and leave the
    rest alone.

    Returns only the resolutions that were ACTED ON, so a caller can see at a
    glance whether anything changed. Idempotent: running it again on an
    unchanged view resolves nothing and writes nothing, because a terminalised
    operation is no longer unresolved."""
    acted: List[Resolution] = []
    for r in classify_operations(journal.path, recon):
        if not r.terminal:
            continue
        journal.append([
            event(E.ORDER_STATUS, r.operation_id,
                  client_order_id=r.client_order_id, status=r.outcome,
                  resolved_at=now.isoformat(), evidence=r.evidence,
                  evidence_id=r.evidence_id,
                  view_fetched_at=r.view_fetched_at,
                  resolver="deterministic", by_model=False),
            event(E.REMEDIATION, r.operation_id,
                  note=f"admin operation {r.kind} resolved to {r.outcome}",
                  evidence=r.evidence),
        ])
        acted.append(r)
    return acted
