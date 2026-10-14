"""
orbit/exec/operations.py — LOGICAL OPERATION IDENTITY AND LIFECYCLE.

ORBIT A1 SAFETY CLOSURE, blockers A, C and E.

THE DEFECT THIS EXISTS TO PREVENT (reproduced 2026-09-08):

    cycle A: CLOSE submitted, exchange response times out -> UNKNOWN
    cycle B: the same CLOSE proposed again
    => a NEW action_id, a NEW client_order_id, a SECOND external mutation.

Identity was `hash(cycle_id, tool, params)`, so a change of cycle produced a
change of identity. But UNKNOWN DOES NOT MEAN FAILED. An unresolved external
mutation must be RESOLVED, not replaced.

THE MODEL

  logical_key   what this mutation IS, independent of when it was requested:
                instrument + kind + side/target. No cycle, no epoch, no session.

  generation    how many times that logical operation has ALREADY reached a
                terminal outcome. It advances only on termination, so a
                legitimately new action later is a new operation — removing
                cycle_id from the hash alone would have made every future
                identical action a permanent duplicate.

  operation_id  logical_key : generation
  client_order_id  sha256(operation_id) — stable across cycles, sessions,
                restarts and writer epochs for as long as the operation is
                unresolved.

TERMINALITY (blocker E). ACK means only that the exchange accepted the request.
It does not mean filled, cancelled, rejected, or expired. Only positive evidence
makes an operation terminal; absence from one shallow open-orders snapshot does
not.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from orbit.audit.journal import Journal
from orbit.audit.records import E, canonical


class OpStatus(str, Enum):
    # ---- NONTERMINAL: an external mutation may exist and is unresolved ----
    PENDING = "PENDING"                    # intent durable, possibly not sent
    SUBMITTED = "SUBMITTED"                # sent, no answer yet
    ACK = "ACK"                            # accepted — NOT filled
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    UNKNOWN = "UNKNOWN"                    # outcome not established
    # ---- TERMINAL: only with positive evidence ----
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"                  # refused BEFORE acceptance
    EXPIRED = "EXPIRED"
    EFFECTIVE = "EFFECTIVE"
    """SAFETY CLOSURE ROUND 2, finding N6. The terminal outcome of an ADMIN
    mutation — a CANCEL or a MODIFY_STOP — whose effect has been positively
    CONFIRMED against the exchange. It is deliberately not FILLED: an
    amendment never fills, and calling it filled would make the audit lie about
    what happened. A cancel or an amend that has merely been ACKNOWLEDGED is
    still nonterminal, because acknowledgement is not application."""


TERMINAL = frozenset({OpStatus.FILLED, OpStatus.CANCELLED, OpStatus.REJECTED,
                      OpStatus.EXPIRED, OpStatus.EFFECTIVE})
NONTERMINAL = frozenset(OpStatus) - TERMINAL


class Role(str, Enum):
    ENTRY = "ENTRY"            # may create exposure
    EXIT = "EXIT"              # reduces exposure; always reduce_only
    PROTECTIVE = "PROTECTIVE"  # a resting stop
    ADMIN = "ADMIN"            # cancel / amend


@dataclass(frozen=True)
class LogicalOperation:
    logical_key: str
    generation: int
    operation_id: str
    client_order_id: str
    instrument: str
    kind: str
    side: Optional[str]
    reduce_only: bool
    role: Role
    contracts: Optional[str]
    status: OpStatus
    epoch: Optional[int] = None
    created_at: Optional[str] = None
    target_client_order_id: Optional[str] = None
    filled_contracts: Decimal = Decimal("0")
    overfilled: bool = False
    """More arrived than was intended. Terminal, but not the same thing as a
    clean fill, and never hidden inside one."""
    stop: Optional[str] = None
    """The approved stop price, for an operation that sets or moves one. The
    resolver needs it to decide whether an amendment actually took effect."""

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL

    @property
    def unresolved(self) -> bool:
        return not self.terminal


def _h(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode()).hexdigest()


def logical_key(instrument: str, kind: str, side: Optional[str] = None,
                target_client_order_id: Optional[str] = None) -> str:
    """Deliberately excludes cycle_id, epoch, session and timestamp. Two
    requests for the same mutation are the same logical operation whenever they
    are made."""
    return _h({"instrument": instrument, "kind": kind, "side": side,
               "target": target_client_order_id})[:32]


def client_order_id_for(operation_id: str) -> str:
    return "orbitA1" + hashlib.sha256(operation_id.encode()).hexdigest()[:24]


# ======================================================================
class OperationLedger:
    """Reconstructs every logical operation from the durable journal."""

    def __init__(self, journal_path: str,
                 records: Optional[List[Dict[str, Any]]] = None):
        self.path = journal_path
        self._ops: Dict[str, Dict[str, Any]] = {}
        self._by_cid: Dict[str, str] = {}
        self._load(Journal.load(journal_path).records
                   if records is None else records)

    @classmethod
    def from_records(cls, records: List[Dict[str, Any]],
                     journal_path: str) -> "OperationLedger":
        """SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 6.

        A ledger over an ALREADY-LOADED prefix. The action path loads the
        journal once, pins that prefix in the evidence, and hands the same
        records to the ledger, the idempotency check and the state derivation.
        Before this, the ledger re-opened the file by path and folded whatever
        was there at that instant - a second interpretation of history that
        the evidence never named.
        """
        return cls(journal_path, records=records)

    @staticmethod
    def _dec(x) -> Decimal:
        """SAFETY CLOSURE ROUND 3, finding R3-4. This used binary floats.

        0.01 + 0.06 == 0.06999999999999999 in binary floating point, which is
        LESS than 0.07, so an operation that had filled EXACTLY reported
        PARTIALLY_FILLED — nonterminal, blocking the next operation on that key
        and any clean shutdown, for ever. Contract sizes are exact decimal lot
        steps; representing them in binary is not an approximation of the right
        answer, it is the wrong arithmetic."""
        if x in (None, "", "None"):
            return Decimal("0")
        try:
            return Decimal(str(x))
        except (InvalidOperation, ValueError, TypeError):
            return Decimal("0")

    def _load(self, records: List[Dict[str, Any]]) -> None:
        fills: Dict[str, Decimal] = {}
        for rec in records:
            for ev in rec["events"]:
                t, cid = ev["e"], ev.get("client_order_id")
                if t in (E.INTENT.value, E.PROTECTIVE_INTENT.value):
                    oid = ev.get("operation_id") or ev.get("action_id")
                    if oid is None:
                        continue
                    self._ops[oid] = {
                        "operation_id": oid,
                        "logical_key": ev.get("logical_key", ""),
                        "generation": int(ev.get("generation", 0)),
                        "client_order_id": cid,
                        "instrument": ev.get("instrument", ""),
                        "kind": ev.get("order_kind", ""),
                        "side": ev.get("side"),
                        "reduce_only": bool(ev.get("reduce_only", False)),
                        "role": ev.get("role", Role.ENTRY.value),
                        "contracts": ev.get("contracts"),
                        "epoch": ev.get("epoch"),
                        "created_at": rec["ts"],
                        "target": ev.get("target_client_order_id"),
                        "stop": ev.get("stop"),
                        "filled": Decimal("0"),
                        "overfilled": False,
                        "status": OpStatus.PENDING,
                    }
                    if cid:
                        self._by_cid[cid] = oid
                    continue
                oid = self._by_cid.get(cid) if cid else None
                if oid is None or oid not in self._ops:
                    continue
                o = self._ops[oid]
                if t == E.SUBMIT_ATTEMPTED.value:
                    o["status"] = OpStatus.SUBMITTED
                elif t in (E.SUBMIT_ACK.value, E.PROTECTIVE_ACK.value):
                    o["status"] = OpStatus.ACK          # NOT terminal
                elif t == E.SUBMIT_FAILED.value:
                    o["status"] = OpStatus.REJECTED     # refused before accept
                elif t == E.SUBMIT_UNKNOWN.value:
                    o["status"] = OpStatus.UNKNOWN
                elif t == E.FILL.value:
                    fills[oid] = fills.get(oid, Decimal("0")) \
                        + self._dec(ev.get("contracts"))
                    want = self._dec(o["contracts"])
                    o["filled"] = fills[oid]
                    if want > 0 and fills[oid] >= want:
                        o["status"] = OpStatus.FILLED
                        # An overfill is a DIFFERENT event from a fill, and it
                        # must be visible rather than absorbed into "done".
                        o["overfilled"] = fills[oid] > want
                    else:
                        o["status"] = OpStatus.PARTIALLY_FILLED
                elif t == E.ORDER_STATUS.value:
                    try:
                        o["status"] = OpStatus(ev["status"])
                    except (KeyError, ValueError):
                        pass

    # ------------------------------------------------------------------
    def all(self) -> List[LogicalOperation]:
        return [LogicalOperation(
            o["logical_key"], o["generation"], o["operation_id"],
            o["client_order_id"], o["instrument"], o["kind"], o["side"],
            o["reduce_only"], Role(o["role"]), o["contracts"], o["status"],
            o["epoch"], o["created_at"], o["target"],
            o.get("filled", Decimal("0")), bool(o.get("overfilled")),
            o.get("stop"))
            for o in self._ops.values()]

    def unresolved(self) -> List[LogicalOperation]:
        return [o for o in self.all() if o.unresolved]

    def by_client_order_id(self, cid: str) -> Optional[LogicalOperation]:
        oid = self._by_cid.get(cid)
        return next((o for o in self.all() if o.operation_id == oid), None)

    def owns(self, cid: str) -> bool:
        """HISTORICAL AUTHORSHIP ONLY: did ORBIT ever intend this identity?

        Blocker I established that ownership is durable rather than inferred
        from the account. SAFETY CLOSURE ROUND 4B2, finding I1, establishes that
        authorship alone is not enough to MUTATE a resting order, and this
        predicate must not be used for that. Use `resting_authority`.
        """
        return cid in self._by_cid

    # ------------------------------------------------------------------
    # SAFETY CLOSURE ROUND 4B2 — finding I1.
    #
    # Round 4B routed every mutating tool through one ownership predicate, and
    # that predicate was `cid in self._by_cid`. Any INTENT therefore conferred
    # authority for ever, whatever the durable lifecycle later proved. A stop
    # whose submission was DEFINITIVELY REJECTED, and whose id then reappeared
    # on the venue as a resting row, was reported owned and amended.
    #
    # Three different things had been collapsed into one boolean:
    #
    #     HISTORICAL AUTHORSHIP   ORBIT once intended this identity.
    #     CURRENT LIVE OWNERSHIP  the durable lifecycle does not contradict a
    #                             live row bearing it.
    #     AUTHORITY TO MUTATE     both of the above, AND the durable role agrees
    #                             with the role the row is observed to have.
    #
    # THE UNKNOWN CASE IS THE POINT OF THE DISTINCTION, not an oversight.
    # An UNKNOWN submission may genuinely have reached the venue — that is why
    # logical operation resolution exists — and a resting row bearing a
    # deterministic id ORBIT derived from its own operation id is evidence that
    # it did. UNKNOWN therefore keeps authority. What loses it is DEFINITIVE
    # evidence that contradicts the row: a submission refused before acceptance
    # cannot be resting, and an order positively established as cancelled,
    # filled or expired cannot be resting either. Those are contradictions
    # between durable history and current exchange state, and a contradiction
    # is a reason to stop, not a reason to act.
    # ------------------------------------------------------------------
    CONSISTENT_WITH_RESTING = frozenset({
        OpStatus.PENDING, OpStatus.SUBMITTED, OpStatus.ACK,
        OpStatus.PARTIALLY_FILLED, OpStatus.UNKNOWN})
    """The statuses under which a live resting order is a coherent claim.

    Found by the round-4B2 review of this predicate: it was first written as two
    deny-lists — REJECTED, and CANCELLED/FILLED/EXPIRED — and `EFFECTIVE` fell
    through both and kept authority. EFFECTIVE is the confirmed terminal outcome
    of an ADMIN mutation; a protective order never reaches it, and an admin
    mutation's own identity is not a resting order. Enumerating what is FORBIDDEN
    is the wrong shape for a safety predicate, because every status added later
    defaults to permitted. This is the allow-list, and everything terminal is
    outside it.

    UNKNOWN IS DELIBERATELY INSIDE IT. An unknown submission may genuinely have
    reached the venue — that is why logical operation resolution exists — and a
    resting row bearing an id ORBIT derived from its own operation id is
    evidence that it did. What loses authority is DEFINITIVE evidence that
    contradicts a resting row, never the mere absence of evidence.
    """

    def resting_authority(self, cid: Optional[str], observed=None
                          ) -> Tuple[bool, str, str]:
        """(may the model mutate this resting order, code, why not).

        `observed` is the exchange row, canonicalised, when the caller has one.
        Without it the role agreement cannot be checked and the caller gets the
        weaker lifecycle answer — stated rather than hidden, and the two call
        sites that lack a view (they run before one is taken, and this round
        introduces no new fetch) are followed by one that has it.
        """
        if not cid:
            return False, "NOT_OUR_ORDER", "no order identity was given"
        op = self.by_client_order_id(cid)
        if op is None:
            return (False, "NOT_OUR_ORDER",
                    f"{cid!r} has no durable record: ORBIT never intended it. "
                    f"Ownership is never inferred from the order being visible "
                    f"in the account, nor from the shape of its id.")
        if op.status not in self.CONSISTENT_WITH_RESTING:
            return (False, "ORDER_STATE_CONTRADICTED",
                    f"{cid!r} was durably established as {op.status.value}, "
                    f"which is a terminal outcome: it was refused before "
                    f"acceptance, or it has left the book. Either way it "
                    f"cannot be a live resting order ORBIT may mutate, and a "
                    f"row bearing that id contradicts ORBIT's own record. A "
                    f"contradiction is a reason to reconcile, not a licence to "
                    f"mutate.")
        if observed is not None and getattr(observed, "is_protective", False):
            # The durable ROLE governs. `order_kind` is not a second opinion:
            # it is set by the recorder that wrote the intent, and an entry
            # mistakenly filed under a protective kind must not thereby become
            # protection. Role is what travels to the exchange boundary and
            # what `reduce_only` is checked against.
            protective = op.role in (Role.PROTECTIVE, Role.PROTECTIVE.value)
            if not protective:
                return (False, "ORDER_ROLE_CONTRADICTED",
                        f"{cid!r} is durably recorded as a {op.role} "
                        f"{op.kind} operation, and the venue presents it as a "
                        f"protective order. An entry, or the identity of an "
                        f"admin mutation, does not become protection because a "
                        f"row says so.")
        return True, "", ""

    def open_for(self, key: str) -> Optional[LogicalOperation]:
        return next((o for o in self.all()
                     if o.logical_key == key and o.unresolved), None)

    def next_generation(self, key: str) -> int:
        return sum(1 for o in self.all() if o.logical_key == key and o.terminal)

    def new_operation(self, instrument: str, kind: str, role: Role,
                      reduce_only: bool, side: Optional[str] = None,
                      contracts: Optional[str] = None,
                      target_client_order_id: Optional[str] = None
                      ) -> Tuple[Optional[LogicalOperation], Optional[LogicalOperation]]:
        """Returns (new_operation, blocking_unresolved_operation).

        If an operation with the same logical key is unresolved, NO new
        operation is minted and the caller must resolve the existing one."""
        key = logical_key(instrument, kind, side, target_client_order_id)
        existing = self.open_for(key)
        if existing is not None:
            return None, existing
        gen = self.next_generation(key)
        oid = f"{key}:g{gen}"
        return LogicalOperation(
            key, gen, oid, client_order_id_for(oid), instrument, kind, side,
            reduce_only, role, contracts, OpStatus.PENDING,
            target_client_order_id=target_client_order_id), None
