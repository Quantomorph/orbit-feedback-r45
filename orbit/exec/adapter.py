"""
orbit/exec/adapter.py — THE EXCHANGE BOUNDARY.

ORBIT-AGENT-ARCH-001, step 6. The last gate before the outside world, and a
separately testable seam: nothing above it may reach OKX except through here.

THE BOUNDARY ENFORCES TWO THINGS ITSELF, rather than trusting its callers:

  1. FENCING. Every mutating call fences against the durable writer authority
     first. A superseded worker is stopped here, at the last possible instant.

  2. WRITE-AHEAD. Every mutating call verifies that a durable INTENT for this
     client order id is ALREADY COMMITTED in the journal. If the caller skipped
     the write-ahead, the adapter refuses. The ordering guarantee therefore does
     not depend on every call site remembering to do things in the right order —
     which is exactly the kind of assumption this project has already had to
     correct twice.

No credentials live here. `NullAdapter` performs no I/O of any kind. A real OKX
adapter is a later step and will subclass the same base, inheriting both checks.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional

from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.exec.writer import Lease, WriterAuthority


# The payload fields bound for each mutation shape. Deliberately per-method:
# a field is bound only where it is genuinely part of THIS mutation's payload.
# `stop` on an entry INTENT, for instance, records the protective level that was
# approved, not a field of the entry order, and binding it there would compare
# two different things.
BOUND_FIELDS = {
    "submit_order": ("logical_operation_id", "instrument", "order_kind", "role",
                     "side", "contracts", "reduce_only", "order_type", "price",
                     "target_client_order_id"),
    "place_protective_stop": ("logical_operation_id", "instrument", "role",
                              "reduce_only", "contracts", "stop"),
    "amend_stop": ("logical_operation_id", "instrument", "order_kind", "role",
                   "reduce_only", "stop", "target_client_order_id"),
    "cancel_order": ("logical_operation_id", "instrument", "order_kind", "role",
                     "target_client_order_id"),
}

BOUND_FIELDS["place_protective_stop"] = (
    "logical_operation_id", "instrument", "role", "side", "reduce_only",
    "contracts", "stop")

NUMERIC_FIELDS = frozenset({"contracts", "price", "stop"})
BOOL_FIELDS = frozenset({"reduce_only"})

# The names a subclass may NOT redefine. Everything a mutation must pass
# through, plus the guard itself.
SEALED = frozenset({
    "submit_order", "place_protective_stop", "amend_stop", "cancel_order",
    "_guard", "_bind_to_intent", "_check_semantics", "_settle",
    "_intent_committed", "_intent_record",
})


def _norm(field: str, value: Any) -> Any:
    """One comparison vocabulary for both sides.

    The journal stores strings; the caller holds Decimals and bools. Comparing
    them raw would make the binding pass or fail for reasons of representation
    rather than of meaning, which is its own kind of unsafe."""
    if value in (None, "", "None"):
        return None
    if field in NUMERIC_FIELDS:
        try:
            return Decimal(str(value))
        except Exception:                                    # noqa: BLE001
            return ("UNPARSEABLE", str(value))
    if field in BOOL_FIELDS:
        if isinstance(value, str):
            return value.strip().lower() in ("true", "1", "yes")
        return bool(value)
    return str(value)


class WriteAheadViolation(RuntimeError):
    """A mutation was attempted with no durable INTENT behind it."""


class AdapterRefused(RuntimeError):
    """This adapter must never be called in this test/scenario."""


class InconsistentOrderSemantics(RuntimeError):
    """SAFETY CLOSURE, blocker B. The role of an order and its reduce_only flag
    disagree. An ENTRY that is reduce_only cannot open the position it was sized
    for; an EXIT that is NOT reduce_only can, on a hedge-mode account, open an
    opposite position instead of closing the one we hold. Either way the order
    would do something other than what the gateway approved, so the boundary
    refuses to send it."""


class DurableIntentMismatch(RuntimeError):
    """SAFETY CLOSURE ROUND 2, finding N2.

    The mutation about to reach the exchange is NOT the mutation that was
    approved and durably journalled. The boundary previously proved only that
    SOME intent existed for this client order id — so a valid INTENT for a long
    of 0.01 contracts acted as permission to send a SHORT of 99.99. Existence of
    an intent is not authorisation of a payload."""


class GuardBypassed(TypeError):
    """SAFETY CLOSURE ROUND 3, R3-2. A subclass tried to redefine part of the
    guarded surface. The safety contract must not rest on a comment saying these
    methods are not overridable — Python will happily let a subclass replace
    them, so the class object refuses at definition time."""


class MissingTargetOrder(RuntimeError):
    """SAFETY CLOSURE, blocker J. An amend or a cancel is addressed to an order
    that already exists on the exchange. The mutation's own identity is not that
    order's identity, and the boundary will not guess which order was meant."""


@dataclass(frozen=True)
class ExchangeMutation:
    """THE mutation: validated, bound, and then SENT — one object, not a set of
    positional arguments reassembled at the boundary.

    SAFETY CLOSURE ROUND 3, finding R3-2. The base adapter validated role,
    reduce_only, instrument, order_kind and the logical operation id, and then
    called

        _do_submit(cid, side, contracts, order_type, price)

    so the real venue subclass — the thing that actually talks to OKX — did not
    receive the safety property the boundary claims to enforce. It would have
    had to RECONSTRUCT reduce_only from something, which is precisely the
    reasoning a boundary exists to make unnecessary.

    The object the guard checks is now the object the I/O hook receives, and
    `fingerprint()` lets a test prove they are the same one rather than two that
    happen to look alike."""
    method: str
    client_order_id: str
    logical_operation_id: Optional[str] = None
    instrument: Optional[str] = None
    order_kind: Optional[str] = None
    role: Optional[str] = None
    side: Optional[str] = None
    contracts: Optional[Decimal] = None
    reduce_only: Optional[bool] = None
    order_type: Optional[str] = None
    price: Optional[Decimal] = None
    stop: Optional[Decimal] = None
    target_client_order_id: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "client_order_id": self.client_order_id,
            "logical_operation_id": self.logical_operation_id,
            "instrument": self.instrument,
            "order_kind": self.order_kind,
            "role": self.role,
            "side": self.side,
            "contracts": (str(self.contracts)
                          if self.contracts is not None else None),
            "reduce_only": self.reduce_only,
            "order_type": self.order_type,
            "price": str(self.price) if self.price is not None else None,
            "stop": str(self.stop) if self.stop is not None else None,
            "target_client_order_id": self.target_client_order_id,
        }

    def fingerprint(self) -> str:
        return hashlib.sha256(
            json.dumps(self.as_dict(), sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()


@dataclass
class AdapterCall:
    method: str
    client_order_id: Optional[str]
    epoch: int
    journal_seq_at_call: int
    args: Dict[str, Any] = field(default_factory=dict)
    mutation: Optional[ExchangeMutation] = None
    mutation_fingerprint: Optional[str] = None
    epoch_still_current_after: Optional[bool] = None
    """SAFETY CLOSURE, blocker H. Fencing before the call protects the DECISION
    to act. It says nothing about the interval during which the action was
    outstanding. This records whether our authority was still current when the
    exchange answered, so a response produced under superseded authority can be
    treated as an unestablished outcome rather than as our own result."""


@dataclass
class AdapterResult:
    ok: bool
    exchange_order_id: Optional[str] = None
    detail: str = ""
    unknown: bool = False          # timeout: the outcome is NOT established
    superseded: bool = False       # our authority died while this was in flight


class ExchangeAdapter(ABC):
    """Base. A subclass implements exactly ONE thing: `_do_mutation`.

    The guarded surface is SEALED by `__init_subclass__`, so "these checks are
    not overridable" is enforced by the class object instead of asserted in a
    docstring (SAFETY CLOSURE ROUND 3, R3-2)."""

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        clashes = sorted(SEALED & set(cls.__dict__))
        if clashes:
            raise GuardBypassed(
                f"{cls.__name__} redefines the guarded exchange surface "
                f"{clashes}. Fencing, write-ahead, semantics and durable-intent "
                f"binding are not advisory: a subclass implements _do_mutation "
                f"and nothing else on this path.")

    def __init__(self, authority: WriterAuthority, journal: Journal):
        self.authority = authority
        self.journal = journal
        self.calls: List[AdapterCall] = []

    # -------------------------------------------------- the two guards
    def _guard(self, method: str, lease: Optional[Lease],
               client_order_id: Optional[str], require_intent: bool = True,
               **args) -> "AdapterCall":
        self.authority.fence(lease)                      # 1. fencing
        if require_intent and not self._intent_committed(client_order_id):
            raise WriteAheadViolation(                    # 2. write-ahead
                f"{method} for {client_order_id!r} has no durable INTENT in the "
                f"journal; no exchange mutation may precede its write-ahead "
                f"record")
        self._check_semantics(method, args)               # 3. semantics
        if require_intent:
            self._bind_to_intent(method, client_order_id, args)   # 4. binding
        mutation = self._build_mutation(method, client_order_id, args)
        call = AdapterCall(
            method, client_order_id, lease.epoch if lease else -1,
            self._journal_seq(), args, mutation,
            mutation.fingerprint() if mutation else None)
        self.calls.append(call)
        return call

    @staticmethod
    def _build_mutation(method: str, client_order_id: Optional[str],
                        args: Dict[str, Any]) -> "ExchangeMutation":
        """The validated payload, as ONE immutable object. This is what the I/O
        hook receives — not a reduced positional argument list assembled a
        second time from the same values."""
        def _d(v):
            return None if v in (None, "", "None") else Decimal(str(v))
        return ExchangeMutation(
            method=method, client_order_id=client_order_id or "",
            logical_operation_id=args.get("logical_operation_id"),
            instrument=args.get("instrument"),
            order_kind=args.get("order_kind"),
            role=args.get("role"),
            side=args.get("side"),
            contracts=_d(args.get("contracts")),
            reduce_only=args.get("reduce_only"),
            order_type=args.get("order_type"),
            price=_d(args.get("price")),
            stop=_d(args.get("stop")),
            target_client_order_id=args.get("target_client_order_id"))

    # -------------------------------------------------- finding N2
    def _bind_to_intent(self, method: str, client_order_id: Optional[str],
                        args: Dict[str, Any]) -> None:
        """Prove the outgoing mutation IS the journalled one, field by field.

        The comparison is over a FIXED list per method, and a field the caller
        simply omitted is compared as absent — otherwise omission would itself
        be the bypass."""
        fields = BOUND_FIELDS.get(method)
        if fields is None:
            return
        intent = self._intent_record(client_order_id)
        if intent is None:
            raise WriteAheadViolation(
                f"{method} for {client_order_id!r} has no durable INTENT to "
                f"bind against")
        diffs = []
        for f in fields:
            approved = _norm(f, intent.get(f))
            outgoing = _norm(f, args.get(f))
            if approved != outgoing:
                diffs.append(f"{f}: approved={intent.get(f)!r} "
                             f"outgoing={args.get(f)!r}")
        if diffs:
            raise DurableIntentMismatch(
                f"{method} for {client_order_id!r} does not match its durable "
                f"INTENT and will NOT be sent. " + "; ".join(diffs))

    def _intent_record(self, client_order_id: Optional[str]):
        if client_order_id is None:
            return None
        found = None
        for rec in Journal.load(self.journal.path).records:
            for ev in rec["events"]:
                if ev["e"] in (E.INTENT.value, E.PROTECTIVE_INTENT.value) \
                        and ev.get("client_order_id") == client_order_id:
                    found = ev
        return found

    # -------------------------------------------------- blocker B
    @staticmethod
    def _check_semantics(method: str, args: Dict[str, Any]) -> None:
        """The role of an order and its reduce_only flag must agree, and the
        boundary checks it itself rather than trusting the layer above."""
        if method not in ("submit_order", "place_protective_stop"):
            return
        role = args.get("role")
        reduce_only = args.get("reduce_only")
        if role is None or reduce_only is None:
            raise InconsistentOrderSemantics(
                f"{method} must state both role and reduce_only; got "
                f"role={role!r} reduce_only={reduce_only!r}")
        if role == "ENTRY" and reduce_only:
            raise InconsistentOrderSemantics(
                "an ENTRY order cannot be reduce_only: it would be unable to "
                "open the position it was sized for")
        if role in ("EXIT", "PROTECTIVE") and not reduce_only:
            raise InconsistentOrderSemantics(
                f"a {role} order MUST be reduce_only: without it, on a "
                f"hedge-mode account, it can open an opposite position instead "
                f"of closing the one we hold")
        if role == "ADMIN":
            raise InconsistentOrderSemantics(
                "ADMIN is not an order role; cancels and amends do not submit "
                "orders")

    # -------------------------------------------------- blocker H
    def _settle(self, call: "AdapterCall", lease: Optional[Lease],
                res: "AdapterResult") -> "AdapterResult":
        """Re-fence AFTER the exchange answers. If our authority died while the
        call was outstanding, the answer is not ours to record as an outcome:
        another writer may already be acting on the same account, and the
        operation must stay unresolved until it is positively re-established."""
        still = self.authority.is_current(lease)
        call.epoch_still_current_after = still
        if still or res.unknown:
            return res
        return AdapterResult(
            False, res.exchange_order_id,
            f"the writer lease was superseded while {call.method} was in "
            f"flight; the outcome is NOT established ({res.detail})",
            unknown=True, superseded=True)

    def _intent_committed(self, client_order_id: Optional[str]) -> bool:
        if client_order_id is None:
            return False
        for rec in Journal.load(self.journal.path).records:
            for ev in rec["events"]:
                if ev["e"] in (E.INTENT.value, E.PROTECTIVE_INTENT.value) \
                        and ev.get("client_order_id") == client_order_id:
                    return True
        return False

    def _journal_seq(self) -> int:
        recs = Journal.load(self.journal.path).records
        return recs[-1]["seq"] if recs else 0

    def intent_seq(self, client_order_id: str) -> Optional[int]:
        """Sequence number of the INTENT record. Tests compare this against the
        adapter call to prove ordering from real data, not from narrative."""
        for rec in Journal.load(self.journal.path).records:
            for ev in rec["events"]:
                if ev["e"] in (E.INTENT.value, E.PROTECTIVE_INTENT.value) \
                        and ev.get("client_order_id") == client_order_id:
                    return rec["seq"]
        return None

    # -------------------------------------------------- public surface
    def submit_order(self, lease, client_order_id, side, contracts,
                     order_type, price=None, *, reduce_only=None, role=None,
                     instrument=None, order_kind=None,
                     logical_operation_id=None) -> AdapterResult:
        call = self._guard(
            "submit_order", lease, client_order_id, side=side,
            contracts=str(contracts), order_type=order_type,
            price=str(price) if price is not None else None,
            reduce_only=reduce_only, role=role, instrument=instrument,
            order_kind=order_kind, logical_operation_id=logical_operation_id,
            target_client_order_id=None)
        return self._settle(call, lease, self._do_mutation(call.mutation))

    def place_protective_stop(self, lease, client_order_id, contracts,
                              stop_price, *, reduce_only=None, role=None,
                              instrument=None, side=None,
                              logical_operation_id=None) -> AdapterResult:
        call = self._guard("place_protective_stop", lease, client_order_id,
                           contracts=str(contracts), stop=str(stop_price),
                           reduce_only=reduce_only, role=role, side=side,
                           instrument=instrument, order_kind="PROTECTIVE",
                           logical_operation_id=logical_operation_id)
        return self._settle(call, lease, self._do_mutation(call.mutation))

    def amend_stop(self, lease, client_order_id, new_stop, *,
                   target_client_order_id, order_kind="MODIFY_STOP",
                   role="ADMIN", reduce_only=True, instrument=None,
                   logical_operation_id=None) -> AdapterResult:
        """`client_order_id` identifies the MUTATION (write-ahead, idempotency,
        audit). `target_client_order_id` identifies the resting order being
        changed. They are different things and both are required."""
        if not target_client_order_id:
            raise MissingTargetOrder(
                "amend_stop must name the resting order it amends")
        call = self._guard("amend_stop", lease, client_order_id,
                           new_stop=str(new_stop), stop=str(new_stop),
                           order_kind=order_kind, role=role,
                           reduce_only=reduce_only, instrument=instrument,
                           logical_operation_id=logical_operation_id,
                           target_client_order_id=target_client_order_id)
        return self._settle(call, lease, self._do_mutation(call.mutation))

    def cancel_order(self, lease, client_order_id, *,
                     target_client_order_id, order_kind="CANCEL",
                     role="ADMIN", instrument=None,
                     logical_operation_id=None) -> AdapterResult:
        if not target_client_order_id:
            raise MissingTargetOrder(
                "cancel_order must name the resting order it cancels")
        call = self._guard("cancel_order", lease, client_order_id,
                           order_kind=order_kind, role=role,
                           instrument=instrument,
                           logical_operation_id=logical_operation_id,
                           target_client_order_id=target_client_order_id)
        return self._settle(call, lease, self._do_mutation(call.mutation))

    # -------------------------------------------------- subclass hook
    @abstractmethod
    def _do_mutation(self, mutation: "ExchangeMutation") -> AdapterResult:
        """The ONLY thing a venue adapter implements.

        It receives the exact object the guard fenced, write-ahead checked,
        semantically validated and bound to the durable INTENT. It must send
        those fields and no others, and it must never recompute or infer an
        execution semantic — `reduce_only` above all — from anything else."""


class NullAdapter(ExchangeAdapter):
    """Performs NO I/O. Records calls and returns simulated outcomes.

    `fail_next` / `timeout_next` let tests drive rejection and the
    outcome-unknown case without any network.

    The per-method `_do_*` helpers below are a convenience OF THE SIMULATOR, so
    a test can intercept one shape of mutation. They are not part of the venue
    adapter API: a real OKX adapter subclasses `ExchangeAdapter` and implements
    `_do_mutation`, which is the only hook that receives the validated object."""

    def __init__(self, authority, journal):
        super().__init__(authority, journal)
        self.fail_next = False
        self.timeout_next = False

    def _do_mutation(self, mutation):
        m = mutation
        if m.method == "submit_order":
            return self._do_submit(m.client_order_id, m.side, m.contracts,
                                   m.order_type, m.price)
        if m.method == "place_protective_stop":
            return self._do_place_stop(m.client_order_id, m.contracts, m.stop)
        if m.method == "amend_stop":
            return self._do_amend_stop(m.target_client_order_id, m.stop)
        return self._do_cancel(m.target_client_order_id)

    def _outcome(self, cid, what):
        if self.timeout_next:
            self.timeout_next = False
            return AdapterResult(False, None, f"{what} timed out", unknown=True)
        if self.fail_next:
            self.fail_next = False
            return AdapterResult(False, None, f"{what} rejected by exchange")
        return AdapterResult(True, f"X-{cid}", f"{what} accepted")

    def _do_submit(self, cid, side, contracts, order_type, price):
        return self._outcome(cid, "submit")

    def _do_place_stop(self, cid, contracts, stop_price):
        return self._outcome(cid, "stop")

    def _do_amend_stop(self, cid, new_stop):
        return self._outcome(cid, "amend")

    def _do_cancel(self, cid):
        return self._outcome(cid, "cancel")


class ForbiddenAdapter(ExchangeAdapter):
    """Raises on ANY mutation. Used to prove that a rejected action never
    reaches the exchange — the assertion is enforced by the object, not by
    counting.

    It refuses from `_do_mutation` rather than by overriding `_guard`, because
    the guard is sealed (R3-2) and because refusing there is a stronger claim
    anyway: everything upstream ran, and the mutation still did not go out."""

    def _do_mutation(self, mutation):
        raise AdapterRefused(
            f"{mutation.method} reached the exchange boundary")
