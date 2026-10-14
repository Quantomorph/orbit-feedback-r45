"""
orbit/tools/session.py — THE TOOL SURFACE CLAUDE WILL EVENTUALLY SEE.

ORBIT-AGENT-ARCH-001, steps 6B / 6C / 6E / 6F / 6G / 6H / 6I.

    CLAUDE CAN BE WRONG,
    BUT CLAUDE MUST NOT BE ABLE TO MAKE ORBIT UNSAFE BY BEING WRONG.

READ tools return a snapshot with a durable reference id, and every reference is
accumulated into the cycle's information context. A decision may later cite only
what was actually returned.

ACTION tools return an INTENT, never an execution. The ordering is fixed:

    schema → authoritative state → writer fence → re-reconcile → protection
    invariants → gateway → DURABLE WRITE-AHEAD INTENT → exchange adapter
    → journal result → reconcile → deterministic result

Nothing in this module recomputes risk, size, leverage or margin from what the
model asked for. Those come from the gateway, which reads exchange-verified
state. The model's numbers are treated as a request, never as an input to a
safety calculation.

No credentials. No network. No model.
"""

from __future__ import annotations

import os
import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from orbit.audit.cycle import CycleRecorder
from orbit.audit.information import DecisionContext, SeriesRef
from orbit.audit.journal import Journal
from orbit.audit.blobstore import BlobStore
from orbit.audit.derivation import (LocalStateUndecidable,
                                    LocalStateUntrusted, derive_intended)
from orbit.audit.evidence import put as put_evidence
from orbit.audit.records import E, canonical
from orbit.core.precision import BTC_USDT_SWAP as SPEC
from orbit.exec.adapter import (DurableIntentMismatch, ExchangeAdapter,
                                InconsistentOrderSemantics, MissingTargetOrder,
                                WriteAheadViolation)
from orbit.exec.operations import (OperationLedger, Role, logical_key)
from orbit.exec.protection import (build_ladder, canonical_orders,
                                   order_identity)
from orbit.exec.recon import F, ReconResult, reconcile
from orbit.exec.writer import Lease, StaleWriterError, WriterAuthority
from orbit.risk.gateway import Code, Gateway, Kind, ProposedAction
from orbit.risk.limits import A1, A1Limits, RunState
from orbit.tools.registry import ACTION_TOOLS, READ_TOOLS

D = Decimal


class ActionStatus(str, Enum):
    APPROVED = "APPROVED"                 # gateway said yes; not yet sent
    REJECTED = "REJECTED"                 # gateway or policy said no
    SUBMITTED = "SUBMITTED"               # sent; outcome not yet known
    ACKNOWLEDGED = "ACKNOWLEDGED"         # exchange accepted; NOT filled
    FILLED = "FILLED"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    UNKNOWN = "UNKNOWN"                   # timeout: real state not established
    BLOCKED = "BLOCKED"                   # lifecycle forbids it
    REQUIRES_RECONCILIATION = "REQUIRES_RECONCILIATION"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"
    EMERGENCY_STATE = "EMERGENCY_STATE"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    DUPLICATE_SUPPRESSED = "DUPLICATE_SUPPRESSED"
    OPERATION_UNRESOLVED = "OPERATION_UNRESOLVED"
    """SAFETY CLOSURE, blocker A. An earlier request for the SAME logical
    mutation has not reached a terminal outcome. It is not repeated: an
    unestablished outcome must be RESOLVED, never replaced."""


@dataclass(frozen=True)
class ToolResult:
    """A read snapshot. `ref_id` is what a decision may cite."""
    ref_id: str
    tool: str
    instrument: Optional[str]
    params: Dict[str, Any]
    local_ts: str
    server_ts: Optional[str]
    snapshot_id: str
    data_hash: str
    freshness_seconds: float
    source: str
    cycle_id: str
    data: Any

    @property
    def token(self) -> str:
        return f"{self.tool}@{self.ref_id}"


@dataclass(frozen=True)
class ActionResult:
    status: ActionStatus
    code: str
    reason: str
    action_id: Optional[str] = None
    client_order_id: Optional[str] = None
    computed: Dict[str, Any] = field(default_factory=dict)
    exchange_order_id: Optional[str] = None

    @property
    def reached_exchange(self) -> bool:
        return self.status in (ActionStatus.SUBMITTED, ActionStatus.ACKNOWLEDGED,
                               ActionStatus.FILLED,
                               ActionStatus.PARTIALLY_FILLED,
                               ActionStatus.UNKNOWN)


def _h(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode()).hexdigest()[:32]


def _num(x, field: str) -> Decimal:
    """Reject NaN, infinity, and anything that is not a finite decimal.

    `Decimal("NaN")` and `Decimal("Infinity")` both parse. Neither may travel
    any further into a risk calculation."""
    try:
        v = D(str(x))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"{field} is not a number: {x!r}")
    if not v.is_finite():
        raise ValueError(f"{field} must be finite, got {x!r}")
    return v


class DecisionAlreadyFrozen(RuntimeError):
    """One decision, one snapshot. Re-freezing would let the record of what the
    model knew be rewritten after the fact."""


@dataclass(frozen=True)
class DecisionSnapshot:
    """SAFETY CLOSURE, blocker M.

    The information context used to be rebuilt on demand from a MUTABLE list of
    references, so a read performed AFTER a decision still appeared in the
    context that decision was verified against — the check "a decision may cite
    only what its own cycle provided" could be satisfied retroactively. And the
    prompt hash was hash({"cycle": cycle_id}): it recorded the cycle id a second
    time and said nothing whatever about what the model was asked.

    A snapshot is taken once, at the moment of asking, from the references that
    existed then, over the exact prompt text that was sent. It is immutable."""
    decision_id: str
    context: DecisionContext
    frozen_at: str
    prompt_bytes: int

    @property
    def prompt_hash(self) -> str:
        return self.context.prompt_hash


# `LocalStateContradicted` lived here. SAFETY CLOSURE ROUND 4C4: the partial
# comparison that raised it is deleted (C4-I1/C4-I2) and the class went with it,
# so nothing can be written against a mechanism that no longer exists.


class ReentrantAction(RuntimeError):
    """Two actions at once on one ToolSession.

    SAFETY CLOSURE ROUND 4C2, C2-I4. `_auth` and the seal are per-action
    mutable session fields, so the runtime contract they depend on — one action
    at a time, one writer — is now enforced rather than assumed. If concurrent
    actions are ever wanted, they need separate sessions, not a shared one.
    """


class HiddenFetch(RuntimeError):
    """A pre-mutation safety component asked for a second exchange observation.

    SAFETY CLOSURE ROUND 4C, R4-4. Raised rather than tolerated: the defect this
    replaces was invisible precisely because a second fetch looks identical to
    the first at the call site.
    """


@dataclass(frozen=True)
class AuthoritativeState:
    """THE observation one action is authorised against.

    Frozen, identified, and taken under writer authority. `snapshot_id` is a
    digest of what was actually observed together with the writer epoch and the
    action's `now`, so the durable record can point at the evidence rather than
    merely assert that evidence existed.
    """
    snapshot_id: str
    """SAFETY CLOSURE ROUND 4C2, C2-I1/I2. This is now the CONTENT ID of the
    durable evidence artifact, not a digest of a hand-picked field list. The
    identity and the bytes cannot disagree because the identity IS the hash of
    the bytes, and the bytes are on disk before any mutation depends on them."""
    taken_at: datetime
    lease_epoch: Optional[int]
    view: Any
    recon: ReconResult
    evidence: bytes = b""


class ToolSession:
    """One decision cycle's tool surface.

    The writer lease, the authority, the adapter, the gateway and the journal
    are constructor arguments held privately. None of them is reachable through
    a tool, and none of the tool methods accepts a lease, an epoch, a run state,
    a reconciliation verdict or an approval flag as an argument."""

    def __init__(self, cycle_id: str, journal: Journal, recorder: CycleRecorder,
                 authority: WriterAuthority, adapter: ExchangeAdapter,
                 gateway: Gateway, intended_state, exchange_view_fn,
                 now: datetime, lease: Optional[Lease] = None,
                 limits: A1Limits = A1, policy_version: str = "A1",
                 model_id: str = "none"):
        self._cycle_id = cycle_id
        self._journal = journal
        self._rec = recorder
        self._authority = authority
        self._adapter = adapter
        self._gateway = gateway
        # SAFETY CLOSURE ROUND 4C4, N1. THIS IS CALLER MEMORY AND NOTHING ELSE.
        #
        # It used to be `self._intended`: a mutable slot that the READ path
        # reconciled from and that `_authoritative()` overwrote with the
        # journal-derived state. One durable history therefore produced two
        # answers — `get_system_state()` reporting the constructor's memory
        # (HALTED / PHANTOM_POSITION) while the action path derived RUNNING
        # from the same records — and which answer you got depended on whether
        # an action had already run in this session.
        #
        # It is retained ONLY so the existing construction sites keep their
        # signature. Nothing derives, presents or authorises anything from it:
        # every state answer now comes from `_durable_state()`.
        self._ctor_memory = intended_state
        self._view_fn = exchange_view_fn
        self._now = now
        self._lease = lease
        self._limits = limits
        self._policy_version = policy_version
        self._model_id = model_id
        self._refs: List[SeriesRef] = []
        self._results: Dict[str, ToolResult] = {}
        self._recon: Optional[ReconResult] = None
        # SAFETY CLOSURE ROUND 4C, R4-4. One authoritative pre-mutation
        # observation per action, and a seal that makes a second one raise
        # rather than quietly return a different world.
        self._auth: Optional[AuthoritativeState] = None
        # The evidence store lives beside the journal so a separate process,
        # holding only the durable artifacts, can find it without being told.
        self._evidence = BlobStore(
            os.path.join(os.path.dirname(os.path.abspath(journal.path)),
                         "evidence"))
        self._view_sealed = False
        self._in_action = False
        self._action_lock = threading.Lock()
        self._snapshots: Dict[str, DecisionSnapshot] = {}
        # SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 6. THE ONE
        # interpretation of the journal for the current action: the LoadResult
        # read once under writer authority, and the (seq, hash) it ends at.
        # The ledger, idempotency, derivation and evidence all consume it.
        self._pinned: Optional[Tuple[Any, int, str]] = None
        # SAFETY CLOSURE ROUND 4C4, N1. THE state derived from that pinned
        # prefix. Not a second cache to keep in step with a first: it is
        # memoization OF THE PIN, created with it and discarded with it, so it
        # cannot outlive the history it was derived from.
        self._derived: Optional[Any] = None
        # Set when the pinned journal is NOT trusted, so the refusal is not
        # appended to a file whose integrity has just been rejected.
        self._journal_untrusted = False

    # ==================================================================
    # READ TOOLS — snapshot based, every result citable
    # ==================================================================
    def _snapshot(self, tool: str, data: Any, *, instrument=None, params=None,
                  server_ts=None, source="okx-demo(null)",
                  view=None) -> ToolResult:
        """SAFETY CLOSURE ROUND 4C2, C2-I3. ONE ToolResult, ONE observation.

        This helper used to call `_view()` itself, AFTER its caller had already
        derived the data from a different view. `get_positions()` therefore
        returned a position from one world labelled with the freshness of
        another: a 600-second-old long, reported as 1.0 seconds fresh, from an
        account that was flat in the observation the freshness came from.

        The caller now passes the exact view its data came from, so the data,
        the freshness, the server timestamp and the data hash all describe the
        same moment. Tools that do not consume exchange state pass nothing and
        cause no fetch: a placeholder must not reach for the venue merely
        because a generic helper wants a number.
        """
        params = params or {}
        dh = _h(data)
        ref = _h({"cycle": self._cycle_id, "tool": tool, "params": params,
                  "data": dh})
        fresh = (None if view is None
                 else (self._now - view.fetched_at).total_seconds())
        r = ToolResult(ref, tool, instrument, params, self._now.isoformat(),
                       server_ts, _h({"tool": tool, "params": params}), dh,
                       fresh, source, self._cycle_id, data)
        self._refs.append(SeriesRef(tool, ref, r.local_ts,
                                    len(data) if hasattr(data, "__len__") else None))
        self._results[r.token] = r
        return r

    def _view(self):
        if getattr(self, "_view_sealed", False):
            raise HiddenFetch(
                "a pre-mutation safety component asked the exchange for a "
                "second opinion after the authoritative observation was "
                "frozen. Every local decision for one action is made from that "
                "one observation; if a component needs something the snapshot "
                "does not carry, that is a schema problem, not a reason to "
                "fetch again.")
        return self._view_fn()

    def get_market_state(self) -> ToolResult:
        v = self._view()
        return self._snapshot("get_market_state",
                              {"mark_price": str(v.mark_price),
                               "reachable": v.reachable,
                               "fetched_at": str(v.fetched_at)},
                              instrument=self._limits.instrument,
                              server_ts=str(v.server_time) if v.server_time else None,
                              view=v)

    def get_candles(self, timeframe: str = "5m", limit: int = 100) -> ToolResult:
        return self._snapshot("get_candles", {"timeframe": timeframe,
                                              "rows": int(limit)},
                              instrument=self._limits.instrument,
                              params={"timeframe": timeframe, "limit": int(limit)})

    def get_orderbook(self, depth: int = 20) -> ToolResult:
        return self._snapshot("get_orderbook", {"depth": int(depth)},
                              instrument=self._limits.instrument,
                              params={"depth": int(depth)})

    def get_funding(self) -> ToolResult:
        return self._snapshot("get_funding", {"available": False,
                                              "note": "historical funding fetch "
                                                      "is broken (ledger §7)"},
                              instrument=self._limits.instrument)

    def get_open_interest(self) -> ToolResult:
        return self._snapshot("get_open_interest", {"available": False},
                              instrument=self._limits.instrument)

    def get_account_state(self) -> ToolResult:
        v = self._view()
        return self._snapshot("get_account_state",
                              {"equity": str(v.equity),
                               "margin_mode": v.margin_mode.value},
                              view=v)

    def get_positions(self) -> ToolResult:
        v = self._view()
        p = v.position
        return self._snapshot("get_positions", None if p is None else {
            "side": p.side, "contracts": str(p.contracts),
            "entry_price": str(p.entry_price)},
            instrument=self._limits.instrument,
                              view=v)

    def get_open_orders(self) -> ToolResult:
        v = self._view()
        return self._snapshot("get_open_orders",
                              [{"client_order_id": o.client_order_id,
                                "contracts": str(o.contracts),
                                "protective": o.is_protective,
                                "stop_price": str(o.stop_price) if o.stop_price else None}
                               for o in v.open_orders],
                              view=v)

    def get_recent_fills(self) -> ToolResult:
        v = self._view()
        return self._snapshot("get_recent_fills",
                              [{"fill_id": f.fill_id,
                                "client_order_id": f.client_order_id,
                                "contracts": str(f.contracts)} for f in v.fills],
                              view=v)

    def get_recent_trades(self, limit: int = 50) -> ToolResult:
        return self._snapshot("get_recent_trades", {"rows": int(limit)},
                              instrument=self._limits.instrument,
                              params={"limit": int(limit)})

    # SAFETY CLOSURE ROUND 4C4, N1. THE FAIL-CLOSED READ.
    #
    # `_reconcile()` now folds the durable journal, so it can fail the same two
    # ways the authorization path fails. A read tool must not raise out of a
    # tool call — but it must not paper over the failure either. "I cannot
    # establish the durable state" is reported as the most restrictive state
    # there is, with the code that says which kind of failure it was.
    #
    # HALTED is not a guess and it is not an escalation: it is what the
    # authorization path already does with the identical condition, where every
    # action is refused BLOCKED / LOCAL_STATE_*. The two surfaces now say the
    # same thing about the same journal. There is no path here that reaches
    # RUNNING, and none that consults the exchange: the derivation raises
    # before `_view()` is evaluated, so an underivable state is reported
    # without a venue round trip, exactly as the refusal is decided.
    def _read_state(self):
        """(ReconResult, None, "") or (None, failure code, why). Never raises."""
        try:
            return self._reconcile(), None, ""
        except LocalStateUntrusted as e:
            return None, F.LOCAL_STATE_UNTRUSTED, str(e)
        except LocalStateUndecidable as e:
            return None, F.LOCAL_STATE_DERIVATION_FAILED, str(e)

    def get_system_state(self) -> ToolResult:
        r, failed, why = self._read_state()
        if r is None:
            return self._snapshot("get_system_state", {
                "run_state": RunState.HALTED.value,
                "reconciled": False,
                "local_state_trusted": False,
                "findings": [failed.value],
                "detail": why})
        return self._snapshot("get_system_state", {
            "run_state": r.run_state.value,
            "reconciled": r.reconciled,
            "local_state_trusted": r.local_state_trusted,
            "findings": [f.code.value for f in r.findings]},
            view=r.view)

    def get_current_risk_state(self) -> ToolResult:
        r, failed, why = self._read_state()
        if r is None:
            return self._snapshot("get_current_risk_state", {
                "planned_risk_usdt": None,
                "worst_case_protected_loss": None,
                "protective_order_verified": False,
                "note": "the durable local state could not be established, so "
                        "no risk figure can be derived from it. A figure that "
                        "cannot be derived is not zero.",
                "entries_utc_day": None,
                "realized_pnl_utc_day": None,
                "max_daily_loss_usdt": str(self._limits.max_daily_loss_usdt),
                "run_state": RunState.HALTED.value,
                "findings": [failed.value],
                "detail": why})
        prot = r.protection
        return self._snapshot("get_current_risk_state", {
            "planned_risk_usdt": (str(prot.planned_risk_usdt) if prot else None),
            "worst_case_protected_loss": (
                str(prot.worst_case_protected_loss)
                if prot and prot.worst_case_protected_loss is not None else None),
            "protective_order_verified": bool(prot and prot.protective_order_verified),
            "note": "planned risk is NOT a guaranteed maximum loss; a gap fills "
                    "at the next available price",
            # SAFETY CLOSURE ROUND 4C4, N1. These were read from the
            # constructor's memory, so the model could be shown a day figure
            # nobody had derived from durable history — the exact pair of
            # numbers C4-I1 was about, presented rather than authorised.
            # `r.intended` IS the derived state (see `_durable_state`).
            "entries_utc_day": r.intended.entries_utc_day,
            "realized_pnl_utc_day": str(r.intended.realized_pnl_utc_day),
            "max_daily_loss_usdt": str(self._limits.max_daily_loss_usdt)},
            view=r.view)

    # --- RUNNER INFRASTRUCTURE, deliberately private: this is not a
    # --- capability the model is granted, and CAP1 fails if it becomes one.
    def _freeze_decision_snapshot(self, decision_id: str, *,
                                 prompt_text: str) -> DecisionSnapshot:
        """Take THE snapshot for one decision, over the exact prompt sent.

        Called by the runner immediately before the model is asked, never by the
        model. After this returns, further reads are still permitted — they
        simply are not part of what this decision was given, which is the whole
        point."""
        if not isinstance(prompt_text, str) or not prompt_text.strip():
            raise ValueError(
                "a decision snapshot requires the prompt that was actually "
                "sent; there is no auditable record of what the model knew "
                "without it")
        if decision_id in self._snapshots:
            raise DecisionAlreadyFrozen(
                f"decision {decision_id!r} already has a frozen snapshot; a "
                f"second one would let the record of what the model knew be "
                f"rewritten after the fact")
        # SAFETY CLOSURE ROUND 4C, R4-4, adjacent path. Found by the review of
        # the snapshot repair: this took TWO observations — a possibly-cached
        # reconciliation and a fresh view — and mixed them into ONE durable
        # record of what the model knew. `run_state` and `reconciled` described
        # one world while `account_state_id`, `position_state_id` and
        # `open_orders_id` described another. This is not an authorisation path,
        # so it is not what R4-4 named, but it is the same defect: a record that
        # claims to describe one moment and does not. One observation, and every
        # field in the context derived from it.
        # SAFETY CLOSURE ROUND 4C4, N1. The `run_state` this durable record
        # carries is now the DERIVED one, so it is the same answer the model
        # was shown by `get_system_state()` and the same answer the
        # authorization path will reach. When it cannot be derived the
        # derivation raises out of here rather than being softened: this is the
        # runner's path, not a tool call, and a decision must not be framed on
        # a state ORBIT could not establish. There is nothing to write down
        # about what the model knew if ORBIT did not know it either.
        r = self._reconcile(force=True)
        v = r.view
        ctx = DecisionContext(
            cycle_id=self._cycle_id, decision_id=decision_id,
            market_snapshot_as_of=str(v.fetched_at),
            series=tuple(self._refs),                 # a COPY, taken now
            account_state_id=_h({"equity": str(v.equity)}),
            position_state_id=_h(str(v.position)),
            open_orders_id=_h([o.client_order_id for o in v.open_orders]),
            run_state=r.run_state.value, reconciled=r.reconciled,
            local_state_trusted=r.local_state_trusted,
            policy_version=self._policy_version, model_id=self._model_id,
            # a REAL digest of the REAL prompt, not the cycle id restated
            prompt_hash=hashlib.sha256(prompt_text.encode("utf-8")).hexdigest())
        snap = DecisionSnapshot(decision_id, ctx, self._now.isoformat(),
                                len(prompt_text.encode("utf-8")))
        self._snapshots[decision_id] = snap
        self._rec.record_information(ctx)             # durable, with the hash
        return snap

    def _decision_snapshot(self, decision_id: str) -> Optional[DecisionSnapshot]:
        return self._snapshots.get(decision_id)

    # ==================================================================
    # ACTION TOOLS — intent based, never execution
    # ==================================================================
    def propose_order(self, side: str, stop: Any, entry_type: str = "market",
                      entry_price: Any = None, target: Any = None,
                      instrument: Optional[str] = None) -> ActionResult:
        return self._act("propose_order", Kind.OPEN, dict(
            side=side, stop=stop, entry_type=entry_type,
            entry_price=entry_price, target=target,
            instrument=instrument or self._limits.instrument))

    def close_position(self, instrument: Optional[str] = None) -> ActionResult:
        return self._act("close_position", Kind.CLOSE,
                         dict(instrument=instrument or self._limits.instrument))

    def reduce_position(self, fraction: Any,
                        instrument: Optional[str] = None) -> ActionResult:
        return self._act("reduce_position", Kind.REDUCE, dict(
            fraction=fraction, instrument=instrument or self._limits.instrument))

    def modify_stop(self, new_stop: Any,
                    instrument: Optional[str] = None) -> ActionResult:
        return self._act("modify_stop", Kind.MODIFY_STOP, dict(
            new_stop=new_stop, instrument=instrument or self._limits.instrument))

    def cancel_order(self, client_order_id: str,
                     replacement_client_order_id: Optional[str] = None
                     ) -> ActionResult:
        return self._act("cancel_order", None, dict(
            client_order_id=client_order_id,
            replacement_client_order_id=replacement_client_order_id))

    # ==================================================================
    # THE EXECUTOR — the safety ordering, in one place
    # ==================================================================
    # ------------------------------------------------------------------
    # SAFETY CLOSURE ROUND 4C4, N1 — ONE DETERMINISTIC SOURCE OF TRUTH.
    #
    # Every externally relevant answer about what state ORBIT is in — the
    # model-facing read tools, the record of what the model was told, the
    # protection guards and the authorization path — is a function of exactly
    # ONE thing: the durable journal prefix pinned for this session.
    #
    # Before this there were two. `_reconcile()` folded the CONSTRUCTOR's
    # `IntendedState`; `_authoritative()` folded the JOURNAL and then assigned
    # its result over the constructor's. So the same durable history answered
    # HALTED / PHANTOM_POSITION to `get_system_state()` and RUNNING to the
    # authorization path, and the model-facing answer silently changed the
    # first time an action ran. The model was shown one reality and judged by
    # another.
    #
    # The repair is convergence, not synchronization: there is no second state
    # left to keep in step. `derive_intended` is the only fold, the pinned
    # prefix is the only input, and the constructor argument is inert.
    # ------------------------------------------------------------------
    def _durable_state(self):
        """THE local state for this session: derived, from the pinned prefix.

        Raises `LocalStateUntrusted` / `LocalStateUndecidable` exactly as the
        authorization path does. Inability to derive safe state is never
        equivalent to agreement, and it is never equivalent to RUNNING.

        ON THE LIFETIME OF THE PIN. Reads SHARE it, deliberately: two read
        tools in one cycle must not answer from two different prefixes, which
        is the same divergence in miniature. An ACTION does not share it - it
        resets the pin and this derivation on entry and re-reads under its own
        writer fence, so no action is ever authorised against a history a read
        happened to pin first.
        """
        if self._derived is None:
            head, seq, jhash = self._pin_journal()
            self._derived = derive_intended(head, seq=seq, hash_=jhash,
                                            now=self._now, spec=SPEC)
        return self._derived

    def _reconcile(self, force: bool = False) -> ReconResult:
        if force or self._recon is None:
            self._recon = reconcile(self._durable_state(), self._view(),
                                    self._now, self._limits)
        return self._recon

    # ------------------------------------------------------------------
    # SAFETY CLOSURE ROUND 4C — finding R4-4.
    #
    # One model action used to consume FOUR independent observations of the
    # exchange, and described all of them as one authorization:
    #
    #     _reconcile        (step 3, before writer authority)
    #     _reconcile        (step 5, called "authoritative")
    #     _protection_guard (step 6, its own fetch)
    #     _reconcile        (step 11, after the mutation)
    #
    # Steps 3, 5 and 6 are all PRE-MUTATION safety decisions, and each could
    # land on a different world. The same account and the same request produced
    # REJECTED under one call ordering and ACKNOWLEDGED with the cancel actually
    # sent under another. THE VALUE AUTHORISED WAS NOT THE VALUE ACTED UPON.
    #
    # There is now exactly ONE authoritative pre-mutation observation per
    # action, taken under valid writer authority, and every local safety
    # component downstream consumes it.
    #
    # WHAT THIS DOES NOT CLAIM. It does not make execution atomic and it does
    # not stop the exchange changing between observation and execution — nothing
    # local can. The residual race between the authoritative observation and the
    # venue applying the mutation is REAL and stays explicit for the real-adapter
    # design. The property established is narrower and entirely local:
    #
    #     every pre-mutation safety decision for one action is made from the
    #     same observation, under valid writer authority, and that observation
    #     has an identity the audit can point at.
    # ------------------------------------------------------------------
    def _derive_local_state(self, head, seq, jhash):
        """The authorization state, derived. Any failure stops the action.

        SAFETY CLOSURE ROUND 4C4, C4-I2. Every way this can go wrong — an
        untrusted journal, a prefix that is not there, a hash that does not
        match, a malformed counter, a status this build does not know — raises.
        There is no `except Exception: return None` left on the authorization
        path, because "I could not work out the durable state" is not a licence
        to act on someone else's claim about it.
        """
        self._view_sealed = True     # nothing further may fetch, even on refusal
        # Checkpoint A, scope 5: the day figures are derived for the UTC day
        # of THIS session's clock, valued with the same instrument spec the
        # reconciler and the gateway use.
        # SAFETY CLOSURE ROUND 4C4, N1. The fold itself is `_durable_state()`,
        # which the model-facing reads call too. `head`, `seq` and `jhash` are
        # the pin this action already took; they are CHECKED against the pin
        # the derivation uses rather than derived from a second read, so the
        # authorization path can never be folding a different prefix than the
        # one its evidence artifact names. A raise, not an assert: this is a
        # safety check and `python -O` must not remove it.
        if (head, seq, jhash) != self._pin_journal():
            raise LocalStateUndecidable(
                "the prefix this action pinned is not the prefix the shared "
                "derivation would fold. Two histories in one action is the "
                "defect this convergence exists to make impossible.")
        return self._durable_state()

    def _pin_journal(self) -> Tuple[Any, int, str]:
        """Read the journal ONCE for this action and pin the prefix.

        SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 6. Before this an
        action read the file four times - ledger, prior intent, authoritative
        head, entry-in-flight - and each read could see a different prefix.
        The pin is taken AFTER the writer fence, so the history that authorises
        the action was read under the authority about to act.

        SAFETY CLOSURE ROUND 4C4, CHECKPOINT A.2-R, item A2R-3. This read is now
        guaranteed SIDE-EFFECT-FREE. Before A.2-R, `Journal.load` could roll the
        committed-head checkpoint forward — an unlocked WRITE to durable state,
        reached from inside an action — and on the other interleaving it could
        raise `CheckpointRegressed` straight out of this call and escape the
        tool as an exception. Neither is possible now: `classify_head` only
        classifies, the legitimate one-record window arrives as
        `LoadResult.head_window`, and closing it belongs to the append path
        under `AppendLock`. A pure reader cannot regress the head, and an audit
        process that only reads leaves no trace on durable state.
        """
        if self._pinned is None:
            head = Journal.load(self._journal.path)
            seq = head.records[-1]["seq"] if head.records else 0
            jhash = head.records[-1]["hash"] if head.records else ""
            self._pinned = (head, seq, jhash)
        return self._pinned

    # SAFETY CLOSURE ROUND 4C4, C4-I1 and C4-I2. `_journal_contradiction`
    # lived here. It compared a few selected facts and ended in
    # `except Exception: return None`, where None meant "no contradiction". Both
    # halves were wrong: a partial check let durable risk counters be
    # overridden by an in-memory state, and a swallowed exception let a journal
    # that could not be parsed at all authorise a mutation. It is deleted, not
    # widened. Authorization state is now DERIVED (see `_derive_local_state`),
    # so there is nothing left to compare against a caller.
    # SAFETY CLOSURE ROUND 4C3, C3-I3. `_intended_digest` and `_limits_digest`
    # lived here. They hashed in-memory objects and the artifact carried only
    # those hashes, so nothing could ever be compared against them. They are
    # deleted rather than left unused: a helper named "digest" is an invitation
    # to reuse the pattern that was just found wanting. The artifact now carries
    # the state and the limits structurally.
    def _post_mutation_view(self) -> None:
        """Lift the seal. Only legal after the exchange mutation was attempted.

        Nothing that runs after this point may feed an authorisation decision:
        the action is already sent, `self._auth` is fixed, and the snapshot id
        recorded in the durable INTENT names the evidence that authorised it.
        """
        self._view_sealed = False

    def _authoritative(self) -> "AuthoritativeState":
        """Take THE observation for this action. Exactly once."""
        if self._auth is not None:
            raise HiddenFetch(
                "a second authoritative observation was requested for one "
                "action; there is exactly one")
        # SAFETY CLOSURE ROUND 4C2, C2-I1 and C2-I2.
        #
        # The evidence is SERIALIZED AND MADE DURABLE HERE, before the INTENT
        # that references it and long before the mutation that depends on it.
        # Round 4C wrote a digest of nine hand-picked fields and kept the
        # observation only in memory, so after a restart the audit held a name
        # with nothing behind it — and two views differing only in
        # `server_time`, one RUNNING and one HALTED, shared one name.
        #
        # The artifact is a STRUCTURAL serialization of the whole state, and the
        # identity is the content id of those exact bytes. A field added to
        # ExchangeView tomorrow enters both without anyone remembering to.
        # C3-I3. The journal head is READ FROM DISK, not asserted, so the
        # artifact pins the exact immutable prefix the local state was taken
        # against. Later appends cannot move it. Checkpoint A, scope 6: it is
        # the SAME prefix the ledger and the idempotency check consumed.
        head, seq, jhash = self._pin_journal()
        # SAFETY CLOSURE ROUND 4C4, C4-I1. The state this action is authorised
        # against is DERIVED from exactly the prefix pinned above. The
        # constructor argument has no authorization power: it is not consulted
        # here, it is not serialised into the artifact, and it cannot move a
        # risk counter, invent an order, or hide one.
        #
        # Derived BEFORE the exchange is observed: an action whose durable
        # state cannot be established is refused without consulting the venue,
        # and the refusal record can then say truthfully that no observation
        # was taken.
        # SAFETY CLOSURE ROUND 4C4, N1. This used to continue
        # `self._intended = intended`, promoting the derived state over the
        # constructor's so that everything AFTERWARDS saw the right one. That
        # assignment was the divergence: before it ran, the read tools showed
        # the constructor's memory; after it ran, they showed this. There is no
        # slot to promote into any more — `_durable_state()` is what every
        # path already consults, so the reads and this action are folding the
        # same prefix whether an action has run yet or not.
        intended = self._derive_local_state(head, seq, jhash)
        self._view_sealed = False
        # SAFETY CLOSURE ROUND 4C4, N1. Routing this through `_reconcile()` was
        # tried and REVERTED. It would have left one `reconcile()` call site,
        # but THE AUTHORITATIVE PRE-MUTATION OBSERVATION WOULD NO LONGER HAVE
        # BEEN TAKEN HERE — it would have been taken inside the same helper the
        # POST-mutation reconciliation uses, and R4C.1 (which attributes every
        # venue fetch to the frame that asked for it) could no longer tell the
        # one from the other. The boundary the seal enforces is worth more than
        # a single call site. What N1 requires is not one CALL SITE but one
        # DERIVATION, and `intended` here is exactly `_durable_state()`: the
        # same object, from the same pinned prefix, that the model-facing reads
        # are answered from.
        view = self._view()
        recon = reconcile(intended, view, self._now, self._limits)
        self._recon = recon
        cid, blob = put_evidence(
            self._evidence,
            view=view, now=self._now,
            lease_epoch=(self._lease.epoch if self._lease is not None else None),
            intended=intended, limits=self._limits,
            policy_version=self._policy_version,
            journal_seq=seq, journal_hash=jhash)
        self._auth = AuthoritativeState(
            snapshot_id=cid, taken_at=self._now,
            lease_epoch=(self._lease.epoch if self._lease is not None else None),
            view=view, recon=recon, evidence=blob)
        # From here to the exchange mutation, a fetch is a defect, not a
        # judgement call. Sealing makes it raise instead of quietly returning a
        # different world — the failure mode that produced R4-4 was that the
        # second fetch looked exactly like the first.
        self._view_sealed = True
        return self._auth

    # `_action_id` (hash of cycle_id + tool + params) is DELETED. It was the
    # cause of the duplicate-mutation defect: the same logical request in the
    # next cycle produced a different identity, a different client order id, and
    # a second external mutation for one intent. Identity now comes from
    # `orbit.exec.operations`, which is derived from what the mutation IS and
    # advances a generation only when an operation genuinely terminates.

    @staticmethod
    def _fingerprint(tool: str, params: Dict[str, Any]) -> str:
        return _h({"tool": tool, "params": params})

    @staticmethod
    def _operation_shape(tool: str, kind: Optional[Kind],
                         norm: Dict[str, Any]):
        """(order_kind, side_for_the_key, target_order, role, reduce_only).

        `side_for_the_key` is present only where it distinguishes two genuinely
        different mutations. A CLOSE is a CLOSE whichever way the position
        happens to be facing, so including the side there would let one logical
        exit be requested twice under two identities.

        `role` and `reduce_only` travel from here all the way to the exchange
        boundary, which refuses to send an order whose two disagree."""
        if tool == "propose_order":
            return "OPEN", norm.get("side"), None, Role.ENTRY.value, False
        if tool == "close_position":
            return "CLOSE", None, None, Role.EXIT.value, True
        if tool == "reduce_position":
            return "REDUCE", None, None, Role.EXIT.value, True
        if tool == "modify_stop":
            return "MODIFY_STOP", None, None, Role.ADMIN.value, True
        if tool == "cancel_order":
            return "CANCEL", None, norm.get("client_order_id"), \
                   Role.ADMIN.value, False
        raise ValueError(f"{tool} has no operation shape")

    # `_entry_in_flight` lived here. SAFETY CLOSURE ROUND 4C4, checkpoint A,
    # scope item 6: it was a FOURTH reader of the journal with its OWN
    # terminality rule (any FILL was terminal, so a partially filled entry did
    # not occupy the slot). The derived IntendedState is now built from the
    # pinned prefix inside the same action, so `ReconResult.entry_in_flight()`
    # - which treats PARTIALLY_FILLED as nonterminal - is the one definition.

    def _prior_intent(self, action_id: str) -> Optional[Dict[str, Any]]:
        head, _, _ = self._pin_journal()
        for rec in head.records:
            for ev in rec["events"]:
                if ev["e"] in (E.INTENT.value, E.PROTECTIVE_INTENT.value) \
                        and ev.get("action_id") == action_id:
                    return ev
        return None

    # ------------------------------------------------------------------
    def _validate(self, tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool not in ACTION_TOOLS:
            raise ValueError(f"{tool} is not an action capability")
        inst = params.get("instrument")
        if inst is not None and inst != self._limits.instrument:
            raise ValueError(f"instrument {inst!r} is not permitted; A1 trades "
                             f"only {self._limits.instrument}")
        out = dict(params)
        if tool == "propose_order":
            if params.get("side") not in ("long", "short"):
                raise ValueError(f"side must be long or short, got {params.get('side')!r}")
            if params.get("stop") is None:
                raise ValueError("a stop is mandatory: no position may be opened "
                                 "without a defined maximum-loss boundary")
            out["stop"] = _num(params["stop"], "stop")
            if out["stop"] <= 0:
                raise ValueError("stop must be positive")
            if params.get("entry_type") not in ("market", "limit"):
                raise ValueError("entry_type must be market or limit")
            if params.get("entry_price") is not None:
                out["entry_price"] = _num(params["entry_price"], "entry_price")
            if params.get("target") is not None:
                out["target"] = _num(params["target"], "target")
        elif tool == "reduce_position":
            f = _num(params.get("fraction"), "fraction")
            if not (0 < f < 1):
                raise ValueError("fraction must be strictly between 0 and 1; "
                                 "use close_position for a full exit")
            out["fraction"] = f
        elif tool == "modify_stop":
            out["new_stop"] = _num(params.get("new_stop"), "new_stop")
            if out["new_stop"] <= 0:
                raise ValueError("new_stop must be positive")
        elif tool == "cancel_order":
            if not isinstance(params.get("client_order_id"), str) \
                    or not params["client_order_id"].strip():
                raise ValueError("client_order_id must be a non-empty string")
        return {k: (str(v) if isinstance(v, Decimal) else v)
                for k, v in out.items()}

    # ------------------------------------------------------------------
    def _lifecycle_gate(self, kind: Optional[Kind], r: ReconResult
                        ) -> Optional[ActionResult]:
        from orbit.exec.recon import Disposition
        if r.worst is Disposition.EMERGENCY_CLOSE:
            return ActionResult(ActionStatus.EMERGENCY_STATE, "EMERGENCY_CLOSE",
                                "Python is protecting or flattening the "
                                "position; agent actions are not accepted")
        if r.run_state is RunState.HALTED:
            return ActionResult(ActionStatus.REQUIRES_HUMAN_REVIEW, "HALTED",
                                "a human must clear the halt before any action")
        if not r.reconciled:
            return ActionResult(ActionStatus.REQUIRES_RECONCILIATION,
                                "NOT_RECONCILED",
                                "the exchange view is not trustworthy")
        if kind is Kind.OPEN and r.run_state is not RunState.RUNNING:
            return ActionResult(ActionStatus.BLOCKED, r.run_state.value,
                                "new entries are not permitted in this state; "
                                "risk-reducing actions remain available")
        return None

    # ------------------------------------------------------------------
    # SAFETY CLOSURE ROUND 4B — R4-1 and R4-3.
    #
    #     AN ORDER MAY AFFECT ACCOUNT-STATE SAFETY WITHOUT BEING AN ORDER THE
    #     MODEL IS AUTHORISED TO MUTATE.
    #
    # Reconciliation must see an operator's manual stop: it is real, it rests on
    # the account, and the position's risk depends on it. Seeing it is not
    # authority over it. VISIBILITY IS NOT OWNERSHIP; ACCOUNTING IS NOT
    # AUTHORITY.
    #
    # Before this round the rule existed once, inline, for `cancel_order`.
    # `modify_stop` derived its target from `Position.stop_order_id` — which
    # reconciliation fills from the ladder's WORST resting slice, alien slices
    # included — and mutated it with no ownership test at all. The same identity
    # was refused by one tool and amended by the other.
    #
    # ONE predicate now, called from every site that mutates an existing order,
    # so a tool cannot acquire its own private notion of ownership.
    # ------------------------------------------------------------------
    @staticmethod
    def _owned(ledger: OperationLedger, cid: Optional[str],
               observed=None) -> bool:
        """May the model mutate this resting order?

        SAFETY CLOSURE ROUND 4B2, finding I1. This used to be
        `ledger.owns(cid)` — "an INTENT once existed" — which granted authority
        for ever regardless of what the durable lifecycle later proved. The
        ledger now separates historical authorship from live ownership from
        authority to mutate, and this is the third of those.
        """
        return ledger.resting_authority(cid, observed)[0]

    def _require_owned(self, ledger: OperationLedger, cid: Optional[str],
                       what: str, observed=None) -> Optional[ActionResult]:
        ok, code, why = ledger.resting_authority(cid, observed)
        if ok:
            return None
        return ActionResult(
            ActionStatus.REJECTED, code,
            f"{why} It may therefore not be used as {what}. Reconciliation may "
            f"still count this order when it works out what the account "
            f"actually holds; that is accounting, not authority.")

    # ------------------------------------------------------------------
    def _protection_guard(self, tool: str, p: Dict[str, Any],
                          auth: "AuthoritativeState",
                          ledger: OperationLedger) -> Optional[ActionResult]:
        """Step 6G. A position must never knowingly become unprotected because
        the model asked for something.

        SAFETY CLOSURE ROUND 4C, R4-4. This took its own exchange observation
        and therefore judged protection in a world the gateway never saw. It now
        consumes the authoritative snapshot it is handed. It cannot fetch: the
        view is sealed for the rest of the pre-mutation window.
        """
        v = auth.view
        pos = v.position
        # SAFETY CLOSURE ROUND 4A, R4-2. This guard counted coverage by summing
        # `view.open_orders` DIRECTLY, so it inherited the defect the protection
        # model was repaired for: with one 1.19 stop listed twice against a 2.38
        # position, `reduce_position(0.4)` was ACKNOWLEDGED, and with the same
        # account listed once it was REJECTED. One venue order counts once
        # HERE TOO — the invariant belongs to the identity rule, not to whichever
        # component happens to be asking.
        orders, order_conflicts = canonical_orders(v.open_orders)
        prot = [o for o in orders if o.is_protective]

        # SAFETY CLOSURE ROUND 4B, R4-3. A contradictory duplicate cannot
        # authorise anything: R4A already halts reconciliation on it, and this
        # guard must not reach a different conclusion from the same rows.
        if order_conflicts:
            return ActionResult(
                ActionStatus.REJECTED, "EXCHANGE_ORDERS_CONTRADICTORY",
                "the exchange returned irreconcilable representations of the "
                "same order in one fetch: "
                + "; ".join(c.describe() for c in order_conflicts)
                + ". Protection cannot be established from a list that "
                  "contradicts itself.")

        if tool == "cancel_order":
            target = next((o for o in orders
                           if o.client_order_id == p["client_order_id"]), None)
            if target is None:
                return ActionResult(ActionStatus.REJECTED, "NO_SUCH_ORDER",
                                    f"no open order {p['client_order_id']!r}")
            if target.is_protective and pos is not None:
                bad = self._require_owned(ledger, p["client_order_id"],
                                          "a cancellation target", target)
                if bad is not None:
                    return bad
                bad = self._replacement_gate(p, target, pos, prot, ledger)
                if bad is not None:
                    return bad
        if tool == "reduce_position":
            if pos is None:
                return ActionResult(ActionStatus.REJECTED, "NO_POSITION",
                                    "no position to reduce")
            # Found by the round-4B review of this guard: the cancel branch was
            # routed through the shared model and this one was not, so the two
            # branches of ONE function still disagreed about what protection is.
            # It summed `contracts` over every protective row, unreadable stop
            # prices included, and permitted a reduction behind protection the
            # reconciler had already called uncovered — R4-3, on the other tool.
            # Ownership is deliberately NOT required here: an operator's stop
            # genuinely protects the remainder, and a reduction does not mutate
            # it. That is accounting, which is exactly what this branch needs.
            remaining = pos.contracts * (D("1") - D(p["fraction"]))
            after = build_ladder(prot, remaining, pos.side)
            covered = after.covered_contracts
            if covered < remaining:
                return ActionResult(
                    ActionStatus.REJECTED, "PROTECTION_WOULD_NOT_COVER_REMAINDER",
                    f"after this reduction protective orders would cover "
                    f"{covered} of {remaining} remaining contracts")
            # SAFETY CLOSURE ROUND 4B2, finding I3.
            #
            # Round 4B routed this branch through the shared model and then read
            # only `covered_contracts`. Under-coverage was refused; OVER-coverage
            # was not even looked at. A 2.38 position behind a 2.38 stop, reduced
            # by half, leaves 1.19 of position behind 2.38 of stop — which
            # blocker D established is not over-protection but a REVERSAL: on
            # trigger it closes the position AND opens the opposite one, at the
            # worst possible moment, with no stop of its own. The reconciler
            # calls that STOP_SIZE_OVER_COVERS and stops trading; the guard was
            # authorising the action that creates it.
            #
            # "A reduction mutates nothing, so an alien stop is accounting" was
            # my own sentence in the 4B closure note and it was wrong. A
            # reduction mutates POSITION SIZE, which is one side of the
            # relationship every resting protective order stands in. When the
            # oversized remnant is an operator's manual stop, ORBIT is not even
            # permitted to resize it.
            #
            # NOTHING HERE MAY DEPEND ON N7. There is no atomic
            # reduce-and-resize primitive: a fill and a later amendment are two
            # exchange mutations, and a timeout or a crash between them leaves
            # exactly the reversal state above with no component in existence to
            # repair it. So the safe post-reduction relationship must hold from
            # the primitives A1 HAS — which means the resting protection must
            # already be sized to the remainder.
            #
            # A partial reduction is therefore available only when protection
            # already fits what would be left. CLOSE remains available in every
            # state as the full risk-reducing escape, and it needs no such
            # proof because it leaves no position for a stop to over-cover.
            if after.total_contracts > remaining:
                return ActionResult(
                    ActionStatus.REJECTED, "PROTECTION_WOULD_OVER_COVER_REMAINDER",
                    f"after this reduction {after.total_contracts} contracts of "
                    f"protective orders would rest against {remaining} "
                    f"remaining contracts. The excess does not over-protect: on "
                    f"trigger it would close the position and open the opposite "
                    f"one, unprotected. Resizing protection is a second exchange "
                    f"mutation that is not atomic with this fill, so the "
                    f"remainder must already be correctly protected before the "
                    f"reduction, or the position must be closed instead.")
        return None

    # ------------------------------------------------------------------
    def _replacement_gate(self, p, target, pos, prot,
                          ledger: OperationLedger) -> Optional[ActionResult]:
        """SAFETY CLOSURE ROUND 4B, R4-3. ONE definition of a valid replacement.

        R4-3 existed because reconciliation and this guard answered the same
        question — is this position protected — by two mechanisms that
        disagreed. The reconciler holds that an unreadable stop price is not
        protection and those contracts are uncovered; this guard skipped its
        price comparison entirely when the price was None, and accepted the very
        order the reconciler had refused to count. It also never asked whether
        the replacement was ORBIT's at all.

        The question is not "does `replacement_client_order_id` name a row".
        It is: IF THE TARGET DISAPPEARS, IS THE REMAINING PROTECTION THAT ORBIT
        CAN ACTUALLY VOUCH FOR STILL SUFFICIENT, JUDGED BY THE SAME MODEL
        RECONCILIATION USES? So the hypothetical post-cancel state is built with
        `build_ladder` — the shared primitive, with R4A's identity rule inside
        it — instead of protection arithmetic written a second time here.

        No exchange state is mutated to evaluate it, and no new fetch is taken:
        the rows are the ones already in hand.
        """
        rep_id = p.get("replacement_client_order_id")
        # Found by the round-4B review of this gate: with no replacement named,
        # `rep_id` was None and the lookup below matched the first ANONYMOUS
        # protective row, whose `client_order_id` is also None. An unnamed row
        # would then have been considered as the replacement, and was refused
        # only because it could not be owned. A replacement must be NAMED.
        if not rep_id:
            return ActionResult(
                ActionStatus.REJECTED, "PROTECTION_WOULD_BE_REMOVED",
                "cancelling the protective order would leave an open position "
                "unprotected; a replacement must be named, and must be durably "
                "established on the exchange FIRST")
        rep = next((o for o in prot if o.client_order_id == rep_id), None)
        if rep is None:
            return ActionResult(
                ActionStatus.REJECTED, "PROTECTION_WOULD_BE_REMOVED",
                "cancelling the protective order would leave an open position "
                "unprotected; a replacement must be durably established on the "
                "exchange FIRST")

        # AUTHORITY. An alien stop may keep the account safe; it cannot be
        # cited as ORBIT's replacement, because ORBIT cannot vouch for it,
        # cannot amend it, and whoever placed it can withdraw it.
        not_ours = self._require_owned(ledger, rep_id,
                                       "an authorised replacement", rep)
        if not_ours is not None:
            return not_ours

        # UNKNOWN IS NOT SAFE. Not inferred, not defaulted, not silently
        # converted into valid protection.
        if rep.stop_price is None:
            return ActionResult(
                ActionStatus.REJECTED, "REPLACEMENT_STOP_PRICE_UNKNOWN",
                f"the stop price of replacement {rep_id!r} could not be read. "
                f"Unreadable protection is not protection — reconciliation "
                f"treats those contracts as uncovered, and this guard reaches "
                f"the same conclusion from the same rows.")

        # THE STATE THAT WOULD EXIST AFTER CANCELLATION, judged by the shared
        # model. Only orders ORBIT owns are counted: this is the protection the
        # model may RELY on, which is a narrower set than the protection the
        # account happens to have.
        remaining = [o for o in prot
                     if order_identity(o) != order_identity(target)
                     and self._owned(ledger, o.client_order_id)]
        after = build_ladder(remaining, pos.contracts, pos.side)
        if after.covered_contracts < pos.contracts:
            return ActionResult(
                ActionStatus.REJECTED, "REPLACEMENT_UNDER_COVERS",
                f"after this cancellation, protective orders ORBIT can vouch "
                f"for and read would cover {after.covered_contracts} of "
                f"{pos.contracts} contracts")
        worst = after.worst_slice(pos.side)
        if worst is None or worst.stop_price is None:
            return ActionResult(
                ActionStatus.REJECTED, "REPLACEMENT_STOP_PRICE_UNKNOWN",
                "after this cancellation no readable stop price would remain")
        # SAFETY CLOSURE ROUND 4B2, finding I2. UNKNOWN IS NOT SAFE, SYMMETRICALLY.
        #
        # Round 4B required the REPLACEMENT price to be readable and then
        # compared it only `if target.stop_price is not None`. An unreadable
        # TARGET price therefore skipped the comparison altogether, and a
        # cancellation was authorised that left protection at 29000 against an
        # authorised stop of 29700.1 — a state the reconciler immediately calls
        # STOP_PRICE_WIDER_THAN_INTENDED.
        #
        # The rule is not "refuse anything involving an unreadable order". It is
        # that no cancellation may be authorised unless it can be PROVED not to
        # widen risk, and there are TWO bounds it must be proved against:
        #
        #   the TARGET's own price, when readable — do not widen what rests now;
        #   the AUTHORISED stop, always — do not widen beyond what the gateway
        #   approved for this position.
        #
        # The second bound does not depend on the target being readable, so an
        # unreadable target is still provable: a replacement at or tighter than
        # the authorised stop cannot widen authorised risk whatever the
        # unreadable row was. Only when NEITHER bound is available is the claim
        # unprovable, and then it fails closed.
        # SAFETY CLOSURE ROUND 4C4, N1. The authorised stop comes from the
        # DERIVED durable state, the same fold the gateway and the model-facing
        # report consume. It reached this guard through `self._intended`, which
        # held the derived state only because `_authoritative()` had overwritten
        # it moments earlier — correct by ordering, which is not a property.
        _durable = self._durable_state()
        authorised = (_durable.position.stop_price
                      if _durable.position is not None else None)
        bounds = [("the order being cancelled", target.stop_price),
                  ("the authorised stop", authorised)]
        bounds = [(w, b) for w, b in bounds if b is not None]
        if not bounds:
            return ActionResult(
                ActionStatus.REJECTED, "CANNOT_PROVE_NO_WIDENING",
                "neither the stop price of the order being cancelled nor an "
                "authorised stop price is readable, so it cannot be proved "
                "that this cancellation does not widen risk. Unknown is not "
                "safe in either direction.")
        for what, bound in bounds:
            widens = ((worst.stop_price < bound) if pos.side == "long"
                      else (worst.stop_price > bound))
            if widens:
                return ActionResult(
                    ActionStatus.REJECTED, "REPLACEMENT_LESS_PROTECTIVE",
                    f"the worst stop remaining afterwards, {worst.stop_price}, "
                    f"is further from entry than {what} ({bound}): this widens "
                    f"risk by another route")
        return None

    # ------------------------------------------------------------------
    def _act(self, tool: str, kind: Optional[Kind],
             params: Dict[str, Any]) -> ActionResult:
        """SAFETY CLOSURE ROUND 4C2, C2-I4. The seal is ACTION-LOCAL.

        Round 4C reset it on entry and lifted it only on the successful path
        after an adapter attempt, so every early return — lifecycle, protection,
        gateway, ownership, stale writer, adapter refusal — left the session
        sealed and poisoned the next unrelated read with HiddenFetch. A flat
        account's `close_position()` returned NO_POSITION and then broke
        `get_positions()`.

        Lifting it before individual returns would be the same bug waiting for
        the next return path someone adds. It is lifted in a `finally`, so
        every exit — including an exception — clears it, and no future return
        can forget.
        """
        # SAFETY CLOSURE ROUND 4C3, C3-I5. This was `if self._in_action: raise`
        # followed by `self._in_action = True` — a check and a set with a gap
        # between them. Two threads sharing one session both read False and both
        # entered, then both manipulated `_auth`, `_view_sealed` and `_recon`,
        # and a mutation went out. A boolean is not mutual exclusion.
        #
        # The contract is: AT MOST ONE ACTION PER ToolSession AT A TIME. It is
        # now enforced by an atomic non-blocking acquire, so the loser is
        # refused deterministically rather than queued — waiting would let it
        # act on an observation taken before the winner's mutation. The lock is
        # per session, so unrelated sessions are never serialised, and
        # WriterAuthority remains the separate cross-process rule it always was.
        if not self._action_lock.acquire(blocking=False):
            raise ReentrantAction(
                "ToolSession is single-writer and non-reentrant: one action at "
                "a time. A concurrent or nested action would reset this "
                "action's authoritative snapshot and its seal, which is "
                "precisely the discipline they exist to enforce.")
        self._in_action = True
        try:
            return self._act_locked(tool, kind, params)
        finally:
            # The action is over, however it ended. Its seal governs its own
            # pre-mutation window and nothing after it. Ownership is released
            # LAST, so no other thread can observe a half-cleared session.
            self._auth = None
            self._pinned = None
            # SAFETY CLOSURE ROUND 4C4, N1. The derivation is memoization OF
            # THE PIN and is discarded WITH it, never separately. A derived
            # state that outlived its prefix would be the stale cache this
            # finding was about, wearing the authoritative name.
            self._derived = None
            self._journal_untrusted = False
            self._view_sealed = False
            self._in_action = False
            self._action_lock.release()

    def _act_locked(self, tool: str, kind: Optional[Kind],
                    params: Dict[str, Any]) -> ActionResult:
        # 0 — ONE ACTION, ONE AUTHORITATIVE OBSERVATION.
        #     Found by the round-4C review of this repair: the "exactly once"
        #     guard was scoped to the SESSION, and one session legitimately
        #     serves several actions (an OPEN followed by a CLOSE in the same
        #     cycle). The scope of the invariant is the ACTION, so the snapshot
        #     and the seal are reset here, on entry, and the guard inside
        #     `_authoritative` then means what it says.
        self._auth = None
        self._view_sealed = False
        # Checkpoint A, scope 6: the pin is ACTION-LOCAL too. A standalone
        # `_authoritative()` (the runner's, or a test's) pins a prefix; an
        # action that followed would otherwise inherit a history read before
        # its own writer fence. Reset on entry, as `_auth` is.
        self._pinned = None
        self._derived = None
        self._journal_untrusted = False

        # 1 — SCHEMA
        try:
            norm = self._validate(tool, params)
        except ValueError as e:
            return self._final(tool, None, ActionResult(
                ActionStatus.REJECTED, "MALFORMED", str(e)))

        # 2 — WRITER AUTHORITY FIRST (fenced, from durable state)
        #     SAFETY CLOSURE ROUND 4C, R4-4. This used to run a lifecycle gate
        #     against a PRE-AUTHORITY observation and then take a second one
        #     under authority. Both were pre-mutation safety decisions on
        #     different worlds. Authority is now established BEFORE the
        #     authoritative observation, so the one observation every check
        #     consumes is taken while this worker holds the right to act.
        #     SAFETY CLOSURE ROUND 4C4, checkpoint A, scope 6: and BEFORE the
        #     journal is read, so the one pinned prefix every durable check
        #     consumes was read under that same authority.
        try:
            self._authority.fence(self._lease)
        except StaleWriterError as e:
            return self._final(tool, None, ActionResult(
                ActionStatus.BLOCKED, "STALE_WRITER", str(e)))

        # 3 — THE ONE PINNED JOURNAL INTERPRETATION. Read once, here. An
        #     untrusted journal ends the action now: a ledger, an idempotency
        #     decision or a derived state built from records whose integrity
        #     is rejected would be a decision built on nothing.
        head, _, _ = self._pin_journal()
        if not head.trusted:
            self._journal_untrusted = True
            return self._final(tool, None, ActionResult(
                ActionStatus.BLOCKED, "LOCAL_STATE_UNTRUSTED",
                f"the journal is not trusted "
                f"({head.reason or 'no reason given'}), so no local state can "
                f"be derived from it and no mutation can be authorised."))

        # 4 — LOGICAL OPERATION IDENTITY, from the pinned prefix, before
        #     anything external. Identity used to be hash(cycle_id, tool,
        #     params), so the SAME mutation proposed in a later cycle got a NEW
        #     client order id and a SECOND external mutation was sent for one
        #     logical intent. UNKNOWN DOES NOT MEAN FAILED.
        ledger = OperationLedger.from_records(head.records, self._journal.path)
        order_kind, key_side, target_cid, role, reduce_only = \
            self._operation_shape(tool, kind, norm)

        # 2a — OWNERSHIP. The model may act only on orders ORBIT created.
        #      Existence on the exchange was previously the only test, so any
        #      order in the account — an operator's manual order, another
        #      system's — could be cancelled on the model's say-so.
        if tool == "cancel_order":
            bad = self._require_owned(ledger, target_cid, "a cancellation target")
            if bad is not None:
                return self._final(tool, None, bad)

        op, blocking = ledger.new_operation(
            instrument=norm.get("instrument", self._limits.instrument),
            kind=order_kind, role=role, reduce_only=reduce_only,
            side=key_side, contracts=None, target_client_order_id=target_cid)
        if op is None:
            # An unresolved operation holds the key. Its identity is the one a
            # new request would mint, so the durable checks below are what
            # normally decide; this branch stands for a journal whose intent
            # records do not line up with it, and it refuses either way.
            op = blocking

        action_id = op.operation_id
        fp = self._fingerprint(tool, norm)

        # 2b — IDEMPOTENCY, now DURABLE ACROSS CYCLES AND RESTARTS.
        #      This machinery existed. It did not work, because `action_id`
        #      contained the cycle id, so the same request in the next cycle was
        #      a different action and passed straight through. Removing the
        #      cycle id alone would have made every later identical request a
        #      permanent duplicate; the generation counter in the operation
        #      ledger is the other half, and it advances only on TERMINATION.
        prior = self._prior_intent(action_id)
        if prior is not None:
            if prior.get("fingerprint") == fp:
                return self._final(tool, action_id, ActionResult(
                    ActionStatus.DUPLICATE_SUPPRESSED, "DUPLICATE",
                    "an identical action is already journalled; no second "
                    "exchange action will be taken", action_id,
                    prior.get("client_order_id")))
            if prior.get("client_order_id") == op.client_order_id \
                    and blocking is not None:
                return self._final(tool, action_id, ActionResult(
                    ActionStatus.OPERATION_UNRESOLVED, "OPERATION_UNRESOLVED",
                    f"an earlier {order_kind} for this instrument reached the "
                    f"exchange and its outcome is still "
                    f"{blocking.status.value}. It must be RESOLVED, not "
                    f"replaced: an unestablished outcome is not a failed one, "
                    f"and a second mutation could execute the same intent "
                    f"twice.", action_id, blocking.client_order_id))
            return self._final(tool, action_id, ActionResult(
                ActionStatus.IDENTITY_CONFLICT, "IDENTITY_CONFLICT",
                "this action id already exists in the journal with different "
                "parameters", action_id))
        if blocking is not None:
            return self._final(tool, action_id, ActionResult(
                ActionStatus.OPERATION_UNRESOLVED, "OPERATION_UNRESOLVED",
                f"an earlier {order_kind} for this instrument is still "
                f"{blocking.status.value} and must be resolved first",
                action_id, blocking.client_order_id))

        # 4c — ONE UNRESOLVED ECONOMIC EXIT BLOCKS EVERY FURTHER MODEL-DRIVEN
        #      MUTATION. SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 7.
        #
        #      A CLOSE or a REDUCE whose outcome is not established may or
        #      may not have changed the position. Until reconciliation says
        #      which, the account's exposure is UNKNOWN, and every mutation
        #      the model could ask for is a mutation against unknown state:
        #      a stop amendment for a position that may be gone, a reduction
        #      of a position that may already be flat, an entry beside an
        #      exit that may still execute, a cancellation of the protection
        #      that may be the only thing standing. Idempotency above already
        #      refuses the SAME exit; this refuses everything ELSE, from the
        #      pinned durable record, before any exchange observation.
        #
        #      Before this the old A12 assertion was met - or missed - by the
        #      reconciler's distrust of the view after an UNKNOWN submission,
        #      a rule that says nothing about exits and does not cover an
        #      exit that is merely PENDING or ACK. The rule now exists
        #      explicitly and carries its own code.
        exits = [o for o in ledger.unresolved()
                 if o.role in (Role.EXIT, Role.EXIT.value)
                 and o.operation_id != action_id]
        if exits:
            ex = exits[0]
            return self._final(tool, action_id, ActionResult(
                ActionStatus.OPERATION_UNRESOLVED, "EXIT_UNRESOLVED",
                f"a {ex.kind} for this instrument is still {ex.status.value}: "
                f"the position may or may not have changed, so its exposure "
                f"is not established. No further model-driven position or "
                f"stop mutation is accepted until that exit reaches a "
                f"terminal outcome through reconciliation. Waiting is safe; "
                f"acting on unknown exposure is not.",
                action_id, ex.client_order_id))

        # 5 — THE AUTHORITATIVE OBSERVATION. Once, here, under authority.
        #     SAFETY CLOSURE ROUND 4C4, C4-I2. A failure to establish the
        #     durable local state becomes a REFUSAL with a stable code, and it
        #     is recorded, rather than an exception escaping a tool call. The
        #     two codes are kept apart on purpose: an operator needs to tell a
        #     journal that cannot be trusted from one that cannot be parsed.
        try:
            auth = self._authoritative()
        except LocalStateUntrusted as e:
            return self._final(tool, action_id, ActionResult(
                ActionStatus.BLOCKED, "LOCAL_STATE_UNTRUSTED", str(e),
                action_id))
        except LocalStateUndecidable as e:
            return self._final(tool, action_id, ActionResult(
                ActionStatus.BLOCKED, "LOCAL_STATE_DERIVATION_FAILED", str(e),
                action_id))
        r = auth.recon

        # 5 — LIFECYCLE, from the authoritative state
        gate = self._lifecycle_gate(kind, r)
        if gate is not None:
            return self._final(tool, action_id, gate)

        # 6 — PROTECTION INVARIANTS, from the SAME authoritative state
        guard = self._protection_guard(tool, norm, auth, ledger)
        if guard is not None:
            return self._final(tool, action_id, guard)

        # 7 — DETERMINISTIC GATEWAY
        if kind is not None:
            act = ProposedAction(
                decision_id=action_id, kind=kind,
                symbol=norm.get("instrument", self._limits.instrument),
                side=norm.get("side"),
                entry_type=norm.get("entry_type"),
                entry_price=(D(norm["entry_price"])
                             if norm.get("entry_price") else None),
                stop=D(norm["stop"]) if norm.get("stop") else None,
                target=D(norm["target"]) if norm.get("target") else None,
                reduce_fraction=(D(norm["fraction"])
                                 if norm.get("fraction") else None),
                new_stop=(D(norm["new_stop"]) if norm.get("new_stop") else None))
            v = self._gateway.evaluate(
                act, r.to_system_state(self._limits))
            self._rec.record_gateway_verdict(
                action_id, v.approved, v.code.value, v.reason, v.computed,
                {"contracts": str(v.order.contracts)} if v.order else None)
            if not v.approved:
                return self._final(tool, action_id, ActionResult(
                    ActionStatus.REJECTED, v.code.value, v.reason, action_id,
                    computed=v.computed))
            order = v.order
            cid, contracts = order.client_order_id, order.contracts
            # The gateway derives the client order id from the decision id,
            # which IS the logical operation id, so the two agree by
            # construction. Asserted rather than assumed.
            if cid != op.client_order_id:
                return self._final(tool, action_id, ActionResult(
                    ActionStatus.IDENTITY_CONFLICT, "IDENTITY_CONFLICT",
                    f"the gateway produced client order id {cid} for logical "
                    f"operation {op.operation_id}, which expects "
                    f"{op.client_order_id}", action_id))
            if order.target_client_order_id:
                target_cid = order.target_client_order_id
                # 7a — SAFETY CLOSURE ROUND 4B, R4-1. The SAME ownership
                #      predicate the cancellation gate uses, applied to the
                #      target a stop amendment ends up addressed to. That
                #      target is derived from `Position.stop_order_id`, which
                #      reconciliation fills from the ladder's worst resting
                #      slice — and an alien slice adopted for RISK ACCOUNTING
                #      does not thereby become an order the model may MUTATE.
                #      Refused outright: the amendment is NOT silently
                #      retargeted at some other owned stop, because the model
                #      asked to move THIS one.
                _row = next((o for o in canonical_orders(r.view.open_orders)[0]
                             if o.client_order_id == target_cid), None)
                bad = self._require_owned(ledger, target_cid,
                                          "the target of a stop amendment",
                                          _row)
                if bad is not None:
                    return self._final(tool, action_id, bad)
        else:
            order = None
            cid = op.client_order_id          # the MUTATION's own identity
            contracts = None
            self._rec.record_gateway_verdict(action_id, True, "OK",
                                             "cancel permitted by policy")

        # 8 — DURABLE WRITE-AHEAD INTENT (before the exchange, always)
        #     EVERY mutation now writes one, cancels and stop amendments
        #     included, so the exchange boundary can refuse any call that has
        #     no write-ahead record behind it without exception. The record
        #     carries what the order IS — instrument, kind, side, role,
        #     reduce_only, the logical operation, the epoch — and, for a
        #     mutation addressed to an existing order, BOTH identities.
        wrote = self._journal.record_intent(
            action_id, client_order_id=cid, fingerprint=fp, tool=tool,
            operation_id=op.operation_id, logical_key=op.logical_key,
            generation=op.generation, logical_operation_id=op.operation_id,
            instrument=(order.inst_id if order is not None
                        else self._limits.instrument),
            order_kind=order_kind, role=role, reduce_only=reduce_only,
            target_client_order_id=target_cid,
            # SAFETY CLOSURE ROUND 4C, R4-4. The identity of the ONE
            # observation this action was authorised against, so the audit can
            # point at the evidence rather than assert that evidence existed.
            authoritative_snapshot=auth.snapshot_id,
            authoritative_epoch=auth.lease_epoch,
            side=(order.side if order is not None else None),
            intended_contracts=(str(norm.get("requested", contracts))
                                if contracts is not None else None),
            contracts=str(contracts) if contracts is not None else None,
            intended_stop=str(norm.get("stop") or norm.get("new_stop") or ""),
            stop=(str(order.stop_price)
                  if order is not None and order.stop_price else None),
            order_type=(order.order_type if order is not None else None),
            price=(str(order.price)
                   if order is not None and order.price is not None else None),
            planned_risk_usdt=(str(order.planned_risk_usdt)
                               if order is not None else "0"),
            epoch=self._lease.epoch if self._lease else None)
        if wrote is None:
            return self._final(tool, action_id, ActionResult(
                ActionStatus.DUPLICATE_SUPPRESSED, "DUPLICATE",
                "intent already journalled", action_id, cid))

        # 8a — THE OBSERVATION AND THE MUTATION UNDER ONE AUTHORITY.
        #      The snapshot recorded which writer epoch it was taken under;
        #      the adapter fences again at the moment of the call. This asserts
        #      the two are the same epoch, so an authorisation cannot have been
        #      computed under one authority and executed under another.
        if (self._lease is not None
                and auth.lease_epoch != self._lease.epoch):
            return self._final(tool, action_id, ActionResult(
                ActionStatus.BLOCKED, "STALE_WRITER",
                f"the authoritative observation was taken under writer epoch "
                f"{auth.lease_epoch} and this worker now holds "
                f"{self._lease.epoch}; the state that authorised this action "
                f"was not observed under the authority about to act",
                action_id))

        # 9 — EXCHANGE ADAPTER
        self._rec.record_submit_attempted(action_id, cid)
        try:
            if kind is Kind.OPEN:
                res = self._adapter.submit_order(
                    self._lease, cid, order.side, order.contracts,
                    order.order_type, order.price,
                    reduce_only=order.reduce_only, role=order.role,
                    instrument=order.inst_id, order_kind=order_kind,
                    logical_operation_id=op.operation_id)
            elif kind in (Kind.CLOSE, Kind.REDUCE):
                res = self._adapter.submit_order(
                    self._lease, cid, order.side, order.contracts, "market",
                    reduce_only=order.reduce_only, role=order.role,
                    instrument=order.inst_id, order_kind=order_kind,
                    logical_operation_id=op.operation_id)
            elif kind is Kind.MODIFY_STOP:
                res = self._adapter.amend_stop(
                    self._lease, cid, order.stop_price,
                    target_client_order_id=target_cid,
                    order_kind=order_kind, role=order.role,
                    reduce_only=order.reduce_only, instrument=order.inst_id,
                    logical_operation_id=op.operation_id)
            else:
                res = self._adapter.cancel_order(
                    self._lease, cid, target_client_order_id=target_cid,
                    order_kind=order_kind, role=role,
                    instrument=self._limits.instrument,
                    logical_operation_id=op.operation_id)
        except StaleWriterError as e:
            self._rec.record_submit_unknown(action_id, cid, 1)
            return self._final(tool, action_id, ActionResult(
                ActionStatus.BLOCKED, "STALE_WRITER", str(e), action_id, cid))
        except WriteAheadViolation as e:
            return self._final(tool, action_id, ActionResult(
                ActionStatus.BLOCKED, "WRITE_AHEAD_VIOLATION", str(e),
                action_id, cid))
        except (InconsistentOrderSemantics, MissingTargetOrder,
                DurableIntentMismatch) as e:
            # The boundary refused the call. Nothing left this process.
            return self._final(tool, action_id, ActionResult(
                ActionStatus.BLOCKED, type(e).__name__, str(e), action_id, cid))

        # 10 — JOURNAL THE RESULT. Acceptance is not execution.
        if res.unknown:
            self._rec.record_submit_unknown(action_id, cid, 1)
            out = ActionResult(ActionStatus.UNKNOWN, "TIMEOUT",
                               "the exchange did not answer; the real state is "
                               "NOT established and must be reconciled before "
                               "any retry", action_id, cid)
        elif not res.ok:
            self._rec.record_submit_failed(action_id, cid, res.detail)
            out = ActionResult(ActionStatus.REJECTED, "EXCHANGE_REJECTED",
                               res.detail, action_id, cid)
        else:
            self._rec.record_submit_ack(action_id, cid, res.exchange_order_id)
            out = ActionResult(
                ActionStatus.ACKNOWLEDGED, "ACK",
                "the exchange accepted the request. This is NOT a fill: the "
                "position is confirmed only by reconciliation.",
                action_id, cid,
                computed=(v.computed if kind is not None else {}),
                exchange_order_id=res.exchange_order_id)

        # 11 — POST-MUTATION RECONCILIATION
        #      SAFETY CLOSURE ROUND 4C, R4-4. A NEW observation is correct and
        #      expected here: the mutation has already been attempted and this
        #      is how its effect is established. The distinction the seal
        #      enforces is that this evidence is POST-MUTATION and can never
        #      become the evidence that AUTHORISED the mutation — by the time
        #      the seal lifts, the adapter call is behind us and `auth` is
        #      already the durable record of what authorised it.
        self._post_mutation_view()
        self._reconcile(force=True)
        self._rec.record_recon(self._recon)
        return self._final(tool, action_id, out)

    # ------------------------------------------------------------------
    def _final(self, tool: str, action_id: Optional[str],
               result: ActionResult) -> ActionResult:
        """SAFETY CLOSURE ROUND 4C3, C3-I2. Every verdict names its evidence.

        Round 4C2 kept evidence for refused actions and bound it durably only
        inside the INTENT — which exists only once lifecycle, protection,
        ownership and the gateway have all APPROVED. So a refusal left a blob on
        disk, a verdict in the journal, and NO durable mapping between them.
        After many cycles, "a blob exists" proves nothing about which evidence
        produced which refusal.

        The verdict record now names the exact content id. Actions refused
        BEFORE an authoritative observation was taken — a schema failure, an
        earlier durable idempotency decision — legitimately have none, and that
        absence is written explicitly rather than left ambiguous. A missing key
        and "there was no observation" must not look alike.

        No fake INTENT is written for an action that was never authorised to
        mutate: this is a verdict record, and it says so.
        """
        auth = self._auth
        if self._journal_untrusted:
            # SAFETY CLOSURE ROUND 4C4, checkpoint A. The verdict is that the
            # journal cannot be trusted. Appending to it would either raise
            # (the append path refuses a broken chain, and the refusal would
            # then escape the tool call as an exception instead of a stable
            # result) or extend a file whose integrity is already rejected.
            # The refusal is returned, not written; the untrusted file is
            # left exactly as it was found, for the human who must look at it.
            return result
        self._rec.record_remediation(
            action_id, f"tool {tool} -> {result.status.value}",
            code=result.code, cycle_id=self._cycle_id,
            authoritative_snapshot=(auth.snapshot_id if auth else None),
            authoritative_observation=("taken" if auth else "not_taken"))
        return result
