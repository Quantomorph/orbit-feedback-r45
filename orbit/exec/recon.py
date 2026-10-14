"""
orbit/exec/recon.py — STATE RECONCILIATION AS A SAFETY-CRITICAL STATE MACHINE.

ORBIT-AGENT-ARCH-001, build step 4.

`reconciled=True` is not a convenience flag and is never set optimistically. It
means: **Python has independently compared its own durable record of what it
intended and submitted against what the exchange reports, and found no
discrepancy that makes the view of account, position or order state
untrustworthy.**

THE INVARIANT THIS MODULE EXISTS TO GUARANTEE:

    If ORBIT cannot establish a trustworthy view of account / position / order
    state, ORBIT cannot open a new position.

It is enforced structurally, not by convention: the reconciler is the only
producer of `SystemState`, and the gateway refuses every OPEN unless
`reconciled` is True and `run_state` is RUNNING. No discrepancy anywhere in this
file returns "carry on" by default; the default for anything unrecognised is to
stop.

DISPOSITION LADDER — every finding is assigned exactly one, worst wins:

    SAFE_TO_RECONCILE     Python adopts exchange truth and continues.
    BLOCK_NEW_ENTRIES     Risk-reducing actions only. Remediation runs.
    REQUIRE_HUMAN_REVIEW  HALTED. A person must clear it.
    EMERGENCY_CLOSE       Python flattens or protects NOW, then HALTED.

Remedies are executed by Python. The model is never asked to fix state, is never
shown a choice about it, and cannot decline one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum, IntEnum
from typing import FrozenSet, List, Optional, Tuple

from orbit.core.precision import BTC_USDT_SWAP as SPEC, Side
from orbit.exec.protection import (MarginMode, ProtectionAssessment,
                                   ProtectionLadder, assess, build_ladder,
                                   canonical_orders)
from orbit.risk.limits import A1, A1Limits, RunState
from orbit.risk.modeled_loss import modeled_loss
from orbit.risk.state import Position, SystemState

D = Decimal


# ======================================================================
# LADDER
# ======================================================================

class Disposition(IntEnum):
    SAFE_TO_RECONCILE = 0
    BLOCK_NEW_ENTRIES = 1
    REQUIRE_HUMAN_REVIEW = 2
    EMERGENCY_CLOSE = 3


class F(str, Enum):
    """Finding codes. Stable — A1 reports reconciliation incidents by these."""
    PHANTOM_POSITION = "PHANTOM_POSITION"
    POSITION_MISSING_ON_EXCHANGE = "POSITION_MISSING_ON_EXCHANGE"
    POSITION_CLOSED_EXPLAINED = "POSITION_CLOSED_EXPLAINED"
    POSITION_UNPROTECTED = "POSITION_UNPROTECTED"
    STOP_PRICE_WIDER_THAN_INTENDED = "STOP_PRICE_WIDER_THAN_INTENDED"
    STOP_PRICE_TIGHTER_THAN_INTENDED = "STOP_PRICE_TIGHTER_THAN_INTENDED"
    STOP_SIZE_MISMATCH = "STOP_SIZE_MISMATCH"
    INTENDED_STOP_UNKNOWN = "INTENDED_STOP_UNKNOWN"
    POSITION_LARGER_THAN_INTENDED = "POSITION_LARGER_THAN_INTENDED"
    POSITION_SMALLER_THAN_INTENDED = "POSITION_SMALLER_THAN_INTENDED"
    PARTIAL_FILL = "PARTIAL_FILL"
    UNKNOWN_ORDER_STATUS = "UNKNOWN_ORDER_STATUS"
    UNKNOWN_ORDER_UNRESOLVED = "UNKNOWN_ORDER_UNRESOLVED"
    UNKNOWN_RESOLVED_BY_CLIENT_ID = "UNKNOWN_RESOLVED_BY_CLIENT_ID"
    DUPLICATE_FILL_EVENT = "DUPLICATE_FILL_EVENT"
    DOUBLE_EXECUTION = "DOUBLE_EXECUTION"
    EXCHANGE_UNREACHABLE = "EXCHANGE_UNREACHABLE"
    EXCHANGE_UNREACHABLE_PERSISTENT = "EXCHANGE_UNREACHABLE_PERSISTENT"
    EXCHANGE_INCONSISTENT = "EXCHANGE_INCONSISTENT"
    STALE_EXCHANGE_VIEW = "STALE_EXCHANGE_VIEW"
    # SAFETY CLOSURE ROUND 4-5, R4-5. "Old" and "impossible" are different
    # diagnoses and must not share a code. STALE_EXCHANGE_VIEW says the
    # observation describes a moment that has PASSED; these two say the
    # observation cannot be placed in time at all, so no freshness claim about
    # it is meaningful in either direction.
    FUTURE_DATED_EXCHANGE_VIEW = "FUTURE_DATED_EXCHANGE_VIEW"
    SERVER_TIME_UNAVAILABLE = "SERVER_TIME_UNAVAILABLE"
    ORPHANED_ORDER = "ORPHANED_ORDER"
    ORPHANED_PROTECTIVE_ORDER = "ORPHANED_PROTECTIVE_ORDER"
    CLOCK_SKEW = "CLOCK_SKEW"
    CLOCK_SKEW_SEVERE = "CLOCK_SKEW_SEVERE"
    COLD_START_WITH_POSITION = "COLD_START_WITH_POSITION"
    JOURNAL_UNAVAILABLE = "JOURNAL_UNAVAILABLE"
    DIRTY_SHUTDOWN = "DIRTY_SHUTDOWN"
    UNRECORDED_OWN_FILL = "UNRECORDED_OWN_FILL"
    DAY_COUNTERS_UNRELIABLE = "DAY_COUNTERS_UNRELIABLE"
    STOP_SIZE_OVER_COVERS = "STOP_SIZE_OVER_COVERS"
    PROTECTIVE_STOP_PRICE_UNKNOWN = "PROTECTIVE_STOP_PRICE_UNKNOWN"
    STOP_LADDER_HETEROGENEOUS = "STOP_LADDER_HETEROGENEOUS"
    EXCHANGE_ORDERS_CONTRADICTORY = "EXCHANGE_ORDERS_CONTRADICTORY"
    RISK_BUDGET_EXCEEDED_BY_FILL = "RISK_BUDGET_EXCEEDED_BY_FILL"
    REMEDIATION_OUTSTANDING = "REMEDIATION_OUTSTANDING"
    # SAFETY CLOSURE ROUND 4C4, N1. The two ways deriving the authoritative
    # local state can fail. They already existed as ACTION refusal codes
    # (`LOCAL_STATE_UNTRUSTED`, `LOCAL_STATE_DERIVATION_FAILED`); they are
    # finding codes too so that the model-facing state report and the
    # authorization path answer in ONE vocabulary. An operator reading either
    # surface must be able to tell a journal that cannot be TRUSTED from one
    # that cannot be INTERPRETED, and both from a healthy system.
    LOCAL_STATE_UNTRUSTED = "LOCAL_STATE_UNTRUSTED"
    LOCAL_STATE_DERIVATION_FAILED = "LOCAL_STATE_DERIVATION_FAILED"
    UNCLASSIFIED = "UNCLASSIFIED"


class Remedy(str, Enum):
    ADOPT_EXCHANGE_TRUTH = "ADOPT_EXCHANGE_TRUTH"
    PLACE_PROTECTIVE_STOP = "PLACE_PROTECTIVE_STOP"
    TIGHTEN_STOP_TO_INTENDED = "TIGHTEN_STOP_TO_INTENDED"
    RESIZE_STOP_TO_POSITION = "RESIZE_STOP_TO_POSITION"
    CANCEL_ORDER = "CANCEL_ORDER"
    QUERY_ORDER_BY_CLIENT_ID = "QUERY_ORDER_BY_CLIENT_ID"
    FLATTEN_POSITION = "FLATTEN_POSITION"
    RECONSTRUCT_POSITION_FROM_EXCHANGE = "RECONSTRUCT_POSITION_FROM_EXCHANGE"
    SWEEP_EXCHANGE_HISTORY = "SWEEP_EXCHANGE_HISTORY"
    RESTORE_DAY_COUNTERS = "RESTORE_DAY_COUNTERS"
    RESIZE_STOP_TO_POSITION_DOWN = "RESIZE_STOP_TO_POSITION_DOWN"
    REDUCE_POSITION_TO_BUDGET = "REDUCE_POSITION_TO_BUDGET"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"


@dataclass(frozen=True)
class Finding:
    """TWO INDEPENDENT TRUST DIMENSIONS. Conflating them was a real defect in
    the first version of this module, identified at step-5 approval.

    view_trustworthy   -- can we SEE the exchange clearly? This is what
                          `reconciled` reports. It is about account, order and
                          position state as the exchange holds it.
    local_trustworthy  -- is OUR OWN durable record sound? A crash can leave a
                          perfectly visible exchange and a wrong journal.

    A state can be entirely visible and still be one we deliberately refuse to
    trade from: reconciled=True with run_state=NO_NEW_ENTRY. Reporting that as
    "not reconciled" would have hidden the difference between 'we are blind'
    and 'we can see, and we are choosing not to act'.
    """
    code: F
    disposition: Disposition
    view_trustworthy: bool
    detail: str
    remedies: Tuple[Remedy, ...] = ()
    local_trustworthy: bool = True


# ======================================================================
# INPUTS — local intent (durable) and exchange observation
# ======================================================================

class OrderStatus(str, Enum):
    """SAFETY CLOSURE, blocker E. The nonterminal / terminal split is the whole
    point of this enum, and it is stated here rather than inferred at each use.

    ACK means the exchange ACCEPTED the request. It does not mean filled,
    cancelled, rejected or expired. Treating it as settled is how a live order
    came to be forgotten across a shutdown."""
    SUBMITTED = "SUBMITTED"
    ACK = "ACK"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    UNKNOWN = "UNKNOWN"          # submitted, outcome not established
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"        # refused BEFORE acceptance
    EXPIRED = "EXPIRED"
    EFFECTIVE = "EFFECTIVE"      # an ADMIN mutation confirmed applied (N6)


TERMINAL_STATUSES = frozenset({OrderStatus.FILLED, OrderStatus.CANCELLED,
                               OrderStatus.REJECTED, OrderStatus.EXPIRED,
                               OrderStatus.EFFECTIVE})
NONTERMINAL_STATUSES = frozenset(OrderStatus) - TERMINAL_STATUSES


@dataclass(frozen=True)
class SubmittedOrder:
    """SAFETY CLOSURE, blocker C. The first version recorded only how much and
    what state. Nothing downstream could then answer 'what IS this in-flight
    order' — which instrument, which direction, whether it can open exposure —
    and authorship grading was left matching on size alone."""
    client_order_id: str
    intended_contracts: Decimal
    filled_contracts: Decimal
    status: OrderStatus
    submitted_at: datetime
    is_protective: bool = False
    resolution_attempts: int = 0
    instrument: Optional[str] = None
    kind: Optional[str] = None              # OPEN / CLOSE / REDUCE / MODIFY_STOP
    side: Optional[Side] = None
    reduce_only: Optional[bool] = None
    role: Optional[str] = None              # ENTRY / EXIT / PROTECTIVE / ADMIN
    logical_operation_id: Optional[str] = None
    epoch: Optional[int] = None
    created_at: Optional[str] = None

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def unresolved(self) -> bool:
        return not self.terminal


@dataclass(frozen=True)
class IntendedPosition:
    side: Side
    contracts: Decimal
    entry_price: Decimal
    stop_price: Optional[Decimal]
    """None is a REAL state, not an error: the window between a fill being
    journalled and its protective order being placed. Recovery crashed on it
    in the first version of this module -- found by crash window W5."""
    stop_client_id: Optional[str]
    opened_at: datetime


@dataclass(frozen=True)
class IntendedState:
    """Python's own durable record. On a cold start this is loaded from the
    journal; `journal_loaded=False` means we have no memory of our own intent
    and must not assume the exchange is showing us something we created."""
    journal_loaded: bool
    position: Optional[IntendedPosition] = None
    submitted_orders: Tuple[SubmittedOrder, ...] = ()
    known_fill_ids: FrozenSet[str] = frozenset()
    entries_utc_day: int = 0
    realized_pnl_utc_day: Decimal = D("0")
    clean_shutdown: bool = True
    daily_figures_derived: Optional[bool] = None
    """SAFETY CLOSURE ROUND 4C4, R4C4-DAYFIG-1.

    True when `entries_utc_day` and `realized_pnl_utc_day` above ARE the
    durable derivation over this prefix -- including a genuine zero day, which
    is a derived fact and not an absence. False when the derivation was
    attempted and REFUSED, in which case those two numbers carry no meaning and
    must not be read as figures: a `0` that means "unknown" is the one value
    that would let a restart erase a realized daily loss and hand the daily-loss
    limit back its full budget. None means the state was hand-built and never
    claimed to be derived, which is how every fixture and every pre-derivation
    caller is judged -- unchanged.
    """
    position_fill_backed: Optional[bool] = None
    """SAFETY CLOSURE ROUND 4C4, checkpoint A.1 (replaces checkpoint A's
    `entry_fills_on_record`, a lifetime count that said nothing about the
    CURRENT position). True only when the durable derivation has proved that
    `position` is exactly the position ORBIT's own fills produce - side, size
    and average entry. The derivation refuses to produce a state at all when
    they disagree, so a derived state always carries True; a hand-built state
    leaves it None and is judged by the older day-counter heuristic below.
    With the day figures rolling over at UTC midnight, `entries_utc_day == 0`
    alongside an open position is the ORDINARY state of a position held
    overnight, not evidence that the counters were lost."""
    """False when the previous process did not shut down cleanly.

    THIS IS THE FIELD THAT ENCODES THE RULE 'a missing local record is not
    evidence that nothing happened'. A journal only carries NEGATIVE
    information -- "there is no position" -- if the process that wrote it
    stopped in an orderly way. After a crash, absence proves nothing, because
    the crash may have occurred between the exchange filling an order and
    Python persisting the fill."""


@dataclass(frozen=True)
class ExchangePosition:
    side: Side
    contracts: Decimal
    entry_price: Decimal


@dataclass(frozen=True)
class ExchangeOrder:
    client_order_id: Optional[str]
    contracts: Decimal
    is_protective: bool
    stop_price: Optional[Decimal] = None


@dataclass(frozen=True)
class Fill:
    fill_id: str
    client_order_id: str
    contracts: Decimal


@dataclass(frozen=True)
class ExchangeView:
    fetched_at: datetime
    reachable: bool
    consistent: bool                       # two reads agreed
    server_time: Optional[datetime]
    equity: Decimal
    mark_price: Decimal
    margin_mode: MarginMode = MarginMode.UNKNOWN
    position: Optional[ExchangePosition] = None
    open_orders: Tuple[ExchangeOrder, ...] = ()
    fills: Tuple[Fill, ...] = ()
    consecutive_failures: int = 0
    can_place_orders: bool = True
    isolated_margin_posted: Optional[Decimal] = None


# ======================================================================
# RESULT
# ======================================================================

@dataclass(frozen=True)
class ReconResult:
    reconciled: bool
    run_state: RunState
    findings: Tuple[Finding, ...]
    remedies: Tuple[Remedy, ...]
    protection: Optional[ProtectionAssessment]
    position: Optional[Position]
    now: datetime
    view: ExchangeView
    intended: IntendedState

    @property
    def worst(self) -> Disposition:
        return max((f.disposition for f in self.findings),
                   default=Disposition.SAFE_TO_RECONCILE)

    @property
    def clean(self) -> bool:
        """Everything is visible, sound, and nothing blocks trading."""
        return (self.worst is Disposition.SAFE_TO_RECONCILE and self.reconciled
                and self.run_state is RunState.RUNNING)

    @property
    def local_state_trusted(self) -> bool:
        return all(x.local_trustworthy for x in self.findings)

    def codes(self):
        return [f.code for f in self.findings]

    def entry_in_flight(self) -> bool:
        """An entry order submitted but not terminal. Derived from the durable
        record, so it survives a restart."""
        for o in self.intended.submitted_orders:
            if o.is_protective:
                continue
            if o.role is not None and o.role != "ENTRY":
                continue          # an exit or an admin mutation is not an entry
            if o.status in NONTERMINAL_STATUSES:
                return True
        return False

    def to_system_state(self, limits: A1Limits = A1,
                        entry_in_flight: Optional[bool] = None) -> SystemState:
        """The ONLY producer of SystemState. The gateway consumes nothing else."""
        return SystemState(
            now=self.now,
            data_as_of=self.view.fetched_at,
            mark_price=self.view.mark_price,
            equity=self.view.equity,
            position=self.position,
            realized_pnl_utc_day=self.intended.realized_pnl_utc_day,
            entries_utc_day=self.intended.entries_utc_day,
            run_state=self.run_state,
            environment=limits.environment,
            reconciled=self.reconciled,
            entry_in_flight=(self.entry_in_flight() if entry_in_flight is None
                             else entry_in_flight),
        )


# ======================================================================
# THE RECONCILER
# ======================================================================

CLOCK_SKEW_TOLERANCE_S = 5
CLOCK_SKEW_SEVERE_S = 60
MAX_RESOLUTION_ATTEMPTS = 3


def reconcile(intended: IntendedState, view: ExchangeView, now: datetime,
              limits: A1Limits = A1) -> ReconResult:
    f: List[Finding] = []

    # ---------------- view-level: can we see anything at all? ----------
    if not view.reachable:
        if view.consecutive_failures >= 3:
            f.append(Finding(F.EXCHANGE_UNREACHABLE_PERSISTENT,
                             Disposition.REQUIRE_HUMAN_REVIEW, False,
                             f"exchange unreachable for {view.consecutive_failures} "
                             f"consecutive attempts; state cannot be verified",
                             (Remedy.ESCALATE_TO_HUMAN,)))
        else:
            f.append(Finding(F.EXCHANGE_UNREACHABLE,
                             Disposition.BLOCK_NEW_ENTRIES, False,
                             "exchange unreachable; existing exchange-resident "
                             "protection stands but no new risk may be taken",
                             ()))
        return _finish(f, intended, view, now, None, limits)

    if not view.consistent:
        f.append(Finding(F.EXCHANGE_INCONSISTENT,
                         Disposition.REQUIRE_HUMAN_REVIEW, False,
                         "two reads of exchange state disagreed; ORBIT does not "
                         "guess between contradictory exchange responses",
                         (Remedy.ESCALATE_TO_HUMAN,)))

    # ---------------- can this observation be placed in time? ----------
    # SAFETY CLOSURE ROUND 4-5, R4-5. THE COMPARISON USED TO BE ONE-SIDED.
    #
    # `age > max_data_age_seconds` asks only whether the observation is too
    # OLD. A view stamped in the FUTURE produces a NEGATIVE age, which is not
    # greater than any positive limit, so it raised no finding at all: the
    # filed shape `fetched_at = now + 600s` gave age `-600.0`, findings `[]`,
    # `run_state=RUNNING`, and the gateway APPROVED the OPEN. Fail-open, and
    # the more absurd the timestamp the fresher the data looked.
    #
    # A negative age is not "very fresh data". It is a contradiction: the
    # observation claims to have been taken at a moment that has not happened.
    # Both sides of the pair are LOCAL — `fetched_at` is stamped by the process
    # that performed the fetch and `now` is the same wall clock read later — so
    # there is no venue clock in this comparison and no skew to tolerate. The
    # condition is therefore EXACTLY `age < 0`, with no tolerance, no grace
    # period and no epsilon; `age == 0` is a legitimate instantaneous read and
    # is NOT refused by this rule.
    #
    # It is NOT clamped to zero. `max(age, 0)` would turn an impossible
    # timestamp into maximally fresh data and destroy the only evidence that
    # anything was wrong.
    age = (now - view.fetched_at).total_seconds()
    if age < 0:
        f.append(Finding(F.FUTURE_DATED_EXCHANGE_VIEW,
                         Disposition.BLOCK_NEW_ENTRIES, False,
                         f"exchange view is dated {-age:.6f}s in the FUTURE "
                         f"(fetched_at={view.fetched_at}, now={now}); an "
                         f"observation cannot have been taken at a moment that "
                         f"has not occurred, so its freshness cannot be "
                         f"established and it is not evidence of current state",
                         ()))
    elif age > limits.max_data_age_seconds:
        f.append(Finding(F.STALE_EXCHANGE_VIEW, Disposition.BLOCK_NEW_ENTRIES,
                         False, f"exchange view is {age:.0f}s old (limit "
                         f"{limits.max_data_age_seconds}s); it does not describe "
                         f"current state", ()))

    # SAFETY CLOSURE ROUND 4-5, R4-5. A FRESHNESS CLAIM NEEDS THE VENUE CLOCK.
    #
    # The skew check below is the only thing that compares the venue's clock to
    # ours, and it ran only `if view.server_time is not None`. An observation
    # carrying no `server_time` therefore skipped it entirely and was treated as
    # fresh BECAUSE a timestamp was missing — absence of evidence read as
    # evidence of soundness. Freshness is a positive claim about when the venue
    # answered, and it is not available from our own clock alone.
    if view.server_time is None:
        f.append(Finding(F.SERVER_TIME_UNAVAILABLE,
                         Disposition.BLOCK_NEW_ENTRIES, False,
                         "the observation carries no venue server_time, so the "
                         "venue clock cannot be compared with ours and the "
                         "freshness of this view cannot be established; a "
                         "missing timestamp is not a fresh one",
                         ()))
    else:
        skew = abs((view.server_time - now).total_seconds())
        if skew > CLOCK_SKEW_SEVERE_S:
            f.append(Finding(F.CLOCK_SKEW_SEVERE, Disposition.REQUIRE_HUMAN_REVIEW,
                             False, f"clock skew {skew:.0f}s exceeds "
                             f"{CLOCK_SKEW_SEVERE_S}s; every freshness and "
                             f"ordering guarantee is void",
                             (Remedy.ESCALATE_TO_HUMAN,)))
        elif skew > CLOCK_SKEW_TOLERANCE_S:
            f.append(Finding(F.CLOCK_SKEW, Disposition.BLOCK_NEW_ENTRIES, False,
                             f"clock skew {skew:.0f}s exceeds tolerance "
                             f"{CLOCK_SKEW_TOLERANCE_S}s; freshness checks are "
                             f"unreliable", ()))

    # ---------------- one order, one row -------------------------------
    # SAFETY CLOSURE ROUND 4A, R4-2. Checked over the WHOLE open-order list and
    # before anything is concluded from it, because `is_protective` is itself
    # an execution-critical field: a contradiction about whether an order
    # protects the position must not be filtered away by the protective filter
    # that is about to consume it.
    #
    # Two representations of one identity that disagree are not a duplicate.
    # ORBIT does not choose between them and does not add them: at most one is
    # true and nothing in the view says which.
    _, _conflicts = canonical_orders(view.open_orders)
    if _conflicts:
        f.append(Finding(
            F.EXCHANGE_ORDERS_CONTRADICTORY, Disposition.REQUIRE_HUMAN_REVIEW,
            False,
            "the exchange returned irreconcilable representations of the same "
            "order in one fetch: "
            + "; ".join(c.describe() for c in _conflicts)
            + ". Coverage, modelled protection and risk capacity are all "
              "derived from this list, so none of them can be established "
              "while it contradicts itself.",
            (Remedy.ESCALATE_TO_HUMAN,)))
        return _finish(f, intended, view, now, None, limits)

    # ---------------- do we know our own intent? -----------------------
    if not intended.journal_loaded:
        if view.position is not None:
            unprotected = not _protective_orders(view)
            f.append(Finding(
                F.COLD_START_WITH_POSITION,
                Disposition.EMERGENCY_CLOSE if unprotected
                else Disposition.REQUIRE_HUMAN_REVIEW,
                False,
                "started with no durable record but the exchange holds a "
                "position; ORBIT cannot distinguish this from a position it "
                "never created, so it is treated as one"
                + ("; it is UNPROTECTED" if unprotected else "; it is protected"),
                (Remedy.FLATTEN_POSITION, Remedy.ESCALATE_TO_HUMAN) if unprotected
                else (Remedy.ESCALATE_TO_HUMAN,)))
        else:
            f.append(Finding(F.JOURNAL_UNAVAILABLE, Disposition.BLOCK_NEW_ENTRIES,
                             True,
                             "no durable journal: entries-today and realized "
                             "daily P&L are unknown, so the daily limits cannot "
                             "be enforced", (Remedy.ESCALATE_TO_HUMAN,),
                             local_trustworthy=False))
        return _finish(f, intended, view, now, None, limits)

    # ---------------- did we stop cleanly? ------------------------------
    if not intended.clean_shutdown:
        f.append(Finding(F.DIRTY_SHUTDOWN, Disposition.BLOCK_NEW_ENTRIES, True,
                         "the previous process did not shut down cleanly, so "
                         "the absence of a local record is not evidence that "
                         "nothing happened; exchange order and fill history "
                         "must be swept before any new risk is taken",
                         (Remedy.SWEEP_EXCHANGE_HISTORY,),
                         local_trustworthy=False))

    # ---------------- order-level ---------------------------------------
    f.extend(_order_findings(intended, view))

    # ---------------- position-level ------------------------------------
    pos_findings, adopted = _position_findings(intended, view)
    f.extend(pos_findings)

    # ---------------- protection-level ----------------------------------
    if adopted is not None:
        f.extend(_protection_findings(intended, view, adopted))

        # A position that exists but was never counted against the daily entry
        # limit means the limit is not being enforced. Recovering a position
        # without recovering the counters would silently grant extra entries.
        #
        # SAFETY CLOSURE ROUND 4C4, checkpoint A.1. When the state was DERIVED
        # from durable fills, the question is whether THIS position is the one
        # the fills produce - a position entered yesterday has zero entries
        # today and is not unreliable. A hand-built state (no
        # `position_fill_backed`) is still judged by the day counter.
        no_entry_on_record = (
            not intended.position_fill_backed
            if intended.position_fill_backed is not None
            else intended.entries_utc_day < 1)
        if no_entry_on_record:
            f.append(Finding(F.DAY_COUNTERS_UNRELIABLE,
                             Disposition.BLOCK_NEW_ENTRIES, True,
                             "a position is open but no durable entry fill "
                             "stands behind it and the day's entry counter is "
                             "zero: the 2-entries-per-UTC-day limit cannot be "
                             "enforced until the counters are rebuilt from "
                             "exchange history",
                             (Remedy.RESTORE_DAY_COUNTERS,
                              Remedy.SWEEP_EXCHANGE_HISTORY),
                             local_trustworthy=False))

    # ---------------- daily risk figures --------------------------------
    # SAFETY CLOSURE ROUND 4C4, R4C4-DAYFIG-1. The check above asks whether an
    # OPEN POSITION is backed by a counted entry. This one asks the prior
    # question, and it is asked whether or not a position is open: were the
    # day's figures DERIVED AT ALL?
    #
    # A flat account with an unknown daily P&L is exactly the dangerous shape.
    # The position check cannot see it -- there is no position -- and
    # `entries_utc_day` and `realized_pnl_utc_day` both read `0`, which the
    # gateway cannot distinguish from a clean day. That is how a restart came
    # to hand the daily-loss limit back its full budget over a day that had
    # already realized its maximum loss.
    #
    # `is False` is deliberate and is not `not`. None means a hand-built state
    # that never claimed derivation, and those are judged exactly as before.
    if intended.daily_figures_derived is False:
        f.append(Finding(F.DAY_COUNTERS_UNRELIABLE,
                         Disposition.BLOCK_NEW_ENTRIES, True,
                         "the day's entry count and realized P&L could not be "
                         "derived from durable history, so neither the "
                         "2-entries-per-UTC-day limit nor the daily-loss limit "
                         "can be enforced. An unknown daily P&L is not a zero "
                         "daily P&L, and a restart may not reset it",
                         (Remedy.RESTORE_DAY_COUNTERS,
                          Remedy.SWEEP_EXCHANGE_HISTORY),
                         local_trustworthy=False))

    return _finish(f, intended, view, now, adopted, limits)


# ----------------------------------------------------------------------
def _own_fill_evidence(intended: IntendedState, view: ExchangeView):
    """Is the position the exchange is showing us one WE opened and failed to
    record? Returns (strength, detail) or None.

    STRONG: a fill on the exchange carries one of OUR deterministic client
            order ids. That is proof of authorship, not inference.
    WEAK:   we have an entry order still in flight (any NONTERMINAL status)
            whose INSTRUMENT, SIDE and SIZE all match what the exchange holds.
            Circumstantial, but enough to prefer reconstruction over
            destruction.
    NONE:   returns None. There is no evidence, and the caller must not adopt
            the position on the strength of an absence.

    SAFETY CLOSURE, blocker C: WEAK previously matched on SIZE ALONE while its
    own docstring claimed side. An in-flight SHORT of the same size would have
    authorised adopting a LONG exchange position as ORBIT's own. A field that
    is unknown (None, from a record written before the schema was extended) is
    NOT treated as a match.
    """
    if view.position is None:
        return None
    entries = {o.client_order_id: o for o in intended.submitted_orders
               if not o.is_protective}
    for fl in view.fills:
        if fl.client_order_id in entries:
            return ("STRONG",
                    f"exchange fill {fl.fill_id} carries our client order id "
                    f"{fl.client_order_id}")
    for o in entries.values():
        if o.status not in NONTERMINAL_STATUSES:
            continue
        if o.intended_contracts != view.position.contracts:
            continue
        if o.side != view.position.side:
            continue          # None never matches: unknown is not agreement
        if o.instrument is not None and o.instrument != SPEC.inst_id:
            continue
        return ("WEAK",
                f"entry order {o.client_order_id} is in flight on "
                f"{o.instrument or SPEC.inst_id} {o.side} with an intent of "
                f"{o.intended_contracts} contracts, matching the position the "
                f"exchange holds in instrument, side and size")
    return None


def _protective_orders(view: ExchangeView) -> Tuple[ExchangeOrder, ...]:
    return tuple(o for o in view.open_orders if o.is_protective)


def _ladder(view: ExchangeView, intended: IntendedState,
            contracts: Decimal, side) -> ProtectionLadder:
    """SAFETY CLOSURE ROUND 3, R3-1. Protection is a LADDER of slices, each
    covering a stated number of contracts at its own stop, deterministically
    ordered so no verdict can depend on the sequence the exchange returned."""
    owned = frozenset(o.client_order_id for o in intended.submitted_orders
                      if o.is_protective and o.client_order_id)
    return build_ladder(view.open_orders, contracts, side, owned)


def _order_findings(intended: IntendedState, view: ExchangeView) -> List[Finding]:
    f: List[Finding] = []
    ours = {o.client_order_id: o for o in intended.submitted_orders}

    # duplicate fill events -> idempotent ingest, not an incident
    seen, dupes = set(), 0
    per_client = {}
    for fill in view.fills:
        if fill.fill_id in seen:
            dupes += 1
            continue
        seen.add(fill.fill_id)
        per_client.setdefault(fill.client_order_id, []).append(fill)
    if dupes:
        f.append(Finding(F.DUPLICATE_FILL_EVENT, Disposition.SAFE_TO_RECONCILE,
                         True, f"{dupes} repeated fill event(s) ignored; fills "
                         f"are de-duplicated by fill_id", ()))

    # a single client order id executed more than it was ever meant to
    for cid, fills in per_client.items():
        o = ours.get(cid)
        if o is not None:
            total = sum((x.contracts for x in fills), D("0"))
            if total > o.intended_contracts:
                f.append(Finding(F.DOUBLE_EXECUTION, Disposition.EMERGENCY_CLOSE,
                                 False,
                                 f"client order {cid} filled {total} contracts "
                                 f"against an intent of {o.intended_contracts}; "
                                 f"this is a double execution",
                                 (Remedy.FLATTEN_POSITION, Remedy.ESCALATE_TO_HUMAN)))

    for o in intended.submitted_orders:
        if o.status is OrderStatus.UNKNOWN:
            # the payoff of deterministic client order ids: the exchange can
            # tell us what happened to an order whose response we lost.
            on_exchange = any(x.client_order_id == o.client_order_id
                              for x in view.open_orders)
            filled = o.client_order_id in per_client
            if on_exchange or filled:
                f.append(Finding(F.UNKNOWN_RESOLVED_BY_CLIENT_ID,
                                 Disposition.SAFE_TO_RECONCILE, True,
                                 f"order {o.client_order_id} had an unknown "
                                 f"outcome and was resolved from the exchange by "
                                 f"its deterministic client id",
                                 (Remedy.ADOPT_EXCHANGE_TRUTH,)))
            elif o.resolution_attempts >= MAX_RESOLUTION_ATTEMPTS:
                f.append(Finding(F.UNKNOWN_ORDER_UNRESOLVED,
                                 Disposition.REQUIRE_HUMAN_REVIEW, False,
                                 f"order {o.client_order_id} is still unresolved "
                                 f"after {o.resolution_attempts} attempts",
                                 (Remedy.ESCALATE_TO_HUMAN,)))
            else:
                f.append(Finding(F.UNKNOWN_ORDER_STATUS,
                                 Disposition.BLOCK_NEW_ENTRIES, False,
                                 f"order {o.client_order_id} was submitted and "
                                 f"its outcome is not established",
                                 (Remedy.QUERY_ORDER_BY_CLIENT_ID,)))
        elif (o.status in (OrderStatus.ACK, OrderStatus.SUBMITTED)
              and D("0") < o.filled_contracts < o.intended_contracts):
            f.append(Finding(F.PARTIAL_FILL, Disposition.BLOCK_NEW_ENTRIES, True,
                             f"order {o.client_order_id} filled "
                             f"{o.filled_contracts} of {o.intended_contracts}; "
                             f"the remainder must be cancelled and protection "
                             f"resized to the position actually held",
                             (Remedy.CANCEL_ORDER, Remedy.RESIZE_STOP_TO_POSITION)))

    # orders on the exchange that are not ours, or protect nothing
    for x in view.open_orders:
        if x.client_order_id not in ours:
            f.append(Finding(F.ORPHANED_ORDER, Disposition.BLOCK_NEW_ENTRIES,
                             True,
                             f"exchange holds order {x.client_order_id!r} that "
                             f"ORBIT has no record of submitting",
                             (Remedy.CANCEL_ORDER,)))
        elif x.is_protective and view.position is None:
            f.append(Finding(F.ORPHANED_PROTECTIVE_ORDER,
                             Disposition.BLOCK_NEW_ENTRIES, True,
                             f"protective order {x.client_order_id} is resting "
                             f"with no position behind it",
                             (Remedy.CANCEL_ORDER,)))
    return f


def _position_findings(intended: IntendedState, view: ExchangeView):
    """Returns (findings, adopted_position_or_None)."""
    f: List[Finding] = []
    ip, xp = intended.position, view.position

    if ip is None and xp is None:
        return f, None

    if ip is None and xp is not None:
        unprotected = not _protective_orders(view)
        evidence = _own_fill_evidence(intended, view)

        # A position ORBIT probably OPENED and failed to record is a bookkeeping
        # failure, not an intruder. Flattening it would realise a result on a
        # position the strategy meant to hold, because of our own crash. So:
        # reconstruct, protect, and only then decide about resuming.
        if evidence is not None or not intended.clean_shutdown:
            strength, why = evidence or ("NONE", "the previous process did not "
                                         "shut down cleanly, so the absent "
                                         "local record proves nothing")
            remedies = [Remedy.RECONSTRUCT_POSITION_FROM_EXCHANGE,
                        Remedy.SWEEP_EXCHANGE_HISTORY,
                        Remedy.RESTORE_DAY_COUNTERS]
            if unprotected:
                remedies.insert(1, Remedy.PLACE_PROTECTIVE_STOP)
            can = view.can_place_orders and view.reachable
            f.append(Finding(
                F.UNRECORDED_OWN_FILL,
                Disposition.BLOCK_NEW_ENTRIES if (can or not unprotected)
                else Disposition.EMERGENCY_CLOSE,
                True,
                f"the exchange holds a {xp.side} position of {xp.contracts} "
                f"contracts with no local record. Evidence of ORBIT's own "
                f"authorship: {strength} -- {why}. The position is "
                + ("UNPROTECTED and a stop must be established before anything "
                   "else" if unprotected else "protected by a resting order")
                + ". Local state is reconstructed from the exchange; trading "
                  "does not resume in this cycle.",
                tuple(remedies) if (can or not unprotected)
                else (Remedy.FLATTEN_POSITION, Remedy.ESCALATE_TO_HUMAN),
                local_trustworthy=False))
            return f, None

        f.append(Finding(
            F.PHANTOM_POSITION,
            Disposition.EMERGENCY_CLOSE if unprotected
            else Disposition.REQUIRE_HUMAN_REVIEW,
            False,
            f"exchange reports a {xp.side} position of {xp.contracts} contracts "
            f"that ORBIT did not open, after a CLEAN shutdown and with no "
            f"evidence of our authorship"
            + ("; it is UNPROTECTED" if unprotected else "; it carries a stop"),
            (Remedy.FLATTEN_POSITION, Remedy.ESCALATE_TO_HUMAN) if unprotected
            else (Remedy.ESCALATE_TO_HUMAN,)))
        return f, None

    if ip is not None and xp is None:
        closing = [x for x in view.fills
                   if x.client_order_id == (ip.stop_client_id or "")]
        if closing:
            f.append(Finding(F.POSITION_CLOSED_EXPLAINED,
                             Disposition.SAFE_TO_RECONCILE, True,
                             "the position is flat on the exchange and a "
                             "matching protective fill explains it; adopting "
                             "flat and recording the realized result",
                             (Remedy.ADOPT_EXCHANGE_TRUTH,)))
            return f, None
        f.append(Finding(F.POSITION_MISSING_ON_EXCHANGE,
                         Disposition.REQUIRE_HUMAN_REVIEW, False,
                         "ORBIT believes a position is open but the exchange "
                         "reports flat, and no fill explains the difference; "
                         "adopting either view without evidence could cancel "
                         "live protection or trade a position twice",
                         (Remedy.ESCALATE_TO_HUMAN,)))
        return f, None

    # both present
    if xp.side != ip.side:
        f.append(Finding(F.EXCHANGE_INCONSISTENT, Disposition.EMERGENCY_CLOSE,
                         False,
                         f"exchange holds a {xp.side} position where ORBIT "
                         f"intended {ip.side}",
                         (Remedy.FLATTEN_POSITION, Remedy.ESCALATE_TO_HUMAN)))
        return f, None

    if xp.contracts > ip.contracts:
        f.append(Finding(F.POSITION_LARGER_THAN_INTENDED,
                         Disposition.EMERGENCY_CLOSE, False,
                         f"exchange position {xp.contracts} exceeds the "
                         f"authorised {ip.contracts} contracts; the excess was "
                         f"never risk-approved",
                         (Remedy.FLATTEN_POSITION, Remedy.ESCALATE_TO_HUMAN)))
    elif xp.contracts < ip.contracts:
        f.append(Finding(F.POSITION_SMALLER_THAN_INTENDED,
                         Disposition.SAFE_TO_RECONCILE, True,
                         f"exchange position {xp.contracts} is smaller than the "
                         f"intended {ip.contracts}; adopting the smaller, and "
                         f"protection must be resized to it",
                         (Remedy.ADOPT_EXCHANGE_TRUTH,
                          Remedy.RESIZE_STOP_TO_POSITION)))

    adopted = Position(side=xp.side, contracts=xp.contracts,
                       size_btc=xp.contracts * SPEC.contract_size_btc,
                       entry_price=xp.entry_price, stop_price=None,
                       stop_order_id=None, opened_at=ip.opened_at)
    return f, adopted


def _protection_findings(intended: IntendedState, view: ExchangeView,
                         adopted: Position) -> List[Finding]:
    f: List[Finding] = []
    ip = intended.position
    prot = _protective_orders(view)

    if not prot:
        can = view.can_place_orders and view.reachable
        f.append(Finding(F.POSITION_UNPROTECTED,
                         Disposition.BLOCK_NEW_ENTRIES if can
                         else Disposition.EMERGENCY_CLOSE,
                         True,
                         "an open position has no protective order on the "
                         "exchange" + ("; Python will place one immediately"
                                       if can else
                                       "; protection cannot be placed, so the "
                                       "position is closed rather than carried "
                                       "unprotected"),
                         (Remedy.PLACE_PROTECTIVE_STOP,) if can
                         else (Remedy.FLATTEN_POSITION, Remedy.ESCALATE_TO_HUMAN)))
        return f

    lad = _ladder(view, intended, adopted.contracts, adopted.side)
    if ip is not None and ip.stop_price is None:
        f.append(Finding(F.INTENDED_STOP_UNKNOWN, Disposition.BLOCK_NEW_ENTRIES,
                         True,
                         "a position is recorded with no intended stop -- the "
                         "crash window between journalling a fill and placing "
                         "its protective order. The resting stop cannot be "
                         "checked against an intent that was never recorded, so "
                         "it is adopted as the current risk and no new entry is "
                         "permitted until the intent is re-established.",
                         (Remedy.RECONSTRUCT_POSITION_FROM_EXCHANGE,),
                         local_trustworthy=False))
    # A slice whose stop price we cannot read protects nothing we can verify.
    # It must never be counted toward "the position is protected".
    if lad.unknown_price_contracts > 0:
        f.append(Finding(
            F.PROTECTIVE_STOP_PRICE_UNKNOWN, Disposition.BLOCK_NEW_ENTRIES, True,
            f"{lad.unknown_price_contracts} contracts rest behind a protective "
            f"order whose stop price could not be read; unreadable protection "
            f"is not protection, and those contracts are treated as uncovered. "
            f"{lad.describe()}",
            (Remedy.RECONSTRUCT_POSITION_FROM_EXCHANGE,
             Remedy.QUERY_ORDER_BY_CLIENT_ID),
            local_trustworthy=False))

    if ip is not None and ip.stop_price is not None:
        # EVERY slice is compared with the authorised stop. Checking one of them
        # and summing the rest is what let 1.19 contracts sit at 29000 behind
        # 1.19 at 29700.1 and be reported clean.
        wider = lad.slices_wider_than(ip.stop_price, adopted.side)
        tighter = lad.slices_tighter_than(ip.stop_price, adopted.side)
        if wider:
            can = view.can_place_orders and view.reachable
            worst = lad.worst_slice(adopted.side)
            f.append(Finding(
                F.STOP_PRICE_WIDER_THAN_INTENDED,
                Disposition.BLOCK_NEW_ENTRIES if can
                else Disposition.EMERGENCY_CLOSE, True,
                f"{len(wider)} protective slice(s) rest WIDER than the intended "
                f"{ip.stop_price}, covering "
                f"{sum((x.contracts for x in wider), D('0'))} contracts — worst "
                f"at {worst.stop_price if worst else None}. Actual risk on "
                f"those contracts exceeds what was authorised, and aggregate "
                f"coverage does not make them safe. {lad.describe()}",
                (Remedy.TIGHTEN_STOP_TO_INTENDED,) if can
                else (Remedy.FLATTEN_POSITION, Remedy.ESCALATE_TO_HUMAN)))
        elif tighter and len(tighter) == len(lad.priced):
            f.append(Finding(
                F.STOP_PRICE_TIGHTER_THAN_INTENDED,
                Disposition.SAFE_TO_RECONCILE, True,
                f"every resting slice is tighter than the intended "
                f"{ip.stop_price}; risk is lower than authorised, so it is "
                f"adopted as-is. {lad.describe()}",
                (Remedy.ADOPT_EXCHANGE_TRUTH,)))

    # Heterogeneous but authorised: every contract IS protected at least as well
    # as the intent, so this is not blocked — but it is recorded, because a
    # ladder collapsed to one number is exactly how the wider slice hid.
    if not lad.uniform and lad.priced and not lad.slices_wider_than(
            ip.stop_price if ip and ip.stop_price is not None
            else (lad.worst_slice(adopted.side).stop_price
                  if lad.worst_slice(adopted.side) else D("0")),
            adopted.side):
        f.append(Finding(
            F.STOP_LADDER_HETEROGENEOUS, Disposition.SAFE_TO_RECONCILE, True,
            f"protection is a ladder rather than a single stop, and every slice "
            f"is at or inside the authorised level. It is reported rather than "
            f"collapsed to one price. {lad.describe()}",
            ()))

    covered = lad.covered_contracts
    if covered < adopted.contracts:
        f.append(Finding(F.STOP_SIZE_MISMATCH, Disposition.BLOCK_NEW_ENTRIES,
                         True,
                         f"protective orders cover {covered} of "
                         f"{adopted.contracts} contracts; part of the position "
                         f"is unprotected",
                         (Remedy.RESIZE_STOP_TO_POSITION,)))
    elif lad.total_contracts > adopted.contracts:
        # SAFETY CLOSURE, blocker D. Only under-coverage was checked. A stop for
        # MORE contracts than the position does not merely over-protect: when it
        # triggers it closes the position AND opens the opposite one, at the
        # worst possible moment, with no stop of its own.
        f.append(Finding(F.STOP_SIZE_OVER_COVERS, Disposition.BLOCK_NEW_ENTRIES,
                         True,
                         f"protective orders cover {lad.total_contracts} "
                         f"contracts against a position of {adopted.contracts}; "
                         f"on trigger the excess "
                         f"{lad.over_covered_contracts} would OPEN an "
                         f"opposite position rather than close this one. "
                         f"{lad.describe()}",
                         (Remedy.RESIZE_STOP_TO_POSITION_DOWN,)))
    return f


# ----------------------------------------------------------------------
# A remedy Python APPLIES AS PART OF RECONCILING, with no external action and
# nothing left outstanding when this function returns. Everything else names
# work that has NOT been done yet.
SELF_APPLYING_REMEDIES = frozenset({Remedy.ADOPT_EXCHANGE_TRUTH})


def _finish(findings, intended, view, now, adopted, limits) -> ReconResult:
    findings = list(findings)

    # SAFETY CLOSURE ROUND 3, R3-1. The adopted position used to take its stop
    # from the FIRST protective order — an arbitrary element of an unordered
    # list. It now takes the
    # WORST resting slice, because that is the one that decides how bad this
    # position can get, and because "the stop" is only well defined at all when
    # the ladder is uniform.
    ladder = None
    if adopted is not None:
        ladder = _ladder(view, intended, adopted.contracts, adopted.side)
        worst = ladder.worst_slice(adopted.side)
        if worst is not None:
            adopted = Position(adopted.side, adopted.contracts, adopted.size_btc,
                               adopted.entry_price, worst.stop_price,
                               worst.client_order_id, adopted.opened_at)

    protection = None
    modelled = None
    if adopted is not None and intended.position is not None and ladder \
            and ladder.priced:
        # SAFETY CLOSURE ROUND 2, N3: the modelled loss is the same function the
        # gateway sizes with, not price distance alone.
        # SAFETY CLOSURE ROUND 3, R3-1: and it is summed over EVERY slice at ITS
        # OWN stop, not the whole position at one convenient price.
        total = ladder.modeled_total(adopted.entry_price, SPEC, limits)
        protection = assess(total, bool(ladder.priced),
                            view.margin_mode, view.isolated_margin_posted,
                            view.equity)
        modelled = modeled_loss(adopted.entry_price,
                                (worst.stop_price if worst else
                                 adopted.entry_price),
                                adopted.size_btc, SPEC, limits)

    # ---------------- SAFETY CLOSURE, blocker L --------------------------
    # THE CONTRACT FOR AN ACTUAL FILL THAT COSTS MORE THAN THE BUDGET.
    #
    # `planned_risk_usdt` at approval time is computed from a REFERENCE price:
    # the mark for a market order, the limit price for a limit order. The
    # position is opened at neither. A market entry into a moving book fills
    # worse, and the distance from the ACTUAL entry to the SAME stop is then
    # larger than the $8 the gateway authorised. Nothing in the system said
    # what happens next, and so nothing happened: the overrun was carried
    # silently for the life of the trade.
    #
    # It is recomputed HERE, at every reconciliation, from the actual entry
    # price and the verified resting stop. If it exceeds the cap:
    #
    #   * it is a FINDING, with both numbers, so it appears in the audit;
    #   * new entries stop, because the account is already carrying more risk
    #     than the policy authorises;
    #   * the stop is NEVER widened. Widening reduces the reported number by
    #     increasing the real maximum loss, which is the exact trade the whole
    #     system exists to refuse;
    #   * the only risk-reducing correction is to REDUCE the position, and
    #     that is Python's action, not the model's;
    #   * risk-reducing actions stay available. An overrun must not trap a
    #     position it has made more expensive to hold.
    #
    # This is a planned figure, not a guaranteed maximum loss: a gap fills at
    # the next available price and can exceed it in either direction.
    if protection is not None \
            and protection.planned_risk_usdt > limits.planned_risk_usdt:
        over = protection.planned_risk_usdt - limits.planned_risk_usdt
        findings.append(Finding(
            F.RISK_BUDGET_EXCEEDED_BY_FILL, Disposition.BLOCK_NEW_ENTRIES, True,
            f"the position actually filled at {adopted.entry_price} and the "
            f"verified protection ladder implies a modelled loss of "
            f"{protection.planned_risk_usdt} USDT against the authorised cap of "
            f"{limits.planned_risk_usdt} USDT — an overrun of {over}. "
            f"Ladder: {ladder.describe() if ladder else 'n/a'}. Components at "
            f"the worst slice: price risk {modelled.price_risk_usdt}, entry fee "
            f"{modelled.entry_fee_usdt}"
            f"{' (actual)' if modelled.entry_fee_is_actual else ' (modelled)'}, "
            f"modelled exit fee {modelled.exit_fee_usdt}, modelled stop "
            f"slippage {modelled.slippage_usdt}. This is the SAME function the "
            f"gateway sized with. The stop is NOT widened to bring the number "
            f"down; only reducing the position reduces the risk. New entries "
            f"stop while it stands, and risk-reducing actions remain available.",
            (Remedy.REDUCE_POSITION_TO_BUDGET,)))

    # ---------------- SAFETY CLOSURE, blocker D ---------------------------
    # An EXECUTABLE remedy that nothing has executed is outstanding work. The
    # earlier version could report SAFE_TO_RECONCILE, hand back a remedy list,
    # and still say RUNNING — so a position whose protection had to be resized
    # was cleared to add another one alongside it.
    #
    # It is raised ONLY when nothing else already blocks: a finding at
    # BLOCK_NEW_ENTRIES or worse has stopped entries on its own, and adding a
    # second finding there would say nothing new while making recovery — which
    # legitimately runs with remediation outstanding — impossible to complete.
    # The gap was specifically the SAFE_TO_RECONCILE finding that still left
    # work to do.
    _worst_before = max((x.disposition for x in findings),
                        default=Disposition.SAFE_TO_RECONCILE)
    outstanding = tuple(dict.fromkeys(
        r for x in findings for r in x.remedies
        if r not in SELF_APPLYING_REMEDIES))
    if outstanding and _worst_before is Disposition.SAFE_TO_RECONCILE:
        findings.append(Finding(
            F.REMEDIATION_OUTSTANDING, Disposition.BLOCK_NEW_ENTRIES, True,
            f"reconciliation produced remediation that has not been carried "
            f"out: {[r.value for r in outstanding]}. Until it has been, the "
            f"account is not in the state the policy authorised, and no new "
            f"entry may be opened. Risk-reducing actions remain available.",
            ()))

    worst = max((x.disposition for x in findings),
                default=Disposition.SAFE_TO_RECONCILE)
    view_ok = all(x.view_trustworthy for x in findings)
    local_ok = all(x.local_trustworthy for x in findings)

    # `reconciled` answers ONE question: can Python see the exchange clearly?
    # It says nothing about whether trading is permitted.
    reconciled = view_ok and worst <= Disposition.BLOCK_NEW_ENTRIES

    # `run_state` answers a DIFFERENT question: is a new entry permitted?
    if worst >= Disposition.REQUIRE_HUMAN_REVIEW:
        run = RunState.HALTED
    elif not view_ok:
        run = RunState.RECONCILING          # we are blind
    elif worst is Disposition.BLOCK_NEW_ENTRIES or not local_ok:
        run = RunState.NO_NEW_ENTRY         # we can see; we choose not to open
    else:
        run = RunState.RUNNING

    remedies = tuple(dict.fromkeys(r for x in findings for r in x.remedies))
    return ReconResult(reconciled, run, tuple(findings), remedies, protection,
                       adopted, now, view, intended)
