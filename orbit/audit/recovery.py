"""
orbit/audit/recovery.py — RESTART, REPLAY, AND WHAT clean_shutdown MEANS.

ORBIT-AGENT-ARCH-001, build step 5d.

CLEAN SHUTDOWN IS NOT "main() RETURNED".

`clean_shutdown=True` is written durably, as the last record, ONLY when all of
the following hold:

  1. every required journal write is durably committed (fsynced),
  2. there is NO unresolved exchange operation -- no INTENT without a terminal
     outcome, and no order left in UNKNOWN,
  3. reconciliation has completed in this session and produced a result,
  4. the persisted state represents the LAST VERIFIED EXCHANGE STATE, not a
     locally assumed one.

AND, on the next start, that marker is not believed on sight:

  ON RESTART, clean_shutdown IS TREATED AS FALSE UNTIL RECOVERY COMPLETES.

So the first reconciliation pass after any restart always runs with
`clean_shutdown=False`, which means the first cycle after a restart can never
open a position. One cycle of caution costs five minutes; the alternative is
trusting a file written by a process that is no longer running.

CORE INVARIANT OF THIS MODULE

    NO TRUSTED DURABLE STATE = NO NEW ENTRY.

It composes with, and does not replace, step 4's

    NO TRUSTWORTHY EXCHANGE STATE = NO NEW ENTRY.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from orbit.audit.derivation import (DailyAccounting, LocalStateUndecidable,
                                    daily_accounting)
from orbit.audit.journal import Journal, LoadResult
from orbit.audit.records import E, event
from orbit.exec.recon import (Disposition, F, IntendedPosition, IntendedState,
                              OrderStatus, ReconResult, SubmittedOrder,
                              TERMINAL_STATUSES)

D = Decimal


@dataclass(frozen=True)
class Unresolved:
    action_id: str
    client_order_id: str
    status: str
    reason: str


# R4C4 DAYFIG-1. The deterministic vocabulary that distinguishes a day whose
# figures ARE zero from a day whose figures COULD NOT BE ESTABLISHED. Those two
# are the same two numbers and opposite safety facts, and before this repair
# recovery reported both as `0`.
DAY_FIGURES_DERIVED = "DERIVED"
"""The figures below are the durable derivation over this prefix. `0` under
this reason is a REAL zero: the history was read and it holds no entry and no
realized P&L for the session's UTC day."""

DAY_FIGURES_NO_CLOCK = "UNDERIVABLE:NO_SESSION_CLOCK"
"""`recover()` was not given the session clock, so no UTC day could be
identified. Zero is not the answer to a question that was not asked."""

DAY_FIGURES_UNDERIVABLE = "UNDERIVABLE:HISTORY_NOT_ACCOUNTABLE"
"""The durable history could not be accounted. The specific reason is appended
after this prefix. INABILITY TO DERIVE IS NEVER EQUIVALENT TO ZERO."""

DAY_FIGURES_UNTRUSTED = "UNDERIVABLE:JOURNAL_UNTRUSTED"
"""The journal chain is broken, so the records are not evidence of anything and
nothing may be derived from them. `derive_intended` already refuses an untrusted
journal outright (`LocalStateUntrusted`); the day figures are held to the same
rule, because a history that may have been rewritten is not a history whose
realized loss can be believed -- least of all when believing it would report
less loss than actually occurred."""


@dataclass(frozen=True)
class RecoveryReport:
    load: LoadResult
    journal_trusted: bool
    clean_marker: bool
    unresolved: Tuple[Unresolved, ...]
    rebuilt: IntendedState
    reconstruction_events: Tuple[Dict[str, Any], ...]
    notes: Tuple[str, ...]
    daily_figures: Optional[DailyAccounting] = None
    """R4C4 DAYFIG-1. The ONE authoritative daily derivation, or None when it
    could not be established. Never a fabricated zero."""
    daily_figures_reason: str = DAY_FIGURES_NO_CLOCK
    """Which of the three cases above applies. `daily_figures_derivable` is the
    predicate; this is the deterministic explanation that goes with it."""

    @property
    def daily_figures_derivable(self) -> bool:
        """R4C4 DAYFIG-1. True only when the day's safety figures ARE the
        durable derivation. A genuine zero day is True; an unaccountable
        history is False."""
        return self.daily_figures is not None

    @property
    def journal_outstanding(self) -> Tuple["Unresolved", ...]:
        """The unresolved operations the JOURNAL ALONE cannot account for.

        `unresolved` is the honest full list: every operation that never reached
        a terminal outcome, ACK included (safety closure, blocker E). This
        property draws the one distinction the durable record can draw by
        itself.

        A nonterminal PROTECTIVE order is a stop we deliberately left resting on
        the exchange. A1's protection is exchange-resident precisely so that it
        survives this process, so its being alive is the intended state, not a
        forgotten outcome — and it is never acted upon before reconciliation has
        verified it is really there. The danger blocker E names is the opposite
        case: an ENTRY or EXIT acknowledged and never accounted for, where the
        local record says nothing happened and the exchange disagrees. Those
        stay outstanding here, and they block."""
        prot = {o.client_order_id for o in self.rebuilt.submitted_orders
                if o.is_protective}
        return tuple(u for u in self.unresolved
                     if u.client_order_id not in prot)

    @property
    def durable_state_trusted(self) -> bool:
        """NO TRUSTED DURABLE STATE = NO NEW ENTRY. This is that predicate.

        R4C4 DAYFIG-1. The day's realized loss and entry count are part of the
        durable state, so a history whose day figures cannot be derived is not
        trusted durable state either."""
        return (self.journal_trusted and self.clean_marker
                and self.daily_figures_derivable
                and not self.journal_outstanding)


# ======================================================================
def rebuild(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic fold over the journal. Replaying it twice yields the same
    state, and a duplicated event changes nothing (idempotent by id)."""
    orders: Dict[str, Dict[str, Any]] = {}
    seen_fills = set()
    position: Optional[Dict[str, Any]] = None
    last_event = None
    reconstructions: List[Dict[str, Any]] = []

    for rec in records:
        rec_ts = rec["ts"]
        for ev in rec["events"]:
            t, aid = ev["e"], ev.get("action_id")
            last_event = t
            cid = ev.get("client_order_id") or aid

            if t == E.INTENT.value or t == E.PROTECTIVE_INTENT.value:
                if cid in orders:
                    continue                      # idempotent: never duplicate
                orders[cid] = {
                    "client_order_id": cid,
                    "intended_contracts": D(str(ev.get("contracts", "0"))),
                    "filled": D("0"),
                    "status": OrderStatus.SUBMITTED,
                    "is_protective": t == E.PROTECTIVE_INTENT.value,
                    "attempts": 0,
                    # from the journal, never from the clock: a rebuild must be
                    # byte-for-byte identical however many times it is run.
                    "ts": rec_ts,
                    # SAFETY CLOSURE, blocker C — what this order actually IS.
                    "instrument": ev.get("instrument"),
                    "kind": ev.get("order_kind"),
                    "side": ev.get("side"),
                    "reduce_only": ev.get("reduce_only"),
                    "role": ev.get("role"),
                    "logical_operation_id": (ev.get("operation_id")
                                             or ev.get("logical_operation_id")),
                    "epoch": ev.get("epoch"),
                    "created_at": rec_ts,
                }
            elif t in (E.SUBMIT_ACK.value, E.PROTECTIVE_ACK.value):
                if cid in orders:
                    orders[cid]["status"] = OrderStatus.ACK
            elif t == E.SUBMIT_FAILED.value:
                if cid in orders:
                    orders[cid]["status"] = OrderStatus.CANCELLED
            elif t == E.SUBMIT_UNKNOWN.value:
                if cid in orders:
                    orders[cid]["status"] = OrderStatus.UNKNOWN
                    orders[cid]["attempts"] = int(ev.get("attempts", 0))
            elif t == E.FILL.value:
                fid = ev.get("fill_id")
                if fid in seen_fills:
                    continue                      # idempotent: never double-count
                seen_fills.add(fid)
                if cid in orders:
                    o = orders[cid]
                    o["filled"] += D(str(ev.get("contracts", "0")))
                    # SAFETY CLOSURE, blocker E. A fill IS positive evidence.
                    # Fully filled is terminal; partly filled is explicitly
                    # PARTIALLY_FILLED rather than left sitting at ACK, so the
                    # unresolved test can be terminality and nothing else.
                    want = o["intended_contracts"]
                    if want > 0 and o["filled"] >= want:
                        o["status"] = OrderStatus.FILLED
                    elif o["filled"] > 0:
                        o["status"] = OrderStatus.PARTIALLY_FILLED
            elif t == E.ORDER_STATUS.value:
                if cid in orders:
                    # SAFETY CLOSURE. An unrecognised status used to raise out
                    # of rebuild(), so ONE status the enum did not know made
                    # recovery impossible and the process could never start.
                    # Recovery fails CLOSED: unknown means unresolved.
                    try:
                        orders[cid]["status"] = OrderStatus(ev.get("status"))
                    except ValueError:
                        orders[cid]["status"] = OrderStatus.UNKNOWN
                        orders[cid]["unrecognised_status"] = ev.get("status")
            elif t == E.POSITION_STATE.value:
                position = ev.get("position")
            elif t == E.COUNTERS.value:
                # R4C4 DAYFIG-1. READ, AND DELIBERATELY NOT USED.
                #
                # This fold used to take the day's entry count and realized
                # P&L straight off the last COUNTERS aggregate. That aggregate
                # is a SUMMARY SOMEONE WROTE, not a fact: it carries no UTC
                # day of its own, it is not tied to the fills it claims to
                # summarize, and when it is absent, stale or contradictory the
                # fold silently reported `0` for a day that held a realized
                # loss. `orbit/audit/derivation.py` settled the question for
                # authorization -- "the aggregate has no authorization power;
                # the figures are derived from fills" -- and recovery is now
                # held to the SAME contract, by calling the SAME function.
                # See `_daily_figures` below.
                pass
            elif t == E.RECONSTRUCTION.value:
                reconstructions.append(ev)

    # R4C4 DAYFIG-1. "entries" and "pnl" are deliberately NOT returned. They
    # were the only fabricated figures this fold produced, and a key that is
    # absent cannot be read by accident where a zero could.
    return {"orders": orders, "position": position,
            "last_event": last_event,
            "reconstructions": reconstructions, "fill_ids": seen_fills}


# ======================================================================
def _daily_figures(load: LoadResult,
                   now: Optional[datetime]
                   ) -> Tuple[Optional[DailyAccounting], str]:
    """R4C4 DAYFIG-1. The day's safety figures, or an honest refusal.

    ONE DERIVATION. This calls `derivation.daily_accounting` -- the same pure
    function the authorization path folds -- so recovery and authorization can
    no longer disagree about a fixed durable prefix: there is no second formula
    left to disagree with.

    It fails CLOSED and it fails NARROWLY. `rebuild` above must keep failing
    soft, because its job is to get the process far enough to ask a human and
    one unrecognised order status must not make ORBIT unstartable. But the day
    figures are not diagnostics, they are the inputs to `max_entries_per_utc_day`
    and `max_daily_loss_usdt`, and for those:

        AN UNDERIVABLE FIGURE IS NOT ZERO.

    So a history this function cannot account yields `None` and a reason --
    never `0`, which is the one value that would let a restart erase a realized
    loss and hand the daily-loss limit back its full budget.
    """
    if not load.trusted:
        return None, (f"{DAY_FIGURES_UNTRUSTED}: "
                      f"{load.reason or 'the journal chain is broken'}")
    if now is None:
        return None, DAY_FIGURES_NO_CLOCK
    try:
        return daily_accounting(load.records, now), DAY_FIGURES_DERIVED
    except LocalStateUndecidable as e:
        return None, f"{DAY_FIGURES_UNDERIVABLE}: {e}"


def recover(path: str, *, now: Optional[datetime] = None) -> RecoveryReport:
    """`now` is the session clock the UTC day is taken from.

    R4C4 DAYFIG-1. It is optional because a caller may legitimately want the
    recovery report for what it says about UNRESOLVED OPERATIONS, which no day
    boundary bears on. It is not optional for the day figures: without a clock
    there is no "today", so they are reported UNDERIVABLE rather than zero, and
    `can_complete_recovery` will not clear such a state to trade.
    """
    load = Journal.load(path)
    st = rebuild(load.records)
    daily, daily_reason = _daily_figures(load, now)
    notes: List[str] = []
    if daily is None:
        notes.append(f"daily risk figures are NOT established: {daily_reason}. "
                     f"They are not zero; they are unknown, and recovery "
                     f"cannot complete until they can be derived.")

    if load.tamper_detected:
        notes.append(f"JOURNAL UNTRUSTED: {load.reason}")
    if load.discarded_tail:
        notes.append(f"{load.discarded_tail} torn trailing record(s) discarded "
                     f"as uncommitted — the expected signature of a crash "
                     f"mid-write, not corruption")

    clean_marker = st["last_event"] == E.CLEAN_SHUTDOWN.value
    if not clean_marker:
        notes.append("no clean-shutdown marker at the tail: the previous "
                     "process did not stop in an orderly way")

    # SAFETY CLOSURE, blocker E. The test is TERMINALITY, not a hand-listed
    # pair of statuses. ACK and PARTIALLY_FILLED were previously treated as
    # settled: an order the exchange had ACCEPTED but not filled counted as
    # resolved, a CLEAN shutdown marker was written over it, and the next start
    # then believed the absence of a local record proved nothing had happened.
    WHY = {
        OrderStatus.SUBMITTED: "an INTENT was committed but no terminal outcome "
                               "was ever recorded; the order may exist on the "
                               "exchange",
        OrderStatus.ACK: "the exchange ACCEPTED this order and no fill, cancel, "
                         "rejection or expiry was ever recorded. Acceptance is "
                         "not an outcome: the order may be resting live",
        OrderStatus.PARTIALLY_FILLED: "the order filled in part and the "
                                      "remainder was never resolved",
        OrderStatus.UNKNOWN: "the submission outcome was never established",
    }
    unresolved: List[Unresolved] = []
    for cid, o in st["orders"].items():
        if o["status"] in TERMINAL_STATUSES:
            continue
        why = WHY.get(o["status"], "the outcome is not established")
        if o.get("unrecognised_status"):
            why = (f"the exchange reported a status this build does not "
                   f"recognise ({o['unrecognised_status']!r}); it is treated as "
                   f"unresolved rather than assumed settled")
        unresolved.append(Unresolved(cid, cid, o["status"].value, why))

    pos = st["position"]
    ipos = None
    if pos:
        sp = pos.get("stop_price")
        ipos = IntendedPosition(
            side=pos["side"], contracts=D(str(pos["contracts"])),
            entry_price=D(str(pos["entry_price"])),
            # A journalled position may legitimately have no stop yet.
            stop_price=None if sp in (None, "", "None") else D(str(sp)),
            stop_client_id=pos.get("stop_client_id"),
            opened_at=datetime.fromisoformat(pos["opened_at"]))

    rebuilt = IntendedState(
        journal_loaded=load.trusted,
        position=ipos,
        submitted_orders=tuple(
            SubmittedOrder(o["client_order_id"], o["intended_contracts"],
                           o["filled"], o["status"],
                           datetime.fromisoformat(o["ts"]), o["is_protective"],
                           o["attempts"],
                           instrument=o.get("instrument"),
                           kind=o.get("kind"), side=o.get("side"),
                           reduce_only=o.get("reduce_only"),
                           role=o.get("role"),
                           logical_operation_id=o.get("logical_operation_id"),
                           epoch=o.get("epoch"),
                           created_at=o.get("created_at"))
            for o in st["orders"].values()),
        # R4C4 DAYFIG-1. THE DERIVATION, or a value that cannot authorize.
        # When the figures are underivable the state carries
        # `daily_figures_derived=False`, and reconciliation refuses new entries
        # on the strength of that flag -- not on the strength of these two
        # numbers, which in that case mean nothing and are never consulted.
        entries_utc_day=(0 if daily is None else daily.entries_utc_day),
        realized_pnl_utc_day=(D("0") if daily is None
                              else daily.realized_pnl_utc_day),
        daily_figures_derived=daily is not None,
        # ALWAYS FALSE ON THE FIRST PASS. The marker is not believed on sight.
        clean_shutdown=False,
    )

    return RecoveryReport(load, load.trusted, clean_marker,
                          tuple(unresolved), rebuilt,
                          tuple(st["reconstructions"]), tuple(notes),
                          daily_figures=daily,
                          daily_figures_reason=daily_reason)


# ======================================================================
def outstanding_operations(report: RecoveryReport,
                           recon: ReconResult) -> Tuple[Unresolved, ...]:
    """The nonterminal operations reconciliation has NOT positively accounted
    for.

    SAFETY CLOSURE, blocker E, with the boundary drawn where it belongs. An
    operation is outstanding when its OUTCOME is unestablished — not merely
    when an order is alive. A protective stop that has been acknowledged AND is
    verified RESTING in the reconciled exchange view is fully established: we
    know exactly what it is and we deliberately want it live, because A1's
    protection is exchange-resident and must survive our process. An entry that
    was acknowledged and is nowhere to be seen is a different thing entirely,
    and it stays outstanding."""
    resting = {o.client_order_id for o in recon.view.open_orders
               if o.client_order_id}
    by_cid = {o.client_order_id: o for o in report.rebuilt.submitted_orders}
    out = []
    for u in report.unresolved:
        so = by_cid.get(u.client_order_id)
        if so is not None and so.is_protective \
                and u.client_order_id in resting and recon.reconciled:
            continue
        out.append(u)
    return tuple(out)


def can_complete_recovery(report: RecoveryReport,
                          recon: ReconResult) -> Tuple[bool, str]:
    """Recovery completes only when the journal is trustworthy, no exchange
    operation is outstanding, and reconciliation found nothing beyond the
    dirty-shutdown flag that recovery itself clears."""
    if not report.journal_trusted:
        return False, "the journal chain is broken; history may have been rewritten"
    # R4C4 DAYFIG-1. A state whose daily risk figures are not established may
    # not be cleared to trade. `complete_recovery` returns the state that MAY
    # BEGIN TRADING, and the gateway takes `max_entries_per_utc_day` and
    # `max_daily_loss_usdt` straight off it; clearing a state whose day figures
    # are unknown would hand the daily-loss limit back its full budget on the
    # strength of a number nobody derived. NO TRUSTED DURABLE STATE = NO NEW
    # ENTRY, and the day's realized loss is part of the durable state.
    if not report.daily_figures_derivable:
        return False, (f"the daily risk figures are not established "
                       f"({report.daily_figures_reason}); an unknown daily "
                       f"P&L is not a zero daily P&L")
    outstanding = outstanding_operations(report, recon)
    if outstanding:
        return False, (f"{len(outstanding)} exchange operation(s) remain "
                       f"unresolved: "
                       f"{[(u.client_order_id, u.status) for u in outstanding]}")
    if not recon.reconciled:
        return False, "the exchange view is not trustworthy"
    residual = [f for f in recon.findings if f.code is not F.DIRTY_SHUTDOWN]
    worst = max((f.disposition for f in residual),
                default=Disposition.SAFE_TO_RECONCILE)
    if worst is not Disposition.SAFE_TO_RECONCILE:
        return False, (f"reconciliation still reports {worst.name} findings that "
                       f"recovery does not itself clear: "
                       f"{[f.code.value for f in residual]}")
    return True, "ok"


def complete_recovery(journal: Journal, report: RecoveryReport,
                      recon: ReconResult) -> Optional[IntendedState]:
    """Writes RECOVERY_COMPLETE and returns the state that may begin trading.
    Returns None when recovery cannot complete — and the caller must then keep
    treating durable state as untrusted."""
    ok, why = can_complete_recovery(report, recon)
    journal.append_one(E.RECOVERY_COMPLETE, None, ok=ok, reason=why,
                       clean_marker=report.clean_marker,
                       unresolved=[u.client_order_id for u in report.unresolved],
                       recon_findings=[f.code.value for f in recon.findings],
                       reconciled=recon.reconciled)
    if not ok:
        return None
    return replace(report.rebuilt, clean_shutdown=True)


def write_clean_shutdown(journal: Journal, report_unresolved,
                         recon: Optional[ReconResult]) -> bool:
    """Condition 1-4 of the clean-shutdown definition, checked, not assumed.

    `report_unresolved` is a count or the sequence itself. It must be computed
    with `outstanding_operations`, not from a hand-listed pair of statuses: an
    ACKNOWLEDGED order is NOT settled, and writing a clean marker over one is
    how a live order came to be forgotten across a restart."""
    n_unresolved = (report_unresolved if isinstance(report_unresolved, int)
                    else len(report_unresolved))
    if n_unresolved:
        journal.append_one(E.SHUTDOWN_BEGIN, None,
                           clean=False, reason="unresolved exchange operations")
        return False
    if recon is None or not recon.reconciled:
        journal.append_one(E.SHUTDOWN_BEGIN, None,
                           clean=False,
                           reason="no completed reconciliation in this session")
        return False
    journal.append_one(E.SHUTDOWN_BEGIN, None, clean=True)
    journal.append_one(E.CLEAN_SHUTDOWN, None,
                       verified_against_exchange_at=str(recon.view.fetched_at),
                       run_state=recon.run_state.value)
    return True
