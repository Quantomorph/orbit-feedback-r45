"""
orbit/audit/derivation.py — SAFETY CLOSURE ROUND 4C4, findings C4-I1 and C4-I2.

WHAT THIS EXISTS TO PREVENT.

Through Round 4C3, `IntendedState` arrived as a constructor argument and the
production path checked only that it did not contradict a few selected facts.
Independent review turned that into two exchange mutations that should never
have happened.

C4-I1. A journal durably recording `entries_utc_day = 2` and
`realized_pnl_utc_day = -20` was handed an in-memory state claiming `0` and `0`.
Nothing objected. Reconciliation said RUNNING and clean, the gateway saw a fresh
day with no losses, and an order went to the exchange — bypassing BOTH
`max_entries_per_utc_day` and `max_daily_loss_usdt` with a state the durable
history flatly contradicted.

C4-I2. `_journal_contradiction` ended in `except Exception: return None`, and
`None` meant "no contradiction". A journal whose COUNTERS held `"NOT_AN_INT"`
made `rebuild` raise, the exception was swallowed, and the mutation proceeded.

    INABILITY TO DERIVE DURABLE LOCAL STATE IS NEVER EQUIVALENT TO AGREEMENT.

THE DESIGN.

Authorization-relevant local state is DERIVED here, from the exact journal
prefix the evidence artifact pins, and nothing else. There is no list of
important fields to keep in step with the schema, because the caller no longer
supplies any of them: the whole `IntendedState` is a function of durable
history. A field added to `IntendedState` tomorrow is derived or the derivation
refuses to produce a state at all.

Every failure — load, verify, parse, rebuild, revive, validate — raises. Nothing
here returns a default, coerces a malformed value to zero, or treats "I could
not tell" as "nothing is wrong".

ON STATE THAT IS "AHEAD OF THE JOURNAL". Round 4C3 kept an exception for local
state ahead of the last committed record. That exception is withdrawn. A fact
that has not been committed does not authorize an exchange mutation; if it
matters, it is committed first. That is what write-ahead already exists for.

DAILY ACCOUNTING FROM PRIMITIVE FACTS (checkpoint A, scope item 5).

The first C4-I1 repair still read `entries_utc_day` and `realized_pnl_utc_day`
from the COUNTERS aggregate. That closed the reviewed reproducer and left the
class open: authorization trusted a number that SOMEONE WROTE INTO THE JOURNAL,
and a stale COUNTERS record from yesterday stood for ever because nothing here
knew what day it was. The two figures are now DERIVED, by `daily_accounting`,
from the primitive execution facts the journal holds - INTENT (what an order
is) and FILL (what executed, at what price) - for the UTC day of the session
clock. A COUNTERS record is still parsed strictly, because a record the fold
cannot interpret makes the history uninterpretable, but it moves nothing.

    entries_utc_day      distinct ENTRY logical operations whose FIRST positive
                         fill lies on the current UTC day
    realized_pnl_utc_day average-cost fold over EVERY fill in journal order,
                         realized on the day of the reducing fill, net of the
                         fill's recorded `fee` - or, when a fill carries none,
                         the modelled taker fee (the same modelled-unless-actual
                         rule `orbit.risk.modeled_loss` already applies)

ACCOUNTING TIMESTAMP (checkpoint A.1, review finding 2). Checkpoint A assigned a
fill to a UTC day by the journal record's COMMIT time. That is not the policy.
"Realized P&L per UTC calendar day" is about when the trade EXECUTED, and the
two differ whenever ingestion lags execution: a gain executed at 23:59:50 and
committed at 00:00:10 was moved into the new day, where it OFFSET that day's
losses and let an entry through that the daily-loss limit should have refused
(reproduced before this change). So the accounting timestamp is now the FILL's
own `executed_at` — the venue's execution time (OKX `fillTime`), written by the
recorder tz-aware and normalized to UTC — and NEVER the commit time, the venue's
data-generation `ts`/`server_ts`, or the session clock.

A fill with no `executed_at`, or one that cannot be read as a tz-aware
timestamp, FAILS CLOSED. The commit-day fallback was considered and rejected:
it is conservative for a prior-day LOSS arriving today (counted today, so the
limit bites sooner) but NOT for a prior-day GAIN (counted today, so the limit
bites later). A fallback that is unsafe in one direction is not a fallback.
A fill executed on a LATER UTC day than `now` fails closed; bounded clock-skew
semantics between venue execution time and the session clock remain R4-5.

FEES (checkpoint A.1, review finding 1). The fold reads ONE fee field,
`fee_cost_usdt`, a non-negative normalized cost, and subtracts it. The venue's
raw signed value and any rebate are recorded beside it for audit and are NOT
consumed here — see `orbit/exec/fees.py` for why a signed "fee" had no fixed
meaning and how OKX's sign is normalized at ingestion. The legacy `fee` key
fails closed. A fill with no fee fields at all is charged the modelled taker
fee (modelled-unless-actual, as `orbit.risk.modeled_loss` does).

POSITION PROVENANCE (checkpoint A.1, review finding 3). The fold now derives
a CONCRETE position — side, contracts, average entry — from the fills, and
requires the durable POSITION_STATE to agree with it. A lifetime count of
entry fills proved nothing about the CURRENT position: a legitimate round trip
in the morning followed by a POSITION_STATE with no entry fill behind it was
accepted, and the model was allowed to amend the stop of a position ORBIT's
own execution record had never opened (reproduced before this change). Any
disagreement — a claimed position the fills do not back, a fill-derived
position the record does not claim, a side, size or entry price that differs —
fails closed.

What fails closed, and why: a fill with no price (cannot be valued); a fill
with no execution time (cannot be assigned to a day); a fill against an order
ORBIT has no INTENT for (cannot be classified as entry or exit); an entry with
no side (cannot be signed); a reduce-only exit that fills MORE than the open
position (a reversal ORBIT's own record says cannot have happened); a fee
under the ambiguous legacy key; a POSITION_STATE the fills contradict. None of
these is a default, a zero, or a best guess.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

from orbit.audit.records import E
from orbit.core.precision import BTC_USDT_SWAP, InstrumentSpec
from orbit.exec.fees import (FEE_COST_FIELD, LEGACY_AMBIGUOUS_FEE_FIELD,
                             REBATE_FIELD)
from orbit.exec.recon import (IntendedPosition, IntendedState, OrderStatus,
                              SubmittedOrder)


class LocalStateUndecidable(RuntimeError):
    """The durable local state needed for authorization cannot be established.

    Distinct from "the state is bad": this is "the state cannot be determined".
    Both stop the action, and they are separate codes so an operator can tell a
    corrupt journal from a disagreement.
    """


class LocalStateUntrusted(LocalStateUndecidable):
    """The journal itself is not trusted, so nothing derived from it is."""


def _dec(v: Any, what: str) -> Decimal:
    try:
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        raise LocalStateUndecidable(
            f"{what} is durably recorded as {v!r}, which is not a number. A "
            f"malformed durable value is not zero and is not a default.")


def _int(v: Any, what: str) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        raise LocalStateUndecidable(
            f"{what} is durably recorded as {v!r}, which is not an integer.")


def derive_intended(load_result: Any, *, seq: int, hash_: str,
                    now: Optional[datetime] = None,
                    spec: InstrumentSpec = BTC_USDT_SWAP) -> IntendedState:
    """The authoritative local state, from exactly this durable prefix.

    `seq` and `hash_` are the prefix the evidence artifact pins. They are
    verified here rather than assumed, so a state can never be derived from a
    different history than the one the artifact names.

    `now` is the session clock the UTC day is taken from. Without it there is
    no "today", so the day figures cannot be derived and the derivation
    refuses rather than reporting zero for a day it cannot identify.
    """
    if now is None:
        raise LocalStateUndecidable(
            "no session clock was supplied, so the current UTC day cannot be "
            "identified and the daily limits cannot be derived. Zero is not "
            "the answer to a question that was not asked.")
    if not load_result.trusted:
        raise LocalStateUntrusted(
            f"the journal is not trusted "
            f"({load_result.reason or 'no reason given'}), so no local state "
            f"can be derived from it.")
    records = load_result.records
    if seq:
        at = [r for r in records if r["seq"] == seq]
        if not at:
            raise LocalStateUndecidable(
                f"the pinned journal prefix ends at seq {seq}, which is not "
                f"present.")
        if at[0]["hash"] != hash_:
            raise LocalStateUndecidable(
                f"the record at seq {seq} does not have the pinned hash. The "
                f"history this state would be derived from is not the history "
                f"the evidence names.")
        records = [r for r in records if r["seq"] <= seq]
    elif records:
        raise LocalStateUndecidable(
            "no journal prefix was pinned, but the journal is not empty.")
    return _fold(records, now, spec)


# ======================================================================
# DAILY ACCOUNTING FROM PRIMITIVE FACTS
# ======================================================================
@dataclass(frozen=True)
class FillPosition:
    """The position ORBIT's own fills say it holds. Average cost."""
    side: str
    contracts: Decimal
    avg_entry_price: Decimal


@dataclass(frozen=True)
class DailyAccounting:
    entries_utc_day: int
    realized_pnl_utc_day: Decimal
    fill_position: Optional[FillPosition]
    """The CONCRETE position derived from primitive fills, or None when the
    fills net to flat. Checkpoint A.1: this replaces a lifetime count of entry
    fills, which could not say anything about the CURRENT position."""
    utc_day: str


def _utc_time(ts: Any, what: str) -> datetime:
    if ts in (None, "", "None"):
        raise LocalStateUndecidable(
            f"{what} carries no execution time. A fill that cannot be placed "
            f"on a UTC day cannot be accounted, and the commit day is not a "
            f"safe substitute: it would move a prior-day gain into today.")
    try:
        t = datetime.fromisoformat(str(ts))
    except (TypeError, ValueError):
        raise LocalStateUndecidable(
            f"{what} carries timestamp {ts!r}, which cannot be interpreted.")
    if t.tzinfo is None:
        raise LocalStateUndecidable(
            f"{what} carries a naive timestamp {ts!r}; a UTC day cannot be "
            f"assigned to a time with no zone.")
    return t.astimezone(timezone.utc)


def _utc_day(ts: Any, what: str) -> str:
    return _utc_time(ts, what).strftime("%Y-%m-%d")


def daily_accounting(records: List[Dict[str, Any]], now: datetime,
                     spec: InstrumentSpec = BTC_USDT_SWAP) -> DailyAccounting:
    """The two daily-limit figures, from INTENT and FILL records alone.

    Deterministic: the same records and the same `now` give the same figures,
    and a duplicated FILL (same fill_id) counts once. Every malformed or
    unclassifiable fact raises `LocalStateUndecidable`.
    """
    if now.tzinfo is None:
        raise LocalStateUndecidable("the session clock has no timezone; a UTC "
                                    "day cannot be identified from it.")
    today = now.astimezone(timezone.utc).strftime("%Y-%m-%d")
    # what each order IS, from its write-ahead record
    orders: Dict[str, Dict[str, Any]] = {}
    seen_fills = set()
    # average-cost position: side, contracts, average entry price
    pos_side: Optional[str] = None
    pos_qty = Decimal("0")
    pos_avg = Decimal("0")
    entered_ops = set()          # logical entry operations with a positive fill
    entries_today = 0
    realized_today = Decimal("0")
    cs = spec.contract_size_btc

    for rec in records:
        rec_ts = rec.get("ts")
        for ev in rec["events"]:
            t = ev["e"]
            if t in (E.INTENT.value, E.PROTECTIVE_INTENT.value):
                cid = ev.get("client_order_id") or ev.get("action_id")
                if cid in orders:
                    continue
                orders[cid] = {
                    "role": ev.get("role") or (
                        "PROTECTIVE" if t == E.PROTECTIVE_INTENT.value
                        else "ENTRY"),
                    "side": ev.get("side"),
                    "op": (ev.get("operation_id")
                           or ev.get("logical_operation_id") or cid),
                }
                continue
            if t == E.COUNTERS.value:
                # R4C4 DAYFIG-1. PARSED STRICTLY, AND STILL NOT USED.
                #
                # `_fold` below already refuses a COUNTERS record it cannot
                # interpret (C4-I2: a history this fold cannot read is not a
                # history it may authorize from). This function did not, and
                # it is the function `recovery.recover` now derives from -- so
                # a journal carrying `entries_utc_day = "NOT_AN_INT"` left
                # recovery reporting confident figures while authorization
                # refused the same prefix outright. That is the divergence
                # again, in its most dangerous direction: recovery the LESS
                # restrictive of the two.
                #
                # The aggregate still moves nothing. It only has to be
                # READABLE, because an unreadable record makes the history
                # unaccountable for BOTH callers, identically.
                if "entries_utc_day" in ev:
                    _int(ev["entries_utc_day"], "entries_utc_day")
                if "realized_pnl_utc_day" in ev:
                    _dec(ev["realized_pnl_utc_day"], "realized_pnl_utc_day")
                continue
            if t != E.FILL.value:
                continue
            fid = ev.get("fill_id")
            if fid in seen_fills:
                continue
            seen_fills.add(fid)
            cid = ev.get("client_order_id") or ev.get("action_id")
            o = orders.get(cid)
            if o is None:
                raise LocalStateUndecidable(
                    f"fill {fid!r} is recorded against {cid!r}, for which no "
                    f"INTENT exists. A fill ORBIT cannot classify as an entry "
                    f"or an exit cannot be accounted, and a fill ORBIT did "
                    f"not intend is a contradiction to reconcile, not to "
                    f"ignore.")
            qty = _dec(ev.get("contracts", None), f"contracts of fill {fid!r}")
            if qty <= 0:
                raise LocalStateUndecidable(
                    f"fill {fid!r} has contracts {qty}, which is not a fill.")
            if ev.get("price") in (None, "", "None"):
                raise LocalStateUndecidable(
                    f"fill {fid!r} carries no price; an execution with no "
                    f"price cannot be valued, and an unvalued fill is not a "
                    f"zero-P&L fill.")
            price = _dec(ev["price"], f"price of fill {fid!r}")
            if price <= 0:
                raise LocalStateUndecidable(
                    f"fill {fid!r} has price {price}, which is impossible.")
            # THE ACCOUNTING DAY IS THE EXECUTION DAY. Not the commit day
            # (`rec_ts`), not `server_ts`. Checkpoint A.1, finding 2.
            day = _utc_day(ev.get("executed_at"), f"fill {fid!r}")
            if day > today:
                raise LocalStateUndecidable(
                    f"fill {fid!r} executed on UTC day {day}, which is after "
                    f"the session's day {today}. Durable history from the "
                    f"future is not accountable; the clocks disagree.")
            notional = price * qty * cs
            # ONE fee field, unambiguous. Checkpoint A.1, finding 1.
            if LEGACY_AMBIGUOUS_FEE_FIELD in ev:
                raise LocalStateUndecidable(
                    f"fill {fid!r} carries the legacy {LEGACY_AMBIGUOUS_FEE_FIELD!r} "
                    f"field, whose sign has no fixed meaning (OKX: negative is "
                    f"a charge; Checkpoint A read it the other way). A value "
                    f"with two possible meanings is not accounted either way.")
            if REBATE_FIELD in ev:
                # validated, recorded, NOT applied: a rebate never makes the
                # daily-loss figure less conservative (orbit/exec/fees.py).
                reb = _dec(ev[REBATE_FIELD], f"rebate of fill {fid!r}")
                if reb < 0:
                    raise LocalStateUndecidable(
                        f"fill {fid!r} records a negative rebate {reb}; a "
                        f"normalized rebate cannot be negative.")
            if ev.get(FEE_COST_FIELD) in (None, "", "None"):
                fee = notional * spec.taker_fee          # modelled taker fee
            else:
                fee = _dec(ev[FEE_COST_FIELD], f"fee cost of fill {fid!r}")
                if fee < 0:
                    raise LocalStateUndecidable(
                        f"fill {fid!r} records a negative fee cost {fee}; a "
                        f"normalized cost cannot be negative, so this record "
                        f"was not written by the fee normalizer.")
            role = o["role"]
            realized = Decimal("0")
            if role == "ENTRY":
                side = o["side"]
                if side not in ("long", "short"):
                    raise LocalStateUndecidable(
                        f"entry order {cid!r} has side {side!r}; a fill with "
                        f"no side cannot be accounted.")
                if o["op"] not in entered_ops:
                    entered_ops.add(o["op"])
                    if day == today:
                        entries_today += 1
                if pos_qty == 0:
                    pos_side, pos_qty, pos_avg = side, qty, price
                elif side == pos_side:
                    pos_avg = (pos_avg * pos_qty + price * qty) / (pos_qty + qty)
                    pos_qty += qty
                else:
                    raise LocalStateUndecidable(
                        f"entry fill {fid!r} is {side} while {pos_qty} "
                        f"contracts are held {pos_side}. A1 forbids reversal "
                        f"in one action; ORBIT's own record contradicts "
                        f"itself and is not accounted.")
            elif role in ("EXIT", "PROTECTIVE"):
                if pos_qty <= 0 or qty > pos_qty:
                    raise LocalStateUndecidable(
                        f"{role.lower()} fill {fid!r} of {qty} contracts "
                        f"against {pos_qty} held: a reduce-only order cannot "
                        f"have executed beyond the position. Durable history "
                        f"contradicts itself.")
                sign = Decimal("1") if pos_side == "long" else Decimal("-1")
                realized = (price - pos_avg) * qty * cs * sign
                pos_qty -= qty
                if pos_qty == 0:
                    pos_side, pos_avg = None, Decimal("0")
            elif role == "ADMIN":
                raise LocalStateUndecidable(
                    f"fill {fid!r} is recorded against an ADMIN mutation "
                    f"{cid!r}; a cancel or an amendment does not fill.")
            else:
                raise LocalStateUndecidable(
                    f"order {cid!r} has role {role!r}, which this build does "
                    f"not account for.")
            if day == today:
                realized_today += realized - fee

    fp = (None if pos_qty == 0
          else FillPosition(pos_side, pos_qty, pos_avg))
    return DailyAccounting(entries_today, realized_today, fp, today)


def _check_position_provenance(ipos: Optional[IntendedPosition],
                               fp: Optional[FillPosition],
                               spec: InstrumentSpec) -> None:
    """The durable POSITION_STATE must be the position the fills produce.

    Checkpoint A.1, finding 3. Side and size must match exactly; the entry
    price within one tick, because the writer and this fold may round an
    average differently at the last digit and a tick is the venue's own
    resolution. Anything else is a contradiction between two of ORBIT's own
    records, and a contradiction is not a licence to act.
    """
    if ipos is None and fp is None:
        return
    if ipos is None:
        raise LocalStateUndecidable(
            f"ORBIT's fills net to {fp.contracts} contracts {fp.side} at "
            f"{fp.avg_entry_price}, but no durable POSITION_STATE claims a "
            f"position. The execution record and the position record "
            f"disagree.")
    if fp is None:
        raise LocalStateUndecidable(
            f"the durable POSITION_STATE claims {ipos.contracts} contracts "
            f"{ipos.side}, but no ENTRY fill in ORBIT's record opened it: "
            f"the fills net to flat. A position with no execution behind it "
            f"is not a position ORBIT may manage on the model's say-so.")
    if ipos.side != fp.side or ipos.contracts != fp.contracts:
        raise LocalStateUndecidable(
            f"the durable POSITION_STATE claims {ipos.contracts} {ipos.side}; "
            f"ORBIT's fills say {fp.contracts} {fp.side}. The two records "
            f"disagree.")
    if abs(ipos.entry_price - fp.avg_entry_price) > spec.tick_size:
        raise LocalStateUndecidable(
            f"the durable POSITION_STATE claims entry {ipos.entry_price}; "
            f"ORBIT's fills average {fp.avg_entry_price}, more than one tick "
            f"({spec.tick_size}) away. The two records disagree.")


def _fold(records: List[Dict[str, Any]], now: datetime,
          spec: InstrumentSpec) -> IntendedState:
    """A strict re-implementation of the durable fold.

    `recovery.rebuild` deliberately fails SOFT in places — an unrecognised order
    status becomes UNKNOWN so that one bad enum cannot make a process
    unstartable. That is right for recovery, whose job is to get far enough to
    ask a human. It is wrong for authorization, whose job is to refuse. So this
    fold is separate and every malformed value raises.
    """
    orders: Dict[str, Dict[str, Any]] = {}
    seen_fills = set()
    position: Optional[Dict[str, Any]] = None
    clean = False

    for rec in records:
        rec_ts = rec["ts"]
        for ev in rec["events"]:
            t = ev["e"]
            cid = ev.get("client_order_id") or ev.get("action_id")
            if t in (E.INTENT.value, E.PROTECTIVE_INTENT.value):
                if cid in orders:
                    continue
                orders[cid] = {
                    "client_order_id": cid,
                    "intended_contracts": _dec(ev.get("contracts", "0"),
                                               f"contracts of {cid!r}"),
                    "filled": Decimal("0"),
                    "status": OrderStatus.SUBMITTED,
                    "is_protective": t == E.PROTECTIVE_INTENT.value,
                    "attempts": 0,
                    "ts": rec_ts,
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
                clean = False
            elif t in (E.SUBMIT_ACK.value, E.PROTECTIVE_ACK.value):
                if cid in orders:
                    orders[cid]["status"] = OrderStatus.ACK
            elif t == E.SUBMIT_FAILED.value:
                if cid in orders:
                    orders[cid]["status"] = OrderStatus.CANCELLED
            elif t == E.SUBMIT_UNKNOWN.value:
                if cid in orders:
                    orders[cid]["status"] = OrderStatus.UNKNOWN
                    orders[cid]["attempts"] = _int(ev.get("attempts", 0),
                                                   f"attempts of {cid!r}")
            elif t == E.FILL.value:
                fid = ev.get("fill_id")
                if fid in seen_fills:
                    continue
                seen_fills.add(fid)
                if cid in orders:
                    o = orders[cid]
                    o["filled"] += _dec(ev.get("contracts", "0"),
                                        f"fill {fid!r}")
                    want = o["intended_contracts"]
                    if want > 0 and o["filled"] >= want:
                        o["status"] = OrderStatus.FILLED
                    elif o["filled"] > 0:
                        o["status"] = OrderStatus.PARTIALLY_FILLED
            elif t == E.ORDER_STATUS.value:
                if cid in orders:
                    try:
                        orders[cid]["status"] = OrderStatus(ev.get("status"))
                    except ValueError:
                        raise LocalStateUndecidable(
                            f"{cid!r} has durable status {ev.get('status')!r}, "
                            f"which is not a status this build understands. "
                            f"Unknown is not safe.")
            elif t == E.POSITION_STATE.value:
                position = ev.get("position")
            elif t == E.COUNTERS.value:
                # Parsed STRICTLY and then NOT USED. Checkpoint A, scope 5:
                # the aggregate has no authorization power; the figures are
                # derived from fills below. A malformed record still fails
                # closed because a history this fold cannot interpret is not
                # a history it may authorize from.
                if "entries_utc_day" in ev:
                    _int(ev["entries_utc_day"], "entries_utc_day")
                if "realized_pnl_utc_day" in ev:
                    _dec(ev["realized_pnl_utc_day"], "realized_pnl_utc_day")
            elif t == E.CLEAN_SHUTDOWN.value:
                clean = True
            elif t in (E.RUN_START.value, E.SUBMIT_ATTEMPTED.value):
                clean = False

    ipos = None
    if position:
        try:
            sp = position.get("stop_price")
            ipos = IntendedPosition(
                side=position["side"],
                contracts=_dec(position["contracts"], "position contracts"),
                entry_price=_dec(position["entry_price"], "position entry"),
                stop_price=(None if sp in (None, "", "None")
                            else _dec(sp, "position stop")),
                stop_client_id=position.get("stop_client_id"),
                opened_at=datetime.fromisoformat(position["opened_at"]))
        except LocalStateUndecidable:
            raise
        except Exception as e:
            raise LocalStateUndecidable(
                f"the durable position payload cannot be interpreted: {e}")

    acct = daily_accounting(records, now, spec)
    _check_position_provenance(ipos, acct.fill_position, spec)

    return IntendedState(
        journal_loaded=True,
        clean_shutdown=clean,
        position=ipos,
        submitted_orders=tuple(
            SubmittedOrder(
                o["client_order_id"], o["intended_contracts"], o["filled"],
                o["status"], datetime.fromisoformat(o["ts"]),
                o["is_protective"], o["attempts"],
                instrument=o["instrument"], kind=o["kind"], side=o["side"],
                reduce_only=o["reduce_only"], role=o["role"],
                logical_operation_id=o["logical_operation_id"],
                epoch=o["epoch"], created_at=o["created_at"])
            for o in orders.values()),
        entries_utc_day=acct.entries_utc_day,
        realized_pnl_utc_day=acct.realized_pnl_utc_day,
        # R4C4 DAYFIG-1. This fold reaches here only by DERIVING the two
        # figures above from primitive fills; every other outcome raised. So
        # the claim is always True here, and it is stated rather than implied
        # because `recovery.recover` now makes the same claim from the same
        # function and a consumer must be able to test it the same way.
        daily_figures_derived=True,
        position_fill_backed=True)
