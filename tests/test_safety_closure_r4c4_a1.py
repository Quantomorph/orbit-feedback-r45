"""
tests/test_safety_closure_r4c4_a1.py — ORBIT A1 SAFETY CLOSURE, ROUND 4C4,
checkpoint A.1 — independent review of checkpoint A.

Three review findings against the fill-derived daily accounting, each
reproduced against the untouched checkpoint A tree before repair:

    F1  FEE SIGN. A negative `fee` was read as a rebate and clamped to zero.
        OKX: negative = CHARGED, positive = rebate. Raw OKX fees would have
        made every charged fee vanish and understated the daily loss.
    F2  ACCOUNTING DAY. A fill was assigned to the UTC day of its journal
        COMMIT. A +20 gain executed 23:59:50, committed 00:00:10, offset a
        -20 loss today and an entry went out (reproduced: ACK, 1 call).
    F3  POSITION PROVENANCE. `entry_fills_on_record` was a lifetime count. A
        legitimate round trip in the morning, then a POSITION_STATE with no
        entry fill behind it: the model was allowed to amend its stop
        (reproduced: ACK, 1 call).

    A VALUE WITH TWO POSSIBLE MEANINGS IS NOT ACCOUNTED EITHER WAY.
    THE ACCOUNTING DAY IS THE EXECUTION DAY.
    A POSITION IS THE POSITION THE FILLS PRODUCE, OR IT IS NOT A POSITION.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, pos, stop_order
from orbit.audit.cycle import CycleRecorder
from orbit.audit.derivation import (LocalStateUndecidable, daily_accounting,
                                    derive_intended)
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.core.precision import BTC_USDT_SWAP as SPEC
from orbit.exec.fees import (FEE_COST_FIELD, LEGACY_AMBIGUOUS_FEE_FIELD,
                             REBATE_FIELD, VENUE_RAW_FIELD, FeeUnreadable,
                             FillFee, normalize_okx_fee, zero_fee)
from orbit.exec.recon import IntendedState
from orbit.risk.limits import A1
from orbit.tools.session import ActionStatus

PASS, FAIL = [], []
TMP = tempfile.mkdtemp()
N = [0]


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def banner(t):
    print("\n" + "-" * 78)
    print(t)


def raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


def fresh(name, intended=None, exch=None):
    N[0] += 1
    d = os.path.join(TMP, f"{name}{N[0]}")
    os.makedirs(d, exist_ok=True)
    r = Rig(d, name, intended=intended, exch=exch or Exch())
    r.acquire()
    return r


def calls(r):
    return len(r.adapter.calls)


def trip(r, n, entry_price, exit_price, *, entry_fee=None, exit_fee=None,
         when=None, entry_exec=None, exit_exec=None, contracts="1",
         side="long"):
    """A round trip written with EXPLICIT FILL fields. `entry_fee`/`exit_fee`
    are dicts of the exact durable fee keys to write (None = write nothing:
    the fold then charges the modelled taker fee)."""
    when = when or NOW
    xside = "short" if side == "long" else "long"
    e, x = f"t{n}-e", f"t{n}-x"
    for cid, kind, sd, role, ro, price, fee, ex in (
            (e, "OPEN", side, "ENTRY", False, entry_price, entry_fee, entry_exec),
            (x, "CLOSE", xside, "EXIT", True, exit_price, exit_fee, exit_exec)):
        r._append_at(when, E.INTENT, cid, client_order_id=cid,
                     contracts=contracts, instrument="BTC-USDT-SWAP",
                     order_kind=kind, side=sd, role=role, reduce_only=ro)
        r._append_at(when, E.FILL, cid, client_order_id=cid, fill_id=cid + "-f",
                     contracts=contracts, price=price,
                     executed_at=(ex or when).isoformat(), **(fee or {}))


def acct(r, now=None):
    return daily_accounting(Journal.load(r.path).records, now or NOW, SPEC)


def undecidable(r, now=None):
    try:
        acct(r, now)
        return None
    except LocalStateUndecidable as e:
        return str(e)


LIM = A1.max_entries_per_utc_day
LOSS = A1.max_daily_loss_usdt
# one contract at 30000: notional 300 USDT; modelled taker fee 0.15
MODELLED = D("30000") * D("1") * SPEC.contract_size_btc * SPEC.taker_fee


# ======================================================================
banner("F1 — FEE SIGN / NORMALIZATION")
# ======================================================================

# --- the normalizer, with ACTUAL OKX sign semantics
f = normalize_okx_fee("-0.15")
check("F1.1  OKX negative raw fee is a CHARGE: cost 0.15, rebate 0, raw kept",
      f.fee_cost_usdt == D("0.15") and f.rebate_usdt == 0
      and f.venue_fee_raw == "-0.15" and f.fee_venue == "okx",
      str(f))
f = normalize_okx_fee("0.05")
check("F1.2  OKX positive raw fee is a REBATE: cost 0, rebate 0.05",
      f.fee_cost_usdt == 0 and f.rebate_usdt == D("0.05"), str(f))
f = normalize_okx_fee("0")
check("F1.3  OKX zero fee: cost 0, rebate 0, raw '0' kept",
      f.fee_cost_usdt == 0 and f.rebate_usdt == 0 and f.venue_fee_raw == "0")
check("F1.4  a MISSING OKX fee is not a zero fee: the normalizer refuses it",
      raises(FeeUnreadable, lambda: normalize_okx_fee(None)))
check("F1.5  a non-numeric or non-finite OKX fee is refused",
      raises(FeeUnreadable, lambda: normalize_okx_fee("abc"))
      and raises(FeeUnreadable, lambda: normalize_okx_fee("NaN"))
      and raises(FeeUnreadable, lambda: normalize_okx_fee("-Infinity")))
check("F1.6  a FillFee cannot be built with a negative cost or a negative "
      "rebate, or with both a cost and a rebate",
      raises(FeeUnreadable, lambda: FillFee(D("-1"), D("0"), "x", "t"))
      and raises(FeeUnreadable, lambda: FillFee(D("0"), D("-1"), "x", "t"))
      and raises(FeeUnreadable, lambda: FillFee(D("1"), D("1"), "x", "t")))
check("F1.7  the durable field set is exactly the four normalized keys, and "
      "the ambiguous legacy key is not among them",
      set(zero_fee().as_event_fields()) == {FEE_COST_FIELD, REBATE_FIELD,
                                            VENUE_RAW_FIELD, "fee_venue"}
      and LEGACY_AMBIGUOUS_FEE_FIELD not in zero_fee().as_event_fields())

# --- the recorder writes only normalized fields
r = fresh("f1rec", intended=flat())
rec = CycleRecorder(r.journal)
rec.record_fill_group("a", "e", "f", "1", "30000", None, 0, "0",
                      executed_at=NOW, fee=normalize_okx_fee("-0.15"))
ev = [x for rr in Journal.load(r.path).records for x in rr["events"]
      if x["e"] == E.FILL.value][-1]
check("F1.8  the recorder writes fee_cost_usdt=0.15 and venue_fee_raw='-0.15' "
      "for an OKX charge, and never the legacy key",
      ev.get(FEE_COST_FIELD) == "0.15" and ev.get(VENUE_RAW_FIELD) == "-0.15"
      and ev.get(REBATE_FIELD) == "0" and LEGACY_AMBIGUOUS_FEE_FIELD not in ev,
      str({k: ev.get(k) for k in (FEE_COST_FIELD, REBATE_FIELD, VENUE_RAW_FIELD)}))
check("F1.9  the recorder refuses a raw venue value in place of a FillFee",
      raises(ValueError, lambda: rec.record_fill_group(
          "a", "e", "f2", "1", "30000", None, 0, "0", executed_at=NOW,
          fee="-0.15")))

# --- the fold, end to end through the recorder (the production write path)
def okx_trip(r, n, entry_price, exit_price, entry_raw, exit_raw):
    e, x = f"o{n}-e", f"o{n}-x"
    rec = CycleRecorder(r.journal)
    for cid, kind, sd, role, ro, price, raw in (
            (e, "OPEN", "long", "ENTRY", False, entry_price, entry_raw),
            (x, "CLOSE", "short", "EXIT", True, exit_price, exit_raw)):
        r.journal.append_one(E.INTENT, cid, client_order_id=cid, contracts="1",
                             instrument="BTC-USDT-SWAP", order_kind=kind,
                             side=sd, role=role, reduce_only=ro)
        rec.record_fill_group(cid, cid, cid + "-f", "1", price, None, 0, "0",
                              executed_at=NOW,
                              fee=(None if raw is None
                                   else normalize_okx_fee(raw)))


r = fresh("f1a", intended=flat())
okx_trip(r, 0, "30000", "30000", "-0.15", "-0.15")
check("F1.10 FLAT round trip with two OKX-charged fees realizes exactly -0.30",
      acct(r).realized_pnl_utc_day == D("-0.30"), str(acct(r).realized_pnl_utc_day))

r = fresh("f1b", intended=flat())
okx_trip(r, 0, "30000", "30100", "-0.15", "-0.15")      # +1.00 gross
check("F1.11 PROFITABLE trip: +1.00 gross, two OKX charges -> +0.70",
      acct(r).realized_pnl_utc_day == D("0.70"), str(acct(r).realized_pnl_utc_day))

r = fresh("f1c", intended=flat())
okx_trip(r, 0, "30000", "29900", "-0.15", "-0.15")      # -1.00 gross
check("F1.12 LOSING trip: -1.00 gross, two OKX charges -> -1.30 (fees deepen "
      "the loss, never soften it)",
      acct(r).realized_pnl_utc_day == D("-1.30"), str(acct(r).realized_pnl_utc_day))

r = fresh("f1d", intended=flat())
okx_trip(r, 0, "30000", "30000", "0", "0")
check("F1.13 ZERO recorded fees: exactly 0, the modelled fee is NOT applied "
      "over an explicit zero",
      acct(r).realized_pnl_utc_day == D("0"), str(acct(r).realized_pnl_utc_day))

r = fresh("f1e", intended=flat())
okx_trip(r, 0, "30000", "30000", None, None)
check("F1.14 MISSING fee on both legs: the modelled taker fee is charged on "
      "each (-0.30), never zero",
      acct(r).realized_pnl_utc_day == -(MODELLED * 2),
      f"{acct(r).realized_pnl_utc_day} vs {-(MODELLED * 2)}")

r = fresh("f1f", intended=flat())
okx_trip(r, 0, "30000", "30000", "0.10", "0.10")        # OKX rebates
check("F1.15 OKX REBATES (positive raw) never improve the figure: flat trip "
      "with two 0.10 rebates realizes exactly 0, not +0.20",
      acct(r).realized_pnl_utc_day == D("0"), str(acct(r).realized_pnl_utc_day))

# --- THE PROOF: a charged OKX fee cannot be read as a rebate anywhere
r = fresh("f1g", intended=flat())
okx_trip(r, 0, "30000", "29900", "-0.15", "-0.15")
ev = [x for rr in Journal.load(r.path).records for x in rr["events"]
      if x["e"] == E.FILL.value]
check("F1.16 PROOF: for an OKX charge, every durable record carries "
      "rebate_usdt == 0 and fee_cost_usdt > 0; the raw sign survives only in "
      "the audit-only field and is never consumed",
      all(D(x[REBATE_FIELD]) == 0 and D(x[FEE_COST_FIELD]) > 0
          and x[VENUE_RAW_FIELD].startswith("-") for x in ev)
      and acct(r).realized_pnl_utc_day == D("-1.30"))

# --- the legacy ambiguous key fails closed, whatever its sign
for sign, label in (("-0.15", "negative"), ("0.15", "positive"), ("0", "zero")):
    r = fresh("f1h", intended=flat())
    trip(r, 0, "30000", "30000", entry_fee={"fee": sign}, exit_fee={"fee": sign})
    why = undecidable(r)
    check(f"F1.17 the legacy signed `fee` key ({label}) is REFUSED: a value "
          f"with two possible meanings is not accounted either way",
          why is not None and "legacy" in why, (why or "accounted")[:80])

# --- the durable path: a raw OKX charge written under checkpoint A semantics
#     would have been a rebate; under A.1 the record cannot even be written
#     with that meaning, and if it exists it is refused.
r = fresh("f1i", intended=flat())
trip(r, 0, "30000", "30000", entry_fee={"fee": "-0.15"}, exit_fee={"fee": "-0.15"})
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().propose_order("long", "29700")
check("F1.18 END TO END: a journal carrying raw-signed fees blocks the action "
      "(LOCAL_STATE_DERIVATION_FAILED) with zero mutations, instead of "
      "understating the day's loss",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == 0,
      f"{out.status.value}/{out.code}")

# --- normalized negatives are refused too (they cannot come from the normalizer)
r = fresh("f1j", intended=flat())
trip(r, 0, "30000", "30000", entry_fee={FEE_COST_FIELD: "-0.15"},
     exit_fee={FEE_COST_FIELD: "0"})
check("F1.19 a NEGATIVE fee_cost_usdt is refused: the normalizer cannot "
      "produce it, so the record was not written by the normalizer",
      undecidable(r) is not None)
r = fresh("f1k", intended=flat())
trip(r, 0, "30000", "30000", entry_fee={FEE_COST_FIELD: "0", REBATE_FIELD: "-1"},
     exit_fee={FEE_COST_FIELD: "0"})
check("F1.20 a NEGATIVE rebate_usdt is refused likewise",
      undecidable(r) is not None)

# --- the daily-loss limit sees the fees
r = fresh("f1l", intended=flat())
okx_trip(r, 0, "30000", "28020", "-0.15", "-0.15")     # -19.80 gross, -20.10 net
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().propose_order("long", "29700")
check("F1.21 a -19.80 gross day with two OKX charges is a -20.10 day: the "
      "daily-loss limit is REACHED and the entry refused. Under checkpoint A "
      "semantics the charges vanished and this entry went out",
      out.code == "DAILY_LOSS_REACHED" and calls(r) == 0,
      f"{out.status.value}/{out.code}")


# ======================================================================
banner("F2 — UTC ACCOUNTING DAY IS THE EXECUTION DAY")
# ======================================================================
MIDNIGHT = NOW.replace(hour=0, minute=0, second=0)
Y = MIDNIGHT - timedelta(seconds=10)          # 23:59:50 yesterday
T = MIDNIGHT + timedelta(seconds=10)          # 00:00:10 today
ZERO = {FEE_COST_FIELD: "0"}


def loss_today(r, n=9):
    trip(r, n, "30000", "28000", entry_fee=ZERO, exit_fee=ZERO,
         when=NOW - timedelta(hours=1))        # -20 executed and committed today


# THE REPRODUCER
r = fresh("f2a", intended=flat())
trip(r, 0, "30000", "32000", entry_fee=ZERO, exit_fee=ZERO,
     when=T, entry_exec=Y - timedelta(minutes=30), exit_exec=Y)   # +20, executed
loss_today(r)                                                     # yesterday
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
a = acct(r)
out = r.session().propose_order("long", "29700")
check("F2.1  THE REPRODUCER: a +20 gain EXECUTED 23:59:50 yesterday and "
      "COMMITTED 00:00:10 today does not offset today's -20: today is -20, "
      "DAILY_LOSS_REACHED, zero mutations (checkpoint A: ACK, one mutation)",
      a.realized_pnl_utc_day == D("-20") and a.entries_utc_day == 1
      and out.code == "DAILY_LOSS_REACHED" and calls(r) == 0,
      f"pnl={a.realized_pnl_utc_day} entries={a.entries_utc_day} "
      f"{out.status.value}/{out.code}")

r = fresh("f2b", intended=flat())
trip(r, 0, "30000", "32000", entry_fee=ZERO, exit_fee=ZERO,
     when=T, entry_exec=T, exit_exec=T)                # +20 executed today
loss_today(r)
a = acct(r)
check("F2.2  the same trip EXECUTED after midnight IS today's: +20 - 20 = 0, "
      "two entries today",
      a.realized_pnl_utc_day == D("0") and a.entries_utc_day == 2,
      f"pnl={a.realized_pnl_utc_day} entries={a.entries_utc_day}")

r = fresh("f2c", intended=flat())
trip(r, 0, "30000", "32000", entry_fee=ZERO, exit_fee=ZERO,
     when=T, entry_exec=Y - timedelta(minutes=30), exit_exec=Y)
a = acct(r)
check("F2.3  POSITIVE prior-day P&L arriving today counts for yesterday: "
      "today is 0 with 0 entries",
      a.realized_pnl_utc_day == D("0") and a.entries_utc_day == 0,
      f"pnl={a.realized_pnl_utc_day} entries={a.entries_utc_day}")

r = fresh("f2d", intended=flat())
trip(r, 0, "30000", "28000", entry_fee=ZERO, exit_fee=ZERO,
     when=T, entry_exec=Y - timedelta(minutes=30), exit_exec=Y)
a = acct(r)
check("F2.4  NEGATIVE prior-day P&L arriving today counts for yesterday too: "
      "today is 0 (the policy is the execution day, not 'whichever is worse')",
      a.realized_pnl_utc_day == D("0") and a.entries_utc_day == 0,
      f"pnl={a.realized_pnl_utc_day} entries={a.entries_utc_day}")

# the entry leg yesterday, the exit leg today: entry counts yesterday, P&L today
r = fresh("f2e", intended=flat())
trip(r, 0, "30000", "28000", entry_fee=ZERO, exit_fee=ZERO,
     when=T, entry_exec=Y, exit_exec=T)
a = acct(r)
check("F2.5  entry executed yesterday, exit executed today: 0 entries today, "
      "-20 realized today",
      a.realized_pnl_utc_day == D("-20") and a.entries_utc_day == 0,
      f"pnl={a.realized_pnl_utc_day} entries={a.entries_utc_day}")

# missing / malformed execution time fails closed
r = fresh("f2f", intended=flat())
r._append_at(NOW, E.INTENT, "m", client_order_id="m", contracts="1",
             instrument="BTC-USDT-SWAP", order_kind="OPEN", side="long",
             role="ENTRY", reduce_only=False)
r._append_at(NOW, E.FILL, "m", client_order_id="m", fill_id="m-f",
             contracts="1", price="30000", **ZERO)          # no executed_at
why = undecidable(r)
check("F2.6  a fill with NO executed_at fails closed (no commit-day fallback)",
      why is not None and "execution time" in why, (why or "accounted")[:90])

for bad, label in (("yesterday-ish", "unparseable"),
                   ("2026-09-08T11:00:00", "naive (no zone)")):
    r = fresh("f2g", intended=flat())
    r._append_at(NOW, E.INTENT, "m", client_order_id="m", contracts="1",
                 instrument="BTC-USDT-SWAP", order_kind="OPEN", side="long",
                 role="ENTRY", reduce_only=False)
    r._append_at(NOW, E.FILL, "m", client_order_id="m", fill_id="m-f",
                 contracts="1", price="30000", executed_at=bad, **ZERO)
    check(f"F2.7  a {label} executed_at fails closed",
          undecidable(r) is not None)

# timezone normalization: 01:30 at UTC+2 is 23:30 UTC yesterday
r = fresh("f2h", intended=flat())
madrid = timezone(timedelta(hours=2))
exec_local = datetime(NOW.year, NOW.month, NOW.day, 1, 30, tzinfo=madrid)
trip(r, 0, "30000", "32000", entry_fee=ZERO, exit_fee=ZERO, when=T,
     entry_exec=exec_local - timedelta(minutes=5), exit_exec=exec_local)
a = acct(r)
check("F2.8  TIMEZONE NORMALIZATION: an execution stamped 01:30+02:00 is "
      "23:30 UTC yesterday and counts for yesterday",
      a.realized_pnl_utc_day == D("0") and a.entries_utc_day == 0,
      f"pnl={a.realized_pnl_utc_day} entries={a.entries_utc_day}")
r = fresh("f2i", intended=flat())
exec_local = datetime(NOW.year, NOW.month, NOW.day, 2, 30, tzinfo=madrid)
trip(r, 0, "30000", "32000", entry_fee=ZERO, exit_fee=ZERO, when=T,
     entry_exec=exec_local - timedelta(minutes=5), exit_exec=exec_local)
a = acct(r)
check("F2.9  ...and 02:30+02:00 is 00:30 UTC today and counts for today",
      a.realized_pnl_utc_day == D("20") and a.entries_utc_day == 1,
      f"pnl={a.realized_pnl_utc_day} entries={a.entries_utc_day}")

# the recorder normalizes to UTC on write
r = fresh("f2j", intended=flat())
rec = CycleRecorder(r.journal)
rec.record_fill_group("a", "e", "f", "1", "30000", None, 0, "0",
                      executed_at=datetime(NOW.year, NOW.month, NOW.day, 1, 30,
                                           tzinfo=madrid), fee=zero_fee())
ev = [x for rr in Journal.load(r.path).records for x in rr["events"]
      if x["e"] == E.FILL.value][-1]
check("F2.10 the recorder writes executed_at normalized to UTC",
      ev["executed_at"].endswith("+00:00") and "23:30" in ev["executed_at"],
      ev["executed_at"])
check("F2.11 the recorder refuses a naive or unparseable executed_at",
      raises(ValueError, lambda: rec.record_fill_group(
          "a", "e", "f2", "1", "30000", None, 0, "0",
          executed_at=datetime(2026, 9, 8, 1, 30), fee=zero_fee()))
      and raises(ValueError, lambda: rec.record_fill_group(
          "a", "e", "f3", "1", "30000", None, 0, "0",
          executed_at="not a time", fee=zero_fee())))

# executed_at is NOT server_ts: a fill carrying only server_ts fails closed
r = fresh("f2k", intended=flat())
r._append_at(NOW, E.INTENT, "m", client_order_id="m", contracts="1",
             instrument="BTC-USDT-SWAP", order_kind="OPEN", side="long",
             role="ENTRY", reduce_only=False)
r._append_at(NOW, E.FILL, "m", client_order_id="m", fill_id="m-f",
             contracts="1", price="30000", server_ts=NOW.isoformat(), **ZERO)
check("F2.12 OKX `ts`/server_ts is NOT an execution time: a fill carrying "
      "only server_ts fails closed",
      undecidable(r) is not None)

# execution on a later UTC day than now
r = fresh("f2l", intended=flat())
trip(r, 0, "30000", "30000", entry_fee=ZERO, exit_fee=ZERO, when=NOW,
     entry_exec=NOW + timedelta(days=1), exit_exec=NOW + timedelta(days=1))
check("F2.13 a fill EXECUTED on a later UTC day than now fails closed",
      undecidable(r) is not None)


# ======================================================================
banner("F3 — THE POSITION IS THE POSITION THE FILLS PRODUCE")
# ======================================================================
def claim_position(r, side="long", contracts="2.38", entry="30000",
                   stop="29700.1", cid="stop1", own_stop=True):
    if own_stop:
        r.journal.append_one(E.PROTECTIVE_INTENT, cid, client_order_id=cid,
                             contracts=contracts, instrument="BTC-USDT-SWAP",
                             order_kind="PROTECTIVE", role="PROTECTIVE",
                             reduce_only=True, stop=stop)
        r.journal.append_one(E.PROTECTIVE_ACK, cid, client_order_id=cid)
    r.journal.append_one(E.POSITION_STATE, None, position={
        "side": side, "contracts": contracts, "entry_price": entry,
        "stop_price": stop, "stop_client_id": cid,
        "opened_at": (NOW - timedelta(minutes=30)).isoformat()})


def entry_fill(r, cid, contracts, price, side="long", when=None):
    when = when or NOW
    r._append_at(when, E.INTENT, cid, client_order_id=cid, contracts=contracts,
                 instrument="BTC-USDT-SWAP", order_kind="OPEN", side=side,
                 role="ENTRY", reduce_only=False)
    r._append_at(when, E.FILL, cid, client_order_id=cid, fill_id=cid + "-f",
                 contracts=contracts, price=price,
                 executed_at=when.isoformat(), **ZERO)


# THE REPRODUCER
r = fresh("f3a", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
trip(r, 0, "30000", "30000", entry_fee=ZERO, exit_fee=ZERO,
     when=NOW - timedelta(hours=3))                  # a legitimate morning trip
claim_position(r)                                    # then: a position with no fill
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().modify_stop("29750")
check("F3.1  THE REPRODUCER: a legitimate historical round trip, then a "
      "POSITION_STATE with NO entry fill behind it, exchange agreeing -> the "
      "stop amendment is BLOCKED with zero mutations (checkpoint A: ACK)",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == 0,
      f"{out.status.value}/{out.code}")
def derive_why(r):
    head = Journal.load(r.path)
    try:
        derive_intended(head, seq=head.records[-1]["seq"],
                        hash_=head.records[-1]["hash"], now=NOW, spec=SPEC)
        return None
    except LocalStateUndecidable as e:
        return str(e)


why = derive_why(r)
check("F3.2  ...and the refusal says why: the fills net to flat",
      why is not None and "net to flat" in why, (why or "")[:100])

# the control: the same position WITH its entry fill is accepted
r = fresh("f3b", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
trip(r, 0, "30000", "30000", entry_fee=ZERO, exit_fee=ZERO,
     when=NOW - timedelta(hours=3))
entry_fill(r, "e-now", "2.38", "30000")
claim_position(r)
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().modify_stop("29750")
check("F3.3  CONTROL: the same claim backed by its own entry fill is accepted",
      out.status is ActionStatus.ACKNOWLEDGED and calls(r) == 1,
      f"{out.status.value}/{out.code}")

# size disagreement
r = fresh("f3c", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
entry_fill(r, "e", "1.19", "30000")
claim_position(r, contracts="2.38")
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().modify_stop("29750")
check("F3.4  POSITION_STATE claims 2.38 but the fills opened 1.19: BLOCKED",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == 0,
      f"{out.status.value}/{out.code}")

# side disagreement
r = fresh("f3d", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
entry_fill(r, "e", "2.38", "30000", side="short")
claim_position(r, side="long")
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().modify_stop("29750")
check("F3.5  POSITION_STATE claims LONG but the fills opened SHORT: BLOCKED",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == 0,
      f"{out.status.value}/{out.code}")

# entry price disagreement beyond one tick
r = fresh("f3e", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
entry_fill(r, "e", "2.38", "30050")
claim_position(r, entry="30000")
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().modify_stop("29750")
check("F3.6  POSITION_STATE claims entry 30000 but the fills averaged 30050: "
      "BLOCKED (more than one tick apart)",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == 0,
      f"{out.status.value}/{out.code}")

# entry price within one tick is tolerated (writer rounding)
r = fresh("f3f", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
entry_fill(r, "e", "2.38", "30000.05")
claim_position(r, entry="30000")
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().modify_stop("29750")
check("F3.7  an entry price within ONE TICK of the fill average is tolerated",
      out.status is ActionStatus.ACKNOWLEDGED, f"{out.status.value}/{out.code}")

# the other direction: fills say open, POSITION_STATE says flat
r = fresh("f3g", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
entry_fill(r, "e", "2.38", "30000")
r.journal.append_one(E.CLEAN_SHUTDOWN, None)          # no POSITION_STATE
out = r.session().close_position()
check("F3.8  the fills say 2.38 long but no POSITION_STATE claims it: BLOCKED "
      "(the execution record and the position record disagree)",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == 0,
      f"{out.status.value}/{out.code}")

# an overnight position is still fine: its entry fill is yesterday's
r = fresh("f3h", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
entry_fill(r, "e", "2.38", "30000", when=NOW - timedelta(days=1))
claim_position(r)
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
s = r.session()
sysr = s.get_system_state()
out = s.close_position()
check("F3.9  a position entered YESTERDAY is fill-backed today: 0 entries today, "
      "not DAY_COUNTERS_UNRELIABLE, closable",
      out.status is ActionStatus.ACKNOWLEDGED
      and "DAY_COUNTERS_UNRELIABLE" not in sysr.data["findings"],
      f"{out.status.value}/{out.code} {sysr.data['findings']}")

# the derived state carries the concrete proof, not a count
r = fresh("f3i", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))
head = Journal.load(r.path)
st = derive_intended(head, seq=head.records[-1]["seq"],
                     hash_=head.records[-1]["hash"], now=NOW, spec=SPEC)
check("F3.10 a derived IntendedState carries position_fill_backed=True and no "
      "lifetime count field",
      st.position_fill_backed is True
      and not hasattr(st, "entry_fills_on_record"))
check("F3.11 a hand-built IntendedState leaves position_fill_backed None, so "
      "the reconciler keeps judging it by the day counter",
      IntendedState(journal_loaded=True).position_fill_backed is None)

# an exchange that DISAGREES with the unbacked claim is still refused (the
# provenance refusal comes before the exchange is consulted at all)
r = fresh("f3j", intended=flat(), exch=Exch())          # exchange flat
claim_position(r)
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
n = [0]
real = r.exch.view
def counting():
    n[0] += 1
    return real()
r.exch.view = counting
out = r.session().modify_stop("29750")
check("F3.12 the provenance refusal is decided from durable state alone; the "
      "exchange is not consulted",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and n[0] == 0,
      f"{out.status.value}/{out.code} fetches={n[0]}")


# ======================================================================
print(f"\nRESULTS: {len(PASS)} passed, {len(FAIL)} failed")
for f in FAIL:
    print(f"  FAILED: {f}")
sys.exit(1 if FAIL else 0)
