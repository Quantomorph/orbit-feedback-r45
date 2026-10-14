"""
tests/test_safety_closure_r4c4.py — ORBIT A1 SAFETY CLOSURE, ROUND 4C4,
checkpoint A.

Round 4C3 was accepted with one question reopened: an `IntendedState` handed
to the ToolSession constructor still had AUTHORIZATION POWER. Independent
review turned that into two exchange mutations that should never have happened:

    C4-I1  journal: 2 entries today, -20 realized.  memory: 0 and 0.
           -> RUNNING, APPROVED, one order sent. Both daily limits bypassed.
    C4-I2  a hash-valid journal with COUNTERS = "NOT_AN_INT". The strict
           rebuild raised; the check swallowed it as "no contradiction";
           the mutation proceeded.

    A FACT THAT HAS NOT BEEN DURABLY COMMITTED DOES NOT AUTHORIZE A MUTATION.
    INABILITY TO DERIVE DURABLE STATE IS NEVER AGREEMENT.
    CANNOT RECONSTRUCT != SAFE.

Checkpoint A adds, on top of the C4-I1/C4-I2 production work already in the
tree:

    5  daily accounting DERIVED from primitive fills, with UTC-day rollover,
       so no aggregate COUNTERS record anyone wrote can move a limit;
    6  ONE pinned journal interpretation per action - the ledger, idempotency,
       derivation and evidence all read the same prefix, loaded once;
    7  ONE UNRESOLVED ECONOMIC EXIT BLOCKS EVERY FURTHER MODEL-DRIVEN
       MUTATION, with its own refusal code (EXIT_UNRESOLVED).

Every test here says what it would have proved against the prior tree.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import timedelta
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, owning, pos, stop_order
from orbit.audit.blobstore import BlobStore
from orbit.audit.checkpoint import HeadCheckpoint
from orbit.audit.evidence import load as load_evidence
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.exec.operations import OperationLedger, OpStatus, logical_key
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


def attempt(name, fn):
    """A missing capability is a FAILING test, never an aborted suite."""
    try:
        ok, detail = fn()
    except Exception as e:
        check(name, False, f"{type(e).__name__}: {e}"[:140])
        return False
    check(name, ok, detail)
    return bool(ok)


def fresh(name, intended=None, exch=None):
    N[0] += 1
    d = os.path.join(TMP, f"{name}{N[0]}")
    os.makedirs(d, exist_ok=True)
    r = Rig(d, name, intended=intended, exch=exch or Exch())
    r.acquire()
    return r


def calls(r):
    return [(c.method, c.args.get("target_client_order_id")) for c in r.adapter.calls]


def st(entries=0, pnl="0", position=None, orders=()):
    return IntendedState(journal_loaded=True, clean_shutdown=True,
                         entries_utc_day=entries, realized_pnl_utc_day=D(pnl),
                         position=position, submitted_orders=tuple(orders))


def events(r, kind):
    return [ev for rec in Journal.load(r.path).records for ev in rec["events"]
            if ev["e"] == kind.value]


def evidence_dir(r):
    return os.path.join(os.path.dirname(r.path), "evidence")


def last_intent_evidence(r):
    ev = events(r, E.INTENT)[-1]
    return load_evidence(BlobStore(evidence_dir(r)), ev["authoritative_snapshot"])


LIM = A1.max_entries_per_utc_day
LOSS = A1.max_daily_loss_usdt


# ======================================================================
banner("C4-I1 — CALLER-SUPPLIED LOCAL STATE HAS NO AUTHORIZATION POWER")
# The original reproducer, exactly as reviewed: the DURABLE history says the
# day's limits are exhausted; the MEMORY handed to the constructor says the day
# is fresh. Before C4-I1 the memory won and an order went to the exchange.
# ======================================================================
memory_fresh = st(entries=0, pnl="0")

r = fresh("i1", intended=st(entries=LIM, pnl=str(-LOSS)))
out = r.session(memory=memory_fresh).propose_order("long", "29700")
check("C4-I1.1  THE REPRODUCER: journal 2 / -20, memory 0 / 0 -> the entry is "
      "refused and ZERO adapter mutations are made",
      out.status is ActionStatus.REJECTED
      and out.code in ("ENTRY_LIMIT_REACHED", "DAILY_LOSS_REACHED")
      and calls(r) == [], f"{out.status.value}/{out.code} {calls(r)}")

r = fresh("i1", intended=st(entries=LIM, pnl="0"))
out = r.session(memory=memory_fresh).propose_order("long", "29700")
check("C4-I1.2  the ENTRY limit alone, from the journal, refuses the entry the "
      "memory would have allowed",
      out.code == "ENTRY_LIMIT_REACHED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

r = fresh("i1", intended=st(entries=1, pnl=str(-LOSS)))
out = r.session(memory=memory_fresh).propose_order("long", "29700")
check("C4-I1.3  the DAILY LOSS limit alone, from the journal, refuses the entry "
      "the memory would have allowed",
      out.code == "DAILY_LOSS_REACHED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

# the memory cannot HIDE durable state either
r = fresh("i1", intended=held(),
          exch=Exch(position=pos(), orders=[stop_order()]))
out = r.session(memory=st()).modify_stop("29750")
check("C4-I1.4  memory claiming FLAT cannot hide a held position: the verdict "
      "follows the journal and amends ORBIT's own stop",
      out.status is ActionStatus.ACKNOWLEDGED
      and calls(r) == [("amend_stop", "stop1")],
      f"{out.status.value}/{out.code} {calls(r)}")

# the memory cannot be AHEAD of the journal
r = fresh("i1", intended=flat(),
          exch=Exch(position=pos(), orders=[stop_order()]))
out = r.session(memory=held()).modify_stop("29750")
check("C4-I1.5  memory AHEAD of the journal (a position and an owned stop the "
      "journal never recorded) authorises nothing",
      not out.reached_exchange and calls(r) == [],
      f"{out.status.value}/{out.code} {calls(r)}")

# and the evidence records what was DERIVED, not what was supplied
r = fresh("i1", intended=st(entries=1, pnl="-5"))
r.session(memory=memory_fresh).propose_order("long", "29700")
doc = last_intent_evidence(r)
check("C4-I1.6  the authoritative evidence carries the DERIVED local state, "
      "not the constructor's",
      doc["intended"]["fields"]["entries_utc_day"] == 1
      and D(doc["intended"]["fields"]["realized_pnl_utc_day"]["__dec__"])
      == D("-5"),
      f"{doc['intended']['fields'].get('entries_utc_day')} "
      f"{doc['intended']['fields'].get('realized_pnl_utc_day')}")

# the model-facing counters: reported from what the journal says, not memory.
# (Recorded as an observation, not asserted: model-facing derivation is a
# later 4C4 item. It must never be LESS restrictive than the journal.)


# ======================================================================
banner("C4-I2 — FAILURE TO DERIVE DURABLE STATE FAILS CLOSED")
# Every way the journal can fail to yield a state must end in a stable
# refusal with ZERO adapter mutations. Before C4-I2 the swallowed exception
# meant "no contradiction" and the order went out.
# ======================================================================
def malformed_case(label, evkind, **payload):
    r = fresh("i2", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    r.journal.append_one(evkind, "x", **payload)
    out = r.session().modify_stop("29750")
    return r, out


r, out = malformed_case("counters", E.COUNTERS, entries_utc_day="NOT_AN_INT",
                        realized_pnl_utc_day="0")
check("C4-I2.1  THE REPRODUCER: a hash-valid journal with a malformed COUNTERS "
      "record blocks the action with zero adapter mutations",
      out.status is ActionStatus.BLOCKED
      and out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code} {calls(r)}")

r, out = malformed_case("fill", E.FILL, client_order_id="e1", fill_id="bad",
                        contracts="lots", price="30000")
check("C4-I2.2  a FILL whose contracts are not a number blocks the action",
      out.status is ActionStatus.BLOCKED
      and out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

r, out = malformed_case("status", E.ORDER_STATUS, client_order_id="stop1",
                        status="TELEPORTED")
check("C4-I2.3  an ORDER_STATUS this build does not understand blocks the "
      "action: unknown is not safe",
      out.status is ActionStatus.BLOCKED
      and out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

r, out = malformed_case("position", E.POSITION_STATE,
                        position={"side": "long", "contracts": "2.38"})
check("C4-I2.4  a POSITION_STATE payload that cannot be interpreted blocks "
      "the action",
      out.status is ActionStatus.BLOCKED
      and out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code}")


def _tampered():
    r = fresh("i2t", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    lines = open(r.path).read().split("\n")
    rec = json.loads(lines[1])
    rec["events"][0]["contracts"] = "9999"          # rewrite history
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    open(r.path, "w").write("\n".join(lines))
    out = r.session().modify_stop("29750")
    return (out.status is ActionStatus.BLOCKED
            and out.code == "LOCAL_STATE_UNTRUSTED" and calls(r) == [],
            f"{out.status.value}/{out.code} {calls(r)}")


attempt("C4-I2.5  a journal whose hash chain is broken yields a STABLE "
        "LOCAL_STATE_UNTRUSTED refusal, not an exception, with zero mutations",
        _tampered)


def _truncated():
    r = fresh("i2u", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    raw = open(r.path).read().split("\n")
    raw = raw[:-3] + [""]                           # drop 2 COMMITTED records
    open(r.path, "w").write("\n".join(raw))
    out = r.session().modify_stop("29750")
    return (out.status is ActionStatus.BLOCKED
            and out.code == "LOCAL_STATE_UNTRUSTED" and calls(r) == [],
            f"{out.status.value}/{out.code} {calls(r)}")


attempt("C4-I2.6  committed records missing behind the head checkpoint yield "
        "LOCAL_STATE_UNTRUSTED with zero mutations",
        _truncated)


def _no_append_when_untrusted():
    r = fresh("i2n", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    lines = open(r.path).read().split("\n")
    rec = json.loads(lines[1])
    rec["events"][0]["contracts"] = "9999"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    open(r.path, "w").write("\n".join(lines))
    before = open(r.path, "rb").read()
    r.session().modify_stop("29750")
    after = open(r.path, "rb").read()
    return (before == after,
            f"journal grew by {len(after) - len(before)} bytes")


attempt("C4-I2.7  the refusal is NOT appended to the journal it has just "
        "declared untrusted: an untrusted file is not extended",
        _no_append_when_untrusted)


def _refusal_recorded():
    r, out = malformed_case("counters2", E.COUNTERS,
                            entries_utc_day="NOT_AN_INT",
                            realized_pnl_utc_day="0")
    rem = [ev for ev in events(r, E.REMEDIATION)
           if ev.get("code") == "LOCAL_STATE_DERIVATION_FAILED"]
    return (len(rem) == 1
            and rem[0].get("authoritative_observation") == "not_taken"
            and rem[0].get("authoritative_snapshot") is None,
            str(rem[-1] if rem else None)[:120])


attempt("C4-I2.8  a derivation refusal on a TRUSTED journal is recorded, and "
        "it says honestly that no exchange observation was taken",
        _refusal_recorded)


def _no_fetch_on_derivation_failure():
    r = fresh("i2f", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    r.journal.append_one(E.COUNTERS, "x", entries_utc_day="NOT_AN_INT",
                         realized_pnl_utc_day="0")
    n = [0]
    real = r.exch.view

    def counting():
        n[0] += 1
        return real()
    r.exch.view = counting
    r.session().modify_stop("29750")
    return n[0] == 0, f"exchange fetched {n[0]} times"


attempt("C4-I2.9  when the durable state cannot be derived the exchange is "
        "not consulted at all: no observation is taken for an action that "
        "cannot be authorised",
        _no_fetch_on_derivation_failure)

r, out = malformed_case("usable", E.COUNTERS, entries_utc_day="NOT_AN_INT",
                        realized_pnl_utc_day="0")
try:
    later = r.session().get_positions() is not None
except Exception as e:                                       # noqa: BLE001
    later = f"{type(e).__name__}"
check("C4-I2.10 after the refusal the session is not poisoned: a later read "
      "works (the seal is action-local on this exit too)",
      later is True, str(later))


# ======================================================================
banner("SCOPE 5 — DAILY ACCOUNTING FROM PRIMITIVE FILLS, UTC-DAY ROLLOVER")
# entries_utc_day  = distinct ENTRY logical operations whose FIRST positive
#                    fill falls on the UTC day of the session clock;
# realized_pnl     = average-cost fold over ALL fills, realized on the day of
#                    the reducing fill, net of the fill's recorded fee or the
#                    modelled taker fee when none is recorded.
# A COUNTERS aggregate has no authorization power.
# ======================================================================
def counters_override(entries, pnl):
    """A journal whose FILLS say one thing and whose last COUNTERS record
    says another. Before scope 5, the COUNTERS record decided."""
    r = fresh("s5", intended=st(entries=1, pnl="0"))
    r.journal.append_one(E.COUNTERS, "x", entries_utc_day=entries,
                         realized_pnl_utc_day=str(pnl))
    return r


r = counters_override(0, "0")
r.journal.append_one(E.COUNTERS, "y", entries_utc_day=0,
                     realized_pnl_utc_day="0")
# fills: 1 entry today. COUNTERS claims 0. Two more entries would need 3.
o1 = r.session("c1").propose_order("long", "29700")
check("S5.1  a COUNTERS record claiming a fresh day does not erase the entry "
      "the fills record: one entry today + one more = 2, the limit",
      o1.status is ActionStatus.ACKNOWLEDGED, f"{o1.status.value}/{o1.code}")
# the ACK above wrote an INTENT for a second entry (nonterminal) -> in flight.
o2 = r.session("c2").propose_order("short", "30300")
check("S5.2  ...and a THIRD entry is refused whatever COUNTERS says",
      not o2.reached_exchange and len(r.adapter.calls) == 1,
      f"{o2.status.value}/{o2.code}")

r = counters_override(LIM, str(-LOSS))
out = r.session().propose_order("long", "29700")
check("S5.3  a COUNTERS record claiming the limits are EXHAUSTED does not "
      "refuse an entry the fills permit (the aggregate has no power in "
      "either direction)",
      out.status is ActionStatus.ACKNOWLEDGED, f"{out.status.value}/{out.code}")

# rollover: yesterday's entries do not count today
YDAY = NOW - timedelta(days=1)
r = fresh("s5r", intended=st(entries=LIM, pnl=str(-LOSS)))
tomorrow = NOW + timedelta(days=1)
r.exch.now = tomorrow
out = r.session(now=tomorrow).propose_order("long", "29700")
check("S5.4  ROLLOVER: two entries and a -20 day YESTERDAY leave today's "
      "limits untouched",
      out.status is ActionStatus.ACKNOWLEDGED, f"{out.status.value}/{out.code}")

# a position entered yesterday and exited today realizes TODAY
r = fresh("s5x", intended=st(entries=0, pnl=str(-LOSS)))   # harness: entered
out = r.session().propose_order("long", "29700")            # yesterday, out today
check("S5.5  a loss REALIZED today on a position entered yesterday counts "
      "against today's daily loss, with zero entries today",
      out.code == "DAILY_LOSS_REACHED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

# the same history, one day later: neither the entry nor the loss counts
r.exch.now = tomorrow
out = r.session("next", now=tomorrow).propose_order("long", "29700")
check("S5.6  ...and the day after, that loss no longer counts",
      out.status is ActionStatus.ACKNOWLEDGED, f"{out.status.value}/{out.code}")

# midnight straddle: an entry at 23:59:59 yesterday and one at 00:00:01 today
r = fresh("s5m", intended=flat())
just_before = NOW.replace(hour=0, minute=0, second=0) - timedelta(seconds=1)
just_after = NOW.replace(hour=0, minute=0, second=1)
for n, when in ((0, just_before), (1, just_after)):
    r._synth_round_trip(n, D("0"), when, when)
r.journal.append_one(E.CLEAN_SHUTDOWN, None)       # history written; shut down
o = r.session().propose_order("long", "29700")
check("S5.7  MIDNIGHT STRADDLE: the 23:59:59 entry is yesterday's, the "
      "00:00:01 entry is today's, so one more entry is still permitted",
      o.status is ActionStatus.ACKNOWLEDGED, f"{o.status.value}/{o.code}")

# a fill dated on a LATER UTC day than the session clock is not accountable
r = fresh("s5f", intended=flat())
r._synth_round_trip(0, D("0"), tomorrow, tomorrow)
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().propose_order("long", "29700")
check("S5.8  a durable fill dated on a LATER UTC day than now fails closed: "
      "history from the future is not accountable",
      out.status is ActionStatus.BLOCKED
      and out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

# a fill with no price cannot be accounted
r = fresh("s5p", intended=flat())
r.journal.append_one(E.INTENT, "np", client_order_id="np", contracts="1",
                     instrument="BTC-USDT-SWAP", order_kind="OPEN",
                     side="long", role="ENTRY", reduce_only=False)
r.journal.append_one(E.FILL, "np", client_order_id="np", fill_id="np-f",
                     contracts="1", executed_at=NOW.isoformat())
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().propose_order("long", "29700")
check("S5.9  a fill with no price cannot be accounted and fails closed",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

# a fill against an order ORBIT has no record of cannot be accounted
r = fresh("s5o", intended=flat())
r.journal.append_one(E.FILL, "ghost", client_order_id="ghost", fill_id="g-f",
                     contracts="1", price="30000", executed_at=NOW.isoformat())
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().propose_order("long", "29700")
check("S5.10 a fill against an order with no durable INTENT fails closed",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

# fees: a fill without a recorded fee is charged the modelled taker fee
from orbit.audit.derivation import daily_accounting
from orbit.core.precision import BTC_USDT_SWAP as SPEC
r = fresh("s5fee", intended=flat())
for cid, kind, side, role, ro, price in (
        ("fe", "OPEN", "long", "ENTRY", False, "30000"),
        ("fx", "CLOSE", "short", "EXIT", True, "30000")):
    r.journal.append_one(E.INTENT, cid, client_order_id=cid, contracts="1",
                         instrument="BTC-USDT-SWAP", order_kind=kind,
                         side=side, role=role, reduce_only=ro)
    r.journal.append_one(E.FILL, cid, client_order_id=cid, fill_id=cid + "-f",
                         contracts="1", price=price,
                         executed_at=NOW.isoformat())       # no fee field
acct = daily_accounting(Journal.load(r.path).records, NOW, SPEC)
expected_fee = D("2") * D("30000") * SPEC.contract_size_btc * SPEC.taker_fee
check("S5.11 a flat round trip with no recorded fees realizes exactly minus "
      "the modelled taker fees, never zero",
      acct.realized_pnl_utc_day == -expected_fee and acct.entries_utc_day == 1,
      f"{acct.realized_pnl_utc_day} vs {-expected_fee}")

r = fresh("s5fee2", intended=flat())
for cid, kind, side, role, ro, price, fee in (
        ("fe", "OPEN", "long", "ENTRY", False, "30000", "0.10"),
        ("fx", "CLOSE", "short", "EXIT", True, "30100", "0.20")):
    r.journal.append_one(E.INTENT, cid, client_order_id=cid, contracts="1",
                         instrument="BTC-USDT-SWAP", order_kind=kind,
                         side=side, role=role, reduce_only=ro)
    r.journal.append_one(E.FILL, cid, client_order_id=cid, fill_id=cid + "-f",
                         contracts="1", price=price, fee_cost_usdt=fee,
                         executed_at=NOW.isoformat())
acct = daily_accounting(Journal.load(r.path).records, NOW, SPEC)
check("S5.12 a recorded fee cost REPLACES the modelled one: +1.00 gross, -0.30 fees",
      acct.realized_pnl_utc_day == D("0.70"), str(acct.realized_pnl_utc_day))

# short side, partial exits, average cost
r = fresh("s5s", intended=flat())
seq = (("se", "OPEN", "short", "ENTRY", False, "2", "30000"),
       ("sx1", "REDUCE", "long", "EXIT", True, "1", "29000"),   # +10
       ("sx2", "CLOSE", "long", "EXIT", True, "1", "31000"))    # -10
for cid, kind, side, role, ro, c, price in seq:
    r.journal.append_one(E.INTENT, cid, client_order_id=cid, contracts=c,
                         instrument="BTC-USDT-SWAP", order_kind=kind,
                         side=side, role=role, reduce_only=ro)
    r.journal.append_one(E.FILL, cid, client_order_id=cid, fill_id=cid + "-f",
                         contracts=c, price=price, fee_cost_usdt="0",
                         executed_at=NOW.isoformat())
acct = daily_accounting(Journal.load(r.path).records, NOW, SPEC)
check("S5.13 a SHORT with two partial exits realizes +10 and -10 at average "
      "cost: net zero, one entry",
      acct.realized_pnl_utc_day == D("0") and acct.entries_utc_day == 1,
      f"{acct.realized_pnl_utc_day} entries={acct.entries_utc_day}")

# an exit larger than the open position is not a reversal ORBIT will account
r = fresh("s5over", intended=flat())
for cid, kind, side, role, ro, c, price in (
        ("oe", "OPEN", "long", "ENTRY", False, "1", "30000"),
        ("ox", "CLOSE", "short", "EXIT", True, "2", "30000")):
    r.journal.append_one(E.INTENT, cid, client_order_id=cid, contracts=c,
                         instrument="BTC-USDT-SWAP", order_kind=kind,
                         side=side, role=role, reduce_only=ro)
    r.journal.append_one(E.FILL, cid, client_order_id=cid, fill_id=cid + "-f",
                         contracts=c, price=price, fee_cost_usdt="0",
                         executed_at=NOW.isoformat())
out = r.session().propose_order("long", "29700")
check("S5.14 a reduce-only exit that filled MORE than the open position is a "
      "contradiction in durable history and fails closed",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

# a duplicated FILL record counts once
r = fresh("s5dup", intended=st(entries=1, pnl="0"))
fill_ev = events(r, E.FILL)[-1]
r.journal.append_one(E.FILL, fill_ev["action_id"], **{
    k: v for k, v in fill_ev.items() if k not in ("e", "action_id")})
acct = daily_accounting(Journal.load(r.path).records, NOW, SPEC)
check("S5.15 a duplicated FILL record (same fill_id) counts once",
      acct.entries_utc_day == 1, str(acct.entries_utc_day))

# a malformed COUNTERS record still fails closed even though it has no power
r = fresh("s5mal", intended=flat())
r.journal.append_one(E.COUNTERS, "x", entries_utc_day="NOT_AN_INT",
                     realized_pnl_utc_day="0")
out = r.session().propose_order("long", "29700")
check("S5.16 a malformed COUNTERS record still fails closed: a record the "
      "fold cannot interpret makes the history uninterpretable",
      out.code == "LOCAL_STATE_DERIVATION_FAILED" and calls(r) == [],
      f"{out.status.value}/{out.code}")

# an overnight position is NOT mislabelled DAY_COUNTERS_UNRELIABLE
r = fresh("s5on", intended=held(),
          exch=Exch(position=pos(), orders=[stop_order()]))
r.exch.now = tomorrow
s = r.session("on", now=tomorrow)
sysr = s.get_system_state()
close = s.close_position()
check("S5.17 a position held OVERNIGHT has zero entries today and is still "
      "closable, and local state is not called unreliable for it",
      "DAY_COUNTERS_UNRELIABLE" not in sysr.data["findings"]
      and close.status is ActionStatus.ACKNOWLEDGED,
      f"{sysr.data['findings']} {close.status.value}/{close.code}")


# ======================================================================
banner("SCOPE 6 — ONE PINNED JOURNAL INTERPRETATION PER ACTION")
# ======================================================================
def _one_load():
    r = fresh("s6", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    n = [0]
    real = Journal.load
    size0 = os.path.getsize(r.path)

    def counting(path):
        # the journal is APPENDED to during the action (verdict, INTENT, ACK,
        # RECON...) and each append re-reads the head under its lock; those
        # are writes, not interpretations. Count only loads made while the
        # file is still exactly the prefix the action started from: that is
        # the pinned load, plus the FIRST append's own locked re-read.
        if os.path.abspath(path) == os.path.abspath(r.path) \
                and os.path.getsize(path) == size0:
            n[0] += 1
        return real(path)
    Journal.load = staticmethod(counting)
    try:
        out = r.session().modify_stop("29750")
    finally:
        Journal.load = staticmethod(real)
    return (out.status is ActionStatus.ACKNOWLEDGED and n[0] <= 2,
            f"{out.status.value}/{out.code} pre-append journal loads={n[0]}")


attempt("S6.1  an action interprets the journal ONCE before its mutation (the "
        "append path's own locked re-reads are writes, not interpretations)",
        _one_load)


def _ledger_from_pinned():
    r = fresh("s6b", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    led = OperationLedger.from_records(Journal.load(r.path).records, r.path)
    live = OperationLedger(r.path)
    return ([o.operation_id for o in led.all()]
            == [o.operation_id for o in live.all()],
            f"{len(led.all())} vs {len(live.all())}")


attempt("S6.2  the ledger can be built from an already-loaded prefix and agrees "
        "with a fresh load of the same file", _ledger_from_pinned)


def _pinned_head_in_evidence():
    r = fresh("s6c", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    head_before = Journal.load(r.path).records[-1]
    out = r.session().modify_stop("29750")
    doc = last_intent_evidence(r)
    return (out.status is ActionStatus.ACKNOWLEDGED
            and doc["journal_seq"] == head_before["seq"]
            and doc["journal_hash"] == head_before["hash"],
            f"evidence pins seq {doc['journal_seq']}, head was "
            f"{head_before['seq']}")


attempt("S6.3  the evidence pins exactly the prefix the ledger and the "
        "derivation consumed: the head as it stood BEFORE the action appended "
        "anything", _pinned_head_in_evidence)


def _pin_is_action_local():
    """Found attacking the repair: a standalone `_authoritative()` pinned a
    prefix that a LATER action inherited, so history appended between the two
    - here, the day's second entry - was invisible to the action's verdict."""
    r = fresh("s6d", intended=st(entries=LIM - 1, pnl="0"))
    s = r.session("pin")
    s._authoritative()                       # the runner's standalone snapshot
    r._synth_round_trip(9, D("0"), NOW, NOW) # a further entry lands today
    r.journal.append_one(E.CLEAN_SHUTDOWN, None)
    out = s.propose_order("long", "29700")
    return (out.code == "ENTRY_LIMIT_REACHED" and calls(r) == [],
            f"{out.status.value}/{out.code} {calls(r)}")


attempt("S6.4  the pin is ACTION-LOCAL: history appended after a standalone "
        "observation and before the action is seen by the action",
        _pin_is_action_local)

# a rebate is not a gain. Checkpoint A.1: expressed with the NORMALIZED
# `rebate_usdt` field; the legacy signed `fee` is refused outright (see the
# A.1 test family).
r = fresh("s5reb", intended=flat())
for cid, kind, side, role, ro, price in (
        ("re", "OPEN", "long", "ENTRY", False, "30000"),
        ("rx", "CLOSE", "short", "EXIT", True, "30000")):
    r.journal.append_one(E.INTENT, cid, client_order_id=cid, contracts="1",
                         instrument="BTC-USDT-SWAP", order_kind=kind,
                         side=side, role=role, reduce_only=ro)
    r.journal.append_one(E.FILL, cid, client_order_id=cid, fill_id=cid + "-f",
                         contracts="1", price=price, fee_cost_usdt="0",
                         rebate_usdt="0.50", executed_at=NOW.isoformat())
acct = daily_accounting(Journal.load(r.path).records, NOW, SPEC)
check("S5.18 a recorded REBATE is not counted as a gain: a flat round trip with "
      "two 0.50 rebates realizes exactly zero, not +1.00",
      acct.realized_pnl_utc_day == D("0"), str(acct.realized_pnl_utc_day))


# ======================================================================
banner("SCOPE 7 — ONE UNRESOLVED ECONOMIC EXIT BLOCKS EVERY FURTHER "
       "MODEL-DRIVEN MUTATION")
# A CLOSE whose outcome is UNKNOWN may or may not have flattened the position.
# Until reconciliation establishes which, the model may not touch the position
# or its protection: a stop amendment against a position that no longer exists,
# a reduction of a position that may already be gone, an entry into an account
# whose exposure is unknown - each is a mutation against unknown state.
# ======================================================================
def exit_unresolved_rig(how="timeout"):
    r = fresh("s7", intended=held(),
              exch=Exch(position=pos(), orders=[stop_order()]))
    r.adapter.timeout_next = True
    first = r.session("x1").close_position()
    assert first.status is ActionStatus.UNKNOWN, first
    return r, first


r, first = exit_unresolved_rig()
out = r.session("x2").modify_stop("29800")
check("S7.1  an unresolved CLOSE blocks a MODIFY_STOP with the dedicated code "
      "and zero further mutations",
      out.status is ActionStatus.OPERATION_UNRESOLVED
      and out.code == "EXIT_UNRESOLVED" and len(r.adapter.calls) == 1,
      f"{out.status.value}/{out.code} calls={len(r.adapter.calls)}")
check("S7.2  the refusal names the unresolved exit",
      out.client_order_id == first.client_order_id, str(out.client_order_id))

r, first = exit_unresolved_rig()
out = r.session("x2").reduce_position("0.5")
check("S7.3  an unresolved CLOSE blocks a REDUCE",
      out.code == "EXIT_UNRESOLVED" and len(r.adapter.calls) == 1,
      f"{out.status.value}/{out.code}")

r, first = exit_unresolved_rig()
out = r.session("x2").propose_order("short", "30300")
check("S7.4  an unresolved CLOSE blocks a new ENTRY",
      out.code == "EXIT_UNRESOLVED" and len(r.adapter.calls) == 1,
      f"{out.status.value}/{out.code}")

r, first = exit_unresolved_rig()
out = r.session("x2").cancel_order("stop1", replacement_client_order_id="x")
check("S7.5  an unresolved CLOSE blocks a CANCEL of the protective order",
      out.code == "EXIT_UNRESOLVED" and len(r.adapter.calls) == 1,
      f"{out.status.value}/{out.code}")

r, first = exit_unresolved_rig()
out = r.session("x2").close_position()
check("S7.6  the SAME logical CLOSE proposed again is still the durable "
      "idempotency refusal (it decides first, and names the same id)",
      out.status in (ActionStatus.DUPLICATE_SUPPRESSED,
                     ActionStatus.OPERATION_UNRESOLVED)
      and out.client_order_id == first.client_order_id
      and len(r.adapter.calls) == 1, f"{out.status.value}/{out.code}")

# every nonterminal exit status blocks
blocked, detail = True, []
for status in ("PENDING", "SUBMITTED", "ACK", "PARTIALLY_FILLED", "UNKNOWN"):
    rr = fresh("s7s", intended=held(),
               exch=Exch(position=pos(), orders=[stop_order()]))
    if status == "UNKNOWN":
        rr.adapter.timeout_next = True
        rr.session("y1").close_position()
    else:
        k = logical_key(A1.instrument, "CLOSE")
        oid = f"{k}:g0"
        from orbit.exec.operations import client_order_id_for
        cid = client_order_id_for(oid)
        rr.journal.record_intent(oid, client_order_id=cid, fingerprint="fp",
                                 tool="close_position", operation_id=oid,
                                 logical_key=k, generation=0,
                                 logical_operation_id=oid,
                                 instrument=A1.instrument, order_kind="CLOSE",
                                 role="EXIT", reduce_only=True, contracts="2.38")
        if status in ("SUBMITTED", "ACK", "PARTIALLY_FILLED"):
            rr.rec.record_submit_attempted(oid, cid)
        if status in ("ACK", "PARTIALLY_FILLED"):
            rr.rec.record_submit_ack(oid, cid, "X")
        if status == "PARTIALLY_FILLED":
            rr.rec.record_order_status(oid, cid, "PARTIALLY_FILLED")
    before = len(rr.adapter.calls)
    o = rr.session("y2").modify_stop("29800")
    if o.code != "EXIT_UNRESOLVED" or len(rr.adapter.calls) != before:
        blocked = False
        detail.append((status, o.code))
check("S7.7  EVERY nonterminal exit status blocks a stop mutation: PENDING, "
      "SUBMITTED, ACK, PARTIALLY_FILLED, UNKNOWN", blocked, str(detail))

# a TERMINAL exit does not block
r, first = exit_unresolved_rig()
r.rec.record_order_status(first.action_id, first.client_order_id, "CANCELLED")
out = r.session("x3").modify_stop("29800")
check("S7.8  once the exit is TERMINAL (positive evidence) a stop mutation is "
      "permitted again: the block is about unresolved outcome, not history",
      out.status is ActionStatus.ACKNOWLEDGED and len(r.adapter.calls) == 2,
      f"{out.status.value}/{out.code}")

# the block does not depend on the exchange view: it is decided from the
# pinned journal before any observation
def _decided_before_observation():
    r, first = exit_unresolved_rig()
    n = [0]
    real = r.exch.view

    def counting():
        n[0] += 1
        return real()
    r.exch.view = counting
    out = r.session("x2").modify_stop("29800")
    return out.code == "EXIT_UNRESOLVED" and n[0] == 0, f"fetches={n[0]}"


attempt("S7.9  the exit-unresolved refusal is decided from durable state alone "
        "and takes no exchange observation", _decided_before_observation)

# the refusal survives a restart (a new process object, same journal)
r, first = exit_unresolved_rig()
r2 = Rig(os.path.dirname(r.path), "s7", intended=held(),
         exch=Exch(position=pos(), orders=[stop_order()]))
r2.authority, r2.lease = r.authority, r.lease
from orbit.exec.adapter import NullAdapter
r2.adapter = NullAdapter(r.authority, r2.journal)
out = r2.session("z").modify_stop("29800")
check("S7.10 the refusal survives a restart: the rebuilt process reads the "
      "unresolved exit from the journal",
      out.code == "EXIT_UNRESOLVED" and len(r2.adapter.calls) == 0,
      f"{out.status.value}/{out.code}")

# an unresolved ADMIN mutation (a stop amendment) is NOT an economic exit:
# it does not trigger this gate (the same-key idempotency rule still applies).
r = fresh("s7adm", intended=held(),
          exch=Exch(position=pos(), orders=[stop_order()]))
r.adapter.timeout_next = True
a1 = r.session("a1").modify_stop("29800")
o = r.session("a2").close_position()
# NOTE: the CLOSE is still refused here, by the PRE-EXISTING rule that an
# UNKNOWN submission makes the exchange view untrustworthy (NOT_RECONCILED).
# That rule is not this checkpoint's; what is asserted is only that the exit
# gate does not misclassify an admin mutation as an economic exit.
check("S7.11 an unresolved STOP AMENDMENT is not an economic exit: the exit "
      "gate does not fire for it",
      a1.status is ActionStatus.UNKNOWN and o.code != "EXIT_UNRESOLVED",
      f"{a1.status.value} then {o.status.value}/{o.code}")


# ======================================================================
print(f"\nRESULTS: {len(PASS)} passed, {len(FAIL)} failed")
for f in FAIL:
    print(f"  FAILED: {f}")
sys.exit(1 if FAIL else 0)
