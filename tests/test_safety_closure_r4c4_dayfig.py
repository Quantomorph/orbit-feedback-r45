"""
tests/test_safety_closure_r4c4_dayfig.py — SAFETY CLOSURE R4C4, DAYFIG-1.

THE DEFECT THIS SUITE EXISTS FOR.

    `recovery.rebuild` read the day's entry count and realized P&L off the last
    COUNTERS record. `derivation.daily_accounting` derived the same two figures
    from primitive INTENT and FILL facts, on the fill's EXECUTION day. One
    journal, two computations, and nothing obliging them to agree.

    A COUNTERS record is a summary somebody wrote. It carries no UTC day of its
    own, so yesterday's aggregate stood for ever; it is not tied to the fills it
    claims to summarize, so a stale one outlived them; and when there was none
    at all, the fold reported `0` — over a day that had realized its maximum
    loss.

    DIRECTION. `0` is the dangerous answer. `entries_utc_day` and
    `realized_pnl_utc_day` are the inputs to `max_entries_per_utc_day` and
    `max_daily_loss_usdt`, so a restart that reported zero handed the
    daily-loss limit back its full budget over a day that had already spent it.
    Reproduced end to end before the repair: `complete_recovery` cleared a
    tradeable state carrying `0/0` for a journal holding `2/-20.00`, and the
    gateway APPROVED an OPEN it should have refused.

WHAT THE REPAIR IS.

    ONE DERIVATION, called by both. `recovery.recover` no longer computes day
    figures; it calls `derivation.daily_accounting` — the same pure function the
    authorization fold calls. There is no second formula left to disagree with.

    The two folds keep their different failure policies, which is deliberate and
    is NOT a second interpretation of history: `rebuild` still fails soft on an
    unrecognised ORDER_STATUS, because one bad enum must not make ORBIT
    unstartable, while the DAY FIGURES fail closed, because they are safety
    inputs. When they cannot be derived they are reported UNDERIVABLE with a
    reason, never as zero, and `can_complete_recovery` refuses to clear such a
    state to trade.

WHAT IS ASSERTED HERE.

    A  one prefix, one set of figures, across recovery / authorization
    B  a realized loss survives a genuine process restart
    C  the daily entry count survives a genuine process restart
    D  a real zero is distinguishable from a failure to derive, by reason
    E  same-day fills fold deterministically rather than overwriting
    F  the UTC day boundary is the EXECUTION day, and the repair did not move it
    G  call order — recovery first or authorization first — changes nothing
    H  query order — reading before or after authorization — changes nothing
    I  malformed / untrusted / unaccountable history cannot yield permissive zero
    J  the JSEQ / F4 / N1 properties this touches are intact
    R2 N1-R2: the action-entry derivation reset, defended behaviourally

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, pos, stop_order
from orbit.audit.derivation import (LocalStateUndecidable, daily_accounting,
                                    derive_intended)
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.audit.recovery import (DAY_FIGURES_DERIVED, DAY_FIGURES_NO_CLOCK,
                                  DAY_FIGURES_UNDERIVABLE,
                                  can_complete_recovery, complete_recovery,
                                  rebuild, recover)
from orbit.exec.protection import MarginMode
from orbit.exec.recon import F, ExchangeView, RunState, reconcile
from orbit.risk.gateway import Code, Gateway, Kind, ProposedAction
from orbit.tools.session import ActionStatus

PASS, FAIL = [], []
TMP = tempfile.mkdtemp(prefix="dayfig-suite-")
N = [0]

YESTERDAY = NOW - timedelta(days=1)
LAST_NIGHT = datetime(2026, 9, 7, 23, 59, 0, tzinfo=timezone.utc)
JUST_AFTER = NOW.replace(hour=0, minute=0, second=30)

GW = Gateway()


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def banner(t):
    print("\n" + "-" * 78)
    print(t)


def rig(tag, intended=None, exch=None):
    N[0] += 1
    d = os.path.join(TMP, f"{tag}{N[0]}")
    os.makedirs(d, exist_ok=True)
    r = Rig(d, tag, intended=intended, exch=exch or Exch())
    r.acquire()
    return r


# ======================================================================
# JOURNAL CONSTRUCTION — the history a fixture claims, actually written
# ======================================================================
def journal(tag):
    N[0] += 1
    d = os.path.join(TMP, f"{tag}{N[0]}")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "journal.jsonl")
    return path, Journal(path, clock=lambda: NOW)


def _at(j, when, kind, aid, **payload):
    saved = j._clock
    j._clock = lambda: when
    try:
        return j.append_one(kind, aid, **payload)
    finally:
        j._clock = saved


def round_trip(j, n, pnl, entry_when, exit_when, entry_exec=None, exit_exec=None):
    """One ENTRY fill and one EXIT fill realizing exactly `pnl` USDT.

    1 contract = 0.01 BTC, so a realized P&L of X USDT is an exit price of
    entry + X * 100 with no rounding, and `fee_cost_usdt="0"` is an explicit
    normalized cost — so the DERIVED figure equals the DECLARED figure to the
    cent. The commit time and `executed_at` are separate parameters because the
    accounting day is the EXECUTION day and the two genuinely differ when
    ingestion lags execution.
    """
    e, x = f"entry-{n}", f"exit-{n}"
    entry = D("30000")
    exit_ = entry + D(pnl) * D("100")
    _at(j, entry_when, E.INTENT, e, client_order_id=e, contracts="1",
        instrument="BTC-USDT-SWAP", order_kind="OPEN", side="long",
        reduce_only=False, role="ENTRY", operation_id=f"op:{n}:entry")
    _at(j, entry_when, E.SUBMIT_ACK, e, client_order_id=e)
    _at(j, entry_when, E.FILL, e, client_order_id=e, fill_id=f"fill-{e}",
        contracts="1", price=str(entry), fee_cost_usdt="0",
        executed_at=(entry_exec or entry_when).isoformat())
    _at(j, exit_when, E.INTENT, x, client_order_id=x, contracts="1",
        instrument="BTC-USDT-SWAP", order_kind="CLOSE", side="short",
        reduce_only=True, role="EXIT", operation_id=f"op:{n}:exit")
    _at(j, exit_when, E.SUBMIT_ACK, x, client_order_id=x)
    _at(j, exit_when, E.FILL, x, client_order_id=x, fill_id=f"fill-{x}",
        contracts="1", price=str(exit_), fee_cost_usdt="0",
        executed_at=(exit_exec or exit_when).isoformat())
    _at(j, exit_when, E.POSITION_STATE, None, position=None)


def authorization_figures(path, now=NOW):
    """What the AUTHORIZATION path derives for this prefix."""
    load = Journal.load(path)
    head = load.records[-1]
    st = derive_intended(load, seq=head["seq"], hash_=head["hash"], now=now)
    return st.entries_utc_day, D(str(st.realized_pnl_utc_day))


def recovery_figures(path, now=NOW):
    rep = recover(path, now=now)
    return rep.rebuilt.entries_utc_day, D(str(rep.rebuilt.realized_pnl_utc_day))


VIEW = ExchangeView(fetched_at=NOW - timedelta(seconds=5), reachable=True,
                    consistent=True, server_time=NOW, equity=D("1000"),
                    mark_price=D("30000"), margin_mode=MarginMode.UNKNOWN,
                    position=None, open_orders=(), fills=())
OPEN = ProposedAction(decision_id="probe", kind=Kind.OPEN,
                      symbol="BTC-USDT-SWAP", side="long", entry_type="market",
                      stop=D("29700"), data_as_of=VIEW.fetched_at)


# ======================================================================
banner("A — ONE PREFIX, ONE SET OF FIGURES")
# ======================================================================
# The contract relied on, stated where the reviewer will look for it:
# `derivation.py` settled that the COUNTERS aggregate "has no authorization
# power; the figures are derived from fills". Recovery and authorization
# represent the SAME state over the SAME prefix at the SAME boundary — there is
# no second time definition here to preserve — so they must agree exactly.

p, j = journal("a_stale")
round_trip(j, 1, "-10", NOW, NOW)
round_trip(j, 2, "-10", NOW, NOW)
j.append_one(E.COUNTERS, None, entries_utc_day=0, realized_pnl_utc_day="0")
check("A1. a stale COUNTERS record claiming 0/0 does not erase a -20 day: "
      "recovery reports what the fills say",
      recovery_figures(p) == (2, D("-20.00")), str(recovery_figures(p)))
check("A2. and it is exactly what authorization derives for the same prefix",
      recovery_figures(p) == authorization_figures(p),
      f"recovery={recovery_figures(p)} authorization={authorization_figures(p)}")

p, j = journal("a_none")
round_trip(j, 1, "-10", NOW, NOW)
round_trip(j, 2, "-10", NOW, NOW)
check("A3. with NO COUNTERS record at all the figures are still the fills', "
      "because absence of a summary is not absence of history",
      recovery_figures(p) == authorization_figures(p) == (2, D("-20.00")),
      str(recovery_figures(p)))

p, j = journal("a_one")
round_trip(j, 1, "-15", NOW, NOW)
check("A4. a single round trip agrees across both paths",
      recovery_figures(p) == authorization_figures(p) == (1, D("-15.00")),
      str(recovery_figures(p)))

check("A5. recovery no longer computes day figures of its own: `rebuild` "
      "returns no entry count and no P&L to be read",
      "entries" not in rebuild(Journal.load(p).records)
      and "pnl" not in rebuild(Journal.load(p).records),
      str(sorted(rebuild(Journal.load(p).records))))

# ======================================================================
banner("B/C — A RESTART DOES NOT ERASE THE DAY")
# ======================================================================
# A GENUINE subprocess: a new interpreter, handed only the journal path and the
# session clock. Module state, import caches and class attributes cannot cross
# that boundary, so a figure that lived only in process memory cannot follow.
# Written into the suite's own temp directory, never into the repository:
# a run that fails midway must not leave a file behind in `tests/`.
WORKER = os.path.join(TMP, "_dayfig_worker.py")

with open(WORKER, "w") as fh:
    fh.write('''"""Fresh-process worker for the DAYFIG-1 suite. Production code only."""
import json, sys
from datetime import datetime
sys.path.insert(0, ".")
from orbit.audit.recovery import recover

spec = json.loads(sys.stdin.read())
rep = recover(spec["journal"], now=datetime.fromisoformat(spec["now"]))
print(json.dumps({
    "derivable": rep.daily_figures_derivable,
    "reason": rep.daily_figures_reason,
    "entries": rep.rebuilt.entries_utc_day,
    "pnl": str(rep.rebuilt.realized_pnl_utc_day),
}))
''')


def fresh_process(path, now=NOW):
    out = subprocess.run(
        [sys.executable, WORKER],
        input=json.dumps({"journal": path, "now": now.isoformat()}),
        capture_output=True, text=True, cwd=os.getcwd(),
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if out.returncode != 0:
        return {"error": (out.stderr or "").strip()[-400:]}
    return json.loads(out.stdout)


p, j = journal("bc_loss")
round_trip(j, 1, "-10", NOW, NOW)
round_trip(j, 2, "-10", NOW, NOW)
fp = fresh_process(p)
check("B1. a realized daily loss survives a genuine process restart",
      fp.get("pnl") == "-20.00", str(fp))
check("B2. and the fresh process reports it as DERIVED, not as a guess",
      fp.get("derivable") is True and fp.get("reason") == DAY_FIGURES_DERIVED,
      str(fp.get("reason")))
check("C1. the daily entry count survives a genuine process restart",
      fp.get("entries") == 2, str(fp.get("entries")))
check("C2. and the fresh process agrees with this process's authorization "
      "derivation over the same prefix",
      (fp.get("entries"), D(fp.get("pnl", "0"))) == authorization_figures(p),
      f"fresh={fp.get('entries')}/{fp.get('pnl')} "
      f"authorization={authorization_figures(p)}")

# ======================================================================
banner("D — ZERO IS REAL; UNKNOWN IS NOT ZERO")
# ======================================================================
p, j = journal("d_zero")
j.append_one(E.RUN_START, None, policy_version="A1")
rep_zero = recover(p, now=NOW)
check("D1. a genuine zero day reports 0/0",
      (rep_zero.rebuilt.entries_utc_day,
       rep_zero.rebuilt.realized_pnl_utc_day) == (0, D("0")))
check("D2. and says so: the zero is DERIVED, a fact about the history",
      rep_zero.daily_figures_derivable
      and rep_zero.daily_figures_reason == DAY_FIGURES_DERIVED,
      rep_zero.daily_figures_reason)

p, j = journal("d_unknown")
round_trip(j, 1, "-10", NOW, NOW)
j.append_one(E.COUNTERS, None, entries_utc_day="NOT_AN_INT",
             realized_pnl_utc_day="0")
rep_unk = recover(p, now=NOW)
check("D3. a history that cannot be accounted does NOT report a figure",
      not rep_unk.daily_figures_derivable and rep_unk.daily_figures is None,
      rep_unk.daily_figures_reason[:80])
check("D4. and the two cases are told apart by the reason field, not by the "
      "numbers — which are identical",
      rep_zero.daily_figures_reason != rep_unk.daily_figures_reason
      and rep_unk.daily_figures_reason.startswith(DAY_FIGURES_UNDERIVABLE)
      and (rep_zero.rebuilt.entries_utc_day
           == rep_unk.rebuilt.entries_utc_day == 0),
      f"{rep_zero.daily_figures_reason} vs {rep_unk.daily_figures_reason[:40]}")
check("D5. asking without a session clock is UNDERIVABLE, not zero: there is "
      "no 'today' to answer about",
      recover(p).daily_figures_reason == DAY_FIGURES_NO_CLOCK
      and not recover(p).daily_figures_derivable,
      recover(p).daily_figures_reason)
check("D6. an unestablished day figure is not trusted durable state",
      not rep_unk.durable_state_trusted)

# ======================================================================
banner("E — SAME-DAY FILLS FOLD, THEY DO NOT OVERWRITE")
# ======================================================================
p, j = journal("e_fold")
round_trip(j, 1, "-30", NOW, NOW)
round_trip(j, 2, "10", NOW, NOW)
check("E1. a loss then a gain on one day NETS, and both paths net identically",
      recovery_figures(p) == authorization_figures(p) == (2, D("-20.00")),
      str(recovery_figures(p)))

p, j = journal("e_three")
round_trip(j, 1, "-5", NOW, NOW)
round_trip(j, 2, "-5", NOW, NOW)
round_trip(j, 3, "-5", NOW, NOW)
check("E2. three same-day round trips count three entries and sum to -15",
      recovery_figures(p) == (3, D("-15.00")), str(recovery_figures(p)))
check("E3. folding is deterministic: the same prefix folded twice is equal",
      recovery_figures(p) == recovery_figures(p))

# ======================================================================
banner("F — THE DAY BOUNDARY IS THE EXECUTION DAY, AND IT DID NOT MOVE")
# ======================================================================
# POLICY, NOT A CHOICE MADE HERE. `limits.py` fixes the daily loss limit as
# "realized, UTC calendar day"; checkpoint A.1 fixed the accounting instant as
# the fill's own `executed_at`, never the commit time. This repair adopts that
# policy for recovery. It does not alter it, and these assertions are what
# would catch it if a future change did.

p, j = journal("f_before")
round_trip(j, 1, "-10", LAST_NIGHT, NOW,
           entry_exec=LAST_NIGHT, exit_exec=LAST_NIGHT)
j.append_one(E.COUNTERS, None, entries_utc_day=1, realized_pnl_utc_day="-10")
check("F1. a fill EXECUTED at 23:59 yesterday and COMMITTED today belongs to "
      "yesterday — the commit day does not move it into today",
      recovery_figures(p) == authorization_figures(p) == (0, D("0")),
      str(recovery_figures(p)))

p, j = journal("f_after")
round_trip(j, 1, "-10", JUST_AFTER, JUST_AFTER)
check("F2. a fill executed at 00:00:30 today belongs to today",
      recovery_figures(p) == authorization_figures(p) == (1, D("-10.00")),
      str(recovery_figures(p)))

p, j = journal("f_yday")
round_trip(j, 1, "-10", YESTERDAY, YESTERDAY)
round_trip(j, 2, "-10", YESTERDAY, YESTERDAY)
_at(j, YESTERDAY, E.COUNTERS, None, entries_utc_day=2,
    realized_pnl_utc_day="-20")
check("F3. yesterday's COUNTERS aggregate no longer stands for ever: today is "
      "a fresh day and both paths say so",
      recovery_figures(p) == authorization_figures(p) == (0, D("0")),
      str(recovery_figures(p)))
check("F4b. and a restart across the boundary agrees with it",
      fresh_process(p).get("entries") == 0
      and fresh_process(p).get("pnl") == "0",
      str(fresh_process(p)))

p, j = journal("f_noevent")
_at(j, YESTERDAY, E.RUN_START, None)
check("F5. a day with no events at all is a derived zero, not an unknown",
      recover(p, now=NOW).daily_figures_reason == DAY_FIGURES_DERIVED
      and recovery_figures(p) == (0, D("0")))

# ======================================================================
banner("G — CALL ORDER CHANGES NOTHING")
# ======================================================================
p, j = journal("g_order")
round_trip(j, 1, "-10", NOW, NOW)
round_trip(j, 2, "-10", NOW, NOW)

rec_first = recovery_figures(p)
auth_after = authorization_figures(p)
auth_first = authorization_figures(p)
rec_after = recovery_figures(p)
check("G1. recovery first then authorization gives the same pair as "
      "authorization first then recovery",
      (rec_first, auth_after) == (rec_after, auth_first),
      f"{rec_first}/{auth_after} vs {rec_after}/{auth_first}")
check("G2. and neither call moved the other's answer",
      rec_first == rec_after == auth_first == auth_after == (2, D("-20.00")))
before_hash = Journal.load(p).records[-1]["hash"]
recovery_figures(p)
authorization_figures(p)
check("G3. reading the figures wrote nothing: the prefix is unchanged",
      Journal.load(p).records[-1]["hash"] == before_hash, before_hash[:16])

# THE FIGURES ARE A FUNCTION OF THE JOURNAL, NOT OF THIS PROCESS. Recovery is
# called twice on ONE path in ONE process, with the history growing between the
# calls. An implementation that remembered its first answer -- a cache, a
# memo, a constructor slot -- would return the stale one here, which is the
# `_ctor_memory` class of defect C4-I1 and N1 were about, arriving through a
# new door. The second answer must reflect the record appended in between.
p, j = journal("g_grows")
round_trip(j, 1, "-10", NOW, NOW)
first = recovery_figures(p)
round_trip(j, 2, "-7", NOW, NOW)
second = recovery_figures(p)
check("G4. recovery re-derives from the history in front of it: a fill "
      "appended between two calls MOVES the answer",
      first == (1, D("-10.00")) and second == (2, D("-17.00")),
      f"{first} -> {second}")
check("G5. and the moved answer is still exactly authorization's",
      second == authorization_figures(p),
      f"recovery={second} authorization={authorization_figures(p)}")

# The same, in the direction that matters most: a day that becomes
# UNACCOUNTABLE after a clean read must not keep answering with the clean one.
p, j = journal("g_spoils")
round_trip(j, 1, "-10", NOW, NOW)
check("G6. a clean prefix derives", recover(p, now=NOW).daily_figures_derivable)
j.append_one(E.COUNTERS, None, entries_utc_day="NOT_AN_INT",
             realized_pnl_utc_day="0")
check("G7. and once the history can no longer be accounted, recovery says so "
      "rather than repeating the answer it gave a moment ago",
      not recover(p, now=NOW).daily_figures_derivable,
      recover(p, now=NOW).daily_figures_reason[:70])

# ======================================================================
banner("H — QUERY ORDER CHANGES NOTHING")
# ======================================================================
# The model-facing read and the authorization path over ONE rig, in both
# orders. N1 made both consume the one derivation; DAYFIG-1 must not have
# reintroduced an order dependence through recovery.
r = rig("h_q", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))

s1 = r.session(cycle_id="h1", memory=flat())
read_first = s1.get_current_risk_state().data
auth_second = r.session(cycle_id="h2", memory=flat())._authoritative().recon

s2 = r.session(cycle_id="h3", memory=flat())
auth_first_ = s2._authoritative().recon
read_second = (r.session(cycle_id="h4", memory=flat())
               .get_current_risk_state().data)

check("H1. the model-facing day figures are the same whether the read comes "
      "before or after authorization",
      (read_first["entries_utc_day"], read_first["realized_pnl_utc_day"])
      == (read_second["entries_utc_day"], read_second["realized_pnl_utc_day"]),
      f"{read_first['entries_utc_day']}/{read_first['realized_pnl_utc_day']} vs "
      f"{read_second['entries_utc_day']}/{read_second['realized_pnl_utc_day']}")
check("H2. and the authorization figures likewise",
      (auth_second.intended.entries_utc_day,
       auth_second.intended.realized_pnl_utc_day)
      == (auth_first_.intended.entries_utc_day,
          auth_first_.intended.realized_pnl_utc_day))
check("H3. the model is told exactly what the action path authorises against",
      str(read_first["entries_utc_day"])
      == str(auth_first_.intended.entries_utc_day)
      and str(read_first["realized_pnl_utc_day"])
      == str(auth_first_.intended.realized_pnl_utc_day),
      f"model={read_first['entries_utc_day']}/"
      f"{read_first['realized_pnl_utc_day']} "
      f"action={auth_first_.intended.entries_utc_day}/"
      f"{auth_first_.intended.realized_pnl_utc_day}")

# ======================================================================
banner("I — FAILURE IS CLOSED, AND NOTHING PERMISSIVE COMES OUT OF IT")
# ======================================================================
# The decisive shape: the day has spent its whole loss budget and the position
# is FLAT, so no open position draws attention to a missing counter. This is
# where an erased -20 admits new risk.
p, j = journal("i_flat")
round_trip(j, 1, "-10", NOW, NOW)
round_trip(j, 2, "-10", NOW, NOW)
j.append_one(E.COUNTERS, None, entries_utc_day=0, realized_pnl_utc_day="0")

rep = recover(p, now=NOW)
r1 = reconcile(rep.rebuilt, VIEW, NOW)
ok, why = can_complete_recovery(rep, r1)
cleared = complete_recovery(Journal(p, clock=lambda: NOW), rep, r1)
check("I1. recovery may complete on accountable history",
      ok and cleared is not None, why)
check("I2. and the state it clears to trade carries the day the fills record, "
      "not the aggregate's zero",
      (cleared.entries_utc_day, cleared.realized_pnl_utc_day)
      == (2, D("-20.00")),
      f"{cleared.entries_utc_day}/{cleared.realized_pnl_utc_day}")
v = GW.evaluate(OPEN, reconcile(cleared, VIEW, NOW).to_system_state())
check("I3. so the gateway REFUSES the entry the day forbids — this is the "
      "fail-open the repair closes",
      not v.approved and v.code is Code.ENTRY_LIMIT_REACHED, v.code.value)

p, j = journal("i_loss_only")
round_trip(j, 1, "-25", NOW, NOW)
rep = recover(p, now=NOW)
r1 = reconcile(rep.rebuilt, VIEW, NOW)
cleared = complete_recovery(Journal(p, clock=lambda: NOW), rep, r1)
v = GW.evaluate(OPEN, reconcile(cleared, VIEW, NOW).to_system_state())
check("I4. one entry and -25 realized: the DAILY LOSS limit bites after a "
      "restart, on the same evidence",
      not v.approved and v.code is Code.DAILY_LOSS_REACHED, v.code.value)

p, j = journal("i_undecidable")
round_trip(j, 1, "-10", NOW, NOW)
j.append_one(E.COUNTERS, None, entries_utc_day="NOT_AN_INT",
             realized_pnl_utc_day="0")
rep = recover(p, now=NOW)
r1 = reconcile(rep.rebuilt, VIEW, NOW)
ok, why = can_complete_recovery(rep, r1)
check("I5. history that cannot be accounted does not complete recovery",
      not ok and "not established" in why, why[:90])
check("I6. and complete_recovery returns None rather than a tradeable state",
      complete_recovery(Journal(p, clock=lambda: NOW), rep, r1) is None)
check("I7. reconciliation refuses new entries on an unestablished day, with "
      "NO position open to notice it by",
      F.DAY_COUNTERS_UNRELIABLE in r1.codes()
      and r1.run_state is not RunState.RUNNING,
      f"{[c.value for c in r1.codes()]} {r1.run_state.value}")
v = GW.evaluate(OPEN, r1.to_system_state())
check("I8. so the gateway refuses the OPEN rather than reading 0/0 as a "
      "clean day",
      not v.approved, v.code.value)

p, j = journal("i_untrusted")
round_trip(j, 1, "-10", NOW, NOW)
with open(p) as fh:
    lines = fh.readlines()
body = json.loads(lines[-1])
body["events"][0]["contracts"] = "999"
lines[-1] = json.dumps(body) + "\n"
with open(p, "w") as fh:
    fh.writelines(lines)
rep = recover(p, now=NOW)
check("I9. a TAMPERED journal yields no day figures at all",
      not rep.daily_figures_derivable and not rep.journal_trusted,
      rep.daily_figures_reason[:70])
check("I10. and cannot complete recovery",
      not can_complete_recovery(rep, reconcile(rep.rebuilt, VIEW, NOW))[0])

p, j = journal("i_ghost")
j.append_one(E.RUN_START, None)
j.append_one(E.FILL, "a1", client_order_id="ghost", fill_id="fg",
             contracts="1", price="30000", fee_cost_usdt="0",
             executed_at=NOW.isoformat())
rep_ghost = recover(p, now=NOW)
check("I11. a fill ORBIT never intended cannot be classified as an entry or "
      "an exit, so it is not silently worth zero",
      not rep_ghost.daily_figures_derivable
      and rep_ghost.daily_figures_reason.startswith(DAY_FIGURES_UNDERIVABLE),
      rep_ghost.daily_figures_reason[:80])
check("I12. and that history is not cleared to trade either",
      complete_recovery(Journal(p, clock=lambda: NOW), rep_ghost,
                        reconcile(rep_ghost.rebuilt, VIEW, NOW)) is None)

# ======================================================================
banner("J — THE PRIOR ACCEPTED PROPERTIES THIS TOUCHES")
# ======================================================================
p, j = journal("j_jseq")
round_trip(j, 1, "-10", NOW, NOW)
with open(p) as fh:
    lines = fh.readlines()
body = json.loads(lines[-1])
body["seq"] = body["seq"] + 5
lines[-1] = json.dumps(body) + "\n"
with open(p, "w") as fh:
    fh.writelines(lines)
rep = recover(p, now=NOW)
check("J1. JSEQ contiguity still governs: a sequence-broken journal is "
      "untrusted, and an untrusted journal yields NO day figures",
      not rep.journal_trusted and not rep.daily_figures_derivable,
      f"trusted={rep.journal_trusted} derivable={rep.daily_figures_derivable} "
      f"{rep.daily_figures_reason[:60]}")

p, j = journal("j_f4")
round_trip(j, 1, "-10", NOW, NOW)
before = recover(p, now=NOW)
after = recover(p, now=NOW)
check("J3. F4: recovery is still deterministic — the same prefix recovered "
      "twice is equal, figures included",
      before.rebuilt == after.rebuilt
      and before.daily_figures_reason == after.daily_figures_reason)

r = rig("j_n1", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))
m = r.session(cycle_id="j1", memory=flat()).get_current_risk_state().data
a = r.session(cycle_id="j2", memory=flat())._authoritative().recon
check("J4. N1: the model-facing read and the action path still answer with "
      "one state, and the constructor's memory still moves nothing",
      str(m["entries_utc_day"]) == str(a.intended.entries_utc_day)
      and m["realized_pnl_utc_day"] == str(a.intended.realized_pnl_utc_day),
      f"model={m['entries_utc_day']}/{m['realized_pnl_utc_day']} "
      f"action={a.intended.entries_utc_day}/{a.intended.realized_pnl_utc_day}")

# ======================================================================
banner("R2 — N1-R2: THE ACTION-ENTRY DERIVATION RESET, DEFENDED BEHAVIOURALLY")
# ======================================================================
# Reviewer mutant MR-2 deletes `self._derived = None` from `_act_locked` step 0.
# The action then authorises against a derivation folded from the prefix a READ
# pinned, while its evidence artifact names the newer prefix — two histories in
# one action. Until now that was caught ONLY by N1.12e, an `inspect.getsource`
# structural assertion; every one of the other 1127 assertions passed under it.
#
# This is the behavioural defence the reviewer specified: read first, then make
# the durable state UNDERIVABLE out of band, then act. A session that reuses the
# read's derivation acts on the stale one and ACKNOWLEDGES. A session that
# resets it folds the history in front of it and must REFUSE.
#
# Test-only. It needs no N1 production change and does not widen the DAYFIG-1
# repair.
r = rig("r2", intended=flat(), exch=Exch())
s = r.session(cycle_id="r2c", memory=flat())
read = s.get_system_state().data
check("R2.1 the read succeeds and pins a prefix the action must not inherit",
      read["run_state"] != RunState.HALTED.value, read["run_state"])

# Out of band, after the read's pin: the durable state becomes uninterpretable.
Journal(r.path, clock=lambda: NOW).append_one(
    E.COUNTERS, None, entries_utc_day="NOT_AN_INT", realized_pnl_utc_day="0")

out = s.propose_order("long", stop="29000")
check("R2.2 the SAME session's action folds the history in front of IT, not "
      "the prefix its own earlier read pinned, and therefore REFUSES",
      out.status is ActionStatus.BLOCKED
      and out.code == "LOCAL_STATE_DERIVATION_FAILED",
      f"{out.status.value}/{out.code}")
check("R2.3 and nothing was acknowledged against the stale derivation",
      out.status is not ActionStatus.ACKNOWLEDGED, out.status.value)

# ======================================================================
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
for f in FAIL:
    print(f"  FAILED: {f}")
sys.exit(1 if FAIL else 0)
