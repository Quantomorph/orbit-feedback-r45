"""
tests/repro_daily_figure_divergence.py — R4C4-DAYFIG-1 STANDALONE REPRODUCER.

WHAT THIS SCRIPT IS FOR.

    ONE durable history must produce ONE set of daily risk figures, whoever
    asks. `max_entries_per_utc_day` and `max_daily_loss_usdt` are decided from
    those two numbers, so two ORBIT paths that read the same journal and
    disagree about them are two different daily-loss limits wearing one name.

    R4C4-DAYFIG-1 was a violation of that. `recovery.rebuild` took the day's
    entry count and realized P&L from the last COUNTERS record — a summary
    somebody wrote, carrying no UTC day of its own and no tie to the fills it
    claimed to summarize — while `derivation.daily_accounting` derived them
    from the primitive INTENT and FILL facts on the execution day. Two
    computations, one journal, and nothing that made them agree.

    THE DANGEROUS DIRECTION, which is the one that occurred: recovery
    reporting ZERO over a day that had already realized its maximum loss. A
    restart then handed the daily-loss limit back its full budget.

HOW THIS SCRIPT IS USED AS EVIDENCE.

    It asserts the REPAIRED property. It is not parameterised by tree, it
    contains no copy of the old behaviour, and it is not told which tree it is
    running on.

        against the repaired tree      -> every path converges, exit 0
        against b32d5615 (pre-DAYFIG)  -> the paths contradict, exit 1

    The same bytes are run against both trees. The pre-repair evidence is this
    script FAILING, with the contradictory figures it printed, not a second
    script that imitates the defect.

ON THE TWO PLACES THIS SCRIPT ADAPTS TO THE TREE.

    Both adapt to an API DIFFERENCE. Neither adapts to a BEHAVIOUR
    difference, and neither changes the property asserted — the same
    assertions run, over the same scenarios, on both trees.

    1. `recover()` gained a `now` parameter in the repair, because the day's
       figures cannot be derived without knowing what day it is. The
       pre-DAYFIG `recover()` has no such parameter and calling it with one
       raises TypeError. `_recover_at` passes the clock when the signature
       accepts it. A TypeError is not evidence of a daily-figure defect, so
       the script declines to produce one: the pre-DAYFIG tree must fail on
       CONTRADICTORY VALUES, printed, or the evidence is worthless.

    2. `RecoveryReport.daily_figures_derivable` is new. A tree without it has
       no way to report "I could not establish these", which is itself the
       defect — so its absence is read as the unconditional claim such a tree
       actually makes. That is a statement about the API, not a reimplementation
       of the old fold.

THE PATHS COMPARED, per scenario:

    [R] RECOVERY        `recovery.recover()` — what a restart reconstructs
    [A] AUTHORIZATION   `derivation.derive_intended()` over the pinned prefix
    [F] FRESH PROCESS   a genuine subprocess, new interpreter, handed only the
                        journal path and the session clock

    [F] is a real `subprocess`, not another object in this interpreter: module
    state, import caches and class attributes cannot survive into it, so a
    figure that exists only in process memory cannot follow it across.

THE PROPERTY, stated once and applied to every scenario:

    P1  If authorization DERIVES figures, recovery must derive the SAME ones.
    P2  If authorization REFUSES the history, recovery must NOT claim figures.
        (Zero is a figure. "Unknown" is not zero.)
    P3  A fresh process must reconstruct what this process derived.
    P4  A state cleared to trade must carry the authorization figures. If the
        figures cannot be established, nothing may be cleared to trade.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

sys.path.insert(0, ".")

from orbit.audit.derivation import (LocalStateUndecidable, derive_intended)
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.audit.recovery import (can_complete_recovery, complete_recovery,
                                  recover)
from orbit.exec.protection import MarginMode
from orbit.exec.recon import ExchangeView, reconcile
from orbit.risk.gateway import Gateway, Kind, ProposedAction

WORKER_FLAG = "--fresh-process-worker"

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
YESTERDAY = NOW - timedelta(days=1)
LAST_NIGHT = datetime(2026, 9, 7, 23, 59, 0, tzinfo=timezone.utc)

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))
    return ok


def banner(t):
    print("\n" + "-" * 76)
    print(t)
    print("-" * 76)


# ======================================================================
# CROSS-TREE ADAPTERS — see the module docstring. API only, never behaviour.
# ======================================================================
def _recover_at(path, now):
    if "now" in inspect.signature(recover).parameters:
        return recover(path, now=now)
    return recover(path)


def _claims_figures(report) -> bool:
    """Does this report CLAIM its daily figures are the durable derivation?

    A tree with no such predicate claims them unconditionally — it has no
    vocabulary for "I could not establish these", which is the defect.
    """
    return bool(getattr(report, "daily_figures_derivable", True))


# ======================================================================
# JOURNAL CONSTRUCTION — production writers only
# ======================================================================
def _at(j, when, kind, aid, **payload):
    saved = j._clock
    j._clock = lambda: when
    try:
        return j.append_one(kind, aid, **payload)
    finally:
        j._clock = saved


def round_trip(j, n, pnl, entry_when, exit_when, entry_exec=None, exit_exec=None):
    """One ENTRY fill and one EXIT fill realizing exactly `pnl` USDT.

    1 contract = 0.01 BTC, so a P&L of X is an exit price of entry + X * 100,
    with no rounding. `fee_cost_usdt="0"` is an EXPLICIT normalized cost, so
    the derived figure equals the declared figure to the cent. Commit time and
    `executed_at` are separate parameters on purpose: a fill executed before
    midnight and committed after it is a scenario below.
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


# ----------------------------------------------------------------------
# THE SCENARIOS
# ----------------------------------------------------------------------
def s_stale_counters(j):
    """The reviewer's shape: the day realized -20, the aggregate says nothing."""
    round_trip(j, 1, "-10", NOW, NOW)
    round_trip(j, 2, "-10", NOW, NOW)
    j.append_one(E.COUNTERS, None, entries_utc_day=0, realized_pnl_utc_day="0")


def s_no_counters(j):
    """No aggregate at all — absence must not read as zero."""
    round_trip(j, 1, "-10", NOW, NOW)
    round_trip(j, 2, "-10", NOW, NOW)


def s_single_fill(j):
    round_trip(j, 1, "-15", NOW, NOW)


def s_loss_then_gain(j):
    """Two same-day round trips that must fold, not overwrite."""
    round_trip(j, 1, "-30", NOW, NOW)
    round_trip(j, 2, "10", NOW, NOW)
    j.append_one(E.COUNTERS, None, entries_utc_day=2, realized_pnl_utc_day="-20")


def s_yesterdays_counters(j):
    """Yesterday's loss, and an aggregate with no day of its own."""
    round_trip(j, 1, "-10", YESTERDAY, YESTERDAY)
    round_trip(j, 2, "-10", YESTERDAY, YESTERDAY)
    _at(j, YESTERDAY, E.COUNTERS, None, entries_utc_day=2,
        realized_pnl_utc_day="-20")


def s_straddles_midnight(j):
    """EXECUTED at 23:59 yesterday, COMMITTED today. The accounting day is the
    execution day, so this belongs to yesterday."""
    round_trip(j, 1, "-10", LAST_NIGHT, NOW,
               entry_exec=LAST_NIGHT, exit_exec=LAST_NIGHT)
    j.append_one(E.COUNTERS, None, entries_utc_day=1, realized_pnl_utc_day="-10")


def s_just_after_midnight(j):
    """EXECUTED at 00:00:30 today. Belongs to today."""
    t = NOW.replace(hour=0, minute=0, second=30)
    round_trip(j, 1, "-10", t, t)


def s_genuine_zero(j):
    """A real zero day. Zero here is a derived fact, not an absence."""
    j.append_one(E.RUN_START, None, policy_version="A1")


def s_malformed_counters(j):
    """A COUNTERS record no fold can interpret."""
    round_trip(j, 1, "-10", NOW, NOW)
    j.append_one(E.COUNTERS, None, entries_utc_day="NOT_AN_INT",
                 realized_pnl_utc_day="0")


def s_fill_without_intent(j):
    """A fill ORBIT cannot classify as an entry or an exit."""
    j.append_one(E.RUN_START, None)
    j.append_one(E.FILL, "a1", client_order_id="ghost", fill_id="fg",
                 contracts="1", price="30000", fee_cost_usdt="0",
                 executed_at=NOW.isoformat())


SCENARIOS = [
    ("stale COUNTERS over a -20 day", s_stale_counters),
    ("no COUNTERS record at all", s_no_counters),
    ("one round trip, -15", s_single_fill),
    ("loss then gain, same day", s_loss_then_gain),
    ("yesterday's COUNTERS, nothing today", s_yesterdays_counters),
    ("executed 23:59 yesterday, committed today", s_straddles_midnight),
    ("executed 00:00:30 today", s_just_after_midnight),
    ("genuine zero day", s_genuine_zero),
    ("malformed COUNTERS", s_malformed_counters),
    ("fill with no INTENT", s_fill_without_intent),
]


# ======================================================================
# FRESH-PROCESS WORKER — its own interpreter
# ======================================================================
def _worker(spec):
    """Handed the journal path and the clock, and NOTHING this process derived.

    Everything below is production code.
    """
    sys.path.insert(0, ".")
    from orbit.audit.recovery import recover as _recover
    now = datetime.fromisoformat(spec["now"])
    path = spec["journal"]
    if "now" in inspect.signature(_recover).parameters:
        rep = _recover(path, now=now)
    else:
        rep = _recover(path)
    return {
        "claims": bool(getattr(rep, "daily_figures_derivable", True)),
        "entries": rep.rebuilt.entries_utc_day,
        "pnl": str(rep.rebuilt.realized_pnl_utc_day),
    }


if len(sys.argv) > 1 and sys.argv[1] == WORKER_FLAG:
    print(json.dumps(_worker(json.loads(sys.stdin.read()))))
    raise SystemExit(0)


def fresh_process(path, now):
    out = subprocess.run(
        [sys.executable, os.path.abspath(__file__), WORKER_FLAG],
        input=json.dumps({"journal": path, "now": now.isoformat()}),
        capture_output=True, text=True, cwd=os.getcwd(),
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if out.returncode != 0:
        return {"error": (out.stderr or "").strip()[-300:]}
    return json.loads(out.stdout)


# ======================================================================
# MEASUREMENT
# ======================================================================
def measure(build, now=NOW):
    """(recovery, authorization, fresh) for one synthesized history.

    Each is (claims_figures, entries, pnl) — or (False, None, None) for a path
    that refuses. `claims_figures=False` with numbers present means the numbers
    are not a claim about the day and must not be read as figures.
    """
    tmp = tempfile.mkdtemp(prefix="dayfig-")
    path = os.path.join(tmp, "journal.jsonl")
    j = Journal(path, clock=lambda: NOW)
    build(j)

    try:
        rep = _recover_at(path, now)
        rec = (_claims_figures(rep),
               rep.rebuilt.entries_utc_day,
               D(str(rep.rebuilt.realized_pnl_utc_day)))
        rec_raised = None
    except Exception as e:
        # A RESTART PATH THAT RAISES IS A MEASUREMENT, NOT A CRASH OF THIS
        # SCRIPT. Recovery exists to get a process far enough to ask a human;
        # one that dies on a durable record it cannot parse cannot start at
        # all. That is a different defect from reporting a wrong number, and
        # P5 below asserts it separately. Catching it here is what lets the
        # decisive P4 evidence be reached on a tree where it happens.
        rec = (False, None, None)
        rec_raised = f"{type(e).__name__}: {e}"

    load = Journal.load(path)
    head = load.records[-1]
    try:
        st = derive_intended(load, seq=head["seq"], hash_=head["hash"], now=now)
        auth = (True, st.entries_utc_day, D(str(st.realized_pnl_utc_day)))
        auth_why = ""
    except LocalStateUndecidable as e:
        auth = (False, None, None)
        auth_why = str(e).split(".")[0]

    fp = fresh_process(path, now)
    if "error" in fp:
        fresh = (None, None, None)
    else:
        fresh = (fp["claims"], fp["entries"], D(fp["pnl"]))
    return path, rec, auth, auth_why, fresh, rec_raised


def show(label, triple):
    claims, entries, pnl = triple
    if claims is None:
        return f"    {label:<16} SUBPROCESS FAILED"
    if not claims:
        return f"    {label:<16} claims no figures (unknown is not zero)"
    return f"    {label:<16} entries={str(entries):<6} pnl={pnl}"


# ======================================================================
print("=" * 76)
print("R4C4-DAYFIG-1 — RECOVERY / AUTHORIZATION DAILY-FIGURE DIVERGENCE")
print("=" * 76)
print(f"session clock (UTC)  : {NOW.isoformat()}")
print(f"recover() signature  : {inspect.signature(recover)}")

banner("P1/P2 — ONE PREFIX, ONE SET OF FIGURES")

for name, build in SCENARIOS:
    path, rec, auth, auth_why, fresh, rec_raised = measure(build)
    print(f"\n  {name}")
    if rec_raised:
        print(f"    {'[R] recovery':<16} RAISED  {rec_raised[:110]}")
    else:
        print(show("[R] recovery", rec))
    print(show("[A] authorization", auth) + (f"   ({auth_why})" if auth_why else ""))
    print(show("[F] fresh process", fresh))

    if auth[0]:
        check(f"P1 {name}: recovery derives the authorization figures",
              rec[0] and rec[1] == auth[1] and rec[2] == auth[2],
              f"recovery={rec[1]}/{rec[2]} authorization={auth[1]}/{auth[2]}")
    else:
        check(f"P2 {name}: recovery does not claim figures authorization refuses",
              not rec[0],
              f"recovery claimed {rec[1]}/{rec[2]} over history that cannot "
              f"be accounted")
    check(f"P3 {name}: a fresh process reconstructs the same answer",
          rec_raised is not None or fresh == rec,
          f"in-process={rec} fresh={fresh}")
    check(f"P5 {name}: the restart path does not raise on durable history",
          rec_raised is None, rec_raised or "")

# ======================================================================
banner("P6 — THE FIGURES ARE A FUNCTION OF THE JOURNAL, NOT OF THE PROCESS")
# ======================================================================
# Recovery is called twice on ONE journal path in ONE process, with the history
# growing in between. An implementation that remembered its first answer — a
# cache, a memo, a constructor slot — returns the stale one, and every scenario
# above would still pass because each uses a fresh path. This is the shape the
# whole C4-I1 / N1 line of findings is about, and it must not return here.
tmp = tempfile.mkdtemp(prefix="dayfig-p6-")
path = os.path.join(tmp, "journal.jsonl")
j = Journal(path, clock=lambda: NOW)
round_trip(j, 1, "-10", NOW, NOW)
first_rep = _recover_at(path, NOW)
first = (first_rep.rebuilt.entries_utc_day,
         D(str(first_rep.rebuilt.realized_pnl_utc_day)))
round_trip(j, 2, "-7", NOW, NOW)
second_rep = _recover_at(path, NOW)
second = (second_rep.rebuilt.entries_utc_day,
          D(str(second_rep.rebuilt.realized_pnl_utc_day)))
auth_now = None
load = Journal.load(path)
head = load.records[-1]
try:
    st = derive_intended(load, seq=head["seq"], hash_=head["hash"], now=NOW)
    auth_now = (st.entries_utc_day, D(str(st.realized_pnl_utc_day)))
except LocalStateUndecidable:
    pass

print(f"\n  one path, one process, history grown in between")
print(f"    [R] first call    entries={first[0]} pnl={first[1]}")
print(f"    [R] second call   entries={second[0]} pnl={second[1]}")
print(f"    [A] authorization entries={auth_now[0]} pnl={auth_now[1]}"
      if auth_now else "    [A] authorization REFUSED")
check("P6 a fill appended between two recovery calls moves the answer",
      first != second, f"{first} -> {second}")
check("P6 and the moved answer is exactly what authorization derives",
      auth_now is not None and second == auth_now,
      f"recovery={second} authorization={auth_now}")

# ======================================================================
banner("P4 — WHAT A RESTART IS CLEARED TO TRADE ON")
# ======================================================================
# The decisive case. The day has already realized its maximum loss and the
# position is FLAT, so no open position draws attention to the missing
# counters. This is the shape in which an erased -20 admits new risk.
view = ExchangeView(fetched_at=NOW - timedelta(seconds=5), reachable=True,
                    consistent=True, server_time=NOW, equity=D("1000"),
                    mark_price=D("30000"), margin_mode=MarginMode.UNKNOWN,
                    position=None, open_orders=(), fills=())
action = ProposedAction(decision_id="probe", kind=Kind.OPEN,
                        symbol="BTC-USDT-SWAP", side="long",
                        entry_type="market", stop=D("29700"),
                        data_as_of=view.fetched_at)
GW = Gateway()

for name, build in [("a -20 day, flat, stale COUNTERS", s_stale_counters),
                    ("a -20 day, flat, no COUNTERS", s_no_counters),
                    ("history that cannot be accounted", s_malformed_counters)]:
    tmp = tempfile.mkdtemp(prefix="dayfig-p4-")
    path = os.path.join(tmp, "journal.jsonl")
    j = Journal(path, clock=lambda: NOW)
    build(j)

    try:
        rep = _recover_at(path, NOW)
        r1 = reconcile(rep.rebuilt, view, NOW)
        ok, why = can_complete_recovery(rep, r1)
        cleared = complete_recovery(Journal(path, clock=lambda: NOW), rep, r1)
        p4_raised = None
    except Exception as e:
        ok, why, cleared = False, f"{type(e).__name__}: {e}", None
        p4_raised = why

    load = Journal.load(path)
    head = load.records[-1]
    try:
        auth = derive_intended(load, seq=head["seq"], hash_=head["hash"], now=NOW)
        auth_figs = (auth.entries_utc_day, D(str(auth.realized_pnl_utc_day)))
    except LocalStateUndecidable:
        auth_figs = None

    print(f"\n  {name}")
    if p4_raised:
        print(f"    recovery              : RAISED  {p4_raised[:110]}")
    print(f"    can_complete_recovery = {ok}")
    if not ok:
        print(f"      {why[:150]}")
    if cleared is None:
        print("    cleared to trade      : NOTHING")
        verdict_code = "n/a"
    else:
        r2 = reconcile(cleared, view, NOW)
        state = r2.to_system_state()
        v = GW.evaluate(action, state)
        verdict_code = v.code.value
        print(f"    cleared to trade      : entries={state.entries_utc_day} "
              f"pnl={state.realized_pnl_utc_day} run_state={state.run_state.value}")
        print(f"    gateway OPEN          : approved={v.approved} ({verdict_code})")
    print(f"    authorization figures : "
          f"{'REFUSED' if auth_figs is None else f'{auth_figs[0]}/{auth_figs[1]}'}")

    if auth_figs is None:
        check(f"P4 {name}: nothing is cleared to trade on unaccountable history",
              cleared is None, f"cleared={cleared is not None}")
    else:
        check(f"P4 {name}: a cleared state carries the authorization figures",
              cleared is None
              or (cleared.entries_utc_day == auth_figs[0]
                  and D(str(cleared.realized_pnl_utc_day)) == auth_figs[1]),
              f"cleared={None if cleared is None else cleared.entries_utc_day}/"
              f"{None if cleared is None else cleared.realized_pnl_utc_day} "
              f"authorization={auth_figs[0]}/{auth_figs[1]}")
        # And the safety decision that rests on them.
        if cleared is not None:
            r2 = reconcile(cleared, view, NOW)
            v = GW.evaluate(action, r2.to_system_state())
            check(f"P4 {name}: the gateway refuses the OPEN the day forbids",
                  not v.approved, f"code={v.code.value}")

# ======================================================================
print("\n" + "=" * 76)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 76)
for f in FAIL:
    print(f"  FAILED: {f}")
raise SystemExit(1 if FAIL else 0)
