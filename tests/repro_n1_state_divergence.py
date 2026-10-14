"""
tests/repro_n1_state_divergence.py — R4C4-N1 STANDALONE DETERMINISTIC REPRODUCER.

WHAT THIS SCRIPT IS FOR.

    ONE durable journal must produce ONE answer about whether ORBIT is
    operational, whoever asks and whenever they ask.

    R4C4-N1 was a violation of that: `ToolSession` held two definitions of its
    own local state — the CONSTRUCTOR's `IntendedState`, which the model-facing
    read tools folded, and the state DERIVED from the durable journal, which
    the action/authorization path folded. The same records answered HALTED /
    PHANTOM_POSITION to `get_system_state()` and RUNNING to the action path.

HOW THIS SCRIPT IS USED AS EVIDENCE.

    It asserts the REPAIRED property. It is not parameterised by tree, it
    contains no copy of the old behaviour, and it is not told which tree it is
    running on.

        against the repaired tree   -> every path converges, exit 0
        against 45907fee (pre-N1)   -> the paths contradict, exit 1

    The same bytes are run against both trees. That is the whole design: the
    pre-N1 evidence is this script FAILING, with the contradictory values it
    printed, not a second script that imitates the defect.

    It uses only API present on BOTH trees — no `_durable_state`, no
    `_ctor_memory`, no finding-code enum members added by the repair — so no
    adaptation is needed to run it against 45907fee.

THE FOUR PATHS COMPARED, per scenario:

    [A] MODEL-FACING          `get_system_state()` — what Claude would be told
    [B] ACTION/AUTHORIZATION  `_authoritative()` — what the action path acts on
    [C] DURABLE DERIVATION    `derive_intended()` over the pinned prefix
    [D] FRESH PROCESS         a genuine subprocess, new interpreter, given only
                              the journal path and an exchange observation

    [D] is a real `subprocess`, not another object in this interpreter: module
    state, import caches and class attributes cannot survive into it, so a
    state that only exists in process memory cannot follow it across.

CASE 1 vs CASE 2 (the design-trap determination this script exists to settle):

    CASE 1  the restrictive state is durably derivable and survives a genuine
            process restart; the defect was that ONE PATH failed to derive it.
    CASE 2  the restrictive state exists ONLY in process memory and can vanish
            across a restart — a broader fail-open durability defect.

    The `restart_survives` column printed per scenario is the evidence.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

WORKER_FLAG = "--fresh-process-worker"


# ======================================================================
# FRESH-PROCESS WORKER
# ======================================================================
# Runs in its OWN interpreter. It is handed the durable journal path and a
# literal description of the exchange observation, and NOTHING that the parent
# process derived. Everything below is production code.
def _worker(spec):
    from datetime import datetime, timedelta
    from decimal import Decimal as D

    from orbit.audit.cycle import CycleRecorder
    from orbit.audit.derivation import (LocalStateUndecidable,
                                        LocalStateUntrusted, derive_intended)
    from orbit.audit.journal import Journal
    from orbit.core.precision import BTC_USDT_SWAP as SPEC
    from orbit.exec.adapter import NullAdapter
    from orbit.exec.protection import MarginMode
    from orbit.exec.recon import (ExchangeOrder, ExchangePosition,
                                  ExchangeView)
    from orbit.exec.writer import WriterAuthority
    from orbit.risk.gateway import Gateway
    from orbit.tools.session import ToolSession

    now = datetime.fromisoformat(spec["now"])
    path = spec["journal"]

    # --- the exchange observation, rebuilt from the literal spec ----------
    xp = spec["exchange"]["position"]
    position = (None if xp is None
                else ExchangePosition(xp["side"], D(xp["contracts"]),
                                      D(xp["entry"])))
    orders = tuple(ExchangeOrder(o["cid"], D(o["contracts"]), o["protective"],
                                 D(o["stop"]) if o["stop"] else None)
                   for o in spec["exchange"]["orders"])

    def view_fn():
        return ExchangeView(
            fetched_at=now - timedelta(seconds=5), reachable=True,
            consistent=True, server_time=now, equity=D("1000"),
            mark_price=D("30000"), margin_mode=MarginMode.UNKNOWN,
            position=position, open_orders=orders, fills=())

    # --- the CONSTRUCTOR MEMORY this fresh process is handed --------------
    # The point of the scenario: this is the non-durable input whose influence
    # must be nil. `harness.flat` / `harness.held` are pure IntendedState
    # constructors that write nothing, and they are the SAME objects the parent
    # process is handed - so [A] and [D] differ in the PROCESS BOUNDARY and in
    # nothing else. Rebuilding an approximation here would have made a pre-N1
    # [A]/[D] difference ambiguous between "memory did not cross the boundary"
    # and "the two memories were not the same memory".
    from harness import flat as _flat, held as _held
    memory = _held() if spec["memory"] == "held" else _flat()

    out = {"pid": os.getpid(), "ppid": os.getppid()}

    # --- [C] the authoritative durable derivation, in a fresh process -----
    load = Journal.load(path)
    seq = load.records[-1]["seq"] if load.records else 0
    jhash = load.records[-1]["hash"] if load.records else ""
    out["journal_seq"] = seq
    out["journal_hash"] = jhash
    out["journal_trusted"] = bool(load.trusted)
    try:
        st = derive_intended(load, seq=seq, hash_=jhash, now=now, spec=SPEC)
        out["derived"] = {
            "position": (None if st.position is None else
                         f"{st.position.side} {st.position.contracts}"
                         f" @ {st.position.entry_price}"),
            "entries_utc_day": st.entries_utc_day,
            "realized_pnl_utc_day": str(st.realized_pnl_utc_day),
        }
    except LocalStateUntrusted as e:
        out["derived"] = {"refused": "LOCAL_STATE_UNTRUSTED", "why": str(e)[:120]}
    except LocalStateUndecidable as e:
        out["derived"] = {"refused": "LOCAL_STATE_DERIVATION_FAILED",
                          "why": str(e)[:120]}

    # --- [A] the model-facing answer, in a fresh process ------------------
    journal = Journal(path, clock=lambda: now)
    session = ToolSession(
        cycle_id="fresh-process", journal=journal,
        recorder=CycleRecorder(journal),
        authority=WriterAuthority(spec["writer_dir"], ttl_seconds=30.0),
        adapter=NullAdapter(WriterAuthority(spec["writer_dir"],
                                            ttl_seconds=30.0), journal),
        gateway=Gateway(), intended_state=memory, exchange_view_fn=view_fn,
        now=now, lease=None)
    data = session.get_system_state().data
    out["model_facing"] = {k: data.get(k) for k in
                           ("run_state", "reconciled", "local_state_trusted",
                            "findings")}
    print(json.dumps(out))
    return 0


if len(sys.argv) > 2 and sys.argv[1] == WORKER_FLAG:
    sys.exit(_worker(json.loads(sys.argv[2])))


# ======================================================================
# PARENT PROCESS
# ======================================================================
from datetime import timedelta
from decimal import Decimal as D

from harness import NOW, Exch, Rig, flat, held, pos, stop_order
from orbit.audit.derivation import (LocalStateUndecidable, LocalStateUntrusted,
                                    derive_intended)
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.core.precision import BTC_USDT_SWAP as SPEC

TMP = tempfile.mkdtemp(prefix="repro_n1_")
PASS, FAIL = [], []
_n = [0]

# The two codes the authorization path refuses with. Referenced as STRINGS, not
# as enum members, so this script is identical on a tree that predates them.
REFUSAL_CODES = ("LOCAL_STATE_UNTRUSTED", "LOCAL_STATE_DERIVATION_FAILED")


def check(name, ok, detail=""):
    ok = bool(ok)
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))


def rule(t=""):
    print("\n" + "=" * 78)
    if t:
        print(t)
        print("=" * 78)


def rig(tag, intended, exch):
    _n[0] += 1
    d = os.path.join(TMP, f"{tag}{_n[0]}")
    os.makedirs(d, exist_ok=True)
    r = Rig(d, tag, intended=intended, exch=exch)
    r.acquire()
    return r


def tamper(path):
    """Rewrite one record's `ts`. The hash chain no longer verifies; the
    numbering and the byte framing are untouched, so this is a TAMPER."""
    lines = [l for l in open(path).read().splitlines() if l.strip()]
    rec = json.loads(lines[0])
    rec["ts"] = "2020-01-01T00:00:00+00:00"
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


# ----------------------------------------------------------------------
# THE NORMALISED VERDICT
# ----------------------------------------------------------------------
# Every path answers one of:
#     "<RUN_STATE>"            a state was derived
#     "REFUSED:<CODE>"         the durable state could not be established
# Expressed the same way for every path so they can be compared at all. This
# encodes no expectation about WHICH answer is right on WHICH tree.
def verdict_of_read(data):
    for code in REFUSAL_CODES:
        if code in (data.get("findings") or []):
            return "REFUSED:" + code
    return data.get("run_state")


def verdict_of_action(session):
    try:
        return session._authoritative().recon.run_state.value
    except LocalStateUntrusted:
        return "REFUSED:LOCAL_STATE_UNTRUSTED"
    except LocalStateUndecidable:
        return "REFUSED:LOCAL_STATE_DERIVATION_FAILED"


def verdict_of_derivation(path, now):
    load = Journal.load(path)
    seq = load.records[-1]["seq"] if load.records else 0
    jhash = load.records[-1]["hash"] if load.records else ""
    try:
        derive_intended(load, seq=seq, hash_=jhash, now=now, spec=SPEC)
        return "DERIVABLE", seq, jhash, bool(load.trusted)
    except LocalStateUntrusted:
        return "REFUSED:LOCAL_STATE_UNTRUSTED", seq, jhash, bool(load.trusted)
    except LocalStateUndecidable:
        return ("REFUSED:LOCAL_STATE_DERIVATION_FAILED", seq, jhash,
                bool(load.trusted))


def fresh_process(journal_path, writer_dir, exchange, memory, now):
    """[D] A GENUINE new interpreter. Not another object in this one."""
    spec = {"journal": journal_path, "writer_dir": writer_dir,
            "exchange": exchange, "memory": memory, "now": now.isoformat()}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), WORKER_FLAG,
         json.dumps(spec)],
        capture_output=True, text=True, env=env,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if proc.returncode != 0:
        return {"worker_failed": proc.returncode,
                "stderr": proc.stderr.strip()[-400:]}
    return json.loads(proc.stdout.strip().splitlines()[-1])


# ======================================================================
# SCENARIOS
# ======================================================================
# In every one, the DURABLE JOURNAL and the CONSTRUCTOR MEMORY deliberately
# disagree. That disagreement is the whole subject: it must change nothing.
POSITION_EXCH = {"position": {"side": "long", "contracts": "2.38",
                              "entry": "30000"},
                 "orders": [{"cid": "stop1", "contracts": "2.38",
                             "protective": True, "stop": "29700.1"}]}
FLAT_EXCH = {"position": None, "orders": []}

SCENARIOS = []


def scenario(name, why, intended, exch, exch_spec, memory_name, memory,
             mutate=None, expect_restrictive=False):
    SCENARIOS.append(dict(name=name, why=why, intended=intended, exch=exch,
                          exch_spec=exch_spec, memory_name=memory_name,
                          memory=memory, mutate=mutate,
                          expect_restrictive=expect_restrictive))


# 1. RUNNING. ORBIT's own record holds a fill-backed, protected position and
#    the exchange agrees. Caller memory says flat. THE REPRODUCER SHAPE.
scenario("RUNNING",
         "durable history holds an ORBIT-opened protected position; caller "
         "memory says flat",
         held(), Exch(position=pos(), orders=[stop_order()]), POSITION_EXCH,
         "flat", "flat")

# 2. HALTED / PHANTOM_POSITION. The journal is CLEAN and FLAT and the exchange
#    holds a position ORBIT has no fill for. Caller memory claims the position
#    is ORBIT's own — i.e. memory would talk the system OUT of the restriction.
scenario("HALTED / PHANTOM_POSITION",
         "durable history is clean and flat; the exchange holds a position "
         "ORBIT never opened; caller memory claims it as ORBIT's",
         flat(), Exch(position=pos(), orders=[stop_order()]), POSITION_EXCH,
         "held", "held", expect_restrictive=True)

# 3. UNDERIVABLE. A hash-valid, sequence-contiguous journal the strict fold
#    cannot interpret. Inability to derive is not agreement.
scenario("UNDERIVABLE",
         "the journal is trusted but carries a durable counter that is not a "
         "number; caller memory is healthy",
         flat(), Exch(), FLAT_EXCH, "held", "held",
         mutate=lambda r: r.journal.append_one(
             E.COUNTERS, None, entries_utc_day="NOT_AN_INT",
             realized_pnl_utc_day="0"),
         expect_restrictive=True)

# 4. UNTRUSTED. The hash chain has been rewritten.
scenario("UNTRUSTED",
         "the journal's hash chain is broken; caller memory is healthy",
         flat(), Exch(), FLAT_EXCH, "held", "held",
         mutate=lambda r: tamper(r.path), expect_restrictive=True)


# ======================================================================
rule("R4C4-N1 REPRODUCER — ONE DURABLE HISTORY, HOW MANY ANSWERS?")
print(f"python    : {sys.version.split()[0]}")
print(f"cwd       : {os.getcwd()}")
print(f"session   : NOW = {NOW.isoformat()}")
print(f"scratch   : {TMP}")

rows = []
for sc in SCENARIOS:
    rule(f"SCENARIO — {sc['name']}")
    print(f"premise   : {sc['why']}")
    r = rig(sc["name"].split()[0].lower(), sc["intended"], sc["exch"])
    if sc["mutate"]:
        sc["mutate"](r)

    dv, seq, jhash, trusted = verdict_of_derivation(r.path, NOW)
    print(f"\n  DURABLE ANCHOR")
    print(f"    journal          : {r.path}")
    print(f"    pinned seq       : {seq}")
    print(f"    pinned hash      : {jhash[:32] or '(empty)'}")
    print(f"    trusted          : {trusted}")
    print(f"    [C] derivation   : {dv}")

    mem = held() if sc["memory"] == "held" else flat()
    print(f"\n  CONSTRUCTOR MEMORY (non-durable input)")
    print(f"    memory           : {sc['memory_name']}"
          f"  position={mem.position is not None}"
          f"  entries_utc_day={mem.entries_utc_day}")

    # [A] model-facing
    read = r.session(cycle_id="read", memory=mem).get_system_state().data
    va = verdict_of_read(read)
    # [B] action / authorization
    vb = verdict_of_action(r.session(cycle_id="auth", memory=mem))
    # [D] fresh process
    fp = fresh_process(r.path, os.path.join(TMP, f"w{_n[0]}"), sc["exch_spec"],
                       sc["memory"], NOW)
    vd = (verdict_of_read(fp["model_facing"]) if "model_facing" in fp
          else f"WORKER_FAILED({fp.get('worker_failed')})")

    print(f"\n  THE FOUR PATHS")
    print(f"    [A] model-facing      : {va}   findings={read.get('findings')}")
    print(f"    [B] action/authorize  : {vb}")
    print(f"    [C] durable derivation: {dv}")
    print(f"    [D] fresh process     : {vd}   pid={fp.get('pid')} "
          f"(parent {os.getpid()})")
    if "model_facing" in fp:
        print(f"        fresh derivation  : {fp['derived']}")
        print(f"        fresh anchor      : seq={fp['journal_seq']} "
              f"hash={fp['journal_hash'][:32] or '(empty)'} "
              f"trusted={fp['journal_trusted']}")
    else:
        print(f"        worker stderr     : {fp.get('stderr')}")

    converged = (va == vb == vd)
    restrictive = va.startswith("REFUSED:") or va in ("HALTED", "RECONCILING")
    survives = restrictive and vd == va
    rows.append((sc["name"], va, vb, vd, converged,
                 survives if sc["expect_restrictive"] else None))

    print()
    check(f"{sc['name']}: [A] model-facing and [B] action/authorization agree",
          va == vb, f"A={va} B={vb}")
    check(f"{sc['name']}: [D] a FRESH PROCESS, told only the journal path, "
          f"reaches the same answer",
          vd == va, f"A={va} D={vd}")
    check(f"{sc['name']}: the answer is a function of durable evidence, not "
          f"of the constructor memory handed in",
          va == vb == vd, f"A={va} B={vb} D={vd}")
    if sc["expect_restrictive"]:
        check(f"{sc['name']}: the RESTRICTIVE state SURVIVES a genuine "
              f"process restart (CASE 1 evidence)",
              survives, f"parent={va} fresh={vd}")
    if sc["name"] == "RUNNING":
        check("RUNNING: caller memory claiming FLAT does not manufacture "
              "PHANTOM_POSITION out of a journal that holds a position",
              "PHANTOM_POSITION" not in (read.get("findings") or []),
              str(read.get("findings")))
    if sc["name"].startswith("HALTED"):
        check("HALTED: caller memory claiming the position is ORBIT's does "
              "NOT talk the system out of PHANTOM_POSITION",
              "PHANTOM_POSITION" in (read.get("findings") or [])
              and va == "HALTED", f"{va} {read.get('findings')}")


# ======================================================================
rule("SUMMARY — ONE DURABLE HISTORY, ONE ANSWER?")
print(f"{'scenario':<26} {'[A] model':<34} {'[B] action':<34} "
      f"{'[D] fresh proc':<34} {'converged':<10} restart-survives")
print("-" * 78)
for name, va, vb, vd, conv, surv in rows:
    print(f"{name:<26} {va:<34} {vb:<34} {vd:<34} "
          f"{str(conv):<10} {'-' if surv is None else surv}")

rule()
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("\nTHE PATHS DISAGREE. One durable history produced more than one")
    print("answer about whether ORBIT is operational:")
    for f_ in FAIL:
        print("  FAILED:", f_)
print("=" * 78)
sys.exit(1 if FAIL else 0)
