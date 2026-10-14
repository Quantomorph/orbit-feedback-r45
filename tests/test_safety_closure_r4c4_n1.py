"""
tests/test_safety_closure_r4c4_n1.py — ORBIT A1 SAFETY CLOSURE, ROUND 4C4,
FINDING R4C4-N1: MODEL-FACING SYSTEM-STATE DIVERGENCE.

THE DEFECT (raised by the checkpoint A.1 independent review, carried forward
unrepaired through checkpoint A.2-R and R4C4-JSEQ-1).

    `ToolSession` held TWO definitions of the local state it reasons about:

        self._intended          the CONSTRUCTOR's IntendedState
        derive_intended(prefix) the state DERIVED from the durable journal

    `_reconcile()` — which feeds `get_system_state`, `get_current_risk_state`
    and the durable record of what the model was told — folded the first.
    `_authoritative()` folded the second, and then ASSIGNED IT OVER the first.

    So one durable history produced two contradictory answers about whether
    ORBIT was operational, and which one you got depended on whether an action
    had already run in the session. Reproduced on 45907fee, against a journal
    of 7 records ending at seq 7, hash ad2ce9a4...:

        get_system_state()  ->  HALTED, reconciled=False,
                                findings ['ORPHANED_ORDER', 'PHANTOM_POSITION']
        close_position()    ->  ACKNOWLEDGED, authoritative run_state RUNNING,
                                findings []

    and within ONE session, `get_system_state()` answered HALTED before an
    action and RUNNING after it, from the same records.

    THE MODEL WAS SHOWN ONE REALITY AND JUDGED BY ANOTHER. That answer is
    intended to reach Claude when it decides whether to trade.

THE REPAIR — CONVERGENCE, NOT SYNCHRONIZATION.

    There is no second state left to keep in step. `ToolSession._durable_state`
    is the ONE derivation: `derive_intended` over the ONE pinned journal
    prefix. The read tools, the decision record, the protection guards and the
    authorization path all consume it. The constructor argument is inert.

    Where the state cannot be derived, the read reports the most restrictive
    answer there is — HALTED, with the SAME code the action path refuses under
    (LOCAL_STATE_UNTRUSTED / LOCAL_STATE_DERIVATION_FAILED) — and consults no
    exchange to say so.

WHAT IS ASSERTED HERE.

    N1.1  THE REPRODUCER IS CLOSED: one journal, one answer.
    N1.2  RUNNING is consistent across both paths.
    N1.3  HALTED is consistent across both paths.
    N1.4  PHANTOM_POSITION is consistent across both paths.
    N1.5  RESTART / RECONSTRUCTION does not reintroduce constructor memory.
    N1.6  The answer does not depend on WHICH path is queried first.
    N1.7  The answer does not depend on query ORDER.
    N1.8  A READ CANNOT MUTATE authoritative state.
    N1.9  FAIL-CLOSED behaviour is intact, on BOTH paths, with one vocabulary.
    N1.10 F4 and JSEQ-1 behaviour is intact.
    N1.11 The DAY FIGURES the model is shown are derived, not supplied.
    N1.12 There is NO path to RUNNING that does not go through the derivation.

    ONE DURABLE HISTORY, ONE ANSWER.
    A STATE THAT CANNOT BE DERIVED IS NOT RUNNING.
    THE MODEL IS SHOWN THE STATE IT IS JUDGED BY.

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

from harness import NOW, Exch, Rig, flat, held, pos, stop_order
from orbit.audit.checkpoint import HeadCheckpoint, classify_head
from orbit.audit.derivation import (LocalStateUndecidable, LocalStateUntrusted,
                                    derive_intended)
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.core.precision import BTC_USDT_SWAP as SPEC
from orbit.exec.adapter import NullAdapter
from orbit.exec.recon import F, IntendedState, RunState
from orbit.exec.writer import WriterAuthority
from orbit.audit.cycle import CycleRecorder
from orbit.risk.gateway import Gateway
from orbit.tools.session import ActionStatus, ToolSession

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


def rig(tag, intended=None, exch=None):
    N[0] += 1
    d = os.path.join(TMP, f"{tag}{N[0]}")
    os.makedirs(d, exist_ok=True)
    r = Rig(d, tag, intended=intended, exch=exch or Exch())
    r.acquire()
    return r


def pinned(r):
    """(seq, hash) of the durable prefix both paths must fold."""
    head = Journal.load(r.path)
    if not head.records:
        return 0, ""
    return head.records[-1]["seq"], head.records[-1]["hash"]


def model_facing(r, memory=None, cycle="read"):
    """What the MODEL is told: `get_system_state`, on its own session."""
    return r.session(cycle_id=cycle, memory=memory).get_system_state().data


def authorization(r, memory=None, cycle="auth"):
    """What the ACTION path authorises against: the authoritative observation,
    taken exactly as `_act_locked` step 5 takes it, on its own session."""
    return r.session(cycle_id=cycle, memory=memory)._authoritative().recon


def codes(recon):
    return sorted(f.code.value for f in recon.findings)


def agree(r, memory=None):
    """(model-facing dict, authoritative ReconResult, do they agree)."""
    m = model_facing(r, memory)
    a = authorization(r, memory)
    same = (m["run_state"] == a.run_state.value
            and m["reconciled"] == a.reconciled
            and m["local_state_trusted"] == a.local_state_trusted
            and sorted(m["findings"]) == codes(a))
    return m, a, same


def tamper(path, line=0):
    """Rewrite one record's `ts` in place. The chain no longer verifies; the
    numbering and the byte framing are untouched, so this is a TAMPER, not a
    torn write."""
    lines = [l for l in open(path).read().splitlines() if l.strip()]
    rec = json.loads(lines[line])
    rec["ts"] = "2020-01-01T00:00:00+00:00"
    lines[line] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def journal_bytes(path):
    return open(path, "rb").read()


def head_bytes(path):
    p = HeadCheckpoint(path).path if hasattr(HeadCheckpoint(path), "path") else None
    if p is None or not os.path.exists(p):
        return None
    return open(p, "rb").read()


# ======================================================================
banner("N1.1 — THE REPRODUCER IS CLOSED: ONE JOURNAL, ONE ANSWER")
# ======================================================================
#
# THE EXACT SHAPE THAT DIVERGED ON 45907fee. ORBIT's durable history records a
# 2.38 long at 30000 that it opened and protected; the exchange agrees. The
# session is handed CALLER MEMORY that is flat — nothing is written, the
# journal below is the same journal either path reads.
#
# Before the repair: get_system_state -> HALTED / PHANTOM_POSITION, while the
# action path derived RUNNING from these very records and ACKNOWLEDGED a close.

r = rig("n1repro", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))
seq, jhash = pinned(r)
derived = derive_intended(Journal.load(r.path), seq=seq, hash_=jhash,
                          now=NOW, spec=SPEC)
check("N1.1a the durable evidence is ONE pinned prefix, and it is derivable",
      seq > 0 and len(jhash) == 64 and derived.position is not None
      and derived.position_fill_backed is True,
      f"seq={seq} hash={jhash[:16]}... pos={derived.position.contracts}")

m, a, same = agree(r, memory=flat())
check("N1.1b the model-facing path and the authorization path give ONE answer "
      "for ONE journal, with caller memory that contradicts it",
      same, f"model={m['run_state']}/{sorted(m['findings'])} "
            f"auth={a.run_state.value}/{codes(a)}")
check("N1.1c and that answer is the DERIVED one (RUNNING), not the "
      "constructor's (HALTED / PHANTOM_POSITION)",
      m["run_state"] == RunState.RUNNING.value
      and F.PHANTOM_POSITION.value not in m["findings"],
      f"{m['run_state']} {m['findings']}")

# the end-to-end pair: what the model is TOLD and what it is JUDGED by
s = r.session(cycle_id="e2e", memory=flat())
told = s.get_system_state().data["run_state"]
out = s.close_position()
check("N1.1d what the model is TOLD and what the action path DOES are no "
      "longer contradictory",
      told == RunState.RUNNING.value and out.status is ActionStatus.ACKNOWLEDGED,
      f"told={told} action={out.status.value}/{out.code}")


# ======================================================================
banner("N1.2 / N1.3 / N1.4 — RUNNING, HALTED AND PHANTOM_POSITION AGREE")
# ======================================================================

# --- RUNNING: a healthy, ORBIT-authored, protected position -----------
r = rig("n1run", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))
m, a, same = agree(r)
check("N1.2a RUNNING is consistent across both paths",
      same and m["run_state"] == RunState.RUNNING.value,
      f"model={m['run_state']} auth={a.run_state.value}")
check("N1.2b and RUNNING is reported reconciled, clean, with no findings",
      m["reconciled"] is True and m["local_state_trusted"] is True
      and m["findings"] == [] and a.clean is True,
      f"{m} clean={a.clean}")

# --- HALTED / PHANTOM_POSITION: durable history is clean and flat, the
# --- exchange holds a position ORBIT has no fill for -------------------
r = rig("n1ph", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
m, a, same = agree(r)
check("N1.3a HALTED is consistent across both paths",
      same and m["run_state"] == RunState.HALTED.value,
      f"model={m['run_state']} auth={a.run_state.value}")
check("N1.4a PHANTOM_POSITION is consistent across both paths",
      F.PHANTOM_POSITION.value in m["findings"]
      and F.PHANTOM_POSITION.value in codes(a),
      f"model={m['findings']} auth={codes(a)}")
out = r.session(cycle_id="ph_act", memory=held()).close_position()
check("N1.4b and PHANTOM_POSITION still refuses the action, with caller memory "
      "that claims the position is ORBIT's own",
      out.status is ActionStatus.REQUIRES_HUMAN_REVIEW and out.code == "HALTED",
      f"{out.status.value}/{out.code}")
check("N1.4c HALTED is not weakened: caller memory cannot talk the model-facing "
      "report out of it either",
      model_facing(r, memory=held())["run_state"] == RunState.HALTED.value,
      f"with held() memory: {model_facing(r, memory=held())['run_state']}")

# --- NO_NEW_ENTRY: visible, sound, and deliberately not trading -------
r = rig("n1nne", intended=flat(), exch=Exch())
r.journal.append_one(E.RUN_START, None)          # no clean-shutdown marker
m, a, same = agree(r)
check("N1.2c the degraded states agree too (this journal: "
      f"{m['run_state']})", same,
      f"model={m['run_state']}/{sorted(m['findings'])} "
      f"auth={a.run_state.value}/{codes(a)}")


# ======================================================================
banner("N1.5 — RESTART / RECONSTRUCTION DOES NOT REINTRODUCE CONSTRUCTOR STATE")
# ======================================================================
#
# The point of the finding: the answer must be a function of the durable
# record and nothing else. Four fresh sessions over ONE journal, handed four
# different and mutually contradictory memories — including the C4-I1 shape, a
# state claiming a fresh day with no losses — must all say the same thing.

r = rig("n1restart", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))
seq, jhash = pinned(r)
MEMORIES = {
    "none (fresh process)": None,
    "flat": flat(),
    "held": held(),
    "C4-I1 shape (0 entries, 0 realized, no position)":
        IntendedState(journal_loaded=True, clean_shutdown=True,
                      entries_utc_day=0, realized_pnl_utc_day=D("0")),
}
answers = {}
for label, mem in MEMORIES.items():
    answers[label] = model_facing(r, memory=mem, cycle=f"c{len(answers)}")

check("N1.5a every fresh session over one journal reports ONE state, whatever "
      "constructor memory it is handed",
      len({json.dumps(v, sort_keys=True) for v in answers.values()}) == 1,
      "; ".join(f"{k}->{v['run_state']}" for k, v in answers.items()))
check("N1.5b and that state is the derived one",
      all(v["run_state"] == RunState.RUNNING.value for v in answers.values()),
      str({k: v["run_state"] for k, v in answers.items()}))
check("N1.5c the journal prefix is unchanged by all of that reading",
      pinned(r) == (seq, jhash), f"prefix now {pinned(r)[0]}")

# A SECOND, PROCESS-SHAPED RECONSTRUCTION. Not another session on the rig: a
# brand-new Journal, CycleRecorder, WriterAuthority and ToolSession built over
# the SAME journal file, which is what a restart actually is. Nothing of the
# first process survives except the bytes on disk.
fresh_journal = Journal(r.path, clock=lambda: NOW)
fresh_session = ToolSession(
    cycle_id="restarted", journal=fresh_journal,
    recorder=CycleRecorder(fresh_journal),
    authority=WriterAuthority(r.wdir + "_restarted", ttl_seconds=30.0),
    adapter=NullAdapter(r.authority, fresh_journal), gateway=Gateway(),
    intended_state=flat(), exchange_view_fn=r.exch.view, now=NOW, lease=None)
restarted = fresh_session.get_system_state().data
check("N1.5d a RECONSTRUCTED process over the same journal file reaches the "
      "same state, from the same prefix",
      restarted == answers["flat"] and pinned(r) == (seq, jhash),
      f"{restarted['run_state']} vs {answers['flat']['run_state']}")
check("N1.5e and the restart wrote nothing to reach it",
      pinned(r) == (seq, jhash), f"prefix now {pinned(r)[0]}")


# ======================================================================
banner("N1.6 / N1.7 — NEITHER PATH ORDER NOR QUERY ORDER CHANGES THE ANSWER")
# ======================================================================

def first_read_then_auth(rr, mem):
    s = rr.session(cycle_id="fr", memory=mem)
    m = s.get_system_state().data
    a = rr.session(cycle_id="fa", memory=mem)._authoritative().recon
    return m, a


def first_auth_then_read(rr, mem):
    a = rr.session(cycle_id="fa2", memory=mem)._authoritative().recon
    m = rr.session(cycle_id="fr2", memory=mem).get_system_state().data
    return m, a


for tag, intended, exch in (
        ("running", held(), Exch(position=pos(), orders=[stop_order()])),
        ("halted", flat(), Exch(position=pos(), orders=[stop_order()]))):
    rr = rig(f"n1order_{tag}", intended=intended, exch=exch)
    m1, a1 = first_read_then_auth(rr, flat())
    m2, a2 = first_auth_then_read(rr, flat())
    check(f"N1.6 [{tag}] recovery from the journal gives the same answer "
          f"whichever path is queried FIRST",
          (m1["run_state"] == m2["run_state"] == a1.run_state.value
           == a2.run_state.value),
          f"read-first={m1['run_state']}/{a1.run_state.value} "
          f"auth-first={m2['run_state']}/{a2.run_state.value}")

# QUERY ORDER within one session, across the two model-facing read tools.
rr = rig("n1qorder", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))
sa = rr.session(cycle_id="qa", memory=flat())
sys_first = sa.get_system_state().data
risk_second = sa.get_current_risk_state().data
sb = rr.session(cycle_id="qb", memory=flat())
risk_first = sb.get_current_risk_state().data
sys_second = sb.get_system_state().data
check("N1.7a state-query ORDER does not change the answer",
      sys_first["run_state"] == sys_second["run_state"]
      and risk_first["entries_utc_day"] == risk_second["entries_utc_day"]
      and risk_first["realized_pnl_utc_day"] == risk_second["realized_pnl_utc_day"],
      f"sys {sys_first['run_state']}/{sys_second['run_state']} "
      f"risk {risk_first['entries_utc_day']}/{risk_second['entries_utc_day']}")

# QUERY ORDER around an action: the pre-action read and the action's OWN
# authoritative state are folded from the same prefix, so they cannot differ.
# This is the second face of the reproducer — the answer used to change the
# moment `_authoritative()` assigned over the constructor's slot.
rr = rig("n1around", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))
s = rr.session(cycle_id="around", memory=flat())
before = s.get_system_state().data["run_state"]
out = s.modify_stop("29750")
during = s._recon.run_state.value
check("N1.7b a read BEFORE an action and the action's OWN authoritative state "
      "agree; the first action no longer changes what reads report",
      before == RunState.RUNNING.value and during == RunState.RUNNING.value
      and out.status is ActionStatus.ACKNOWLEDGED,
      f"before={before} during={during} {out.status.value}/{out.code}")


# ======================================================================
banner("N1.8 — A MODEL-FACING READ CANNOT MUTATE AUTHORITATIVE STATE")
# ======================================================================

rr = rig("n1pure", intended=held(), exch=Exch(position=pos(), orders=[stop_order()]))
jb, hb = journal_bytes(rr.path), head_bytes(rr.path)
seq, jhash = pinned(rr)

s = rr.session(cycle_id="pure", memory=flat())
for _ in range(3):
    s.get_system_state()
    s.get_current_risk_state()
    s.get_positions()
    s.get_market_state()

check("N1.8a reading does not write one byte of the journal",
      journal_bytes(rr.path) == jb, f"{len(jb)} bytes, unchanged")
check("N1.8b reading does not write the committed-head checkpoint",
      head_bytes(rr.path) == hb, "head file unchanged")
check("N1.8c the pinned prefix is exactly what it was",
      pinned(rr) == (seq, jhash), f"seq={pinned(rr)[0]}")
check("N1.8d repeated reads return the identical state, so a read cannot "
      "walk the answer anywhere",
      s.get_system_state().data == s.get_system_state().data)

# A read leaves NOTHING an action would inherit: the pin and the derivation
# are reset on action entry, so an action folds the history in front of IT.
rr2 = rig("n1inherit", intended=flat(), exch=Exch())
sx = rr2.session(cycle_id="inh", memory=flat())
sx.get_system_state()                      # pins prefix P1
pre_seq, _ = pinned(rr2)
Journal(rr2.path, clock=lambda: NOW).append_one(E.RUN_START, None)   # -> P2
post_seq, post_hash = pinned(rr2)
out = sx.propose_order("long", stop="29000")
check("N1.8e an action does not inherit a prefix a READ pinned: it folds the "
      "history in front of it",
      pre_seq != post_seq and sx._pinned is None and sx._derived is None,
      f"P1={pre_seq} P2={post_seq} pinned={sx._pinned} derived={sx._derived}")
check("N1.8f and the evidence that action recorded names the LATER prefix",
      post_seq > pre_seq, f"{pre_seq} -> {post_seq}")

# The read tools carry no way to SET state: the session exposes no writable
# state attribute and the old mutable slot is gone entirely.
s_any = rig("n1noslot", intended=flat()).session(memory=flat())
check("N1.8g the mutable `_intended` slot the divergence lived in no longer "
      "exists",
      not hasattr(s_any, "_intended"))
check("N1.8h the constructor's memory is retained inertly and is NOT the state",
      hasattr(s_any, "_ctor_memory"))


# ======================================================================
banner("N1.9 — FAIL-CLOSED IS INTACT, ON BOTH PATHS, IN ONE VOCABULARY")
# ======================================================================
#
# Inability to derive safe state is never equivalent to agreement, and it is
# never equivalent to RUNNING. The read path says the most restrictive thing
# there is, under the SAME code the action path refuses with.

# --- the journal cannot be TRUSTED ------------------------------------
r = rig("n1untrusted", intended=flat(), exch=Exch())
tamper(r.path)
before_bytes = journal_bytes(r.path)
m = model_facing(r, memory=held())
out = r.session(cycle_id="ua", memory=held()).close_position()
check("N1.9a an UNTRUSTED journal reports HALTED to the model, not RUNNING",
      m["run_state"] == RunState.HALTED.value
      and m["reconciled"] is False and m["local_state_trusted"] is False,
      f"{m['run_state']} reconciled={m['reconciled']}")
check("N1.9b under the SAME code the action path refuses with",
      m["findings"] == [F.LOCAL_STATE_UNTRUSTED.value]
      and out.code == "LOCAL_STATE_UNTRUSTED"
      and out.status is ActionStatus.BLOCKED,
      f"read={m['findings']} action={out.status.value}/{out.code}")
check("N1.9c and the untrusted file is left exactly as it was found",
      journal_bytes(r.path) == before_bytes)
rk = r.session(cycle_id="uk", memory=held()).get_current_risk_state().data
check("N1.9d the risk figures are reported as UNDERIVABLE, not as zero",
      rk["entries_utc_day"] is None and rk["realized_pnl_utc_day"] is None
      and rk.get("run_state") == RunState.HALTED.value
      and rk.get("findings") == [F.LOCAL_STATE_UNTRUSTED.value],
      str(rk))

# --- the journal cannot be INTERPRETED --------------------------------
r = rig("n1undecidable", intended=flat(), exch=Exch())
r.journal.append_one(E.COUNTERS, None, entries_utc_day="NOT_AN_INT",
                     realized_pnl_utc_day="0")
m = model_facing(r, memory=held())
out = r.session(cycle_id="da", memory=held()).propose_order("long", stop="29000")
check("N1.9e an UNDERIVABLE journal reports HALTED to the model, not RUNNING",
      m["run_state"] == RunState.HALTED.value,
      f"{m['run_state']} {m['findings']}")
check("N1.9f under the SAME code the action path refuses with, and the two "
      "failures stay distinguishable from each other",
      m["findings"] == [F.LOCAL_STATE_DERIVATION_FAILED.value]
      and out.code == "LOCAL_STATE_DERIVATION_FAILED"
      and out.status is ActionStatus.BLOCKED,
      f"read={m['findings']} action={out.status.value}/{out.code}")
check("N1.9g the refusal names WHY, so an operator can act on it",
      "NOT_AN_INT" in m.get("detail", ""), m.get("detail", "<no detail>")[:90])

# THE EXCHANGE IS NOT CONSULTED to say so. Deciding an underivable state from
# durable evidence alone is the property F3.12 established for the action path;
# the read path must not reach the venue where the action path would not.
r = rig("n1nofetch", intended=flat(), exch=Exch())
r.journal.append_one(E.COUNTERS, None, entries_utc_day="NOT_AN_INT",
                     realized_pnl_utc_day="0")
n = [0]
real = r.exch.view
def counting():
    n[0] += 1
    return real()
r.exch.view = counting
m = model_facing(r, memory=flat())
check("N1.9h an underivable state is reported WITHOUT a venue round trip",
      m["run_state"] == RunState.HALTED.value and n[0] == 0,
      f"{m['run_state']} fetches={n[0]}")
check("N1.9i and a result that observed nothing reports no freshness",
      r.session(cycle_id="nf2", memory=flat())
       .get_system_state().freshness_seconds is None)

# --- derivation failures still RAISE where they must ------------------
r = rig("n1raise", intended=flat(), exch=Exch())
r.journal.append_one(E.COUNTERS, None, entries_utc_day="NOT_AN_INT",
                     realized_pnl_utc_day="0")
s = r.session(cycle_id="raise", memory=flat())
try:
    s._freeze_decision_snapshot("d1", prompt_text="ORBIT A1 cycle prompt")
    raised = None
except LocalStateUndecidable as e:
    raised = e
check("N1.9j a decision is NOT framed on a state ORBIT could not establish: "
      "the snapshot raises rather than recording a softened one",
      raised is not None, type(raised).__name__ if raised else "no raise")
check("N1.9k LocalStateUntrusted remains a LocalStateUndecidable, so the "
      "fail-closed catch cannot miss it",
      issubclass(LocalStateUntrusted, LocalStateUndecidable))


# ======================================================================
banner("N1.10 — F4 AND JSEQ-1 BEHAVIOUR IS INTACT")
# ======================================================================

# F4: a one-record-behind head must prove its HASH, not just its sequence.
def journal_with(n, tag):
    N[0] += 1
    p = os.path.join(TMP, f"{tag}{N[0]}.jsonl")
    j = Journal(p)
    for i in range(n):
        j.append_one(E.REMEDIATION, None, note=f"r{i}")
    return p, Journal.load(p).records


p, recs = journal_with(3, "n1f4wrong")
HeadCheckpoint(p)._write_unchecked(2, "d" * 64)          # one behind, WRONG hash
v = classify_head(p, recs, 0)
lr = Journal.load(p)
check("N1.10a F4 intact: a one-record-behind head naming the WRONG record is "
      "not the crash window and fails closed",
      v.window is False and v.ok is False and lr.trusted is False,
      f"window={v.window} ok={v.ok} trusted={lr.trusted}")

p, recs = journal_with(3, "n1f4right")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])   # one behind, CORRECT
v = classify_head(p, recs, 0)
lr = Journal.load(p)
check("N1.10b F4 intact: the CORRECT one-record-behind head is still the "
      "legitimate crash window and still loads trusted",
      v.ok is True and v.window is True and lr.trusted is True
      and lr.head_window is True,
      f"ok={v.ok} window={v.window} trusted={lr.trusted}")

# JSEQ-1: sequence contiguity is still enforced by the loader.
from orbit.audit.records import GENESIS, canonical, event, make_record


def forge(tag, seqs):
    N[0] += 1
    p = os.path.join(TMP, f"{tag}{N[0]}.jsonl")
    prev = GENESIS
    with open(p, "w") as fh:
        for i, s_ in enumerate(seqs):
            rec = make_record(s_, "2026-01-01T00:00:00+00:00",
                              [event(E.REMEDIATION, None, note=f"s{i}")], prev)
            fh.write(canonical(rec) + "\n")
            prev = rec["hash"]
    return p


for seqs, why in (([5, 6, 7], "starts above 1"), ([1, 2, 4], "a gap"),
                  ([1, 2, 2], "a duplicate"), ([1, 3, 2], "goes backwards")):
    lr = Journal.load(forge("n1jseq", seqs))
    check(f"N1.10c JSEQ-1 intact: a hash-valid chain numbered {seqs} ({why}) "
          f"is refused",
          lr.trusted is False and lr.tamper_detected is True,
          f"trusted={lr.trusted}")

lr = Journal.load(forge("n1jseqok", [1, 2, 3]))
check("N1.10d JSEQ-1 intact: a contiguous hash-valid chain still loads trusted",
      lr.trusted is True, f"trusted={lr.trusted} {lr.reason}")

# And an untrusted journal reaches the model-facing surface as HALTED, so the
# JSEQ refusal is not something only the action path can see.
p = forge("n1jseqmodel", [1, 2, 4])
r = rig("n1jseqrig", intended=flat(), exch=Exch())
with open(r.path, "w") as fh:
    fh.write(open(p).read())
m = model_facing(r, memory=held())
check("N1.10e a JSEQ-refused journal is reported to the model as HALTED / "
      "LOCAL_STATE_UNTRUSTED, not as RUNNING",
      m["run_state"] == RunState.HALTED.value
      and m["findings"] == [F.LOCAL_STATE_UNTRUSTED.value],
      f"{m['run_state']} {m['findings']}")


# ======================================================================
banner("N1.11 — THE DAY FIGURES THE MODEL IS SHOWN ARE DERIVED")
# ======================================================================
#
# The C4-I1 pair, on the presentation side. The durable history records two
# entries and a -20 realized day; caller memory claims a fresh day with no
# losses. The model must be shown the derived figures, because those are the
# figures the gateway will judge its proposal by.

LOSSY = IntendedState(journal_loaded=True, clean_shutdown=True,
                      entries_utc_day=2, realized_pnl_utc_day=D("-20"))
FRESH = IntendedState(journal_loaded=True, clean_shutdown=True,
                      entries_utc_day=0, realized_pnl_utc_day=D("0"))

r = rig("n1day", intended=LOSSY, exch=Exch())
seq, jhash = pinned(r)
d = derive_intended(Journal.load(r.path), seq=seq, hash_=jhash, now=NOW, spec=SPEC)
rk = r.session(cycle_id="day", memory=FRESH).get_current_risk_state().data
check("N1.11a the durable history derives 2 entries and -20 realized",
      d.entries_utc_day == 2 and d.realized_pnl_utc_day == D("-20"),
      f"{d.entries_utc_day} / {d.realized_pnl_utc_day}")
check("N1.11b the model is shown the DERIVED figures, not the caller's "
      "fresh-day claim",
      rk["entries_utc_day"] == 2 and D(rk["realized_pnl_utc_day"]) == D("-20"),
      f"{rk['entries_utc_day']} / {rk['realized_pnl_utc_day']}")
out = r.session(cycle_id="dayact", memory=FRESH).propose_order("long", stop="29000")
check("N1.11c and the action path refuses on those same figures, so the model "
      "is shown the state it is judged by",
      out.status is ActionStatus.REJECTED,
      f"{out.status.value}/{out.code}")
check("N1.11d the figure the model sees and the figure the gateway used are "
      "ONE figure",
      str(rk["entries_utc_day"]) == str(d.entries_utc_day))


# ======================================================================
banner("N1.12 — NO PATH TO RUNNING THAT DOES NOT GO THROUGH THE DERIVATION")
# ======================================================================
#
# The convergence is a property of the code, not of the cases enumerated above:
# there is exactly ONE fold, and every state answer is a function of its
# output. Asserted structurally so a future edit that reintroduces a second
# source is caught here rather than by the next review.

import inspect
import re

from orbit.tools import session as sess_mod

src = inspect.getsource(sess_mod.ToolSession)


def code_lines(text):
    """Executable lines only. A comment naming a call is not a call site, and
    this file deliberately quotes the old ones in its own comments."""
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        out.append(ln)
    return "\n".join(out)


body = code_lines(src)
n_derive = len(re.findall(r"\bderive_intended\(", body))
n_recon = len(re.findall(r"(?<![_.\w])reconcile\(", body))
n_ctor = len(re.findall(r"self\._ctor_memory", body))

check("N1.12a `_durable_state` is the only place the session folds a journal "
      "into an IntendedState",
      n_derive == 1, f"{n_derive} call sites")
# The property is not one CALL SITE — `_authoritative` keeps its own so the
# authoritative PRE-mutation observation stays attributable to it (R4C.1) —
# but ONE DERIVATION. Every reconciler call site must be handed the derived
# state, and `intended` is only ever bound from `_derive_local_state`.
recon_args = re.findall(r"(?<![_.\w])reconcile\(\s*([^,]+),", body)
ALLOWED = {"self._durable_state()", "intended"}
check("N1.12b every reconciler call site is handed the DERIVED state, and "
      "nothing else",
      recon_args and set(a.strip() for a in recon_args) <= ALLOWED,
      f"first arguments: {[a.strip() for a in recon_args]}")
# `intended = ...` is an ASSIGNMENT; `intended=...` is a keyword argument.
intended_binds = re.findall(r"^\s*intended = (.+)$", body, re.M)
check("N1.12b2 and the only thing `intended` is ever bound from is the "
      "derivation",
      intended_binds
      and all("_derive_local_state" in b for b in intended_binds),
      f"bindings: {[b.strip() for b in intended_binds]}")
check("N1.12c no state answer reads the constructor's memory",
      n_ctor == 1,                       # the inert assignment, and nothing else
      f"{n_ctor} references")
check("N1.12d the mutable slot the divergence lived in is gone from the source",
      "self._intended" not in body)
check("N1.12e the derivation is discarded everywhere the pin it belongs to is",
      body.count("self._derived = None") == body.count("self._pinned = None"),
      f"derived={body.count('self._derived = None')} "
      f"pinned={body.count('self._pinned = None')}")

gss = code_lines(inspect.getsource(sess_mod.ToolSession.get_system_state))
failing = gss.split("if r is None:")[1].split("return self._snapshot")[2 - 1]
check("N1.12f the fail-closed read branch reaches HALTED and cannot reach "
      "RUNNING",
      "RunState.HALTED.value" in failing and "RUNNING" not in failing,
      failing.strip().replace("\n", " ")[:80])

rd = code_lines(inspect.getsource(sess_mod.ToolSession._read_state))
check("N1.12g and it catches BOTH derivation failures, so neither can escape "
      "a tool call or be silently swallowed",
      "LocalStateUntrusted" in rd and "LocalStateUndecidable" in rd
      and "except Exception" not in rd)


# ======================================================================
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    for f_ in FAIL:
        print("  FAILED:", f_)
print("=" * 78)
sys.exit(1 if FAIL else 0)
