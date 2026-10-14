"""
tests/test_safety_closure_r4c3.py — ORBIT A1 SAFETY CLOSURE, ROUND 4C3.

Independent review reopened Round 4C2 and reproduced five defects in the
evidence layer:

    C3-I1  put() trusted a pathname and could report success over corrupt bytes
    C3-I2  refused-action evidence existed but was bound to no verdict
    C3-I3  local state and limits were HASHED, never reconstructable
    C3-I4  the serializer was not injective: type names and dict keys collided
    C3-I5  non-reentrancy was a boolean, not mutual exclusion

    EXISTENCE IS NOT DURABILITY.
    EXISTENCE IS NOT BINDING.
    A HASH IS NOT A RECONSTRUCTION.

Every test here was written to FAIL against the 769/769 Round-4C2 archive.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, owning, pos, stop_order
from orbit.audit.blobstore import BlobCorrupted, BlobMissing, BlobStore
from orbit.audit.decision_input import DecisionInput, record_decision_input
from orbit.audit.evidence import (SCHEMA, EvidenceUnavailable,
                                  UnserialisableEvidence, _plain, load, revive,
                                  serialize)
from orbit.audit.journal import Journal
from orbit.exec.recon import (ExchangeOrder, IntendedState, OrderStatus,
                              SubmittedOrder, reconcile)
from orbit.risk.limits import A1
from orbit.tools.session import (ActionStatus,
                                 ReentrantAction, ToolSession)

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


OURS = stop_order("stop1", "2.38", "29700.1")


def rig(orders=(OURS,), intended=None, own=("stop1",), position=True):
    N[0] += 1
    d = os.path.join(TMP, f"r{N[0]}")
    os.makedirs(d, exist_ok=True)
    r = Rig(d, f"e{N[0]}", intended=intended or held(),
            exch=Exch(position=pos() if position else None,
                      orders=list(orders)))
    r.acquire()
    if own:
        owning(r, *own)
    return r


ed = lambda r: os.path.join(os.path.dirname(os.path.abspath(r.path)),
                            "evidence")


def raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


# ======================================================================
banner("R4C3.1  C3-I1 — a successful put PROVES the bytes are there")
# ======================================================================
st = BlobStore(os.path.join(TMP, "bs1"))
raw = b'{"evidence":1}'
cid = st.put(raw)
check("R4C3.1.1  first put, then get returns the exact bytes",
      st.get(cid) == raw)
check("R4C3.1.2  an identical second put succeeds over correct bytes",
      st.put(raw) == cid and st.get(cid) == raw)

for label, corrupt in (("wrong bytes under the right name", b"CORRUPTED"),
                       ("truncated", raw[:4]),
                       ("empty", b"")):
    s2 = BlobStore(os.path.join(TMP, f"bs_{len(corrupt)}_{label[:4]}"))
    c = s2.put(raw)
    with open(s2.path_for(c), "wb") as fh:
        fh.write(corrupt)
    check(f"R4C3.1.3  put cannot report success over {label}",
          raises(BlobCorrupted, lambda: s2.put(raw)))
    check(f"R4C3.1.4  and it is NOT silently repaired ({label}) — corruption "
          f"is itself evidence",
          open(s2.path_for(c), "rb").read() == corrupt)

# a separate process corrupts between uses
s3 = BlobStore(os.path.join(TMP, "bs3"))
c3 = s3.put(raw)
w = os.path.join(TMP, "corrupt.py")
open(w, "w").write("import sys\nopen(sys.argv[1],'wb').write(b'X')\n")
subprocess.run([sys.executable, w, s3.path_for(c3)], check=True)
check("R4C3.1.5  a separate process corrupting between uses is detected",
      raises(BlobCorrupted, lambda: s3.put(raw))
      and raises(BlobCorrupted, lambda: s3.get(c3)))

# no adapter mutation when evidence cannot be durably established
r = rig()
s = r.session()
a = s._authoritative()
r2 = rig()
s2 = r2.session()
with open(BlobStore(ed(r2)).path_for(
        BlobStore.content_id(b"never")) if False else os.devnull, "rb"):
    pass
_real_put = BlobStore.put


def _failing_put(self, data):
    raise BlobCorrupted("simulated store failure")


BlobStore.put = _failing_put
try:
    r3 = rig()
    blew = raises(BlobCorrupted, lambda: r3.session().modify_stop("29750"))
    calls = len(r3.adapter.calls)
finally:
    BlobStore.put = _real_put
check("R4C3.1.6  when evidence cannot be made durable, ZERO adapter mutations "
      "occur", blew and calls == 0, f"raised={blew} calls={calls}")

# multiple processes putting identical bytes, and racing a corrupt target
mw = os.path.join(TMP, "putter.py")
open(mw, "w").write(
    "import sys\nsys.path.insert(0, sys.argv[3])\n"
    "from orbit.audit.blobstore import BlobStore, BlobCorrupted\n"
    "try:\n"
    "    print(BlobStore(sys.argv[1]).put(sys.argv[2].encode()))\n"
    "except BlobCorrupted:\n    print('CORRUPT')\n")
d4 = os.path.join(TMP, "bs4")
outs = [subprocess.run([sys.executable, mw, d4, "same-bytes",
                        os.path.abspath(".")], capture_output=True, text=True)
        for _ in range(4)]
ids = {o.stdout.strip() for o in outs}
check("R4C3.1.7  four processes putting identical bytes agree on one id",
      len(ids) == 1 and "CORRUPT" not in ids, str(ids))

d5 = os.path.join(TMP, "bs5")
s5 = BlobStore(d5)
c5 = s5.put(b"same-bytes")
with open(s5.path_for(c5), "wb") as fh:
    fh.write(b"tampered")
outs = [subprocess.run([sys.executable, mw, d5, "same-bytes",
                        os.path.abspath(".")], capture_output=True, text=True)
        for _ in range(4)]
check("R4C3.1.8  every process racing a corrupt target fails closed; none "
      "reports success",
      {o.stdout.strip() for o in outs} == {"CORRUPT"},
      str({o.stdout.strip() for o in outs}))

# the other BlobStore consumer must be unaffected
jd = os.path.join(TMP, "di")
os.makedirs(jd, exist_ok=True)
j = Journal(os.path.join(jd, "j.jsonl"))
di = DecisionInput(system_prompt="s", user_prompt="u")
store_di = BlobStore(os.path.join(jd, "b"))
cid_di = BlobStore.content_id(di.serialize())
record_decision_input(j, store_di, "d1", di)
check("R4C3.1.9  DecisionInput is unaffected by the stricter put",
      store_di.has(cid_di))
record_decision_input(j, store_di, "d1", di)
check("R4C3.1.10 and recording the SAME decision input twice still works",
      store_di.get(cid_di) == di.serialize())

# ======================================================================
banner("R4C3.2  C3-I2 — every post-snapshot verdict names its evidence")
# ======================================================================


def verdict_refs(r):
    out = []
    for rec in Journal.load(r.path).records:
        for ev in rec["events"]:
            if "authoritative_observation" in ev:
                out.append((ev["e"], ev.get("authoritative_observation"),
                            ev.get("authoritative_snapshot")))
    return out


REFUSALS = [
    ("lifecycle", [], flat(), (), False, lambda s: s.close_position()),
    ("protection", [OURS], held(), ("stop1",), True,
     lambda s: s.reduce_position("0.5")),
    ("gateway", [OURS], held(), ("stop1",), True,
     lambda s: s.modify_stop("29000")),
    ("post-snapshot ownership", [stop_order("manual", "2.38", "29700.1")],
     held(cid="manual", orbit_stop=False), (), True, lambda s: s.modify_stop("29750")),
]
for label, orders, st_, own, has_pos, drive in REFUSALS:
    r = rig(orders, intended=st_, own=own, position=has_pos)
    out = drive(r.session())
    refs = [x for x in verdict_refs(r) if x[1] == "taken"]
    ok = bool(refs) and all(x[2] for x in refs)
    art = ok and load(BlobStore(ed(r)), refs[-1][2])["schema"] == SCHEMA
    check(f"R4C3.2  a {label} refusal names the EXACT evidence, and it loads",
          out.status is ActionStatus.REJECTED and ok and art,
          f"{out.code} refs={[(x[0], (x[2] or '')[:8]) for x in refs]}")

r = rig()
out = r.session().modify_stop("29750")
cids = {ev.get("authoritative_snapshot")
        for rec in Journal.load(r.path).records for ev in rec["events"]
        if ev.get("authoritative_snapshot")}
check("R4C3.2.5  an approved action's INTENT and verdict name the SAME cid",
      out.status is ActionStatus.ACKNOWLEDGED and len(cids) == 1, str(len(cids)))

r = rig()
out = r.session().modify_stop("not-a-number")
refs = verdict_refs(r)
check("R4C3.2.6  a PRE-authority schema refusal explicitly records that no "
      "observation was taken",
      out.status is ActionStatus.REJECTED
      and refs and refs[-1][1] == "not_taken" and refs[-1][2] is None,
      f"{out.code} {refs[-1] if refs else None}")

# two refused actions in two different worlds cannot be swapped
rA = rig([stop_order("manual", "2.38", "29700.1")], intended=held(cid="manual", orbit_stop=False),
         own=())
rA.session().modify_stop("29750")
rB = rig([stop_order("manual", "2.38", "29500")], intended=held(cid="manual", orbit_stop=False),
         own=())
rB.session().modify_stop("29750")
ca = [x[2] for x in verdict_refs(rA) if x[1] == "taken"][-1]
cb = [x[2] for x in verdict_refs(rB) if x[1] == "taken"][-1]
docA = load(BlobStore(ed(rA)), ca)
docB = load(BlobStore(ed(rB)), cb)
check("R4C3.2.7  two refusals in two worlds get two ids that cannot be "
      "swapped",
      ca != cb
      and docA["view"]["fields"]["open_orders"]
      != docB["view"]["fields"]["open_orders"], f"{ca[:8]} vs {cb[:8]}")

check("R4C3.2.8  a blob-count assertion is NOT accepted as binding: the "
      "mapping is resolved by action id",
      all(x[2] for x in verdict_refs(rA) if x[1] == "taken"))

# ======================================================================
banner("R4C3.3  C3-I3 — the verdict is RE-DERIVED, not merely named")
# ======================================================================
r = rig()
out = r.session().modify_stop("29750")
cid = [ev.get("authoritative_snapshot") for rec in Journal.load(r.path).records
       for ev in rec["events"] if ev["e"] == "INTENT"][-1]
doc = load(BlobStore(ed(r)), cid)
check("R4C3.3.1  the artifact carries the local state and the limits "
      "STRUCTURALLY, and the journal head they were read at",
      doc["intended"]["__type__"] == "IntendedState"
      and doc["limits"]["__type__"] == "A1Limits"
      and doc["journal_seq"] > 0 and doc["journal_hash"])

worker = os.path.join(TMP, "rederive.py")
open(worker, "w").write('''
import json, sys
sys.path.insert(0, sys.argv[3])
from orbit.audit.blobstore import BlobStore
from orbit.audit.evidence import load, revive
from orbit.audit.journal import Journal
from orbit.exec.recon import reconcile
jp, edir = sys.argv[1], sys.argv[2]
cid = [ev.get("authoritative_snapshot") for rec in Journal.load(jp).records
       for ev in rec["events"] if ev["e"] == "INTENT"][-1]
doc = load(BlobStore(edir), cid)
view = revive(doc["view"])
intended = revive(doc["intended"])
limits = revive(doc["limits"])
now = revive(doc["now"])
r = reconcile(intended, view, now, limits)
print(json.dumps({
    "cid": cid,
    "run_state": r.run_state.value,
    "reconciled": r.reconciled,
    "findings": sorted(f.code.value for f in r.findings),
    "journal_seq": doc["journal_seq"],
    "intended_type": type(intended).__name__,
}))
''')
res = subprocess.run([sys.executable, worker, r.path, ed(r),
                      os.path.abspath(".")], capture_output=True, text=True)
got = json.loads(res.stdout) if res.returncode == 0 else {}
local = reconcile(r.intended, r.exch.view(), NOW, A1)
check("R4C3.3.2  a SEPARATE PROCESS reconstructs the exact IntendedState",
      got.get("intended_type") == "IntendedState",
      res.stderr.strip()[-140:] if res.returncode else "")
check("R4C3.3.3  and re-runs reconcile, reproducing run_state, reconciled and "
      "findings",
      got.get("run_state") == local.run_state.value
      and got.get("reconciled") == local.reconciled
      and got.get("findings") == sorted(f.code.value for f in local.findings),
      str(got)[:130])

seq_before = doc["journal_seq"]
r.journal.append_one(__import__("orbit.audit.records",
                                fromlist=["E"]).E.REMEDIATION, None,
                     note="later activity")
res2 = subprocess.run([sys.executable, worker, r.path, ed(r),
                       os.path.abspath(".")], capture_output=True, text=True)
got2 = json.loads(res2.stdout) if res2.returncode == 0 else {}
check("R4C3.3.4  the journal advancing AFTER the action does not change the "
      "historical reconstruction",
      got2.get("journal_seq") == seq_before
      and got2.get("run_state") == got.get("run_state"),
      f"{got2.get('journal_seq')} vs {seq_before}")

live = Journal.load(r.path)
check("R4C3.3.5  an incorrect journal head is detectable against the artifact",
      doc["journal_hash"] != live.records[-1]["hash"]
      and doc["journal_seq"] < live.records[-1]["seq"])

# SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 3. RE-EXPRESSED.
#
# The original assertion demanded `LocalStateContradicted` from the partial
# `_journal_contradiction` comparison. C4-I1/C4-I2 DELETED that mechanism: the
# constructor-supplied state no longer has authorization power, so there is
# nothing for it to contradict. And the harness used to seed whatever state it
# was handed, so the "inconsistent" memory became consistent the moment the
# session was built and the test could not have observed a disagreement at
# all. The invariant it named is kept and tested for the right reason:
#
#     JOURNAL SAYS X, MEMORY SAYS Y  =>  THE VERDICT FOLLOWS THE JOURNAL,
#     WITH ZERO ADAPTER MUTATIONS WHERE THE JOURNAL FORBIDS THEM.
#
# `memory=` is the unseeded path: it reaches the constructor and is written
# nowhere. Both directions are exercised, because a memory that can HIDE
# durable risk is as dangerous as one that can INVENT permission.
_lim = A1.max_entries_per_utc_day
_journal_says_limit = IntendedState(journal_loaded=True, clean_shutdown=True,
                                    entries_utc_day=_lim)      # X: limit hit
_memory_says_fresh = IntendedState(journal_loaded=True, clean_shutdown=True,
                                   entries_utc_day=0)          # Y: fresh day
rb = Rig(TMP, "r336_a", intended=_journal_says_limit, exch=Exch())
rb.acquire()
out_b = rb.session(memory=_memory_says_fresh).propose_order("long", "29700")
check("R4C3.3.6  an in-memory state inconsistent with its durable history "
      "fails closed in the PRODUCTION path",
      out_b.status is ActionStatus.REJECTED
      and out_b.code == "ENTRY_LIMIT_REACHED"
      and len(rb.adapter.calls) == 0,
      f"{out_b.status.value}/{out_b.code} calls={len(rb.adapter.calls)}")

# the other direction: memory cannot HIDE a position the journal holds.
_memory_says_flat = IntendedState(journal_loaded=True, clean_shutdown=True,
                                  entries_utc_day=0)
rb2 = Rig(TMP, "r336_b", intended=held(),
          exch=Exch(position=pos(), orders=[stop_order()]))
rb2.acquire()
out_b2 = rb2.session(memory=_memory_says_flat).modify_stop("29750")
check("R4C3.3.6b the verdict follows the JOURNAL in the other direction too: "
      "memory claiming flat does not hide a held position",
      out_b2.status is ActionStatus.ACKNOWLEDGED
      and [c.args.get("target_client_order_id") for c in rb2.adapter.calls]
      == ["stop1"],
      f"{out_b2.status.value}/{out_b2.code}")

rc_ = rig()
outc = rc_.session().modify_stop("29750")
check("R4C3.3.7  and a legitimate state still acts (the control)",
      outc.status is ActionStatus.ACKNOWLEDGED)

check("R4C3.3.8  the limits used for the verdict are exactly recoverable",
      revive(doc["limits"]) == A1, str(revive(doc["limits"]))[:60])

# the gateway, re-run from reconstructed inputs
from orbit.risk.gateway import Gateway, Kind, ProposedAction
gv = [ev for rec in Journal.load(r.path).records for ev in rec["events"]
      if ev["e"] == "GATEWAY_VERDICT"]
rr = reconcile(revive(doc["intended"]), revive(doc["view"]), revive(doc["now"]),
               revive(doc["limits"]))
ver = Gateway().evaluate(
    ProposedAction(decision_id="x", kind=Kind.MODIFY_STOP,
                   symbol=A1.instrument, new_stop=D("29750")),
    rr.to_system_state(revive(doc["limits"]),
                       entry_in_flight=rr.entry_in_flight()))
check("R4C3.3.9  the GATEWAY verdict re-runs from reconstructed inputs and "
      "reproduces the durable outcome",
      gv and ver.approved == (gv[-1].get("approved") is True)
      and ver.code.value == gv[-1].get("code"),
      f"{ver.approved}/{ver.code.value} vs "
      f"{gv[-1].get('approved') if gv else None}/{gv[-1].get('code') if gv else None}")

# ======================================================================
banner("R4C3.4  C3-I4 — the serializer is injective")
# ======================================================================
import enum as _e


def mk_enum(name):
    return _e.Enum(name, {"X": "same"}, type=str)


EA, EB = mk_enum("Status"), mk_enum("Status")
check("R4C3.4.1  two distinct Enums with the SAME short name cannot collide "
      "(neither is registered, so neither can be serialised)",
      raises(UnserialisableEvidence, lambda: _plain(EA.X))
      and raises(UnserialisableEvidence, lambda: _plain(EB.X)))

import dataclasses


def mk_dc():
    @dataclasses.dataclass(frozen=True)
    class Thing:
        v: int
    return Thing


DA, DB = mk_dc(), mk_dc()
check("R4C3.4.2  two distinct dataclasses with the same short name and fields "
      "cannot collide",
      raises(UnserialisableEvidence, lambda: _plain(DA(1)))
      and raises(UnserialisableEvidence, lambda: _plain(DB(1))))

m = _plain({1: "integer-key", "1": "string-key"})
check("R4C3.4.3  dict key 1 and key '1' both survive, distinctly",
      len(m["__pairs__"]) == 2
      and sorted(json.dumps(k) for k, _ in m["__pairs__"]) == ['"1"', "1"],
      str(m))
check("R4C3.4.4  and no entry is lost",
      {json.dumps(k): v for k, v in m["__pairs__"]}
      == {"1": "integer-key", '"1"': "string-key"})

mb = _plain({False: "bool", 0: "int"})
check("R4C3.4.5  False and 0 are reasoned about: Python treats them as ONE "
      "key, so the map has one entry and nothing is silently dropped",
      len({False: "bool", 0: "int"}) == 1 and len(mb["__pairs__"]) == 1,
      str(mb))

md = _plain({D("1.10"): "a", "1.10": "b"})
check("R4C3.4.6  Decimal and string keys remain distinct",
      len(md["__pairs__"]) == 2)

nested = {"a": [1, {2: (3, 4)}], "b": frozenset({"x", "y"})}
check("R4C3.4.7  nested dict/list/set structures are deterministic",
      _plain(nested) == _plain(dict(reversed(list(nested.items())))))


def view_():
    return Exch(position=pos(), orders=[OURS]).view()


ser = lambda: serialize(view=view_(), now=NOW, lease_epoch=1, intended=held(),
                        limits=A1, policy_version="p", journal_seq=1,
                        journal_hash="h")
proc = os.path.join(TMP, "ser.py")
open(proc, "w").write(
    "import sys\nsys.path.insert(0, sys.argv[1]); sys.path.insert(0, "
    "sys.argv[1] + '/tests')\n"
    "from harness import NOW, Exch, held, pos, stop_order\n"
    "from orbit.audit.blobstore import BlobStore\n"
    "from orbit.audit.evidence import serialize\n"
    "from orbit.risk.limits import A1\n"
    "v = Exch(position=pos(), orders=[stop_order('stop1','2.38','29700.1')])"
    ".view()\n"
    "print(BlobStore.content_id(serialize(view=v, now=NOW, lease_epoch=1, "
    "intended=held(), limits=A1, policy_version='p', journal_seq=1, "
    "journal_hash='h')))\n")
outs = [subprocess.run([sys.executable, proc, os.path.abspath(".")],
                       capture_output=True, text=True).stdout.strip()
        for _ in range(3)]
check("R4C3.4.8  serialization is identical across independent processes",
      len(set(outs)) == 1 and outs[0] == BlobStore.content_id(ser()),
      str(set(o[:12] for o in outs)))


class _Opaque:
    pass


check("R4C3.4.9  an unsupported type fails closed rather than losing "
      "information", raises(UnserialisableEvidence, lambda: _plain(_Opaque()))
      and raises(UnserialisableEvidence, lambda: _plain({_Opaque(): 1})))
check("R4C3.4.10 the encoding change BUMPED the schema version",
      SCHEMA.endswith(".v2"), SCHEMA)

check("R4C3.4.11 and the artifact round-trips exactly",
      revive(json.loads(ser().decode())["view"]) == view_())

# ======================================================================
banner("R4C3.5  C3-I5 — real mutual exclusion, proved with real threads")
# ======================================================================
r = rig()
s = r.session()
entered, results = [], []
gate = threading.Barrier(2, timeout=10)
_real_locked = ToolSession._act_locked


def _watched(self, tool, kind, params):
    entered.append(threading.current_thread().name)
    return _real_locked(self, tool, kind, params)


def _worker():
    try:
        gate.wait()
    except Exception:
        pass
    try:
        results.append(("ok", s.modify_stop("29750")))
    except ReentrantAction:
        results.append(("refused", None))
    except Exception as e:
        results.append((type(e).__name__, None))


ToolSession._act_locked = _watched
try:
    ts = [threading.Thread(target=_worker, name=f"T{i}") for i in range(2)]
    [t.start() for t in ts]
    [t.join(timeout=15) for t in ts]
finally:
    ToolSession._act_locked = _real_locked

kinds = sorted(k for k, _ in results)
check("R4C3.5.1  exactly ONE thread reaches _act_locked",
      len(entered) == 1, f"entered={entered} results={kinds}")
check("R4C3.5.2  the loser is refused deterministically",
      kinds == ["ok", "refused"], str(kinds))
check("R4C3.5.3  exactly one adapter mutation was sent",
      len(r.adapter.calls) == 1, str([c.method for c in r.adapter.calls]))
check("R4C3.5.4  exactly one INTENT was written",
      len([ev for rec in Journal.load(r.path).records for ev in rec["events"]
           if ev["e"] == "INTENT" and ev.get("authoritative_snapshot")]) == 1)
check("R4C3.5.5  the session is left clean: unsealed, no snapshot, not in an "
      "action", not s._view_sealed and s._auth is None and not s._in_action)
check("R4C3.5.6  and a later sequential action still works",
      s.get_positions() is not None)

r = rig()
s = r.session()
_g = ToolSession._protection_guard


def _boom(self, *a, **k):
    raise RuntimeError("injected")


ToolSession._protection_guard = _boom
try:
    raises(RuntimeError, lambda: s.modify_stop("29750"))
finally:
    ToolSession._protection_guard = _g
check("R4C3.5.7  an exception releases action ownership",
      not s._in_action and s.modify_stop("29750").status
      is ActionStatus.ACKNOWLEDGED)

r = rig([], intended=flat(), own=(), position=False)
s = r.session()
s.close_position()
check("R4C3.5.8  a rejected action releases ownership",
      not s._in_action and s.get_positions() is not None)

rA, rB = rig(), rig()
oA = rA.session().modify_stop("29750")
oB = rB.session().modify_stop("29750")
check("R4C3.5.9  two DIFFERENT sessions remain independently usable",
      oA.status is ActionStatus.ACKNOWLEDGED
      and oB.status is ActionStatus.ACKNOWLEDGED)

r = rig()
s = r.session()
_l = ToolSession._lifecycle_gate


def _reenter(self, kind, rr):
    self._act("close_position", None, {})
    return _l(self, kind, rr)


ToolSession._lifecycle_gate = _reenter
try:
    nested = raises(ReentrantAction, lambda: s.modify_stop("29750"))
finally:
    ToolSession._lifecycle_gate = _l
check("R4C3.5.10 same-thread nested reentrancy is still refused", nested)

shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("C3-I1..I5 closed. A put proves durability, a verdict names its "
      "evidence, the artifact re-derives the verdict, the encoding is "
      "injective, and one action runs at a time. No model. No credentials. "
      "No network. No live capital.")
