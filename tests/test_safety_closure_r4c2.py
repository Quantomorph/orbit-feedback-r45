"""
tests/test_safety_closure_r4c2.py — ORBIT A1 SAFETY CLOSURE, ROUND 4C2.

Independent review reopened Round 4C and found four defects in the snapshot and
coherence surface Round 4C built:

    C2-I1  the authoritative digest went to disk; the evidence it named did not
    C2-I2  the digest covered nine hand-picked fields, and ExchangeView has more
    C2-I3  one ToolResult mixed data from one observation with freshness from
           another
    C2-I4  an action's seal outlived the action and poisoned later reads

    A HASH PROVES EQUALITY ONLY IF THE ORIGINAL STILL EXISTS.
    IT DOES NOT RECONSTRUCT THE ORIGINAL.

Every test here was written to FAIL against the 713/713 Round-4C archive.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import timedelta
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, owning, pos, stop_order
from orbit.audit.blobstore import BlobStore
from orbit.audit.evidence import (SCHEMA, EvidenceUnavailable, load,
                                  serialize)
from orbit.audit.journal import Journal
from orbit.exec.protection import MarginMode
from orbit.exec.recon import ExchangeView, reconcile
from orbit.risk.limits import A1
from orbit.tools.session import (ActionStatus, HiddenFetch, ReentrantAction,
                                 ToolSession)

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
    # Each rig gets its own directory. Evidence is CONTENT-ADDRESSED, so two
    # rigs observing an identical world legitimately share one artifact — which
    # is a good property and a terrible basis for a corruption test.
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


def evidence_dir(r):
    return os.path.join(os.path.dirname(os.path.abspath(r.path)), "evidence")


def intent_ref(r):
    return [ev.get("authoritative_snapshot")
            for rec in Journal.load(r.path).records
            for ev in rec["events"] if ev["e"] == "INTENT"][-1]


# ======================================================================
banner("R4C2.1  C2-I1 — the evidence is recoverable, not merely named")
# ======================================================================
r = rig()
out = r.session().modify_stop("29750")
cid = intent_ref(r)
store = BlobStore(evidence_dir(r))
check("R4C2.1.1  an authorised mutation leaves a durable evidence artifact",
      out.status is ActionStatus.ACKNOWLEDGED and cid and store.has(cid),
      f"{(cid or '')[:16]}…")

doc = load(store, cid)
check("R4C2.1.2  the artifact carries the exact observation and the rules "
      "applied",
      doc["schema"] == SCHEMA and doc["view"]["__type__"] == "ExchangeView"
      # SAFETY CLOSURE ROUND 4C3, C3-I3: `intended_digest` and
      # `limits_version` were hashes of in-memory objects with no original to
      # compare against. The artifact now carries the local state and the
      # limits STRUCTURALLY, plus the journal head they were read at. The
      # property asserted — the artifact carries the observation and the rules
      # applied — is unchanged and now mechanically checkable.
      and doc["lease_epoch"] == r.lease.epoch
      and doc["intended"]["__type__"] == "IntendedState"
      and doc["limits"]["__type__"] == "A1Limits"
      and doc["journal_seq"] > 0 and doc["journal_hash"]
      and doc["policy_version"] and doc["now"],
      f"schema={doc['schema']}")

raw = store.get(cid)
check("R4C2.1.3  the stored bytes reproduce the content id",
      BlobStore.content_id(raw) == cid)

# a COMPLETELY SEPARATE PROCESS, given only the durable artifacts on disk
worker = os.path.join(TMP, "reconstruct.py")
open(worker, "w").write(
    "import json,os,sys\n"
    "sys.path.insert(0, sys.argv[3])\n"
    "from orbit.audit.blobstore import BlobStore\n"
    "from orbit.audit.evidence import load\n"
    "from orbit.audit.journal import Journal\n"
    "jp, ed = sys.argv[1], sys.argv[2]\n"
    "cid=[ev.get('authoritative_snapshot') for rec in Journal.load(jp).records\n"
    "     for ev in rec['events'] if ev['e']=='INTENT'][-1]\n"
    "doc=load(BlobStore(ed), cid)\n"
    "print(json.dumps({'cid':cid,'id_ok':BlobStore.content_id("
    "BlobStore(ed).get(cid))==cid,'mark':doc['view']['fields']['mark_price'],\n"
    "  'epoch':doc['lease_epoch'],'schema':doc['schema']}))\n")
res = subprocess.run([sys.executable, worker, r.path, evidence_dir(r),
                      os.path.abspath(".")], capture_output=True, text=True)
got = json.loads(res.stdout) if res.returncode == 0 else {}
check("R4C2.1.4  a SEPARATE PROCESS reconstructs the evidence from disk alone",
      got.get("cid") == cid and got.get("id_ok")
      and got.get("epoch") == r.lease.epoch,
      res.stderr.strip()[-120:] if res.returncode else str(got)[:90])

missing = "0" * 64
try:
    load(store, missing)
    ok = False
except EvidenceUnavailable:
    ok = True
check("R4C2.1.5  a MISSING artifact fails closed", ok)

r2 = rig()
r2.session().modify_stop("29750")
c2 = intent_ref(r2)
p2 = BlobStore(evidence_dir(r2)).path_for(c2)
with open(p2, "r+b") as fh:
    fh.seek(20)
    fh.write(b"X")
try:
    load(BlobStore(evidence_dir(r2)), c2)
    ok = False
except EvidenceUnavailable:
    ok = True
check("R4C2.1.6  a CORRUPTED artifact is detected, not returned", ok)

r3 = rig()
r3.session().modify_stop("29750")
c3 = intent_ref(r3)
st3 = BlobStore(evidence_dir(r3))
other = serialize(view=Exch(position=None, orders=[]).view(), now=NOW,
                  lease_epoch=99, intended=held(), limits=A1,
                  policy_version="p", journal_seq=1, journal_hash="h")
oid = st3.put(other)
check("R4C2.1.7  the INTENT cannot be silently rebound: other evidence gets "
      "another id", oid != c3 and st3.has(c3) and load(st3, c3)["lease_epoch"]
      == r3.lease.epoch, f"{oid[:12]} vs {c3[:12]}")

# crash windows around the durability ordering
r4 = rig()
s4 = r4.session()
a4 = s4._authoritative()
check("R4C2.1.8  evidence is durable BEFORE the INTENT: a crash here leaves "
      "harmless unreferenced evidence",
      BlobStore(evidence_dir(r4)).has(a4.snapshot_id)
      and not [ev for rec in Journal.load(r4.path).records
               for ev in rec["events"]
               if ev.get("authoritative_snapshot") == a4.snapshot_id],
      f"{a4.snapshot_id[:12]}…")

r5 = rig()
r5.session().modify_stop("29750")
c5 = intent_ref(r5)
check("R4C2.1.9  and after the INTENT the evidence is still reconstructable",
      load(BlobStore(evidence_dir(r5)), c5)["schema"] == SCHEMA)

# rejected actions are audit facts too
r6 = rig(orders=[stop_order("manual", "2.38", "29700.1")],
         intended=held(cid="manual", orbit_stop=False), own=())
out6 = r6.session().modify_stop("29750")
refs = [ev.get("authoritative_snapshot")
        for rec in Journal.load(r6.path).records
        for ev in rec["events"] if ev.get("authoritative_snapshot")]
check("R4C2.1.10 a REFUSED action still leaves its authorisation evidence "
      "durable",
      out6.status is ActionStatus.REJECTED
      and os.path.isdir(evidence_dir(r6))
      and len(os.listdir(evidence_dir(r6))) >= 1,
      f"{out6.code} blobs={len(os.listdir(evidence_dir(r6)))}")

# ======================================================================
banner("R4C2.2  C2-I2 — every safety-relevant field enters the identity")
# ======================================================================


def view(**kw):
    d = dict(fetched_at=NOW - timedelta(seconds=5), reachable=True,
             consistent=True, server_time=NOW, equity=D("1000"),
             mark_price=D("30000"), margin_mode=MarginMode.UNKNOWN,
             position=pos(), open_orders=(OURS,), fills=(),
             consecutive_failures=0, can_place_orders=True,
             isolated_margin_posted=None)
    d.update(kw)
    return ExchangeView(**d)


def ident(v):
    return BlobStore.content_id(serialize(
        view=v, now=NOW, lease_epoch=1, intended=held(), limits=A1,
        policy_version="p", journal_seq=1, journal_hash="h"))


BASE = ident(view())
from orbit.exec.recon import ExchangeOrder, ExchangePosition, Fill

VARIANTS = {
    "server_time": view(server_time=NOW + timedelta(seconds=120)),
    "fills": view(fills=(Fill("F1", "e1", D("1")),)),
    "can_place_orders": view(can_place_orders=False),
    "consecutive_failures": view(consecutive_failures=3),
    "margin_mode": view(margin_mode=MarginMode.ISOLATED),
    "isolated_margin_posted": view(isolated_margin_posted=D("500")),
    "position": view(position=ExchangePosition("long", D("1.19"), D("30000"))),
    "open_orders": view(open_orders=(stop_order("stop1", "1.19", "29700.1"),)),
    "mark_price": view(mark_price=D("30001")),
    "equity": view(equity=D("999")),
    "reachable": view(reachable=False),
    "consistent": view(consistent=False),
    "fetched_at": view(fetched_at=NOW - timedelta(seconds=6)),
}
for name, v in VARIANTS.items():
    check(f"R4C2.2  changing {name} changes the evidence identity",
          ident(v) != BASE, f"{ident(v)[:12]} vs {BASE[:12]}")

check("R4C2.2.14 identical views produce the identical identity",
      ident(view()) == BASE)
check("R4C2.2.15 Decimal scale is preserved, not normalised away",
      ident(view(equity=D("1000.0"))) != BASE)
check("R4C2.2.16 None is recorded, not omitted",
      ident(view(server_time=None)) != BASE)
check("R4C2.2.17 order permutation is recorded as observed",
      ident(view(open_orders=(OURS, stop_order("b", "1", "29800"))))
      != ident(view(open_orders=(stop_order("b", "1", "29800"), OURS))))
check("R4C2.2.18 enums serialise by type AND value",
      "__enum__" in json.dumps(json.loads(serialize(
          view=view(), now=NOW, lease_epoch=1, intended=held(), limits=A1,
          policy_version="p", journal_seq=1, journal_hash="h").decode())))
check("R4C2.2.19 datetimes carry their offset",
      "__dt__" in serialize(view=view(), now=NOW, lease_epoch=1, intended=held(),
                            limits=A1, policy_version="p", journal_seq=1,
                            journal_hash="h").decode())
check("R4C2.2.20 the serialization is versioned",
      json.loads(serialize(view=view(), now=NOW, lease_epoch=1, intended=held(),
                           limits=A1, policy_version="p", journal_seq=1,
                           journal_hash="h").decode())["schema"] == SCHEMA)

# the maintenance property: the artifact is STRUCTURAL, not a curated list
import dataclasses
doc = json.loads(serialize(view=view(), now=NOW, lease_epoch=1, intended=held(),
                           limits=A1, policy_version="p", journal_seq=1,
                           journal_hash="h").decode())
present = set(doc["view"]["fields"])
declared = {f.name for f in dataclasses.fields(ExchangeView)}
check("R4C2.2.21 EVERY declared ExchangeView field is in the artifact, by "
      "reflection rather than by a hand-maintained list",
      present == declared, f"missing={sorted(declared - present)}")

# ======================================================================
banner("R4C2.3  C2-I3 — one ToolResult, one observation")
# ======================================================================


class Alternating:
    def __init__(self, seq):
        self.seq, self.n = seq, 0

    def view(self):
        v = self.seq[self.n % len(self.seq)]
        self.n += 1
        return v() if callable(v) else v.view()


STALE_LONG = lambda: ExchangeView(
    NOW - timedelta(seconds=600), True, True, NOW, D("1000"), D("30000"),
    MarginMode.UNKNOWN, pos(), (OURS,), (), 0, True, None)
FRESH_FLAT = lambda: ExchangeView(
    NOW - timedelta(seconds=1), True, True, NOW, D("1000"), D("30000"),
    MarginMode.UNKNOWN, None, (), (), 0, True, None)
UNREACHABLE = lambda: ExchangeView(
    NOW - timedelta(seconds=2), False, True, None, D("0"), D("0"),
    MarginMode.UNKNOWN, None, (), (), 5, False, None)

READS = ["get_market_state", "get_account_state", "get_positions",
         "get_open_orders", "get_recent_fills", "get_system_state",
         "get_current_risk_state"]
for tool in READS:
    for label, seq in (("stale/fresh", [STALE_LONG, FRESH_FLAT]),
                       ("position/flat", [STALE_LONG, FRESH_FLAT]),
                       ("reachable/unreachable", [STALE_LONG, UNREACHABLE])):
        r = rig()
        alt = Alternating(seq)
        r.exch = alt
        res = getattr(r.session(), tool)()
        first = seq[0]()
        expect = (NOW - first.fetched_at).total_seconds()
        ok = (alt.n == 1 and res.freshness_seconds == expect)
        if not ok:
            check(f"R4C2.3  {tool} / {label}: ONE observation, data and "
                  f"freshness from it", False,
                  f"fetches={alt.n} freshness={res.freshness_seconds} "
                  f"expected={expect}")
            break
    else:
        check(f"R4C2.3  {tool}: exactly one observation; data, freshness and "
              f"hash all describe it", True)

r = rig()
alt = Alternating([STALE_LONG, FRESH_FLAT])
r.exch = alt
res = r.session().get_positions()
check("R4C2.3.8  the reproduction: stale data is no longer labelled with "
      "another world's freshness",
      res.data["contracts"] == "2.38" and res.freshness_seconds == 600.0
      and alt.n == 1,
      f"{res.data} fresh={res.freshness_seconds} fetches={alt.n}")

r = rig()
alt = Alternating([STALE_LONG, FRESH_FLAT])
r.exch = alt
s = r.session()
t = s.get_candles("5m", 10)
check("R4C2.3.9  a placeholder tool observes nothing and fetches nothing",
      alt.n == 0 and t.freshness_seconds is None,
      f"fetches={alt.n} fresh={t.freshness_seconds}")

r = rig()
s = r.session()
t = s.get_positions()
ctx = s._freeze_decision_snapshot("d1", prompt_text="p").context
check("R4C2.3.10 the decision snapshot preserves the exact results the model "
      "saw", t.token in ctx.refs())

# ======================================================================
banner("R4C2.4  C2-I4 — the seal is action-local, on every exit")
# ======================================================================
EXITS = [
    ("lifecycle rejection (flat CLOSE)", [], flat(), (), False,
     lambda s: s.close_position(), "NO_POSITION"),
    ("protection rejection", [OURS], held(), ("stop1",), True,
     lambda s: s.reduce_position("0.5"),
     "PROTECTION_WOULD_OVER_COVER_REMAINDER"),
    ("gateway rejection (widen)", [OURS], held(), ("stop1",), True,
     lambda s: s.modify_stop("29000"), "STOP_WIDENED"),
    ("ownership rejection", [stop_order("manual", "2.38", "29700.1")],
     held(cid="manual", orbit_stop=False), (), True, lambda s: s.modify_stop("29750"),
     "NOT_OUR_ORDER"),
    ("successful ACK", [OURS], held(), ("stop1",), True,
     lambda s: s.modify_stop("29750"), "ACK"),
]
for label, orders, st, own, has_pos, drive, code in EXITS:
    r = rig(orders, intended=st, own=own, position=has_pos)
    s = r.session()
    out = drive(s)
    try:
        s.get_positions()
        later = True
    except HiddenFetch:
        later = False
    check(f"R4C2.4  after {label}: the seal is gone and later reads work",
          out.code == code and later and not s._view_sealed
          and s._auth is None, f"{out.code} sealed={s._view_sealed}")

r = rig()
s = r.session()
out = s.modify_stop("29750")
check("R4C2.4.6  a successful mutation still gets its post-mutation "
      "reconciliation", out.status is ActionStatus.ACKNOWLEDGED
      and s._recon is not None)

# the seal must still bite DURING the pre-mutation window
r = rig()
s = r.session()
_g = ToolSession._protection_guard


def _sneaky(self, tool, p, auth, ledger):
    self._view()               # a hidden fetch, injected mid-authorisation
    return _g(self, tool, p, auth, ledger)


ToolSession._protection_guard = _sneaky
try:
    raised = False
    try:
        s.modify_stop("29750")
    except HiddenFetch:
        raised = True
finally:
    ToolSession._protection_guard = _g
check("R4C2.4.7  an injected hidden fetch DURING authorisation still raises",
      raised)

r = rig()
s = r.session()
s.modify_stop("29750")
try:
    s.get_positions()
    ok = True
except HiddenFetch:
    ok = False
check("R4C2.4.8  and the session recovers cleanly afterwards", ok)

r = rig()
s = r.session()
_l = ToolSession._lifecycle_gate


def _reenter(self, kind, rr):
    self._act("close_position", None, {})
    return _l(self, kind, rr)


ToolSession._lifecycle_gate = _reenter
try:
    reent = False
    try:
        s.modify_stop("29750")
    except ReentrantAction:
        reent = True
finally:
    ToolSession._lifecycle_gate = _l
check("R4C2.4.9  the single-writer, non-reentrant runtime contract is "
      "ENFORCED, not assumed", reent)

r = rig()
s = r.session()
a = s._authoritative()
try:
    s._authoritative()
    twice = False
except HiddenFetch:
    twice = True
check("R4C2.4.10 no repair permits a second pre-mutation observation", twice)

# ======================================================================
banner("R4C2.5  defects found by reviewing THIS repair")
# ======================================================================
# `MarginMode` is a str-enum. The primitive branch of `_plain` matched it before
# the enum branch and returned a bare string, losing the type — so two different
# enums sharing a value would have serialised identically, the exact collapse
# the artifact exists to prevent. Order of those checks is a correctness
# property, not style.
import enum as _enum


class _A(str, _enum.Enum):
    X = "same"


class _B(str, _enum.Enum):
    X = "same"


from orbit.audit.evidence import UnserialisableEvidence as _UE, _plain


def _closed(fn):
    try:
        fn()
        return False
    except _UE:
        return True


# SAFETY CLOSURE ROUND 4C3, C3-I4A. This asserted that `_plain` gave two
# str-enums DIFFERENT representations, which it did — by short class name, so
# two enums sharing a short name still collided. Type identity now comes from an
# explicit registry, so an unregistered type cannot be serialised at all. The
# property is strictly stronger: these cannot collide because neither can enter
# an artifact.
check("R4C2.5.1  an unregistered enum fails closed rather than being named by "
      "a short class name", _closed(lambda: _plain(_A.X))
      and _closed(lambda: _plain(_B.X)))
check("R4C2.5.2  and a plain string is still a plain string",
      _plain("same") == "same")

# The unknown-type fallback was `repr(v)`, which embeds a memory address: two
# runs observing the identical world would have produced different content ids,
# and the identity would have stopped being a function of what was observed.
from orbit.audit.evidence import UnserialisableEvidence


class _Opaque:
    pass


try:
    _plain(_Opaque())
    _closed = False
except UnserialisableEvidence:
    _closed = True
check("R4C2.5.3  an unserialisable type fails closed rather than producing a "
      "non-reproducible identity", _closed)
check("R4C2.5.4  every type actually present in the authoritative state IS "
      "serialisable (the control)",
      isinstance(serialize(view=view(), now=NOW, lease_epoch=1, intended=held(),
                           limits=A1, policy_version="p", journal_seq=1,
                           journal_hash="h"), bytes))

shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("C2-I1..I4 closed. The evidence exists, its identity is the bytes, one "
      "result describes one observation, and a seal dies with its action. "
      "No model. No credentials. No network. No live capital.")
