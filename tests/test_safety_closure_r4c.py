"""
tests/test_safety_closure_r4c.py — ORBIT A1 SAFETY CLOSURE, ROUND 4C.

    R4-4  one model action consumed FOUR independent observations of the
          exchange and described all of them as one authorization.

          _reconcile        step 3, before writer authority
          _reconcile        step 5, called "authoritative"
          _protection_guard step 6, its own fetch
          _reconcile        step 11, after the mutation

Three of those are PRE-MUTATION safety decisions, each able to land on a
different world. The same account and the same request produced REJECTED under
one call ordering and ACKNOWLEDGED — with the cancel actually sent — under
another.

    THE VALUE AUTHORISED MUST BE THE VALUE ACTED UPON.

WHAT IS AND IS NOT CLAIMED. One frozen snapshot does not make execution atomic
and does not stop the exchange changing between observation and execution.
Nothing local can. The property established is narrower:

    every pre-mutation safety decision for one action is made from the same
    observation, taken under valid writer authority, and that observation has
    an identity the audit can point at.

The residual race between the authoritative observation and the venue applying
the mutation is REAL and remains explicit for the real-adapter design.

Every test here was written to FAIL against the 682/682 Round-4B2 archive.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from decimal import Decimal as D

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from harness import NOW, Exch, Rig, flat, held, owning, pos, stop_order
from orbit.audit.journal import Journal
from orbit.exec.recon import ExchangeOrder
from orbit.tools.session import (ActionStatus, AuthoritativeState, HiddenFetch,
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
REP = stop_order("rep", "2.38", "29700.1")
HALF = stop_order("stop1", "1.19", "29700.1")


class Counting:
    """Records every call to exchange_view_fn and which method asked."""

    def __init__(self, ex):
        self.ex, self.log = ex, []

    def view(self):
        import traceback
        names = [f.name for f in traceback.extract_stack()[:-1]
                 if "session.py" in f.filename]
        self.log.append(names[-2] if len(names) >= 2 else "?")
        return self.ex.view()


class Alternating:
    """A venue that answers differently on each call."""

    def __init__(self, seq):
        self.seq, self.n = seq, 0

    def view(self):
        v = self.seq[self.n % len(self.seq)]
        self.n += 1
        return v.view()


def rig(orders, intended=None, own=(), position=True):
    N[0] += 1
    r = Rig(TMP, f"d{N[0]}", intended=intended or held(),
            exch=Exch(position=pos() if position else None,
                      orders=list(orders)))
    r.acquire()
    if own:
        owning(r, *own)
    return r


calls = lambda r: [c.method for c in r.adapter.calls]

PROTECTED = Exch(position=pos(), orders=[OURS, REP])
THIN = Exch(position=pos(), orders=[OURS])

# ======================================================================
banner("R4C.1  exactly ONE pre-mutation observation, for every action shape")
# ======================================================================
SHAPES = [
    ("OPEN", [], flat(), (), False,
     lambda s: s.propose_order(side="long", stop="29700.1")),
    ("CLOSE", [OURS], held(), ("stop1",), True,
     lambda s: s.close_position()),
    ("REDUCE", [HALF], held(), ("stop1",), True,
     lambda s: s.reduce_position("0.5")),
    ("CANCEL", [OURS, REP], held(), ("stop1", "rep"), True,
     lambda s: s.cancel_order("stop1", replacement_client_order_id="rep")),
    ("MODIFY_STOP", [OURS], held(), ("stop1",), True,
     lambda s: s.modify_stop("29800")),
]
for label, orders, st, own, has_pos, drive in SHAPES:
    r = rig(orders, intended=st, own=own, position=has_pos)
    c = Counting(r.exch)
    r.exch = c
    out = drive(r.session())
    pre = c.log[:c.log.index("_reconcile")] if "_reconcile" in c.log else c.log
    check(f"R4C.1  {label}: exactly one PRE-mutation observation",
          pre == ["_authoritative"] and out.status is ActionStatus.ACKNOWLEDGED,
          f"fetches={c.log} -> {out.status.value}/{out.code}")

# ======================================================================
banner("R4C.2  the verdict follows the AUTHORITATIVE view, not the ordering")
# ======================================================================
for label, seq, world in (("thin / protected / thin / protected",
                           [THIN, PROTECTED], THIN),
                          ("protected / thin / protected / thin",
                           [PROTECTED, THIN], PROTECTED)):
    r = rig([OURS, REP], own=("stop1", "rep"))
    r.exch = Alternating(seq)
    out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
    # the verdict the FIRST (authoritative) world alone would produce
    ctl = rig(list(world.orders), own=("stop1", "rep"))
    exp = ctl.session().cancel_order("stop1",
                                     replacement_client_order_id="rep")
    check(f"R4C.2  {label}: verdict equals the authoritative world's verdict",
          out.status is exp.status and out.code == exp.code
          and calls(r) == calls(ctl),
          f"alternating={out.status.value}/{out.code} "
          f"authoritative-only={exp.status.value}/{exp.code}")

# ======================================================================
banner("R4C.3  the frozen evidence survives the source changing underneath it")
# ======================================================================


class MutatingSource:
    """Serves the protected world once, then empties itself."""

    def __init__(self, ex):
        self.ex, self.n = ex, 0

    def view(self):
        self.n += 1
        v = self.ex.view()
        self.ex.orders = []            # the source changes AFTER the fetch
        return v


r = rig([OURS, REP], own=("stop1", "rep"))
src = MutatingSource(r.exch)
r.exch = src
out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
check("R4C.3.1  authorisation uses the frozen evidence, not the changed source",
      out.status is ActionStatus.ACKNOWLEDGED and calls(r) == ["cancel_order"],
      f"{out.status.value}/{out.code} fetches={src.n}")

r = rig([OURS, REP], own=("stop1", "rep"))
_snap = {}
_real = ToolSession._authoritative


def _spy(self):
    a = _real(self)
    _snap["a"] = a
    _snap["orders_before"] = tuple(a.view.open_orders)
    return a


ToolSession._authoritative = _spy
try:
    r.exch.orders.append(stop_order("late", "2.38", "29000"))
    out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
finally:
    ToolSession._authoritative = _real
check("R4C.3.2  the snapshot's open_orders are an immutable tuple, not an alias",
      isinstance(_snap["a"].view.open_orders, tuple)
      and _snap["orders_before"] == tuple(_snap["a"].view.open_orders),
      f"{type(_snap['a'].view.open_orders).__name__}")
try:
    _snap["a"].view.open_orders[0].contracts = D("99")
    frozen_row = False
except Exception:
    frozen_row = True
try:
    object.__setattr__  # noqa
    _snap["a"].snapshot_id = "tampered"
    frozen_snap = False
except Exception:
    frozen_snap = True
check("R4C.3.3  snapshot and the rows inside it are frozen",
      frozen_row and frozen_snap)

# ======================================================================
banner("R4C.4  no pre-mutation component can fetch after the freeze")
# ======================================================================
r = rig([OURS], own=("stop1",))
s = r.session()
raised = {}
try:
    a = s._authoritative()
    s._view()
except HiddenFetch as e:
    raised["seal"] = str(e)[:40]
check("R4C.4.1  the view is SEALED after the authoritative observation",
      "seal" in raised, str(raised))

r = rig([OURS], own=("stop1",))
s = r.session()
s._authoritative()
try:
    s._authoritative()
    twice = False
except HiddenFetch:
    twice = True
check("R4C.4.2  a second authoritative observation in one action raises",
      twice)

# found by the round-4C review of this repair: the guard was scoped to the
# SESSION, and one session legitimately serves several actions.
r = rig([], intended=flat(), position=False)
s = r.session()
o1 = s.propose_order(side="long", stop="29700.1")
o2 = s.close_position()
check("R4C.4.3  the scope is the ACTION: one session still serves several",
      o1.status is ActionStatus.ACKNOWLEDGED
      and o2.status is ActionStatus.REJECTED and o2.code == "NO_POSITION",
      f"{o1.status.value} then {o2.status.value}/{o2.code}")

import inspect
_g = inspect.getsource(ToolSession._protection_guard)
check("R4C.4.4  _protection_guard does not call _view()",
      "self._view()" not in _g and "auth.view" in _g)

# ======================================================================
banner("R4C.5  every component consumed the SAME rows")
# ======================================================================
seen = {}
_rg = ToolSession._protection_guard
_lg = ToolSession._lifecycle_gate


def _spy_guard(self, tool, p, auth, ledger):
    seen["guard"] = id(auth.view)
    seen["guard_id"] = auth.snapshot_id
    return _rg(self, tool, p, auth, ledger)


def _spy_life(self, kind, r):
    seen.setdefault("life", []).append(id(r.view))
    return _lg(self, kind, r)


ToolSession._protection_guard = _spy_guard
ToolSession._lifecycle_gate = _spy_life
try:
    for label, orders, st, own, has_pos, drive in SHAPES:
        seen.clear()
        r = rig(orders, intended=st, own=own, position=has_pos)
        gspy = {}
        out = drive(r.session())
        same = (len(set(seen.get("life", []))) == 1
                and (("guard" not in seen)
                     or seen["guard"] == seen["life"][0]))
        check(f"R4C.5  {label}: lifecycle, protection and gateway saw ONE view",
              same and out.status is ActionStatus.ACKNOWLEDGED,
              f"life={len(set(seen.get('life', [])))} "
              f"guard={'same' if seen.get('guard') == (seen.get('life') or [0])[0] else seen.get('guard')}")
finally:
    ToolSession._protection_guard = _rg
    ToolSession._lifecycle_gate = _lg

# ======================================================================
banner("R4C.6  auditable identity, and the durable trace to it")
# ======================================================================
r = rig([OURS], own=("stop1",))
s = r.session()
a = s._authoritative()
# SAFETY CLOSURE ROUND 4C2, C2-I1: the identity is now the CONTENT ID of the
# durable evidence artifact (full sha256), not a 24-hex digest of a hand-picked
# field list. The property asserted — the observation has an identity bound to
# the acting epoch — is unchanged; only the identity's provenance is stronger.
check("R4C.6.1  the authoritative observation has an identity",
      isinstance(a, AuthoritativeState) and len(a.snapshot_id) == 64
      and a.lease_epoch == r.lease.epoch, f"{a.snapshot_id[:16]} ep={a.lease_epoch}")

r = rig([OURS], own=("stop1",))
out = r.session().modify_stop("29750")
intents = [ev for rec in Journal.load(r.path).records
           for ev in rec["events"] if ev["e"] == "INTENT"]
check("R4C.6.2  the durable INTENT names the evidence that authorised it",
      intents and intents[-1].get("authoritative_snapshot")
      and intents[-1].get("authoritative_epoch") == r.lease.epoch,
      str(intents[-1].get("authoritative_snapshot") if intents else None))

r1 = rig([OURS], own=("stop1",))
r1.session().modify_stop("29750")
r2 = rig([OURS], own=("stop1",))
r2.session().modify_stop("29750")
ids = []
for rr in (r1, r2):
    ids.append([ev.get("authoritative_snapshot")
                for rec in Journal.load(rr.path).records
                for ev in rec["events"] if ev["e"] == "INTENT"][-1])
check("R4C.6.3  the identity is a digest of what was observed, not a counter",
      ids[0] == ids[1], str(ids))

r = rig([OURS, stop_order("extra", "1.00", "29800")], own=("stop1",))
r.session().modify_stop("29750")
other = [ev.get("authoritative_snapshot")
         for rec in Journal.load(r.path).records
         for ev in rec["events"] if ev["e"] == "INTENT"][-1]
check("R4C.6.4  a different observed world yields a different identity",
      other != ids[0], f"{other} vs {ids[0]}")

# ======================================================================
banner("R4C.7  post-mutation evidence never becomes authorisation evidence")
# ======================================================================
r = rig([OURS, REP], own=("stop1", "rep"))
r.exch = Alternating([THIN, PROTECTED, PROTECTED])
out = r.session().cancel_order("stop1", replacement_client_order_id="rep")
check("R4C.7.1  a LATER favourable observation cannot rescue a refusal",
      out.status is ActionStatus.REJECTED and calls(r) == [],
      f"{out.code} calls={calls(r)}")

r = rig([OURS], own=("stop1",))
c = Counting(r.exch)
r.exch = c
r.session().modify_stop("29750")
check("R4C.7.2  the post-mutation observation happens, and only after the "
      "mutation", c.log == ["_authoritative", "_reconcile"], str(c.log))

# ======================================================================
banner("R4C.8  writer authority is not weakened")
# ======================================================================
from orbit.exec.writer import WriterAuthority as WA
r = rig([OURS], own=("stop1",))
old = r.lease
r.authority.release(old)
newer = WA(r.wdir, owner_id="WORKER2").acquire()
out = r.session(lease=old).modify_stop("29750")
check("R4C.8.1  a stale writer still cannot mutate",
      out.status is ActionStatus.BLOCKED and out.code == "STALE_WRITER"
      and calls(r) == [], f"{out.status.value}/{out.code}")

r = rig([OURS], own=("stop1",))
s = r.session()
a = s._authoritative()
check("R4C.8.2  the authoritative observation records the epoch it was taken "
      "under", a.lease_epoch == r.lease.epoch)
# SAFETY CLOSURE ROUND 4C2, C2-I4: the body of _act moved into
# _act_locked so the seal can be cleared in a finally. The property
# asserted is unchanged; it is read from the body, wherever it lives.
_src = inspect.getsource(ToolSession._act_locked)
check("R4C.8.3  authority is fenced BEFORE the authoritative observation",
      _src.index("self._authority.fence") < _src.index("self._authoritative()"))
check("R4C.8.4  and the epoch that observed is asserted to be the epoch that "
      "acts", "auth.lease_epoch != self._lease.epoch" in _src)

# ======================================================================
banner("R4C.9  defects found by reviewing THIS repair")
# ======================================================================
# 1 — the "exactly once" guard was scoped to the SESSION, not the ACTION.
#     Covered by R4C.4.3 above.
# 2 — _freeze_decision_snapshot took TWO observations and mixed them into one
#     durable record of what the model knew.
_fd = inspect.getsource(ToolSession._freeze_decision_snapshot)
check("R4C.9.1  the decision record derives every field from ONE observation",
      "v = r.view" in _fd and "v = self._view()" not in _fd)


class TwoWorlds:
    def __init__(self):
        self.n = 0

    def view(self):
        self.n += 1
        return (Exch(position=pos(), orders=[OURS]) if self.n == 1
                else Exch(position=None, orders=[])).view()


r = rig([OURS], own=("stop1",))
r.exch = TwoWorlds()
s = r.session()
s.get_market_state()                      # warms any cached reconciliation
ctx = s._freeze_decision_snapshot("d-coherent", prompt_text="p").context
_r = s._recon
check("R4C.9.2  its run_state and its state ids describe the SAME world",
      ctx.run_state == _r.run_state.value
      and ctx.position_state_id == __import__(
          "orbit.tools.session", fromlist=["_h"])._h(str(_r.view.position)),
      f"{ctx.run_state} / pos_id matches: "
      f"{ctx.position_state_id[:8]}")

shutil.rmtree(TMP, ignore_errors=True)
print("\n" + "=" * 78)
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 78)
if FAIL:
    for f in FAIL:
        print("  FAILED:", f)
    sys.exit(1)
print("R4-4 closed. One action, one authoritative observation, under one "
      "writer authority, with an identity the audit can name. Execution is NOT "
      "atomic and is not claimed to be. No model. No credentials. No network. "
      "No live capital.")
