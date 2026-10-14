"""Reproducers against the UNTOUCHED Checkpoint A tree."""
import os, sys, tempfile
from datetime import timedelta
from decimal import Decimal as D
sys.path.insert(0, "."); sys.path.insert(0, "tests")
from harness import NOW, Exch, Rig, flat, held, pos, stop_order
from orbit.audit.records import E
from orbit.exec.recon import IntendedState
from orbit.risk.limits import A1
from orbit.tools.session import ActionStatus
TMP = tempfile.mkdtemp()

def rig(name, intended=None, exch=None):
    d = os.path.join(TMP, name); os.makedirs(d, exist_ok=True)
    r = Rig(d, name, intended=intended, exch=exch or Exch()); r.acquire(); return r

# ---------------- Finding 2: cross-midnight ----------------
# yesterday 23:59:50 a +20 gain executed; it is COMMITTED at 00:00:10 today.
# today at 11:00 a -20 loss is executed and committed.
# Policy: today's realized = -20 -> DAILY_LOSS_REACHED. Commit-day accounting
# says today's realized = +20 - 20 = 0 -> the entry is PERMITTED.
midnight = NOW.replace(hour=0, minute=0, second=0)
r = rig("f2", intended=flat())
r._synth_round_trip(0, D("20"), midnight - timedelta(minutes=30), midnight + timedelta(seconds=10))
#  ^ the exit leg's RECORD ts is 00:00:10 today; the harness has no execution-time
#    concept at all in Checkpoint A, so this IS the "executed yesterday, committed today" case.
r._synth_round_trip(1, D("-20"), NOW - timedelta(hours=1), NOW - timedelta(hours=1))
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
out = r.session().propose_order("long", "29700")
print("F2 cross-midnight (gain committed after midnight offsets today's loss):",
      out.status.value, out.code, "adapter calls", len(r.adapter.calls),
      "<-- DEFECT REPRODUCED" if out.status is ActionStatus.ACKNOWLEDGED else "")

# ---------------- Finding 3: position without an entry fill ----------------
# legit round trip earlier today; then POSITION_STATE claims 2.38 long with stop1,
# no ENTRY fill for it; exchange shows the same position.
r = rig("f3", intended=flat(), exch=Exch(position=pos(), orders=[stop_order()]))
r._synth_round_trip(0, D("0"), NOW - timedelta(hours=3), NOW - timedelta(hours=2))
r.journal.append_one(E.PROTECTIVE_INTENT, "stop1", client_order_id="stop1", contracts="2.38",
                     instrument="BTC-USDT-SWAP", order_kind="PROTECTIVE", role="PROTECTIVE",
                     reduce_only=True, stop="29700.1")
r.journal.append_one(E.PROTECTIVE_ACK, "stop1", client_order_id="stop1")
r.journal.append_one(E.POSITION_STATE, None, position={
    "side": "long", "contracts": "2.38", "entry_price": "30000",
    "stop_price": "29700.1", "stop_client_id": "stop1",
    "opened_at": (NOW - timedelta(minutes=30)).isoformat()})
r.journal.append_one(E.CLEAN_SHUTDOWN, None)
s = r.session()
sysr = s.get_system_state()
out = s.modify_stop("29750")
print("F3 position with no entry fill: system", sysr.data["run_state"], sysr.data["findings"],
      "| modify_stop ->", out.status.value, out.code, "adapter calls", len(r.adapter.calls),
      "<-- DEFECT REPRODUCED" if out.status is ActionStatus.ACKNOWLEDGED else "")
