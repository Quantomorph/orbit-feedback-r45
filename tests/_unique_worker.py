"""tests/_unique_worker.py — a REAL separate process contending for uniqueness.

Used by tests/test_safety_closure_r2.py, section N1. The thing under test is a
FILE shared by independent OS processes, and an in-memory cache in one process
says nothing about what another has already committed. Threads cannot show this.

argv: <journal path> <mode> <barrier epoch seconds> [payload override]
  mode: intent | fill | fillgroup | protective
Prints exactly one of: WROTE | SUPPRESSED | ERROR <type> <msg>
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orbit.audit.cycle import CycleRecorder          # noqa: E402
from orbit.audit.journal import Journal              # noqa: E402

path, mode, barrier = sys.argv[1], sys.argv[2], float(sys.argv[3])
j = Journal(path)
rec = CycleRecorder(j)

while time.time() < barrier:            # every process starts in the same tick
    time.sleep(0.0005)

try:
    if mode == "intent":
        out = j.record_intent("same-action", client_order_id="same-cid",
                              instrument="BTC-USDT-SWAP", order_kind="OPEN",
                              side="long", contracts="0.01", role="ENTRY",
                              reduce_only=False, order_type="market")
    elif mode == "fill":
        out = j.record_fill("a1", "fill-1", client_order_id="same-cid",
                            contracts="0.01")
    elif mode == "fillgroup":
        out = rec.record_fill_group(
            "a1", "same-cid", "fill-1", "0.01", "30000",
            {"side": "long", "contracts": "0.01", "entry_price": "30000",
             "stop_price": "29700.1", "stop_client_id": "stop1",
             "opened_at": "2026-09-08T12:00:00+00:00"},
            1, "0", executed_at="2026-09-08T12:00:00+00:00")
    elif mode == "protective":
        out = rec.record_protective_intent("stop-1", "0.01", "29700.1")
    else:
        raise SystemExit(f"unknown mode {mode}")
    print("WROTE" if out is not None else "SUPPRESSED")
except Exception as e:                                    # noqa: BLE001
    print("ERROR", type(e).__name__, str(e)[:80])
