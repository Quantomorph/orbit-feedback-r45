"""tests/_mapping_worker.py — REAL processes racing one decision_id mapping.

Used by tests/test_safety_closure_r3.py, section R3-5. The association
decision_id -> model_input_hash must be immutable and atomic ACROSS PROCESSES,
so the test that proves it must use processes.

argv: <journal path> <blob dir> <decision id> <user prompt> <barrier epoch>
Prints exactly one of: RECORDED | DUPLICATE | CONFLICT | ERROR <type> <msg>
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orbit.audit.blobstore import BlobStore                        # noqa: E402
from orbit.audit.decision_input import (DecisionInput,             # noqa: E402
                                        DecisionInputConflict,
                                        record_decision_input)
from orbit.audit.journal import Journal                            # noqa: E402

jpath, blobdir, decision_id, prompt, barrier = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], float(sys.argv[5]))

j = Journal(jpath)
store = BlobStore(blobdir)
di = DecisionInput(system_prompt="You are ORBIT A1.", user_prompt=prompt,
                   tool_schema={"get_market_state": {"params": {}}})

while time.time() < barrier:
    time.sleep(0.0005)

try:
    ref = record_decision_input(j, store, decision_id, di)
    print("DUPLICATE" if ref.get("duplicate") else "RECORDED")
except DecisionInputConflict:
    print("CONFLICT")
except Exception as e:                                             # noqa: BLE001
    print("ERROR", type(e).__name__, str(e)[:80])
