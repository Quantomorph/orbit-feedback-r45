"""tests/_reconstruct_worker.py — a REAL separate process that reconstructs a
decision input from disk alone.

Used by tests/test_safety_closure_r2.py, section N4. The requirement is that,
after a restart, the exact bytes submitted to the model can be reproduced with
nothing but the journal and the blob store — no in-memory object from the
process that made the decision. A test that reuses an in-process object proves
nothing about that, so this runs as its own process.

argv: <journal path> <blob dir> <decision id>
Prints one JSON object: {"model_input_hash": ..., "bytes_identical": bool}
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orbit.audit.blobstore import BlobStore                    # noqa: E402
from orbit.audit.decision_input import DecisionInput           # noqa: E402
from orbit.audit.journal import Journal                        # noqa: E402
from orbit.audit.records import E                              # noqa: E402

jpath, blobdir, decision_id = sys.argv[1], sys.argv[2], sys.argv[3]

ref = None
for rec in Journal.load(jpath).records:
    for ev in rec["events"]:
        if ev["e"] == E.DECISION_INPUT.value and ev.get("decision_id") == decision_id:
            ref = ev
if ref is None:
    print(json.dumps({"error": "no DECISION_INPUT record"}))
    raise SystemExit(1)

raw = BlobStore(blobdir).get(ref["content_id"])

# Rebuilt from the bytes on disk, then re-serialised: if the round trip is not
# byte-identical, the artifact does not actually reconstruct anything.
rebuilt = DecisionInput.deserialize(raw)
again = rebuilt.serialize()

print(json.dumps({
    "model_input_hash": hashlib.sha256(raw).hexdigest(),
    "rebuilt_model_input_hash": rebuilt.hashes()["model_input_hash"],
    "bytes_identical": again == raw,
}))
