"""
tests/stress_journal_checkpoint.py — STRESS REPRODUCER for the intermittent
"committed-head checkpoint is N records behind the journal" signature.

SAFETY CLOSURE ROUND 4C4, checkpoint A.1, review finding 4. NOT part of
RUN_TESTS.sh: it is a diagnostic tool, run deliberately, with bounded child
timeouts, and it changes no production code.

WHAT IT DOES. Repeatedly spawns P OS processes against one journal. Each
worker, M times: constructs a NEW `Journal(path)` object (whose constructor
loads the file WITHOUT the append lock) and appends one record. Constructing
per append multiplies the number of unlocked loads that overlap with other
processes' locked commits, which is the interleaving under suspicion.

DIAGNOSTICS retained on failure: every worker's exit code and stderr, the
checkpoint file, the journal's record count, hash-chain validity, and the
lag between the two, so the three candidate explanations can be told apart:

    genuine cross-process ordering/locking defect  -> chain valid, records
                                                       present, checkpoint
                                                       BEHIND by >1
    checkpoint protocol defect                     -> as above, with a
                                                       checkpoint REGRESSION
                                                       visible in the trace
    test/environment artifact                      -> records missing, chain
                                                       broken, or a worker
                                                       killed by the timeout

usage: python3 tests/stress_journal_checkpoint.py [iterations] [procs] [appends]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orbit.audit.checkpoint import HeadCheckpoint      # noqa: E402
from orbit.audit.journal import Journal                # noqa: E402
from orbit.audit.records import E                      # noqa: E402

WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_stress_worker.py")


def one_iteration(tmp: str, i: int, procs: int, appends: int,
                  timeout_s: float) -> dict:
    path = os.path.join(tmp, f"stress{i}.jsonl")
    Journal(path).append_one(E.RUN_START, None)
    ps = [subprocess.Popen([sys.executable, WORKER, path, str(w), str(appends)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           cwd=os.path.dirname(os.path.dirname(
                               os.path.abspath(__file__))))
          for w in range(procs)]
    outs, timed_out = [], []
    for w, p in enumerate(ps):
        try:
            o, e = p.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            p.kill()
            o, e = p.communicate()
            timed_out.append(w)
        outs.append((p.returncode, o.decode(errors="replace"),
                     e.decode(errors="replace")))
    load = Journal.load(path)
    cp = HeadCheckpoint(path).read()
    last_seq = load.records[-1]["seq"] if load.records else 0
    notes = sum(1 for r in load.records for ev in r["events"]
                if str(ev.get("note", "")).startswith("w"))
    # the trace workers leave behind: every checkpoint commit they observed
    trace_path = path + ".trace"
    trace = open(trace_path).read().splitlines() if os.path.exists(trace_path) else []
    return {
        "iteration": i,
        "worker_rcs": [rc for rc, _, _ in outs],
        "worker_stderr": [e[-300:] for rc, _, e in outs if rc != 0],
        "timed_out": timed_out,
        "trusted": load.trusted, "reason": load.reason,
        "chain_records": len(load.records), "last_seq": last_seq,
        "notes_present": notes, "notes_expected": procs * appends,
        "checkpoint_seq": cp.seq, "lag": last_seq - cp.seq,
        "trace_tail": trace[-12:],
    }


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    procs = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    appends = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    tmp = tempfile.mkdtemp(prefix="orbit_stress_")
    t0 = time.time()
    failures = []
    for i in range(iterations):
        r = one_iteration(tmp, i, procs, appends, timeout_s=60.0)
        ok = (all(rc == 0 for rc in r["worker_rcs"]) and r["trusted"]
              and r["notes_present"] == r["notes_expected"]
              and abs(r["lag"]) <= 1 and not r["timed_out"])
        if not ok:
            failures.append(r)
            print(f"--- FAILURE at iteration {i} ---")
            print(json.dumps(r, indent=1))
    dt = time.time() - t0
    print(f"\nSTRESS: {iterations} iterations x {procs} procs x {appends} "
          f"appends = {iterations * procs * appends} appends in {dt:.0f}s; "
          f"failures={len(failures)}")
    print("METHOD: each worker constructs a fresh Journal(path) (unlocked "
          "load) before EVERY append; jittered sleeps 0-4ms; child timeout "
          "60s.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
