"""tests/_append_worker.py — a REAL separate process that appends to a journal.

Used by tests/test_safety_closure.py, section G. Threads share Python objects;
the thing under test here is a FILE shared by independent OS processes, so the
test must use independent OS processes.

argv: <journal path> <worker id> <appends>
"""
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orbit.audit.journal import Journal          # noqa: E402
from orbit.audit.records import E                # noqa: E402

path, wid, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
j = Journal(path)
random.seed(int(wid))
for i in range(n):
    time.sleep(random.uniform(0, 0.004))         # widen the race window
    j.append_one(E.REMEDIATION, None, note=f"w{wid}-{i}")
print(f"worker {wid} wrote {n}")
