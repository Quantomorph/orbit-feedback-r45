"""tests/_stress_worker.py — one OS process for stress_journal_checkpoint.py.

Constructs a FRESH Journal(path) before every append (an unlocked load each
time), appends, and leaves a diagnostic trace of every checkpoint write it
performs: (pid, seq written, seq the checkpoint file held immediately before
the write, whether the write was locked). A write with seq < prior seq is a
checkpoint REGRESSION, and this trace is how it is caught in the act. The
tracing wraps the checkpoint class IN THIS WORKER ONLY; production code is
untouched.

argv: <journal path> <worker id> <appends>
"""
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orbit.audit import checkpoint as _cp                # noqa: E402
from orbit.audit.journal import AppendLock, Journal      # noqa: E402
from orbit.audit.records import E                        # noqa: E402

path, wid, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
TRACE = path + ".trace"
_orig_write = _cp.HeadCheckpoint._write_unchecked
_in_lock = {"held": False}
_orig_enter, _orig_exit = AppendLock.__enter__, AppendLock.__exit__


def _enter(self):
    r = _orig_enter(self)
    _in_lock["held"] = True
    return r


def _exit(self, *exc):
    _in_lock["held"] = False
    return _orig_exit(self, *exc)


def _traced_write(self, seq, rec_hash):
    before = _cp.HeadCheckpoint(self.journal_path).read().seq
    out = _orig_write(self, seq, rec_hash)
    with open(TRACE, "a") as fh:
        fh.write(f"pid={os.getpid()} w={wid} wrote_seq={seq} "
                 f"file_had_seq={before} locked={_in_lock['held']}"
                 f"{' REGRESSION' if seq < before else ''}\n")
    return out


_cp.HeadCheckpoint._write_unchecked = _traced_write
AppendLock.__enter__, AppendLock.__exit__ = _enter, _exit

random.seed(int(wid) * 7919 + os.getpid())
for i in range(n):
    time.sleep(random.uniform(0, 0.004))
    j = Journal(path)                    # UNLOCKED load; may roll forward
    time.sleep(random.uniform(0, 0.002))
    j.append_one(E.REMEDIATION, None, note=f"w{wid}-{i}")
print(f"worker {wid} wrote {n}")
