"""
orbit/audit/locks.py — CROSS-PROCESS FILE LOCKS WITH AN ENFORCED RANK.

ORBIT A1 SAFETY CLOSURE ROUND 4C4, CHECKPOINT A.2-R, item A2R-2.

WHY THIS EXISTS.

Until A.2-R there was exactly ONE cross-process lock in ORBIT: the journal's
append lock. One lock cannot be acquired out of order, so no ordering discipline
was needed and none was written down.

Repairing the journal/checkpoint race (A2R-1) introduces a SECOND cross-process
lock — the checkpoint's own — and the moment there are two, the order in which
they may be taken becomes a safety property rather than a style question. The
append path commits the checkpoint WHILE HOLDING the append lock, so exactly one
order can ever be legal:

    AppendLock (rank 10)  ->  CheckpointLock (rank 20, LEAF)

A thread that held the checkpoint lock and then reached for the append lock
would deadlock against a thread doing the legal thing. `flock` gives no timeout
and no deadlock detection, so such a bug does not raise — the process simply
stops, holding a lock on durable evidence.

WHAT IS ENFORCED.

Ranks are tracked per thread. Acquiring a lock whose rank is not strictly
greater than every rank already held by this thread raises `LockOrderViolation`
instead of blocking. That converts a silent hang into a loud, testable failure,
and it also catches self-deadlock: `flock` conflicts between two file
descriptors in the SAME process, so taking the same lock twice would block
forever. Strictly-greater makes that a raise too.

    rank held    acquiring    result
    ---------    ---------    ------
    (none)       APPEND       ok
    (none)       CHECKPOINT   ok      (a bare checkpoint write, legal)
    APPEND       CHECKPOINT   ok      (the append path: commit under the lock)
    CHECKPOINT   APPEND       LockOrderViolation  (would deadlock)
    APPEND       APPEND       LockOrderViolation  (would self-deadlock)
    CHECKPOINT   CHECKPOINT   LockOrderViolation  (would self-deadlock)

CHECKPOINT IS A LEAF. Nothing may be acquired while it is held, and nothing but
the read-compare-replace of the head file happens inside it. A leaf lock held
across arbitrary work is how a rank discipline decays back into a deadlock.

RELEASE ON FAILURE. Every lock here is a context manager and releases in a
`finally`, so an exception inside the critical section — including one raised by
the rank guard itself — cannot leave a lock or a rank entry behind. The
descriptor is closed on the way out, which releases the `flock` even if the
unlock call fails.

RUNTIME CONTRACT. `fcntl.flock`, POSIX only, local filesystems only. Identical
to the contract already stated in `orbit/audit/journal.py` and enforced at
startup by `orbit/runtime.py`; this module adds no new portability claim.
"""

from __future__ import annotations

import fcntl
import threading
from typing import List

# Lower rank is acquired FIRST. Gaps are deliberate: a future lock can be
# ranked between two existing ones without renumbering call sites.
RANK_APPEND = 10
RANK_CHECKPOINT = 20          # LEAF — nothing may be acquired while it is held

RANK_NAMES = {RANK_APPEND: "AppendLock", RANK_CHECKPOINT: "CheckpointLock"}

LEAF_RANKS = frozenset({RANK_CHECKPOINT})


class LockOrderViolation(RuntimeError):
    """A lock was acquired out of rank order, or re-entered.

    Raised instead of blocking: the alternative is a `flock` that never returns,
    holding a lock on durable evidence with no diagnostic.
    """


_state = threading.local()


def _stack() -> List[int]:
    s = getattr(_state, "ranks", None)
    if s is None:
        s = []
        _state.ranks = s
    return s


def held_ranks() -> List[int]:
    """The ranks this thread currently holds, outermost first. For tests."""
    return list(_stack())


def _describe(ranks: List[int]) -> str:
    return ", ".join(RANK_NAMES.get(r, str(r)) for r in ranks) or "(none)"


def _enter_rank(rank: int) -> None:
    stack = _stack()
    if stack:
        top = stack[-1]
        if top in LEAF_RANKS:
            raise LockOrderViolation(
                f"{RANK_NAMES.get(top, top)} is a LEAF lock: no lock may be "
                f"acquired while it is held, and "
                f"{RANK_NAMES.get(rank, rank)} was requested")
        if rank <= top:
            raise LockOrderViolation(
                f"lock rank violation: this thread holds "
                f"[{_describe(stack)}] and asked for "
                f"{RANK_NAMES.get(rank, rank)} (rank {rank}). Ranks must "
                f"strictly increase; acquiring this lock would deadlock "
                f"against a thread taking them in the declared order "
                f"(AppendLock before CheckpointLock).")
    stack.append(rank)


def _exit_rank(rank: int) -> None:
    stack = _stack()
    if stack and stack[-1] == rank:
        stack.pop()
    elif rank in stack:                       # defensive: never leak an entry
        stack.remove(rank)


class RankedFileLock:
    """An exclusive `flock` on `path`, guarded by the rank discipline above.

    The rank is claimed BEFORE the descriptor is opened and released in a
    `finally`, so a violation never opens a file and never blocks.
    """

    def __init__(self, path: str, rank: int):
        self.path = path
        self.rank = rank
        self._fh = None

    def __enter__(self):
        _enter_rank(self.rank)
        try:
            self._fh = open(self.path, "a+")
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except BaseException:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
            _exit_rank(self.rank)
            raise
        return self

    def __exit__(self, *exc):
        try:
            if self._fh is not None:
                try:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
                finally:
                    # Closing the descriptor releases the flock even if the
                    # explicit unlock raised.
                    self._fh.close()
                    self._fh = None
        finally:
            _exit_rank(self.rank)
        return False
