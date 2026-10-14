"""
orbit/exec/writer.py — SINGLE-WRITER AUTHORITY WITH EPOCH FENCING.

ORBIT-AGENT-ARCH-001, step 6D.

    AT MOST ONE AUTHORITATIVE ORBIT EXECUTION CYCLE MAY MUTATE TRADING STATE
    AT A TIME.

A `threading.Lock` cannot express this: ORBIT can be restarted, scheduled twice,
or run as two processes, and an in-memory lock is invisible across all three. So
authority is DURABLE and its identity is an EPOCH.

MECHANISM

  Authority lives in a directory. Each grant is a file `e<epoch>.json`. To take
  authority at epoch N+1 a worker must EXCLUSIVELY CREATE `e<N+1>.json`
  (O_CREAT|O_EXCL). That is an atomic compare-and-set on any POSIX or Windows
  filesystem: exactly one of two racing workers wins, and the loser is told so
  by the operating system rather than by a convention we hope everyone follows.

  The highest epoch present is the only valid authority. A lease also carries an
  expiry, so a worker that dies holding authority does not hold it forever.

FENCING — THE POINT OF THE WHOLE DESIGN

  Holding a lease OBJECT is not authority. Authority is being the current epoch,
  checked at the moment of use. `fence()` is called immediately before every
  exchange mutation, and it re-reads the durable state. A worker that was paused,
  swapped out, or partitioned and has since been superseded discovers this at
  the last possible instant and raises, rather than submitting an order on
  behalf of a generation that no longer exists.

  This is why an expired-but-unreplaced lease is ALSO refused: a worker whose
  lease lapsed cannot know whether someone else has acted in the meantime.

CLAUDE NEVER TOUCHES THIS. No tool acquires, renews, releases or inspects
authority. It is not in the capability model at all.
"""

from __future__ import annotations

import json
import os
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Callable, List, Optional


class StaleWriterError(RuntimeError):
    """Raised at the fence. Never caught inside the execution path — a stale
    worker must stop, not retry."""


class WriterUnavailableError(RuntimeError):
    """Another worker currently holds valid authority."""


class AuthorityCorruptError(RuntimeError):
    """The authority record cannot be read. Nobody may mutate trading state
    until a human resolves it: an unreadable grant is indistinguishable from a
    grant held by someone we cannot see."""


@dataclass(frozen=True)
class Lease:
    owner_id: str
    epoch: int
    acquired_at: float
    expires_at: float
    pid: int
    host: str

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)

    @staticmethod
    def from_json(s: str) -> "Lease":
        return Lease(**json.loads(s))


class WriterAuthority:
    def __init__(self, directory: str, owner_id: Optional[str] = None,
                 ttl_seconds: float = 30.0,
                 clock: Callable[[], float] = time.time):
        self.dir = directory
        self.owner_id = owner_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self.ttl = ttl_seconds
        self._clock = clock
        os.makedirs(directory, exist_ok=True)

    # ------------------------------------------------------------------
    def _epochs(self) -> List[int]:
        out = []
        for name in os.listdir(self.dir):
            if name.startswith(".tmp-"):
                continue
            if name.startswith("e") and name.endswith(".json"):
                try:
                    out.append(int(name[1:-5]))
                except ValueError:
                    pass
        return sorted(out)

    def _read(self, epoch: int) -> Lease:
        path = os.path.join(self.dir, f"e{epoch}.json")
        try:
            with open(path) as fh:
                return Lease.from_json(fh.read())
        except Exception as e:
            # With atomic publish (see acquire) a grant file is never observed
            # half-written. So an unreadable one is corruption, and the safe
            # answer is that NOBODY holds authority they can prove.
            raise AuthorityCorruptError(
                f"authority record e{epoch}.json is unreadable: {e}")

    def current(self) -> Optional[Lease]:
        eps = self._epochs()
        return self._read(eps[-1]) if eps else None

    def current_epoch(self) -> int:
        eps = self._epochs()
        return eps[-1] if eps else 0

    # ------------------------------------------------------------------
    def acquire(self) -> Lease:
        """Atomic compare-and-set on the epoch.

        DEFECT FIXED 2026-09-08 (found by a 12-thread race, 3 winners):
        `O_CREAT|O_EXCL` creates the file atomically but the CONTENT was written
        afterwards. A racer could observe a created-but-empty grant, conclude
        there was no valid authority, and claim the NEXT epoch. Two corrections:

          1. Publish atomically. The lease is written to a temporary file,
             fsynced, then `os.link`ed into place. Link is atomic and fails if
             the target exists, so a grant is never observed half-written.
          2. Derive the next epoch from the SAME observation that decided the
             slot was free. Re-reading would reintroduce the race in another
             form: a loser would try epoch N+2 instead of colliding on N+1, and
             would win a slot it never checked.
        """
        now = self._clock()
        eps = self._epochs()                      # ONE observation
        top = eps[-1] if eps else 0
        if top:
            cur = self._read(top)
            if now < cur.expires_at and cur.owner_id != self.owner_id:
                raise WriterUnavailableError(
                    f"epoch {cur.epoch} is held by {cur.owner_id} until "
                    f"{cur.expires_at:.3f}; this worker may not mutate state")
        nxt = top + 1
        lease = Lease(self.owner_id, nxt, now, now + self.ttl, os.getpid(),
                      socket.gethostname())
        tmp = os.path.join(self.dir, f".tmp-{uuid.uuid4().hex}")
        with open(tmp, "w") as fh:
            fh.write(lease.to_json())
            fh.flush()
            os.fsync(fh.fileno())
        target = os.path.join(self.dir, f"e{nxt}.json")
        try:
            os.link(tmp, target)                  # atomic publish, content included
        except FileExistsError:
            raise WriterUnavailableError(
                f"lost the race for epoch {nxt}; another worker published it first")
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        try:
            dfd = os.open(self.dir, os.O_RDONLY)
            os.fsync(dfd)
            os.close(dfd)
        except OSError:
            pass
        return lease

    def renew(self, lease: Lease) -> Lease:
        """Extend the CURRENT epoch. A superseded lease cannot be renewed."""
        self.fence(lease)
        now = self._clock()
        new = Lease(lease.owner_id, lease.epoch, lease.acquired_at,
                    now + self.ttl, lease.pid, lease.host)
        path = os.path.join(self.dir, f"e{lease.epoch}.json")
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(new.to_json())
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return new

    def release(self, lease: Lease) -> None:
        """Expire the lease immediately so the next worker need not wait out the
        TTL. The epoch file remains — history is never deleted, and the epoch
        counter never goes backwards."""
        if self.current_epoch() != lease.epoch:
            return
        expired = Lease(lease.owner_id, lease.epoch, lease.acquired_at,
                        self._clock() - 1.0, lease.pid, lease.host)
        path = os.path.join(self.dir, f"e{lease.epoch}.json")
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(expired.to_json())
        os.replace(tmp, path)

    # ------------------------------------------------------------------
    def is_current(self, lease: Optional[Lease]) -> bool:
        if lease is None:
            return False
        cur = self.current()
        if cur is None or cur.epoch != lease.epoch:
            return False
        if cur.owner_id != lease.owner_id:
            return False
        return self._clock() < cur.expires_at

    def fence(self, lease: Optional[Lease]) -> None:
        """CALL IMMEDIATELY BEFORE ANY EXCHANGE MUTATION.

        Holding the object is not authority; being the live epoch is."""
        if lease is None:
            raise StaleWriterError("no writer authority held")
        cur = self.current()
        if cur is None:
            raise StaleWriterError("no authority exists; this lease is void")
        if cur.epoch != lease.epoch:
            raise StaleWriterError(
                f"FENCED: this worker holds epoch {lease.epoch} but authority "
                f"has moved to epoch {cur.epoch} ({cur.owner_id}). A superseded "
                f"worker may not mutate trading state.")
        if cur.owner_id != lease.owner_id:
            raise StaleWriterError(
                f"FENCED: epoch {lease.epoch} is owned by {cur.owner_id}")
        if self._clock() >= cur.expires_at:
            raise StaleWriterError(
                f"FENCED: lease on epoch {lease.epoch} expired at "
                f"{cur.expires_at:.3f}; another worker may have acted since")
