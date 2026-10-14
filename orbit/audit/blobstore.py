"""
orbit/audit/blobstore.py — CONTENT-ADDRESSED DURABLE STORAGE.

ORBIT A1 SAFETY CLOSURE ROUND 2, part of finding N4.

A decision input can be large — a system prompt, a tool schema, several market
payloads. Inlining every one of them into the journal would make the journal
expensive to load, and the journal is loaded on every append. So the bytes live
here and the journal records their content id.

The content id IS the sha256 of the bytes, which makes two properties fall out
rather than needing to be maintained:

  * storage is idempotent. Writing the same input twice writes the same file.
  * the store is self-verifying. `get()` re-hashes what it read and refuses to
    return anything whose bytes are not the bytes that id names, so a corrupted
    or edited blob is an error and never a silent substitution.

Writes are atomic: a temporary file, fsynced, then linked into place, then the
directory fsynced. A crash mid-write leaves a temporary file, never a truncated
blob under a content id that promises otherwise.
"""

from __future__ import annotations

import hashlib
import os
import tempfile


class BlobCorrupted(RuntimeError):
    """The stored bytes are not the bytes this content id names."""


class BlobMissing(KeyError):
    """No blob under that content id."""


class BlobStore:
    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(self.dir, exist_ok=True)

    @staticmethod
    def content_id(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def path_for(self, cid: str) -> str:
        return os.path.join(self.dir, f"{cid}.blob")

    def put(self, data: bytes) -> str:
        """Returns the content id, having PROVED the bytes are readable.

        SAFETY CLOSURE ROUND 4C3, finding C3-I1.

        This used to short-circuit on `os.path.exists(final)`. `get` verified
        the stored bytes; `put` did not. So a blob corrupted after its first
        write could be "put" again, report success, and hand back a
        valid-looking content id — while the object it named was already
        unrecoverable. That matters precisely because identical authoritative
        worlds legitimately reuse one content id: a later action could take that
        cid onward to INTENT and an exchange mutation believing its evidence was
        durable.

            EXISTENCE IS NOT DURABILITY.
            A PRE-EXISTING PATHNAME IS NOT PROOF.

        On finding corruption the store FAILS CLOSED rather than overwriting.
        Silently rewriting correct bytes over a corrupted object would make the
        caller succeed and destroy the only trace that corruption happened — and
        a corruption event is itself safety evidence. Whoever must decide
        whether this was a disk fault or an actor with write access needs to see
        it. Recovery is a deliberate operator act, not a side effect of the next
        write.

        THREAT MODEL, stated exactly. This proves the bytes were present and
        correct AT THE MOMENT PUT RETURNED. It cannot prevent an actor with
        arbitrary write access from corrupting or deleting them immediately
        afterwards; no local store can. That residual window — verified, then
        corrupted, then INTENT and mutation — is real and is not claimed to be
        closed. What is closed is the case where `put` reported success over
        bytes that were ALREADY wrong.
        """
        cid = self.content_id(data)
        final = self.path_for(cid)
        if os.path.exists(final):
            with open(final, "rb") as fh:
                existing = fh.read()
            if existing == data:
                return cid
            raise BlobCorrupted(
                f"an object already stored under {cid[:16]}… does not contain "
                f"the bytes that id names (it hashes to "
                f"{self.content_id(existing)[:16]}…). Refusing to overwrite it: "
                f"a corrupted artifact is itself evidence, and repairing it "
                f"silently would destroy the only trace that it happened.")
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".part")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        try:
            dfd = os.open(self.dir, os.O_RDONLY)
            os.fsync(dfd)
            os.close(dfd)
        except OSError:
            pass
        return cid

    def get(self, cid: str) -> bytes:
        p = self.path_for(cid)
        if not os.path.exists(p):
            raise BlobMissing(cid)
        with open(p, "rb") as fh:
            data = fh.read()
        actual = self.content_id(data)
        if actual != cid:
            raise BlobCorrupted(
                f"blob {cid[:16]}… hashes to {actual[:16]}…; the stored bytes "
                f"are not the bytes this id names")
        return data

    def has(self, cid: str) -> bool:
        try:
            self.get(cid)
            return True
        except (BlobMissing, BlobCorrupted):
            return False
