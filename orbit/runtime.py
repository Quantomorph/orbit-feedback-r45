"""
orbit/runtime.py — THE DEPLOYMENT CONTRACT, STATED AND CHECKED.

ORBIT A1 SAFETY CLOSURE ROUND 2, finding N5.

The journal's cross-process append lock is `fcntl.flock`. `import fcntl` sat at
module scope, so on native Windows `orbit.audit.journal` could not import at
all. The failure would have arrived as an ImportError somewhere inside a
traceback rather than as a stated contract, and nothing in the code or the tests
said which platforms and filesystems ORBIT supports.

THE DECISION TAKEN — option A of the two offered.

    ORBIT A1 runs on POSIX: Linux, WSL2, or a Linux container.
    The journal must live on a LOCAL filesystem.

A cross-platform lock is deliberately NOT claimed. `msvcrt.locking` has
different semantics from `flock` around inheritance, byte ranges and release on
close, and none of it could be exercised here. An untested lock protecting the
uniqueness of an order that spends real money is worse than a start that
refuses: the refusal is loud and immediate, the untested lock fails silently and
only under contention.

If native Windows is required, that is a change to this contract and needs its
own implementation and its own adversarial closure. It is not something to be
implied by an import that happens to work on the developer's machine.
"""

from __future__ import annotations

import sys
from typing import Dict, Optional, Tuple


class UnsupportedPlatform(RuntimeError):
    """Raised at startup, before anything durable or external is touched."""


RUNTIME_CONTRACT: Dict[str, object] = {
    "platforms": ("linux", "linux2", "darwin"),
    "platform_note": (
        "Linux, WSL2 or a Linux container is the supported deployment. macOS is "
        "permitted for development because it provides the same flock "
        "semantics; it is not a supported deployment target."
    ),
    "filesystems": (
        "local filesystems only (ext4, xfs, btrfs, apfs, overlayfs)",
        "NFS is NOT supported: flock over NFS depends on the server, the mount "
        "options and the client implementation, and a lock that is silently "
        "advisory-only would defeat the uniqueness guarantee the journal "
        "depends on",
        "SMB/CIFS and network shares are NOT supported, for the same reason",
    ),
    "reason": (
        "the journal's append lock is fcntl.flock, which is POSIX-only and is "
        "only dependable on a local filesystem. Uniqueness of a durable INTENT "
        "and of a FILL is decided inside that lock, so its semantics are a "
        "safety property, not a portability detail."
    ),
    "unsupported": (
        "native Windows (win32/cygwin): fcntl does not exist there, and no "
        "cross-platform equivalent is claimed because none could be tested"
    ),
}


def check_platform(platform: Optional[str] = None) -> Tuple[bool, str]:
    """(ok, why). Pure — no side effects, so a test can ask about a platform it
    is not running on."""
    p = platform or sys.platform
    if p in RUNTIME_CONTRACT["platforms"]:
        return True, f"{p} is a supported POSIX platform"
    return False, (
        f"{p} is not a supported ORBIT A1 runtime. {RUNTIME_CONTRACT['reason']} "
        f"fcntl is unavailable on this platform. "
        f"{RUNTIME_CONTRACT['unsupported']}"
    )


def require_supported_platform(platform: Optional[str] = None) -> None:
    """Called where the dependency lives. Refuses at startup rather than
    failing later, deeper, and less legibly."""
    ok, why = check_platform(platform)
    if not ok:
        raise UnsupportedPlatform(why)
    return None


def describe() -> str:
    fs = "\n  - ".join(RUNTIME_CONTRACT["filesystems"])
    return (
        "ORBIT A1 RUNTIME CONTRACT\n"
        f"platforms: {', '.join(RUNTIME_CONTRACT['platforms'])}\n"
        f"  {RUNTIME_CONTRACT['platform_note']}\n"
        f"filesystems:\n  - {fs}\n"
        f"why: {RUNTIME_CONTRACT['reason']}\n"
        f"not supported: {RUNTIME_CONTRACT['unsupported']}"
    )
