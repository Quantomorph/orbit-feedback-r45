"""
orbit/audit/evidence.py — SAFETY CLOSURE ROUND 4C2, findings C2-I1 and C2-I2.

WHAT THIS EXISTS TO PREVENT.

Round 4C gave each action an authoritative pre-mutation observation and wrote
its digest into the durable INTENT, claiming that "the audit can point at the
evidence rather than assert that evidence existed". Two things were wrong.

C2-I1. The evidence itself was never stored. The digest went to disk; the bytes
it named lived only in memory and died with the process. This is the mistake
ORBIT already fixed once, for DecisionInput:

    A HASH PROVES EQUALITY ONLY IF THE ORIGINAL STILL EXISTS.
    IT DOES NOT RECONSTRUCT THE ORIGINAL.

C2-I2. The digest was computed from a hand-maintained list of nine fields, and
`ExchangeView` has more than nine. Two views differing only in `server_time` —
one RUNNING, one HALTED on CLOCK_SKEW_SEVERE — produced ONE identity. A single
snapshot id named two different safety worlds.

THE DESIGN.

There is no separate "list of fields that matter". The artifact IS the
serialization of the whole authoritative state, and the identity IS the content
id of those exact bytes. Identity and artifact cannot disagree because they are
the same object seen two ways.

Serialization is STRUCTURAL: every dataclass field is walked by reflection, so a
field added to `ExchangeView` tomorrow enters the artifact and the identity
without anyone remembering to add a line. That is the maintenance property
C2-I2 asked for, and it is the reason this is not another curated dict.

Excluding a field would therefore take a deliberate act. Nothing is excluded.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import json
from decimal import Decimal
from typing import Any, Dict, Optional, Tuple

from orbit.audit.blobstore import BlobCorrupted, BlobMissing, BlobStore

SCHEMA = "orbit.authoritative-evidence.v2"
"""Explicit and versioned. A reader that does not know this string must refuse
to interpret the bytes rather than guess at them.

v2 — SAFETY CLOSURE ROUND 4C3, C3-I4. `_plain` was not injective: two distinct
classes sharing a short name serialised identically, and dict keys `1` and `"1"`
collapsed onto one JSON name, silently losing an entry. Both are changes to the
canonical encoding, so the version moves. Artifacts are not comparable by id
across a bump, and that is the correct consequence rather than a cost.

v2 also carries the durable local state and the limits STRUCTURALLY, plus the
journal head they were derived from (C3-I3), so a verdict can be re-derived
rather than merely named.

v2, ADDITIVE (SAFETY CLOSURE ROUND 4C4, checkpoint A, revised in A.1):
`IntendedState` gained `position_fill_backed` (Optional[bool], default None;
A.1 replaced checkpoint A's short-lived `entry_fills_on_record`). The ENCODING is
unchanged, so the version is not bumped; but because serialization is
structural, an identical local state produces a different content id under
this build than under the previous one. Artifacts from before this change
revive with the field at None. Flagged for review rather than hidden."""


_TYPE_NAMES: Dict[type, str] = {}
_TYPES_BY_NAME: Dict[str, type] = {}


class UnserialisableEvidence(TypeError):
    """A value in the authoritative state has no defined serialization."""


class EvidenceUnavailable(RuntimeError):
    """The evidence that authorised a mutation cannot be produced.

    Raised for both a missing artifact and a corrupted one, because an audit
    that cannot show the evidence must fail closed either way. The two are
    distinguished in the message, never in the outcome.
    """


def _register(t: type, name: str) -> type:
    _TYPE_NAMES[t] = name
    if name in _TYPES_BY_NAME and _TYPES_BY_NAME[name] is not t:
        raise RuntimeError(f"evidence type name {name!r} is already taken")
    _TYPES_BY_NAME[name] = t
    return t


def _type_id(t: type) -> str:
    """An unambiguous identity for a type, from an EXPLICIT registry.

    C3-I4A. Both the enum and the dataclass branches used `type(v).__name__`,
    so two DISTINCT classes sharing a short name — two enums both called
    `Status`, two dataclasses both called `Thing` — produced identical bytes and
    therefore identical evidence identities. A short name is not an identity.

    `module.qualname` was the obvious repair and it is not enough: two classes
    created dynamically in one module share both, and import aliases or a moved
    module would silently change every identity. So the encoding does not derive
    a name from the class at all. It looks the class up in a registry this
    module declares.

    The consequences are deliberate. A type that has not been given a
    serialization contract cannot enter an evidence artifact — it fails closed,
    which is also why two unregistered same-named classes cannot collide:
    neither can be serialised at all. Adding a type is an explicit act, and
    changing a registered name is a schema change that must bump SCHEMA.
    """
    name = _TYPE_NAMES.get(t)
    if name is None:
        raise UnserialisableEvidence(
            f"type {t.__module__}.{t.__qualname__} has no registered evidence "
            f"serialization. A short class name is not an identity and a "
            f"module path is not stable, so this module names types explicitly. "
            f"Register it here and bump SCHEMA.")
    return name


def _plain(v: Any) -> Any:
    """Structure-preserving, lossless-for-comparison serialization.

    Decimal becomes its exact string, NOT a float: `Decimal("1.19")` and
    `Decimal("1.190")` are equal numbers with different exponents, and the
    artifact must record what was actually observed. Datetimes carry their
    offset. Enums carry their value and their type, so a value shared by two
    enums cannot collapse. None is written, never omitted — "absent" and
    "explicitly None" are different observations.
    """
    # Enum FIRST. Found by the round-4C2 review of this function: `MarginMode`
    # is a str-enum, so the primitive branch below matched it and returned a
    # bare string, losing the type. Two different enums sharing a value would
    # then serialise identically — the exact collapse this artifact exists to
    # prevent. Order of these checks is a correctness property, not style.
    if isinstance(v, enum.Enum):
        return {"__enum__": _type_id(type(v)), "value": _plain(v.value)}
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        # A float in safety evidence is itself a defect; record it verbatim
        # rather than silently normalising it away.
        return {"__float__": repr(v)}
    if isinstance(v, Decimal):
        return {"__dec__": str(v)}
    if isinstance(v, _dt.datetime):
        return {"__dt__": v.isoformat(),
                "tz": (None if v.tzinfo is None else str(v.utcoffset()))}
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return {"__type__": _type_id(v.__class__),
                "fields": {f.name: _plain(getattr(v, f.name))
                           for f in dataclasses.fields(v)}}
    if isinstance(v, (list, tuple)):
        # ORDER IS PRESERVED, deliberately. The venue's ordering is part of what
        # was observed. R4A already guarantees that ordering cannot change a
        # verdict, so preserving it here costs nothing and records more.
        return {"__seq__": [_plain(x) for x in v]}
    if isinstance(v, (set, frozenset)):
        # A set has no order, so it is serialised SORTED — the same set always
        # produces the same bytes. Found when the fail-closed rule above caught
        # a frozenset already present in the authoritative state, which is the
        # mechanism doing its job at build time instead of emitting an unstable
        # identity at run time.
        return {"__set__": sorted((_plain(x) for x in v), key=repr)}
    if isinstance(v, dict):
        # C3-I4B. `{str(k): ...}` collapsed key `1` and key `"1"` onto one JSON
        # name and DROPPED an entry — a safety artifact silently losing data. A
        # map is now a canonical SEQUENCE of [serialised key, serialised value]
        # pairs: keys keep their type, nothing collides, and nothing is lost.
        # Sorting is by the serialised key's canonical text, so ordering does
        # not depend on Python's cross-type comparison rules or on insertion
        # order.
        items = [[_plain(k), _plain(v[k])] for k in v]
        items.sort(key=lambda kv: json.dumps(kv[0], sort_keys=True,
                                             separators=(",", ":")))
        return {"__pairs__": items}
    # Found by the round-4C2 review of this function: the fallback was
    # `repr(v)`, which for an ordinary object embeds a memory address. Two runs
    # observing the identical world would then produce DIFFERENT content ids,
    # and the identity would stop being a function of what was observed. An
    # unserialisable type is a schema question for whoever adds it, so it fails
    # closed here rather than producing an identity nobody can reproduce.
    raise UnserialisableEvidence(
        f"authorisation evidence contains a {type(v).__name__}, which has no "
        f"defined serialization. Its identity would not be reproducible, so "
        f"the artifact cannot be built. Give the type an explicit "
        f"serialization in this module and bump SCHEMA.")


def serialize(*, view: Any, now: _dt.datetime, lease_epoch: Optional[int],
              intended: Any, limits: Any, policy_version: str,
              journal_seq: int, journal_hash: str) -> bytes:
    """Everything needed to RE-DERIVE the verdict, not merely to name it.

    SAFETY CLOSURE ROUND 4C3, C3-I3. v1 carried `intended_digest` and
    `limits_version` — hashes of in-memory objects — and a comment asserting
    that "the journal already holds that history immutably". It did not say
    WHICH history: no journal head, no prefix, nothing an auditor could resolve.
    A hash proves equality only against an original you still have, and there
    was no original. So the local state and the limits are now carried
    STRUCTURALLY, and the journal head they were read at is recorded so the
    claim can be checked rather than assumed.

    `journal_seq` and `journal_hash` are the last committed record at the moment
    of the observation. They pin the durable history to an immutable prefix, so
    later appends cannot change what this artifact refers to.
    """
    doc = {
        "schema": SCHEMA,
        "now": _plain(now),
        "lease_epoch": lease_epoch,
        "policy_version": policy_version,
        "journal_seq": journal_seq,
        "journal_hash": journal_hash,
        "intended": _plain(intended),
        "limits": _plain(limits),
        "view": _plain(view),
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def put(store: BlobStore, **kw) -> Tuple[str, bytes]:
    """Make the evidence durable and return (content id, bytes).

    The caller must do this BEFORE the durable INTENT, which must be before the
    exchange mutation. Ordering is the whole point: evidence written after the
    mutation is not what authorised it.
    """
    data = serialize(**kw)
    return store.put(data), data


def load(store: BlobStore, cid: str) -> Dict[str, Any]:
    """Recover the exact evidence from disk alone, or fail closed."""
    try:
        data = store.get(cid)
    except BlobMissing:
        raise EvidenceUnavailable(
            f"no authorisation evidence stored under {cid[:16]}…. The durable "
            f"record names evidence that is not on disk, so what authorised "
            f"this mutation cannot be established.")
    except BlobCorrupted as e:
        raise EvidenceUnavailable(
            f"the authorisation evidence under {cid[:16]}… is corrupted: {e}")
    doc = json.loads(data.decode("utf-8"))
    if doc.get("schema") != SCHEMA:
        raise EvidenceUnavailable(
            f"authorisation evidence {cid[:16]}… declares schema "
            f"{doc.get('schema')!r}, which this reader does not understand. "
            f"Refusing to guess at its meaning.")
    if BlobStore.content_id(data) != cid:
        raise EvidenceUnavailable(f"content id mismatch for {cid[:16]}…")
    return doc


# ----------------------------------------------------------------------
# THE REGISTRY. Every type that may appear in an authoritative artifact,
# named explicitly. Nothing else can be serialised.
# ----------------------------------------------------------------------
def _register_known_types() -> None:
    from orbit.core.precision import InstrumentSpec
    from orbit.exec.protection import MarginMode
    from orbit.exec.recon import (ExchangeOrder, ExchangePosition, ExchangeView,
                                  Fill, IntendedPosition, IntendedState,
                                  OrderStatus, SubmittedOrder)
    from orbit.risk.limits import A1Limits
    for t, n in ((ExchangeView, "ExchangeView"),
                 (ExchangePosition, "ExchangePosition"),
                 (ExchangeOrder, "ExchangeOrder"),
                 (Fill, "Fill"),
                 (MarginMode, "MarginMode"),
                 (OrderStatus, "OrderStatus"),
                 (IntendedState, "IntendedState"),
                 (IntendedPosition, "IntendedPosition"),
                 (SubmittedOrder, "SubmittedOrder"),
                 (A1Limits, "A1Limits"),
                 (InstrumentSpec, "InstrumentSpec")):
        _register(t, n)


_register_known_types()


def revive(doc: Any) -> Any:
    """Turn a serialized artifact back into the objects it was made from.

    SAFETY CLOSURE ROUND 4C3, C3-I3. Without this, "everything needed to
    re-derive the verdict" was an assertion nobody could act on: an auditor
    could read fields but not re-run `reconcile` or the gateway. This is why the
    type registry earns its cost — it maps a name back to a class, so the
    artifact is genuinely round-trippable rather than merely readable.

    Reviving is STRICT. An unknown type name or an unknown tag fails closed
    rather than returning something approximate, because an approximate
    reconstruction that then reproduces the verdict would prove nothing.
    """
    if doc is None or isinstance(doc, (bool, int, str)):
        return doc
    if isinstance(doc, list):
        return [revive(x) for x in doc]
    if not isinstance(doc, dict):
        raise EvidenceUnavailable(f"cannot revive {type(doc).__name__}")
    if "__dec__" in doc:
        return Decimal(doc["__dec__"])
    if "__dt__" in doc:
        return _dt.datetime.fromisoformat(doc["__dt__"])
    if "__float__" in doc:
        return float(doc["__float__"])
    if "__enum__" in doc:
        return _lookup(doc["__enum__"])(revive(doc["value"]))
    if "__seq__" in doc:
        return tuple(revive(x) for x in doc["__seq__"])
    if "__set__" in doc:
        return frozenset(revive(x) for x in doc["__set__"])
    if "__pairs__" in doc:
        return {revive(k): revive(v) for k, v in doc["__pairs__"]}
    if "__type__" in doc:
        cls = _lookup(doc["__type__"])
        return cls(**{k: revive(v) for k, v in doc["fields"].items()})
    raise EvidenceUnavailable(
        f"cannot revive an object with tags {sorted(doc)}")


def _lookup(name: str) -> type:
    t = _TYPES_BY_NAME.get(name)
    if t is None:
        raise EvidenceUnavailable(
            f"evidence names type {name!r}, which this reader does not know. "
            f"Refusing to approximate it.")
    return t
