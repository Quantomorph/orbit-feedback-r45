"""
tests/test_safety_closure_r4c4_jseq.py — ORBIT A1 SAFETY CLOSURE, ROUND 4C4,
FINDING R4C4-JSEQ-1: JOURNAL SEQUENCE CONTIGUITY.

THE DEFECT (recorded as NOTE-3 by the F4 independent review; pre-existing and
broader than F4).

    `Journal.load()` verified two things about every record: that its own hash
    is correct, and that its `prev_hash` is its predecessor's hash. It never
    looked at `seq`.

    `seq` is hashed as ORDINARY BODY CONTENT — `make_record` puts it in `body`
    and hashes the lot — so a chain re-generated end to end carries whatever
    numbering its author chose and every hash still verifies. The chain proves
    each record follows THE record before it. It does not prove that record was
    the one whose sequence number it claims.

    Reproduced against the accepted F4 checkpoint (e8c35a51), every one of these
    hash-valid chains loaded `trusted=True`:

        [5, 6, 7]   -> trusted=True    (no record 1..4 ever existed)
        [1, 2, 4]   -> trusted=True    (a committed record is simply gone)
        [1, 2, 2]   -> trusted=True    (two records hold one sequence number)
        [1, 3, 2]   -> trusted=True    (the numbering goes backwards)
        [0, 1, 2]   -> trusted=True    (starts below the initial sequence)
        [1, 1, 1]   -> trusted=True

    Worse than a bad read: `Journal.__init__` and `_prepare_locked` take the
    next sequence number from `records[-1]["seq"]`, so a journal ending at a
    DUPLICATE or a DECREASED seq hands the next writer a number that has
    already been used — the loader minted the collision it exists to detect.

THE SUPPORTED SEQUENCE MODEL, established before repairing anything.

    ORBIT has NO compaction, NO rotation, NO prefix truncation of the journal
    file, NO snapshot-based sequence offset and NO non-1 start. The file is
    append-only (`journal.py`: "There is no update and no delete"), `Journal`
    begins at `_seq = 0` and every write is `_seq + 1`, and the torn-tail
    repair continues the same numbering. The only "prefix" in the system is a
    READ-SIDE filter over an already-loaded list — `derive_intended` keeps
    `seq <= pinned` and `OperationLedger.from_records` folds what it is handed
    — which takes a PREFIX and therefore preserves contiguity from 1.

    `test_safety_closure.py` G4 already asserted "sequence numbers are
    contiguous from 1" as an OBSERVED property of a journal ORBIT wrote. It was
    never an ENFORCED property of a journal ORBIT read. That gap is the finding.

WHAT IS ASSERTED HERE.

    J1  A valid contiguous journal is still accepted, and still appendable.
    J2  An invalid INITIAL sequence is refused.
    J3  A GAP is refused.
    J4  A DUPLICATE sequence is refused.
    J5  A DECREASING sequence is refused.
    J6  HASH-VALID IS NOT ENOUGH: a chain whose every hash and every prev_hash
        link verifies, checked independently of the loader, is still refused on
        its numbering alone. This is the finding, stated as an assertion.
    J7  A malformed `seq` — a string, a float, a bool, or absent — is refused
        rather than coerced, because it is used as an integer to number the
        next append.
    J8  EXISTING BEHAVIOUR IS PRESERVED: recovery, the checkpoint protocol, the
        torn tail (W4), and the append path's fail-closed refusal.
    J9  THE F4 REPAIR IS INTACT: the one-record-behind window still proves its
        hash, and the empty-hash policy is untouched (NOTE-2).
    J10 MI-1: the `prior is None / head.seq > 0` refusal branch of
        `classify_head`, asserted directly.
    J11 R4C4-JSEQ-1-T1: the adjudication above does NOT depend on the file
        ending in a newline. A hash-valid but sequence-invalid FINAL record is
        TAMPERING whether or not the file is newline-terminated, because no
        crash can produce one.

WHAT THIS DOES NOT CLAIM. Contiguity does not make a forged history detectable
on its own. An actor who re-generates the whole chain AND renumbers it
contiguously AND rewrites the checkpoint beside it produces something this
cannot distinguish from the truth — exactly the limit `checkpoint.py` already
states: no defence against write access to BOTH files. What JSEQ-1 closes is
narrower and real: a chain that is internally hash-consistent but whose
numbering contradicts itself is no longer accepted as history.

No network. No credentials. No model. No live capital.
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from orbit.audit.checkpoint import HeadCheckpoint, classify_head
from orbit.audit.journal import (INITIAL_SEQ, Journal, SimulatedCrash,
                                 TamperedJournalError, Fault, CrashPoint)
from orbit.audit.records import (E, GENESIS, canonical, event, make_record,
                                 record_hash, verify_record)
from orbit.audit.recovery import recover

PASS, FAIL = [], []
TMP = tempfile.mkdtemp(prefix="orbit_jseq_")
_n = [0]


def check(name, ok, detail=""):
    if ok:
        PASS.append(name)
    else:
        FAIL.append(f"{name} :: {detail}")


def _path(tag):
    _n[0] += 1
    return os.path.join(TMP, f"{tag}_{_n[0]}.jsonl")


def real_journal(n, tag):
    """A journal ORBIT actually wrote, holding n committed records."""
    p = _path(tag)
    j = Journal(p)
    for i in range(n):
        j.append_one(E.REMEDIATION, None, note=f"r{i}")
    return p, Journal.load(p).records


# R4C4 DF-R1. The evaluation clock for reports taken over a forged chain.
# It is the instant `forge` stamps on every record it builds, so it is this
# fixture's OWN time and not an ambient one.
FORGED_NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def forge(tag, seqs, bodies=None, newline=True):
    """A FULLY HASH-VALID chain carrying exactly `seqs` as its numbering.

    Every record is built by `make_record`, so every hash is genuine and every
    `prev_hash` links. Nothing here is corrupt in the sense the chain can see;
    only the numbering is a lie.

    `newline=False` omits the terminating newline after the FINAL record only.
    That single byte is what the loader uses to recognise a torn write, so it
    is the one axis on which the adjudication of a sequence-invalid final
    record could silently change (R4C4-JSEQ-1-T1; see J11).
    """
    p = _path(tag)
    prev = GENESIS
    with open(p, "w") as fh:
        for i, s in enumerate(seqs):
            rec = make_record(s, "2026-01-01T00:00:00+00:00",
                              [event(E.REMEDIATION, None, note=f"s{i}")], prev)
            last = (i == len(seqs) - 1)
            fh.write(canonical(rec) + ("" if last and not newline else "\n"))
            prev = rec["hash"]
    return p


def raw_records(path):
    import json
    with open(path) as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def chain_is_hash_valid(path):
    """Verify the hash chain WITHOUT the loader, so J6 does not prove itself
    with the very code under test."""
    prev = GENESIS
    for rec in raw_records(path):
        if not verify_record(rec) or rec["prev_hash"] != prev:
            return False
        prev = rec["hash"]
    return True


def refused(path):
    lr = Journal.load(path)
    return (lr.tamper_detected and not lr.trusted), lr


# ======================================================================
# J1 — THE VALID CASE IS STILL VALID
# ======================================================================
p, recs = real_journal(4, "j1")
lr = Journal.load(p)
check("J1.1 a contiguous journal ORBIT wrote loads TRUSTED",
      lr.trusted and not lr.tamper_detected, lr.reason)
check("J1.2 and its numbering is 1..N, from the authoritative initial sequence",
      [r["seq"] for r in lr.records] == list(range(INITIAL_SEQ, 5)),
      str([r["seq"] for r in lr.records]))
Journal(p).append_one(E.REMEDIATION, None, note="still appendable")
lr2 = Journal.load(p)
check("J1.3 and it is still appendable, contiguously",
      lr2.trusted and [r["seq"] for r in lr2.records] == [1, 2, 3, 4, 5],
      f"trusted={lr2.trusted} seqs={[r['seq'] for r in lr2.records]}")

p2 = forge("j1_forged_ok", [1, 2, 3])
lr = Journal.load(p2)
check("J1.4 a hand-built contiguous chain is accepted too — the rule is "
      "contiguity, not provenance",
      lr.trusted and len(lr.records) == 3, lr.reason)

# ======================================================================
# J2 — INVALID INITIAL SEQUENCE
# ======================================================================
for tag, seqs in [("j2_five", [5, 6, 7]), ("j2_zero", [0, 1, 2]),
                  ("j2_neg", [-1, 0, 1]), ("j2_two", [2, 3, 4])]:
    p = forge(tag, seqs)
    ok, lr = refused(p)
    check(f"J2 a journal beginning at seq {seqs[0]} instead of {INITIAL_SEQ} "
          f"is REFUSED", ok, f"trusted={lr.trusted} reason={lr.reason[:80]!r}")
    check(f"J2 and the refusal for {seqs[0]} names the initial sequence",
          "initial sequence" in lr.reason, lr.reason[:90])
    check(f"J2 and no record from the {seqs[0]}-based chain is retained",
          lr.records == [], f"{len(lr.records)} retained")

# ======================================================================
# J3 — GAP
# ======================================================================
p = forge("j3", [1, 2, 4, 5])
ok, lr = refused(p)
check("J3.1 a sequence GAP is REFUSED", ok,
      f"trusted={lr.trusted} reason={lr.reason[:80]!r}")
check("J3.2 the refusal says the numbering SKIPS, and where",
      "skips" in lr.reason and "seq 4" in lr.reason, lr.reason[:110])
check("J3.3 only the records BEFORE the gap are retained",
      [r["seq"] for r in lr.records] == [1, 2],
      str([r["seq"] for r in lr.records]))

p = forge("j3_tail", [1, 2, 3, 99])
ok, lr = refused(p)
check("J3.4 a gap in the FINAL record is refused, not excused as a torn tail",
      ok, f"trusted={lr.trusted} discarded={lr.discarded_tail}")
check("J3.5 and it is classified as tampering, not as a discarded tail",
      lr.tamper_detected and lr.discarded_tail == 0,
      f"tamper={lr.tamper_detected} discarded={lr.discarded_tail}")

# ======================================================================
# J4 — DUPLICATE
# ======================================================================
p = forge("j4", [1, 2, 2, 3])
ok, lr = refused(p)
check("J4.1 a DUPLICATE sequence number is REFUSED", ok,
      f"trusted={lr.trusted} reason={lr.reason[:80]!r}")
check("J4.2 the refusal says the numbering repeats or goes backwards",
      "repeats or goes backwards" in lr.reason, lr.reason[:110])

p = forge("j4_all", [1, 1, 1])
ok, lr = refused(p)
check("J4.3 a journal that repeats ONE sequence number throughout is REFUSED",
      ok, f"trusted={lr.trusted}")

# The reason this matters beyond the read: the duplicate tail used to become
# the next writer's base.
p = forge("j4_next", [1, 2, 2])
before = raw_records(p)
try:
    Journal(p).append_one(E.REMEDIATION, None, note="must not land")
    landed = True
except TamperedJournalError:
    landed = False
check("J4.4 a duplicated tail can no longer become the next writer's base: "
      "the append is REFUSED",
      landed is False, "the append was accepted onto a duplicated sequence")
check("J4.5 and the refusal wrote nothing to the journal",
      raw_records(p) == before, "the refused append still changed the file")

# ======================================================================
# J5 — DECREASING
# ======================================================================
p = forge("j5", [1, 3, 2])
ok, lr = refused(p)
check("J5.1 a DECREASING sequence is REFUSED", ok,
      f"trusted={lr.trusted} reason={lr.reason[:80]!r}")
check("J5.2 and it is caught at the first record that contradicts its "
      "position, not only at the decrease",
      [r["seq"] for r in lr.records] == [1],
      str([r["seq"] for r in lr.records]))

p = forge("j5_back", [1, 2, 3, 2])
ok, lr = refused(p)
check("J5.3 a journal whose numbering goes BACKWARDS at the tail is REFUSED",
      ok, f"trusted={lr.trusted}")

# ======================================================================
# J6 — HASH-VALID IS NOT ENOUGH.  THIS IS THE FINDING.
# ======================================================================
for tag, seqs, what in [("j6_start", [5, 6, 7], "a non-1 start"),
                        ("j6_gap", [1, 2, 4], "a gap"),
                        ("j6_dup", [1, 2, 2], "a duplicate"),
                        ("j6_dec", [1, 3, 2], "a decrease")]:
    p = forge(tag, seqs)
    check(f"J6 {what}: the chain's OWN evidence is intact — every hash "
          f"verifies and every prev_hash links",
          chain_is_hash_valid(p), "the forged chain was not actually valid, "
                                  "so this case proves nothing")
    ok, lr = refused(p)
    check(f"J6 {what}: and the journal is REFUSED ANYWAY, on its numbering "
          f"alone", ok, f"trusted={lr.trusted} reason={lr.reason[:80]!r}")

# The counterpart: the loader must not have started refusing on hash grounds.
p = forge("j6_control", [1, 2, 3])
check("J6 control: the same construction with honest numbering is hash-valid "
      "AND accepted — the refusals above are about seq, nothing else",
      chain_is_hash_valid(p) and Journal.load(p).trusted)

# ======================================================================
# J7 — A MALFORMED seq IS REFUSED, NOT COERCED
# ======================================================================
def forge_one(tag, seq_value, omit=False):
    """One hash-valid record whose `seq` is whatever we say (or is absent)."""
    p = _path(tag)
    body = {"ts": "2026-01-01T00:00:00+00:00",
            "events": [event(E.REMEDIATION, None)], "prev_hash": GENESIS}
    if not omit:
        body["seq"] = seq_value
    body["hash"] = record_hash(GENESIS, body)
    with open(p, "w") as fh:
        fh.write(canonical(body) + "\n")
    return p, body


for tag, val, label in [("j7_str", "1", "the string \"1\""),
                        ("j7_float", 1.0, "the float 1.0"),
                        ("j7_bool", True, "the bool True (int subclass, == 1)"),
                        ("j7_null", None, "null")]:
    p, body = forge_one(tag, val)
    check(f"J7 {label} is hash-valid — the chain cannot object to it",
          verify_record(body), "construction error")
    ok, lr = refused(p)
    check(f"J7 {label} is REFUSED as a sequence number", ok,
          f"trusted={lr.trusted} reason={lr.reason[:80]!r}")

p, body = forge_one("j7_missing", None, omit=True)
check("J7 a record with NO seq field at all is hash-valid",
      verify_record(body) and "seq" not in body, "construction error")
ok, lr = refused(p)
check("J7 and it is REFUSED rather than defaulted", ok,
      f"trusted={lr.trusted} reason={lr.reason[:80]!r}")

# ======================================================================
# J8 — EXISTING BEHAVIOUR IS PRESERVED
# ======================================================================
p, recs = real_journal(3, "j8_rec")
rep = recover(p)
check("J8.1 recovery over a valid journal still reports it TRUSTED",
      rep.journal_trusted, str(rep.notes))

p = forge("j8_bad", [1, 2, 4])
# R4C4 DF-R1. Explicit clock, so J8.4 below is attributable to the refused
# numbering (UNDERIVABLE:JOURNAL_UNTRUSTED) and not to an unstated "today".
rep = recover(p, now=FORGED_NOW)
check("J8.2 recovery over a sequence-invalid journal reports it UNTRUSTED",
      rep.journal_trusted is False, "recovery trusted a broken numbering")
check("J8.3 and says why, in the recovery notes",
      any("UNTRUSTED" in n and "contiguous" in n for n in rep.notes),
      str(rep.notes))
check("J8.4 and durable state is therefore NOT trusted "
      "(NO TRUSTED DURABLE STATE = NO NEW ENTRY)",
      rep.durable_state_trusted is False)

# The checkpoint protocol still advances with each commit.
p, recs = real_journal(3, "j8_cp")
check("J8.5 the committed-head checkpoint still tracks the journal head",
      HeadCheckpoint(p).read().seq == 3 and
      HeadCheckpoint(p).read().hash == recs[-1]["hash"],
      f"head={HeadCheckpoint(p).read().seq}")

# W4 — the torn tail is still a crash, not corruption, and the repair the
# append path performs still produces CONTIGUOUS numbering.
p = _path("j8_torn")
j = Journal(p)
j.append_one(E.RUN_START, None)
j.append_one(E.REMEDIATION, None, note="second")
with open(p, "a") as fh:
    fh.write('{"seq": 3, "ts": "2026-01-01T00:00')      # torn, no newline
lr = Journal.load(p)
check("J8.6 a TORN final record is still discarded as uncommitted, not called "
      "tampering (W4 is intact)",
      lr.trusted and lr.discarded_tail == 1 and not lr.tamper_detected,
      f"trusted={lr.trusted} discarded={lr.discarded_tail} {lr.reason[:60]}")
Journal(p).append_one(E.REMEDIATION, None, note="after repair")
lr = Journal.load(p)
check("J8.7 and the torn-tail repair still yields a CONTIGUOUS journal",
      lr.trusted and [r["seq"] for r in lr.records] == [1, 2, 3, 4],
      f"trusted={lr.trusted} seqs={[r['seq'] for r in lr.records]}")

# A crash mid-append still leaves a loadable, contiguous journal.
p = _path("j8_crash")
Journal(p).append_one(E.RUN_START, None)
try:
    Journal(p, fault=Fault(at_seq=2, point=CrashPoint.TORN)).append_one(
        E.REMEDIATION, None, note="crash")
except SimulatedCrash:
    pass
lr = Journal.load(p)
check("J8.8 an injected mid-write crash still loads TRUSTED with its prefix",
      lr.trusted and [r["seq"] for r in lr.records] == [1],
      f"trusted={lr.trusted} seqs={[r['seq'] for r in lr.records]}")

# ======================================================================
# J9 — THE F4 REPAIR IS INTACT
# ======================================================================
p, recs = real_journal(3, "j9_right")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])   # one behind, CORRECT
v = classify_head(p, recs, 0)
lr = Journal.load(p)
check("J9.1 F4: a one-record-behind head naming the CORRECT record is still "
      "the legitimate crash window, and still loads TRUSTED",
      v.ok and v.window and lr.trusted and lr.head_window,
      f"ok={v.ok} window={v.window} trusted={lr.trusted}")
check("J9.2 F4: and it still names the roll-forward target",
      v.roll_to_seq == 3 and v.roll_to_hash == recs[2]["hash"],
      f"roll_to={v.roll_to_seq}")
Journal(p).append_one(E.REMEDIATION, None, note="closes")
check("J9.3 F4: and an append still closes that window under the append lock",
      HeadCheckpoint(p).read().seq == 4,
      f"head={HeadCheckpoint(p).read().seq}")

p, recs = real_journal(3, "j9_wrong")
HeadCheckpoint(p)._write_unchecked(2, "d" * 64)          # one behind, WRONG
v = classify_head(p, recs, 0)
lr = Journal.load(p)
check("J9.4 F4: a one-record-behind head naming the WRONG record still fails "
      "closed",
      v.ok is False and v.window is False and lr.trusted is False,
      f"ok={v.ok} window={v.window} trusted={lr.trusted}")

p, recs = real_journal(3, "j9_empty")
HeadCheckpoint(p)._write_unchecked(2, "")
v = classify_head(p, recs, 0)
check("J9.5 NOTE-2: the empty-hash policy is UNCHANGED by JSEQ-1 — a head "
      "carrying no hash is still tolerated",
      v.ok is True and v.window is True, f"ok={v.ok} window={v.window}")

p, recs = real_journal(3, "j9_ahead")
HeadCheckpoint(p)._write_unchecked(5, "e" * 64)
lr = Journal.load(p)
check("J9.6 R3-6: a checkpoint AHEAD of the journal still fails closed",
      lr.trusted is False and "missing" in lr.reason, lr.reason[:80])

p, recs = real_journal(4, "j9_lag")
HeadCheckpoint(p)._write_unchecked(2, recs[1]["hash"])
lr = Journal.load(p)
check("J9.7 R3-6: a lag of two or more still fails closed",
      lr.trusted is False and "behind" in lr.reason, lr.reason[:80])

# ======================================================================
# J10 — MI-1, ASSERTED DIRECTLY
# ======================================================================
# `classify_head` is a PURE, public classifier over a caller-supplied record
# list. Its `prior is None / head.seq > 0` branch refuses a one-behind head
# whose named sequence is not among the records it was given. The branch was
# load-bearing and had no assertion of its own (MI-1). It is asserted here
# against the function directly — no production behaviour is changed, and
# nothing about the branch is weakened.
#
# Note for the reviewer: after JSEQ-1, `Journal.load` can no longer REACH this
# branch, because it now refuses a non-contiguous record list before
# `classify_head` ever sees one, and in a contiguous 1..N list the record at
# seq N-1 always exists. The branch remains correct and load-bearing for direct
# callers of `classify_head` / `verify_against_head`, which is exactly what is
# exercised below.
p, recs = real_journal(4, "j10")
HeadCheckpoint(p)._write_unchecked(3, recs[2]["hash"])    # one behind, correct
missing_prior = [r for r in recs if r["seq"] != 3]        # drop the named one
v = classify_head(p, missing_prior, 0)
check("J10.1 MI-1: a one-behind head naming a seq that is NOT among the "
      "records is REFUSED",
      v.ok is False, f"ok={v.ok} window={v.window}")
check("J10.2 MI-1: it is not treated as the legitimate crash window",
      v.window is False, f"window={v.window}")
check("J10.3 MI-1: the refusal names the missing sequence and says the "
      "journal cannot be shown complete",
      "not among the retained records" in v.reason and "seq 3" in v.reason,
      v.reason[:110])
check("J10.4 MI-1: a refused window offers no roll-forward target",
      v.roll_to_seq == 0 and v.roll_to_hash == "",
      f"roll_to={v.roll_to_seq}/{v.roll_to_hash[:16]}")

# The seq-0 genesis head is the documented exception and must NOT be caught by
# that branch: there is no record to name, so there is nothing to compare.
p2 = _path("j10_genesis")
j = Journal(p2)
j.append_one(E.RUN_START, None)
g = Journal.load(p2).records
HeadCheckpoint(p2)._write_unchecked(0, "")
v = classify_head(p2, g, 0)
check("J10.5 MI-1: the seq-0 genesis head is still the documented exception, "
      "not a refusal",
      v.ok is True and v.window is True, f"ok={v.ok} reason={v.reason[:70]}")


# ======================================================================
# J11 — R4C4-JSEQ-1-T1: NO TERMINATING NEWLINE IS NOT A TORN TAIL
# ======================================================================
# The independent review of R4C4-JSEQ-1 demonstrated mutation M4: the
# sequence-violation branch of `Journal.load` can be changed to hand the
# torn-tail excuse to a FINAL record when the file does not end in a newline —
#
#     if bad_seq:
#         if last and not raw.endswith("\n"):
#             discarded += 1                     # <- forged record repaired away
#         else:
#             tamper = True
#
# — and all 19 suites and all 1058 assertions still passed. J3.4/J3.5 already
# assert the final-record case, but only for a NEWLINE-TERMINATED file, which
# is precisely the side of that branch the mutant leaves alone.
#
# The adjudication the production code states must therefore be asserted on the
# other side too: a fully parseable, hash-valid, sequence-invalid final record
# is TAMPERING regardless of the terminating newline. A crash mid-write leaves
# a BYTE PREFIX of a canonical record — it cannot parse, hash-verify AND carry
# a sequence number the writer never emitted — so the missing newline is not
# evidence of a crash here, and must buy the record nothing.
#
# The class used is the reviewer's: the same sequence-invalid FINAL record as
# J3.4, written without its trailing newline.
p = forge("j11_tail_gap", [1, 2, 3, 99], newline=False)
before = open(p, "rb").read()
check("J11.1 the fixture is what it claims: a final record with NO terminating "
      "newline",
      before.endswith(b"}") and not before.endswith(b"\n"),
      f"last bytes {before[-4:]!r}")
check("J11.2 and the chain's OWN evidence is intact — every hash verifies and "
      "every prev_hash links, so only the numbering is a lie",
      chain_is_hash_valid(p),
      "the forged chain was not actually valid, so this case proves nothing")

ok, lr = refused(p)
check("J11.3 load REFUSES a hash-valid, sequence-invalid FINAL record even "
      "with no terminating newline", ok,
      f"trusted={lr.trusted} reason={lr.reason[:90]!r}")
check("J11.4 tamper_detected is True — this is REWRITING, not a crash",
      lr.tamper_detected is True, f"tamper={lr.tamper_detected}")
check("J11.5 discarded_tail is 0 — the forged record is NOT excused as a torn "
      "tail (this is the assertion M4 fails)",
      lr.discarded_tail == 0, f"discarded={lr.discarded_tail}")
check("J11.6 and the journal is NOT trusted", lr.trusted is False,
      f"trusted={lr.trusted}")
check("J11.7 and the refusal is given on the NUMBERING, naming where it skips, "
      "not on a torn tail",
      "skips" in lr.reason and "seq 99" in lr.reason
      and "torn" not in lr.reason, lr.reason[:120])
check("J11.8 and only the records BEFORE the forged one are retained",
      [r["seq"] for r in lr.records] == [1, 2, 3],
      str([r["seq"] for r in lr.records]))

try:
    Journal(p).append_one(E.REMEDIATION, None, note="must not land")
    raised = None
except TamperedJournalError as exc:
    raised = exc
check("J11.9 a subsequent append raises TamperedJournalError — the forged tail "
      "is never repaired away and never becomes the next writer's base",
      isinstance(raised, TamperedJournalError),
      "the append was accepted onto a sequence-invalid final record")
check("J11.10 and the refused append left the journal bytes UNCHANGED — "
      "nothing was truncated, repaired or appended",
      open(p, "rb").read() == before,
      "the refused append still changed the file")

# The control, on the same axis: the missing newline still means TORN for the
# case it actually describes — a byte prefix that cannot parse. J11 narrows the
# torn-tail excuse; it does not remove it.
p = _path("j11_control")
j = Journal(p)
j.append_one(E.RUN_START, None)
j.append_one(E.REMEDIATION, None, note="second")
with open(p, "a") as fh:
    fh.write('{"seq": 3, "ts": "2026-01-01T00:00')      # torn, no newline
lr = Journal.load(p)
check("J11.11 control: a genuinely TORN final record with no newline is still "
      "discarded as uncommitted, and the journal stays TRUSTED (W4 intact)",
      lr.trusted and lr.discarded_tail == 1 and not lr.tamper_detected,
      f"trusted={lr.trusted} discarded={lr.discarded_tail} {lr.reason[:60]}")


# ======================================================================
print(f"\nRESULTS: {len(PASS)} passed, {len(FAIL)} failed")
for f in FAIL:
    print(f"  FAILED: {f}")
sys.exit(1 if FAIL else 0)
