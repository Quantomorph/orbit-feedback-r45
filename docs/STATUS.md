# Status and known limitations

This is the accepted historical R4-5 checkpoint. Its acceptance was scoped engineering acceptance, not production approval. Later private exchange-integration and bridge work is excluded.

The limitations below summarize private reviews. Their private finding IDs are not consistently present in the code; use the module navigation rather than searching for those IDs.

| Area | Limitation and next evidence needed |
| --- | --- |
| Executing policy evidence | Gateway and audit decision evidence do not fully establish the actual executing policy identity. A closing change must bind durable evidence to the real policy/configuration, including non-default settings. |
| Pre-intent refusals | Tool-session and audit evidence do not durably recover every normalized refused proposed action. A closing change must show recovery after restart without process memory or an intent record. |
| Recovery trust | In `orbit/audit/recovery.py`, durable-state trust alone does not establish recovery completion or permission to trade. Assembled callers need separately reviewed authorization conditions. |
| Startup/recovery integration | The complete recovery, tool-session, and gateway flow remains separately gated. Complete failure-transition evidence is required before execution integration. |
| Other recovery/domain items | Further recorded follow-ups are not described publicly in detail. Their precise public scope needs a separate specification before any claim of closure. |
| Decision state interpretation | `orbit/tools/session.py` records model-facing state that must be distinguished from action-authorization state re-derived later. Evidence and documentation must make that distinction explicit. |

These are retained review limitations, not newly reproduced defects. Omission from this table does not establish that an area is closed.

R4-5 discharged its specific freshness prerequisite. It did not authorize a venue adapter, assembled recovery, model execution, demo/live trading, or use of capital.

## Historical reproducer

`tests/repro_before_a1.py` targets an earlier harness. Its F2 printed verdict is stale under the later execution-time default; see the README for the corrected interpretation and the current regression scripts. Historical bytes are retained unchanged.

## Private references and evidence limits

Source comments that refer to a ledger, a decision list, approval dates, or finding IDs point to private governance records that are not part of this snapshot. They are historical context, not publicly inspectable authority or permission to execute.

The 2026-10-13 Linux rerun is fresh evidence for the unchanged source, not a complete safety verdict. Deterministic identical log bytes alone do not establish independent runs.
