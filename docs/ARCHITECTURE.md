# Architecture for review

ORBIT separates observation, decision context, authorization, durable intent, and the exchange boundary. Read the actual call paths in `orbit/tools/session.py`, `orbit/risk/gateway.py`, and `orbit/exec/adapter.py`; the outline below is a navigation aid, not an independent safety proof.

```text
Observed exchange view + local journal-derived state
                       |
             reconciliation and evidence
                       |
            decision / proposed action
                       |
                  risk gateway
                       |
                 durable intent
                       |
      adapter boundary: writer fencing + intent checks
                       |
          abstract / null / test adapter
```

## Durable state

`orbit/audit/journal.py` records events with sequence numbers and a hash chain. A separately maintained checkpoint anchors committed state. The implementation distinguishes an uncommitted torn tail from corruption of retained records. Hash chaining is not writer authentication, and its claims depend on the journal/checkpoint access model.

`orbit/audit/recovery.py` derives recovery information from durable records. Do not infer permission to trade from a single field such as `durable_state_trusted`; the status document explains the outstanding integration gate.

## Writer and exchange boundary

`orbit/exec/writer.py` represents writer authority. `orbit/exec/adapter.py` checks fencing and durable intent at the mutation boundary. Abstract interfaces and null/test implementations allow offline behavior to be reviewed; this snapshot contains no real venue adapter.

## Observations and risk

`orbit/exec/recon.py` compares exchange observations with local state. `orbit/risk/gateway.py` decides whether a proposed action meets its checks and limits. The R4-5 repair refuses future-dated observations and missing server time; it does not provide tolerance for impossible local timestamps.

## Review the joins

The most useful review targets are the joins between modules: what a caller may assume, which data is durable, and whether authorization uses the same action-specific state that evidence records. A module-level test is not automatically proof of a complete assembled startup or trading flow.
