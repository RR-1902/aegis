# Deterministic validation of AEGIS

AEGIS supports a deterministic validation strategy built around **in-memory
synthetic packets** and the real runtime pipeline.

## Safety of synthetic traffic

Validation helpers build Scapy packet objects **in memory only**.
They do not:

- send packets to the network
- call `scapy.send()`
- call `scapy.sendp()`
- create unbounded loops
- perform flooding
- modify firewall or system state

This allows end-to-end behavioral testing without Npcap, admin privileges, a
real NIC, or dangerous traffic generation.

## Primary validation scenarios

Implemented deterministic validation covers:

- benign normal traffic
- port-scan threshold boundaries
- SYN-flood threshold boundaries
- combined suspicious traffic
- FlowKey strategy sensitivity
- event-time window placement and late-packet behavior
- SecurityEvent identity/persistence
- SAFE_MODE behavior

## Threshold boundaries

Current runtime thresholds under validation:

### PortScanRule

- `19` unique destination ports -> no detection
- `20` -> detection, `MEDIUM`
- `21` -> detection, `HIGH`

### SynFloodRule

- `syn_rate < 10.0` -> no detection
- `syn_rate == 10.0` and `incomplete_connection_ratio == 0.7` -> `MEDIUM`
- `syn_rate > 10.0` and `incomplete_connection_ratio > 0.7` -> `HIGH`

### Risk levels

- `29` -> `LOW`
- `30` -> `MEDIUM`
- `59` -> `MEDIUM`
- `60` -> `HIGH`
- `79` -> `HIGH`
- `80` -> `CRITICAL`

## FlowKey strategy implications

Validation explicitly compares:

- `five_tuple`
- `three_tuple`
- `bidirectional`

Current expected visibility:

- `three_tuple` is the clearest strategy for the current `PortScanRule`
- `five_tuple` fragments multi-port activity across distinct flows
- `bidirectional` preserves current semantics but requires conservative interpretation

## Event-time scenarios

Validation includes:

- packet timestamp determining fixed-window placement
- out-of-order arrivals
- retained late packets
- removed historical windows not being recreated
- sliding overlap membership
- modest future skew acceptance
- excessive future skew rejection

## SAFE_MODE behavior

Validation confirms:

- `SAFE_MODE=true` never performs real enforcement
- simulation must say no system state changed
- `SAFE_MODE=false` still rejects real execution because no `ActionExecutor` exists

## Known heuristic limitations

### Port scan

Possible false positives:
- legitimate discovery
- admin scanning
- monitoring activity

Possible false negatives:
- slow scans
- distributed scans
- `five_tuple` fragmentation

### SYN flood

Possible false positives:
- legitimate bursty connection storms
- load tests

Possible false negatives:
- low-rate floods
- cross-window attacks
- non-TCP floods

## Optional manual live-capture smoke test

Automated correctness does not depend on live capture.

A manual smoke test may be run with:

```bash
python -m app.main
```

Requirements may include:

- Windows admin privileges
- Npcap
- correct `CAPTURE_INTERFACE`

Only benign local/lab traffic should be used. Real blocking is not implemented.
