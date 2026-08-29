# Policy in AEGIS

AEGIS currently defines a **stateless conservative policy layer** with this
boundary:

```text
RiskScore -> PolicyEngine -> ResponseDecision
```

## Separation of responsibilities

- **Detection** answers what suspicious behavior was observed
- **Scoring** answers how serious the combined evidence is
- **Policy** answers what response is permitted or recommended
- **Response** would later execute an allowed action

The current `PolicyEngine` does not execute actions.

## Action vocabulary

Current supported policy actions:

- `LOG_ONLY`
- `ALERT_ONLY`
- `BLOCK_SOURCE`

Current execution modes:

- `NONE`
- `SIMULATE`
- `EXECUTE`

## Conservative attribution

A directional or port-bearing `FlowKey` does **not** automatically prove that
`src_ip` is an attacker. Likewise, bidirectional keys do not justify deriving a
block target from canonical endpoint orientation alone.

Therefore automatic `BLOCK_SOURCE` requires explicit defensible source
attribution in the available detection evidence. Without that, policy is
downgraded to `ALERT_ONLY`.

When a target is present, the role is described conservatively as
`observed_source` rather than claiming attacker/victim semantics.

## Risk mapping

Current conservative behavior:

- `LOW` -> `LOG_ONLY`
- `MEDIUM` -> `ALERT_ONLY`
- `HIGH` / `CRITICAL` -> detection-aware decision

`SynFlood` may justify `BLOCK_SOURCE` when explicit observed-source attribution
is available.

`PortScan` may justify `BLOCK_SOURCE` only for `CRITICAL` risk and only when
explicit observed-source attribution is available.

## SAFE_MODE

`SAFE_MODE` changes execution disposition, not the policy recommendation.

For actionable recommendations:

- `SAFE_MODE=true` -> `SIMULATE`
- `SAFE_MODE=false` -> `EXECUTE`

For `LOG_ONLY` or `ALERT_ONLY`:

- execution mode remains `NONE`

## Recommended vs allowed

`ResponseDecision` separates:

- recommended action
- whether the action is allowed
- whether a future response layer should simulate or execute it

Normal valid policy decisions use `allowed=true`. Unsafe automatic blocking is
handled by downgrading to a safer recommendation rather than by returning a
normal `allowed=false` decision.

## Security boundary

The policy layer is side-effect free. It does not:

- invoke a response engine
- execute shell commands
- modify firewall state
- call OS/network configuration APIs
- call an LLM
