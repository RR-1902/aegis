# Response in AEGIS

AEGIS currently implements a **simulation-only response layer** with this
boundary:

```text
ResponseDecision -> ResponseEngine -> ResponseResult
```

A future executor phase may later extend this to:

```text
ResponseEngine -> ActionExecutor
```

## Separation of responsibilities

- **Policy** decides what is permitted or recommended
- **Response** validates and handles that structured decision
- **Executor** would later perform platform-specific system changes

The current `ResponseEngine` does not execute actions.

## Simulation-only status

This phase does **not** implement:

- firewall modification
- Windows `netsh`
- PowerShell firewall commands
- `iptables` / `nftables` / `ufw`
- subprocess-based execution
- OS/network state modification

## Allowed actions

Current supported actions:

- `LOG_ONLY`
- `ALERT_ONLY`
- `BLOCK_SOURCE`

Unsupported or malformed actions are rejected.

## Validation and fail-closed behavior

Every `ResponseDecision` is validated before handling:

1. decision structure
2. supported action type
3. supported execution mode
4. action-specific consistency
5. target presence
6. target IP validity via `ipaddress`
7. target role validity
8. SAFE_MODE / execution-mode consistency

Invalid or unsupported decisions are rejected. The response layer does not
silently downgrade or invent alternative targets.

## SAFE_MODE

For `BLOCK_SOURCE`:

- `SAFE_MODE=true` -> validate fully, then return `SIMULATED`
- `SAFE_MODE=false` -> validate fully, then reject because no real executor is installed

For `LOG_ONLY` and `ALERT_ONLY`:

- return `NO_ACTION`
- do not simulate or execute external changes

## Truthful simulation

Simulation must explicitly state that no system state changed. AEGIS does not
claim that an IP was actually blocked in this phase.

## Security boundary

The response layer must not:

- execute shell commands
- construct arbitrary subprocess invocations
- modify firewall state
- accept command strings from inputs
- call an LLM to generate commands
