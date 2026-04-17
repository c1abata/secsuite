# TCPENT Safety Model

TCPENT is intentionally defensive, read-only and fail-closed.

`scripts/off` is a separate lab-only simulation module. It is disabled by default, outside the defensive workflow pipeline, and must only be used in isolated authorized environments.

## Non-negotiable controls

- No exploit execution.
- No brute-force, password attacks, spraying or coercion.
- No remote command execution on targets.
- No target state change.
- No persistence mechanisms.

## Allowed behavior

- Passive discovery and inventory.
- Read-only protocol exposure checks.
- Defensive AD audit.
- Deterministic reporting with audit trail and hash chain.

## Enforcement strategy

- Safety module blocks denied categories at runtime.
- Workflow compliance gate blocks/limits execution when legal evidence is missing.
- Threat validation profiles enforce safe nmap arguments (`-Pn --disable-arp-ping`).
