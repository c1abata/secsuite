# TCPENT Threat Model

## Goal

TCPENT supports vulnerability assessment and defensive penetration testing validation only when formally authorized and scoped.

## Primary misuse risks

- Running the suite outside approved scope.
- Collecting sensitive evidence without handling policy.
- Executing invasive actions under the pretext of assessment.
- Producing untraceable outputs that cannot be audited.

## Trust assumptions

- Operator has formal authorization.
- Rules of engagement and scope are approved before execution.
- Targets are provided by authorized stakeholders.
- Output storage is protected.

## Implemented mitigations

- Compliance gate with explicit `Approved | ReviewRequired | Blocked` statuses.
- Structured evidence checks (authorization, ROE, scope, targets, retention).
- Operation-level logging (`operations.ndjson`) and hash chain (`hashchain.ndjson`).
- Safe scan profiles with no offensive payloads.

## Residual risk

- External tools (for example `nmap`) availability impacts active execution.
- Output quality depends on target list quality.
- AD depth depends on environment and credentials.
