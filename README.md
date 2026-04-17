# TCPENT

TCPENT is a defensive, modular VA/PT assessment suite in antirez style: minimal surface, deterministic output, strict guardrails.

## What it does

- environment readiness checks
- passive host/network inventory (Windows + Linux)
- read-only Active Directory audit
- full-stack protocol and port exposure validation
- compliance-gated workflow orchestration with audit trail

## What it does not do

TCPENT blocks offensive behavior by policy:

- exploit execution
- brute-force/spraying/password attacks
- remote command execution
- persistence or target state change

## Repository layout

```text
config/                    suite configuration
modules/Core/              context, logging, audit trail, hash chain, reporting
modules/Safety/            hard guardrails and denied categories
modules/Inventory/         cross-platform host/software inventory
modules/PassiveNetwork/    cross-platform passive network snapshot
modules/ADAudit/           read-only AD auditing and findings
modules/StackMatrix/       full-stack profile and port matrix catalog
modules/ThreatValidation/  safe nmap planning/execution and findings engine
modules/Workflow/          compliance gate and VA/PT workflow controls
scripts/                   TCPENT entry points and installers
tests/unit/                Pester unit tests
docs/                      threat model, compliance mapping, workflow, install guide
```

## Core entry points

```powershell
pwsh -NoProfile -File ./scripts/Invoke-TcpentEnvironmentCheck.ps1 -OutputPath ./output
pwsh -NoProfile -File ./scripts/Invoke-TcpentPassiveAssessment.ps1 -OutputPath ./output
pwsh -NoProfile -File ./scripts/Invoke-TcpentADAudit.ps1 -OutputPath ./output
pwsh -NoProfile -File ./scripts/Invoke-TcpentThreatValidation.ps1 -OutputPath ./output -TargetsPath ./targets.txt -Profile HybridFullStack
pwsh -NoProfile -File ./scripts/Invoke-TcpentVaPtWorkflow.ps1 -OutputPath ./output -AssessmentType VA-PT -AuthorizationPath ./evidence/authorization.txt -RulesOfEngagementPath ./evidence/roe.txt -ScopePath ./evidence/scope.txt -TargetsPath ./targets.txt -DataHandlingPath ./evidence/data-handling.txt -Profile HybridFullStack -ExecuteThreatValidation
```

## Threat profiles

- `HybridFullStack`
- `NetworkEquipment`
- `DomainControllerExposure`
- `LinuxSurface`
- `DatabaseExposure`
- `WebApplication`
- `IoTSurface`
- `PrintInfrastructure`
- `NasStorage`
- `AccessControlSystems`

Legacy profile names are still accepted:

- `ResilienceSnmp`, `IdentityAccess`, `WindowsProtocol`, `UnixExposure`, `MssqlAudit`, `WebTlsBaseline`

## Audit and evidence outputs

Each run produces:

- `execution.log`
- `execution.ndjson`
- `operations.ndjson`
- `hashchain.ndjson`
- report set (`json`, `xml`, `html`, optional `pdf`, `manifest`)

## Install on Ubuntu/Kali

Use:

```bash
./scripts/install-ubuntu-kali.sh
```

Then validate:

```bash
pwsh -NoProfile -File ./scripts/Invoke-TcpentInstallCheck.ps1 -OutputPath ./output/install-check
```

Detailed guide: `docs/install-ubuntu-kali.md`

## Testing

```powershell
Invoke-Pester -Path ./tests/unit
Invoke-ScriptAnalyzer -Path ./modules,./scripts -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

## License

`LICENSE.txt`
