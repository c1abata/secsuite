# TCPENT VA/PT Workflow

## Lifecycle phases

1. Preparation
2. Scope validation
3. Passive discovery
4. Threat validation (dry-run or execute)
5. Analysis
6. Reporting
7. Closure

## Minimal required artifacts

- Authorization evidence
- Rules of engagement
- Approved scope
- Targets list

## Recommended artifacts

- Data handling procedure
- Ticket or change reference

## Example (full workflow)

```powershell
pwsh -NoProfile -File ./scripts/Invoke-TcpentVaPtWorkflow.ps1 \
  -OutputPath ./output \
  -AssessmentType VA-PT \
  -AuthorizationPath ./evidence/authorization.txt \
  -RulesOfEngagementPath ./evidence/roe.txt \
  -ScopePath ./evidence/scope.txt \
  -TargetsPath ./targets.txt \
  -ExcludePath ./exclude.txt \
  -DataHandlingPath ./evidence/data-handling.txt \
  -Profile HybridFullStack \
  -ExecuteThreatValidation
```

## Operational outputs

- Structured report (`json`, `xml`, `html`, optional `pdf`)
- Manifest with file hashes
- Text log + NDJSON log
- Operation audit trail + hash chain
