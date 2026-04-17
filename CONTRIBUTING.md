# Contributing

## Principles

- Defensive by design.
- Read-only checks unless explicitly approved in workflow evidence.
- Deterministic output and traceable logs.
- Small, modular and testable changes.

## Local workflow

1. Run `pwsh -NoProfile -File ./scripts/Invoke-TcpentInstallCheck.ps1`.
2. Run unit tests:
   - `pwsh -NoProfile -Command "Invoke-Pester -Path ./tests/unit"`
3. Run static analysis:
   - `pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path ./modules,./scripts -Recurse -Settings ./PSScriptAnalyzerSettings.psd1"`

## Pull Request checklist

- [ ] Change is scoped and documented.
- [ ] Unit tests added/updated.
- [ ] No offensive behavior introduced.
- [ ] Compliance/logging impact evaluated.
