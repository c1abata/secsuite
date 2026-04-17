# `scripts/off` Lab Module

`SafeRedTeamSuite.ps1` is a lab-only simulation module. It is safety-locked by default and requires explicit unlock steps before any active simulation runs.

## Quick Start

From repo root:

```powershell
pwsh -NoProfile -File ./scripts/Invoke-Tcpent.ps1 -Action off
```

This loads the module in lock mode (`$script:SafeMode = $true`).

To unlock in an isolated and authorized lab:

```powershell
pwsh -NoProfile -File ./scripts/Invoke-Tcpent.ps1 -Action off -EnableLabOffense
```

You will be asked to type `LAB-ONLY` before SafeMode is disabled.

## Direct Script Usage

```powershell
. ./scripts/off/SafeRedTeamSuite.ps1
```

Then unlock manually only in lab conditions:

```powershell
$script:SafeMode = $false
```

## Safety Controls

- Production hostname guardrails (`PROD`, `DC`, `SQL`, etc.).
- Mandatory human confirmation (`YES`) before module execution.
- Inert or reversible operations by default.
- Rollback helpers for persistence simulations.
- Rate limiting and max attempts for credential testing simulations.

## Example Commands

```powershell
Invoke-SafeADRecon -QueryType Users
$cred = Get-Credential
Invoke-SafeSSHPersistence -TargetHost 192.168.1.100 -Credential $cred
Invoke-SafeModbusFuzzing -TargetIP 127.0.0.1 -Iterations 5
```
