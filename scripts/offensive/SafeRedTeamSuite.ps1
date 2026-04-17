[CmdletBinding()]
param()

$target = Join-Path (Split-Path -Parent $PSScriptRoot) (Join-Path 'off' 'SafeRedTeamSuite.ps1')
if (-not (Test-Path $target)) {
    Write-Error "Target script not found: $target"
    exit 1
}

. $target
