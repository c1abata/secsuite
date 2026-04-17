[CmdletBinding()]
param(
    [switch]$EnableLabOffense,
    [switch]$SkipLabConfirmation
)

$ErrorActionPreference = 'Stop'
$offSuitePath = Join-Path $PSScriptRoot (Join-Path 'off' 'SafeRedTeamSuite.ps1')

if (-not (Test-Path $offSuitePath)) {
    Write-Error "Off-suite script not found: $offSuitePath"
    exit 1
}

. $offSuitePath

if (-not $EnableLabOffense) {
    Write-Warning "Lab off-suite loaded in lock mode. SafeMode remains enabled."
    Write-Warning "Run with -EnableLabOffense to unlock lab functions after an explicit confirmation."
    return
}

if (-not $SkipLabConfirmation) {
    Write-Warning "You are about to disable SafeMode for lab-only offensive simulations."
    Write-Warning "Only continue inside an isolated and authorized environment."
    $confirmation = Read-Host "Type 'LAB-ONLY' to continue"
    if ($confirmation -ne 'LAB-ONLY') {
        Write-Warning "Confirmation failed. SafeMode remains enabled."
        return
    }
}

$script:SafeMode = $false
Write-Warning "SafeMode disabled for this session. Use only with explicit authorization in a lab."
