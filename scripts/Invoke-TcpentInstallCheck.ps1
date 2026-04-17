[CmdletBinding()]
param(
    [string]$OutputPath = './output/install-check',
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Core' 'Core.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'StackMatrix' 'StackMatrix.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'ThreatValidation' 'ThreatValidation.psm1')) -Force

$ctx = New-SecSuiteRunContext -OutputPath $OutputPath
Initialize-SecSuiteLogging -Context $ctx | Out-Null

$checks = @(
    [pscustomobject]@{ Name = 'pwsh'; Available = [bool](Get-Command -Name pwsh -ErrorAction SilentlyContinue); Mandatory = $true }
    [pscustomobject]@{ Name = 'nmap'; Available = [bool](Get-Command -Name nmap -ErrorAction SilentlyContinue); Mandatory = $false }
    [pscustomobject]@{ Name = 'jq'; Available = [bool](Get-Command -Name jq -ErrorAction SilentlyContinue); Mandatory = $false }
)

$moduleChecks = @(
    [pscustomobject]@{ Name = 'Core'; Loaded = [bool](Get-Command -Name New-SecSuiteRunContext -ErrorAction SilentlyContinue) }
    [pscustomobject]@{ Name = 'StackMatrix'; Loaded = [bool](Get-Command -Name Resolve-SecStackProfile -ErrorAction SilentlyContinue) }
    [pscustomobject]@{ Name = 'ThreatValidation'; Loaded = [bool](Get-Command -Name New-SecSafeNmapPlan -ErrorAction SilentlyContinue) }
)

$profiles = @(Get-SecThreatProfileNames)

$result = [pscustomobject]@{
    SuiteName = $ctx.SuiteName
    Version = $ctx.Version
    Platform = if ($IsWindows) { 'Windows' } else { 'Linux' }
    CommandChecks = $checks
    ModuleChecks = $moduleChecks
    SupportedProfiles = $profiles
    Status = 'Ready'
}

$missingMandatory = @($checks | Where-Object { $_.Mandatory -and -not $_.Available })
if ($missingMandatory.Count -gt 0) {
    $result.Status = 'MissingMandatoryDependencies'
}

if ($Strict -and (@($checks | Where-Object { -not $_.Available }).Count -gt 0)) {
    $result.Status = 'MissingDependencies'
}

$null = Export-SecSuiteReportSet -Context $ctx -ReportObject $result -BaseName 'install-check'

if ($result.Status -ne 'Ready') {
    Write-Error "Install check failed with status '$($result.Status)'."
    exit 1
}

$result
