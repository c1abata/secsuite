[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$TargetsPath = '.\targets.txt',
    [string]$ExcludePath = '.\exclude.txt',
    [ValidateSet('ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
    [string]$Profile = 'ResilienceSnmp',
    [switch]$Execute
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\Core\Core.psm1') -Force
Import-Module (Join-Path $root 'modules\Safety\Safety.psm1') -Force
Import-Module (Join-Path $root 'modules\ThreatValidation\ThreatValidation.psm1') -Force

$ctx = New-SecSuiteRunContext -OutputPath $OutputPath
Initialize-SecSuiteLogging -Context $ctx | Out-Null
Write-SecLog -Context $ctx -Area 'ThreatValidation' -Message 'Avvio validazione threat-led in modalità difensiva.' -Data @{ profile = $Profile; execute = [bool]$Execute }

Assert-SecSafeAction -Category 'Inventory' -Reason 'La pipeline usa solo discovery non distruttivo.' | Out-Null
$targets = @(Get-SecTargetList -Path $TargetsPath -ExcludePath $ExcludePath)

$sessionFolder = Join-Path $ctx.OutputPath ("threat_validation_{0}_{1}" -f $Profile, (Get-Date -Format 'yyyyMMdd_HHmmss'))
$plan = @(New-SecSafeNmapPlan -Profile $Profile -TargetFile $TargetsPath -ExcludeFile $ExcludePath -OutputDirectory $sessionFolder)
$scan = @(Invoke-SecSafeScanPlan -Plan $plan -Execute:$Execute)
$findings = @(New-SecThreatFindings -ScanResults $scan)

$report = [pscustomobject]@{
    Context = $ctx
    Profile = $Profile
    ExecuteMode = [bool]$Execute
    Targets = $targets
    Plan = $plan
    ScanResults = $scan
    Findings = $findings
    Principles = @(
        'No ARP scans: tutte le command line includono --disable-arp-ping.',
        'No exploit: solo script di discovery/hardening.',
        'Fail-closed: in assenza tool la suite resta in dry-run tracciato.'
    )
}

$paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $report -BaseName ("threat-validation-{0}" -f $Profile.ToLowerInvariant())
Write-SecLog -Context $ctx -Area 'ThreatValidation' -Message 'Validazione completata.' -Data @{ report = $paths; sessionFolder = $sessionFolder; findings = $findings.Count }
$report
