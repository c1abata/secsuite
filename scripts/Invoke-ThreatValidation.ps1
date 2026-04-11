[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$TargetsPath = '.\targets.txt',
    [string]$ExcludePath = '.\exclude.txt',
    [ValidateSet('VA','PT','VA-PT')]
    [string]$AssessmentType = 'VA',
    [string]$AuthorizationPath,
    [string]$RulesOfEngagementPath,
    [string]$ScopePath,
    [string]$DataHandlingPath,
    [int]$RetentionDays = 365,
    [ValidateSet('ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
    [string]$Profile = 'ResilienceSnmp',
    [switch]$Execute
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\Core\Core.psm1') -Force
Import-Module (Join-Path $root 'modules\Safety\Safety.psm1') -Force
Import-Module (Join-Path $root 'modules\ThreatValidation\ThreatValidation.psm1') -Force
Import-Module (Join-Path $root 'modules\Workflow\Workflow.psm1') -Force

try {
    $ctx = New-SecSuiteRunContext -OutputPath $OutputPath
    Initialize-SecSuiteLogging -Context $ctx | Out-Null

    $resolvedTargetsPath = Resolve-SecPath -Path $TargetsPath -ExpectFile
    $resolvedExcludePath = Resolve-SecPath -Path $ExcludePath -ExpectFile -Optional
    $resolvedAuthorizationPath = Resolve-SecPath -Path $AuthorizationPath -ExpectFile -Optional
    $resolvedRulesOfEngagementPath = Resolve-SecPath -Path $RulesOfEngagementPath -ExpectFile -Optional
    $resolvedScopePath = Resolve-SecPath -Path $ScopePath -ExpectFile -Optional
    $resolvedDataHandlingPath = Resolve-SecPath -Path $DataHandlingPath -ExpectFile -Optional

    $compliance = $null
    if ($resolvedAuthorizationPath -or $resolvedRulesOfEngagementPath -or $resolvedScopePath -or $Execute) {
        $compliance = Test-SecVaPtComplianceGate `
            -AssessmentType $AssessmentType `
            -AuthorizationPath $resolvedAuthorizationPath `
            -RulesOfEngagementPath $resolvedRulesOfEngagementPath `
            -ScopePath $resolvedScopePath `
            -TargetsPath $resolvedTargetsPath `
            -DataHandlingPath $resolvedDataHandlingPath `
            -RetentionDays $RetentionDays `
            -ExecutionRequested:$Execute

        if ($Execute -and $compliance.Status -ne 'Approved') {
            throw "Execution blocked by compliance gate. Status: $($compliance.Status)"
        }
    }

    Write-SecLog -Context $ctx -Area 'ThreatValidation' -Message 'Avvio validazione threat-led in modalità difensiva.' -Data @{
        profile = $Profile
        execute = [bool]$Execute
        assessmentType = $AssessmentType
        complianceStatus = if ($compliance) { $compliance.Status } else { 'NotProvided' }
    }

    $report = Invoke-SecOperation -Context $ctx -Area 'ThreatValidation' -FailureMessage 'Threat validation failed.' -ScriptBlock {
        Assert-SecSafeAction -Category 'Inventory' -Reason 'La pipeline usa solo discovery non distruttivo.' | Out-Null
        $targets = @(Get-SecTargetList -Path $resolvedTargetsPath -ExcludePath $resolvedExcludePath)

        # The execution folder keeps each run isolated for evidence preservation.
        $sessionFolder = Join-Path $ctx.OutputPath ("threat_validation_{0}_{1}" -f $Profile, (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $plan = @(New-SecSafeNmapPlan -Profile $Profile -TargetFile $resolvedTargetsPath -ExcludeFile $resolvedExcludePath -OutputDirectory $sessionFolder)
        $scan = @(Invoke-SecSafeScanPlan -Plan $plan -Execute:$Execute)
        $findings = @(New-SecThreatFindings -ScanResults $scan)

        [pscustomobject]@{
            Context = $ctx
            Profile = $Profile
            AssessmentType = $AssessmentType
            ExecuteMode = [bool]$Execute
            Compliance = $compliance
            Targets = $targets
            Plan = $plan
            ScanResults = $scan
            Findings = $findings
            SessionFolder = $sessionFolder
            Principles = @(
                'No ARP scans: tutte le command line includono --disable-arp-ping.',
                'No exploit: solo script di discovery/hardening.',
                'Fail-closed: in assenza tool la suite resta in dry-run tracciato.'
            )
        }
    }

    $paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $report -BaseName ("threat-validation-{0}" -f $Profile.ToLowerInvariant())
    Write-SecLog -Context $ctx -Area 'ThreatValidation' -Message 'Validazione completata.' -Data @{ report = $paths; sessionFolder = $report.SessionFolder; findings = $report.Findings.Count }
    $report
}
catch {
    Write-Error "Failed to run threat validation: $($_.Exception.Message)"
    exit 1
}
