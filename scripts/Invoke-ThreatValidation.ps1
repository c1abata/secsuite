[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$TargetsPath = './targets.txt',
    [string]$ExcludePath = './exclude.txt',
    [ValidateSet('VA','PT','VA-PT')]
    [string]$AssessmentType = 'VA',
    [string]$AuthorizationPath,
    [string]$RulesOfEngagementPath,
    [string]$ScopePath,
    [string]$DataHandlingPath,
    [int]$RetentionDays = 365,
    [ValidateSet('NetworkEquipment','DomainControllerExposure','LinuxSurface','DatabaseExposure','WebApplication','IoTSurface','PrintInfrastructure','NasStorage','AccessControlSystems','HybridFullStack','ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
    [string]$Profile = 'HybridFullStack',
    [switch]$Execute
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Core' 'Core.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Safety' 'Safety.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'StackMatrix' 'StackMatrix.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'ThreatValidation' 'ThreatValidation.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Workflow' 'Workflow.psm1')) -Force

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

    $profileResolved = Resolve-SecStackProfile -Name $Profile

    Write-SecLog -Context $ctx -Area 'ThreatValidation' -Message 'Starting threat validation in defensive mode.' -Data @{
        profile = $profileResolved.Name
        profileInput = $Profile
        execute = [bool]$Execute
        assessmentType = $AssessmentType
        complianceStatus = if ($compliance) { $compliance.Status } else { 'NotProvided' }
    }

    $report = Invoke-SecOperation -Context $ctx -Area 'ThreatValidation' -FailureMessage 'Threat validation failed.' -ScriptBlock {
        Assert-SecSafeAction -Category 'Inventory' -Reason 'Threat validation only runs non-destructive discovery.' | Out-Null
        $targets = @(Get-SecTargetList -Path $resolvedTargetsPath -ExcludePath $resolvedExcludePath)

        $sessionFolder = Join-Path $ctx.OutputPath ("threat_validation_{0}_{1}" -f $profileResolved.Name.ToLowerInvariant(), (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $plan = @(New-SecSafeNmapPlan -Profile $profileResolved.Name -TargetFile $resolvedTargetsPath -ExcludeFile $resolvedExcludePath -OutputDirectory $sessionFolder -Config $ctx.Config.ThreatValidation)
        $scan = @(Invoke-SecSafeScanPlan -Plan $plan -Execute:$Execute -Context $ctx)
        $findings = @(New-SecThreatFindings -ScanResults $scan)
        $coverage = New-SecCoverageSummary -Profile $profileResolved.Name

        [pscustomobject]@{
            Context = $ctx
            Profile = $profileResolved.Name
            ProfileInput = $Profile
            ProfileAliases = @($profileResolved.Aliases)
            ProfileDescription = $profileResolved.Description
            AssessmentType = $AssessmentType
            ExecuteMode = [bool]$Execute
            Compliance = $compliance
            Coverage = $coverage
            Targets = $targets
            Plan = $plan
            ScanResults = $scan
            Findings = $findings
            SessionFolder = $sessionFolder
            Principles = @(
                'No ARP scans: all commands include --disable-arp-ping.',
                'No exploit or brute-force operations are part of this workflow.',
                'Fail-closed: if tools are missing, execution degrades to tracked dry-run.'
            )
        }
    }

    $paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $report -BaseName ("threat-validation-{0}" -f $profileResolved.Name.ToLowerInvariant())
    Write-SecLog -Context $ctx -Area 'ThreatValidation' -Message 'Threat validation completed.' -Data @{ report = $paths; sessionFolder = $report.SessionFolder; findings = $report.Findings.Count }
    $report
}
catch {
    Write-Error "Failed to run threat validation: $($_.Exception.Message)"
    exit 1
}
