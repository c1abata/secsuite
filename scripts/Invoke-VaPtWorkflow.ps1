[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateSet('VA','PT','VA-PT')]
    [string]$AssessmentType = 'VA',
    [Parameter(Mandatory)][string]$AuthorizationPath,
    [Parameter(Mandatory)][string]$RulesOfEngagementPath,
    [Parameter(Mandatory)][string]$ScopePath,
    [Parameter(Mandatory)][string]$TargetsPath,
    [string]$ExcludePath,
    [string]$DataHandlingPath,
    [string]$TicketId,
    [string]$ClientName = 'AuthorizedClient',
    [ValidateSet('NetworkEquipment','DomainControllerExposure','LinuxSurface','DatabaseExposure','WebApplication','IoTSurface','PrintInfrastructure','NasStorage','AccessControlSystems','HybridFullStack','ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
    [string]$Profile = 'HybridFullStack',
    [int]$RetentionDays = 365,
    [switch]$ExecuteThreatValidation,
    [switch]$IncludeADAudit,
    [string]$DomainController,
    [switch]$UseLdaps,
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Core' 'Core.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Safety' 'Safety.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Inventory' 'Inventory.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'PassiveNetwork' 'PassiveNetwork.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'ADAudit' 'ADAudit.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'StackMatrix' 'StackMatrix.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'ThreatValidation' 'ThreatValidation.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Workflow' 'Workflow.psm1')) -Force

try {
    $ctx = New-SecSuiteRunContext -OutputPath $OutputPath
    Initialize-SecSuiteLogging -Context $ctx | Out-Null

    $resolvedAuthorizationPath = Resolve-SecPath -Path $AuthorizationPath -ExpectFile
    $resolvedRulesOfEngagementPath = Resolve-SecPath -Path $RulesOfEngagementPath -ExpectFile
    $resolvedScopePath = Resolve-SecPath -Path $ScopePath -ExpectFile
    $resolvedTargetsPath = Resolve-SecPath -Path $TargetsPath -ExpectFile
    $resolvedExcludePath = Resolve-SecPath -Path $ExcludePath -ExpectFile -Optional
    $resolvedDataHandlingPath = Resolve-SecPath -Path $DataHandlingPath -ExpectFile -Optional

    $engagement = New-SecEngagementRecord `
        -AssessmentType $AssessmentType `
        -AuthorizationPath $resolvedAuthorizationPath `
        -RulesOfEngagementPath $resolvedRulesOfEngagementPath `
        -ScopePath $resolvedScopePath `
        -DataHandlingPath $resolvedDataHandlingPath `
        -TicketId $TicketId `
        -ClientName $ClientName `
        -RetentionDays $RetentionDays

    $compliance = Test-SecVaPtComplianceGate `
        -AssessmentType $AssessmentType `
        -AuthorizationPath $resolvedAuthorizationPath `
        -RulesOfEngagementPath $resolvedRulesOfEngagementPath `
        -ScopePath $resolvedScopePath `
        -TargetsPath $resolvedTargetsPath `
        -DataHandlingPath $resolvedDataHandlingPath `
        -RetentionDays $RetentionDays `
        -ExecutionRequested:$ExecuteThreatValidation

    if ($compliance.Status -ne 'Approved' -and $ExecuteThreatValidation) {
        throw "Workflow blocked by compliance gate. Status: $($compliance.Status)"
    }

    $profileResolved = Resolve-SecStackProfile -Name $Profile

    Write-SecLog -Context $ctx -Area 'Workflow' -Message 'Starting VA/PT workflow.' -Data @{
        assessmentType = $AssessmentType
        executeThreatValidation = [bool]$ExecuteThreatValidation
        includeADAudit = [bool]$IncludeADAudit
        profile = $profileResolved.Name
        complianceStatus = $compliance.Status
    }

    $report = Invoke-SecOperation -Context $ctx -Area 'Workflow' -FailureMessage 'VA/PT workflow failed.' -ScriptBlock {
        $targets = @(Get-SecTargetList -Path $resolvedTargetsPath -ExcludePath $resolvedExcludePath)
        $sessionFolder = Join-Path $ctx.OutputPath ("workflow_{0}_{1}" -f $AssessmentType.ToLowerInvariant(), (Get-Date -Format 'yyyyMMdd_HHmmss'))

        $plan = @(New-SecSafeNmapPlan -Profile $profileResolved.Name -TargetFile $resolvedTargetsPath -ExcludeFile $resolvedExcludePath -OutputDirectory $sessionFolder -Config $ctx.Config.ThreatValidation)
        $scan = @(Invoke-SecSafeScanPlan -Plan $plan -Execute:$ExecuteThreatValidation -Context $ctx)
        $threatFindings = @(New-SecThreatFindings -ScanResults $scan)
        $coverage = New-SecCoverageSummary -Profile $profileResolved.Name

        $adAudit = $null
        $adFindings = @()
        if ($IncludeADAudit) {
            $adAudit = Get-SecADSummary -Config $ctx.Config.ADAudit -DomainController $DomainController -Credential $Credential -UseLdaps:$UseLdaps
            $adFindings = @(New-SecADFindings -AuditData $adAudit)
        }

        [pscustomobject]@{
            Context = $ctx
            Engagement = $engagement
            Compliance = $compliance
            Boundaries = Get-SecExecutionBoundaries
            Lifecycle = [pscustomobject]@{
                Preparation = 'Completed'
                ScopeValidation = if ($compliance.Status -eq 'Approved') { 'Completed' } else { 'ReviewRequired' }
                PassiveDiscovery = 'Completed'
                ThreatValidation = if ($ExecuteThreatValidation) { 'Executed' } else { 'DryRun' }
                Analysis = 'Completed'
                Reporting = 'Completed'
            }
            Environment = [pscustomobject]@{
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                Hostname = $ctx.Hostname
                UserName = $ctx.UserName
                Platform = if ($IsWindows) { 'Windows' } else { 'Linux' }
            }
            PassiveAssessment = [pscustomobject]@{
                Inventory = Get-SecHostInventory
                InstalledSoftware = @(Get-SecInstalledSoftware)
                PassiveNetwork = Get-SecPassiveNetworkSnapshot
            }
            ThreatValidation = [pscustomobject]@{
                Targets = $targets
                Profile = $profileResolved.Name
                ProfileInput = $Profile
                Coverage = $coverage
                ExecuteMode = [bool]$ExecuteThreatValidation
                Plan = $plan
                ScanResults = $scan
                Findings = $threatFindings
                SessionFolder = $sessionFolder
            }
            ADAudit = $adAudit
            ADAuditFindings = $adFindings
        }
    }

    $paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $report -BaseName ("workflow-{0}" -f $AssessmentType.ToLowerInvariant())
    Write-SecLog -Context $ctx -Area 'Workflow' -Message 'VA/PT workflow completed.' -Data @{
        reports = $paths
        threatFindings = @($report.ThreatValidation.Findings).Count
        adFindings = @($report.ADAuditFindings).Count
    }

    $report
}
catch {
    Write-Error "Failed to run the VA/PT workflow: $($_.Exception.Message)"
    exit 1
}
