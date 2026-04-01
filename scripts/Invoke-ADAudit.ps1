[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$DomainController,
    [switch]$UseLdaps,
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\Core\Core.psm1') -Force
Import-Module (Join-Path $root 'modules\ADAudit\ADAudit.psm1') -Force
Import-Module (Join-Path $root 'modules\Safety\Safety.psm1') -Force

$ctx = New-SecSuiteRunContext -OutputPath $OutputPath
Initialize-SecSuiteLogging -Context $ctx | Out-Null
Write-SecLog -Context $ctx -Area 'ADAudit' -Message 'Starting AD audit.' -Data @{ domainController = $DomainController; ldaps = [bool]$UseLdaps }

$audit = Get-SecADSummary -Config $ctx.Config.ADAudit -DomainController $DomainController -Credential $Credential -UseLdaps:$UseLdaps
$findings = New-SecADFindings -AuditData $audit

$report = [pscustomobject]@{
    Context  = $ctx
    ADAudit  = $audit
    Findings = @($findings)
    Safety   = [pscustomobject]@{
        DeniedCategories = @(Get-SecDeniedCategories)
    }
}

$paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $report -BaseName 'ad-audit'
Write-SecLog -Context $ctx -Area 'ADAudit' -Message 'AD audit completed.' -Data @{ findingCount = @($findings).Count; reports = $paths; mode = $audit.CollectionMode }
$report
