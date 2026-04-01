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
$extendedChecks = $null

if (-not [string]::IsNullOrWhiteSpace($audit.DNSRoot)) {
    $extendedChecks = Invoke-SecADSecurityChecks -Domain $audit.DNSRoot -DomainController $DomainController -Credential $Credential -Context $ctx
}
else {
    Write-SecLog -Context $ctx -Level 'WARN' -Area 'ADAudit' -Message 'Extended AD security checks skipped because DNSRoot is unavailable.'
}

$report = [pscustomobject]@{
    Context          = $ctx
    ADAudit          = $audit
    ADAuditExtended  = $extendedChecks
    Findings         = @($findings)
    Safety           = [pscustomobject]@{
        DeniedCategories = @(Get-SecDeniedCategories)
    }
}

$paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $report -BaseName 'ad-audit'
Write-SecLog -Context $ctx -Area 'ADAudit' -Message 'AD audit completed.' -Data @{ findingCount = @($findings).Count; reports = $paths; mode = $audit.CollectionMode }
$report
