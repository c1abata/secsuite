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

try {
    $ctx = New-SecSuiteRunContext -OutputPath $OutputPath
    Initialize-SecSuiteLogging -Context $ctx | Out-Null
    Write-SecLog -Context $ctx -Area 'ADAudit' -Message 'Starting AD audit.' -Data @{ domainController = $DomainController; ldaps = [bool]$UseLdaps }

    $report = Invoke-SecOperation -Context $ctx -Area 'ADAudit' -FailureMessage 'AD audit failed.' -ScriptBlock {
        $audit = Get-SecADSummary -Config $ctx.Config.ADAudit -DomainController $DomainController -Credential $Credential -UseLdaps:$UseLdaps
        $findings = New-SecADFindings -AuditData $audit
        $extendedChecks = $null

        # Extended checks run only when the target domain can be determined safely.
        if (-not [string]::IsNullOrWhiteSpace($audit.DNSRoot)) {
            $extendedChecks = Invoke-SecADSecurityChecks -Domain $audit.DNSRoot -DomainController $DomainController -Credential $Credential -Context $ctx
        }
        else {
            Write-SecLog -Context $ctx -Level 'WARN' -Area 'ADAudit' -Message 'Extended AD security checks skipped because DNSRoot is unavailable.'
        }

        [pscustomobject]@{
            Context          = $ctx
            ADAudit          = $audit
            ADAuditExtended  = $extendedChecks
            Findings         = @($findings)
            Safety           = [pscustomobject]@{
                DeniedCategories = @(Get-SecDeniedCategories)
            }
        }
    }

    $paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $report -BaseName 'ad-audit'
    Write-SecLog -Context $ctx -Area 'ADAudit' -Message 'AD audit completed.' -Data @{ findingCount = @($report.Findings).Count; reports = $paths; mode = $report.ADAudit.CollectionMode }
    $report
}
catch {
    Write-Error "Failed to run AD audit: $($_.Exception.Message)"
    exit 1
}
