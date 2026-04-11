[CmdletBinding()]
param([string]$OutputPath)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\Core\Core.psm1') -Force
Import-Module (Join-Path $root 'modules\Inventory\Inventory.psm1') -Force
Import-Module (Join-Path $root 'modules\PassiveNetwork\PassiveNetwork.psm1') -Force
Import-Module (Join-Path $root 'modules\Safety\Safety.psm1') -Force

try {
    $ctx = New-SecSuiteRunContext -OutputPath $OutputPath
    Initialize-SecSuiteLogging -Context $ctx | Out-Null
    Write-SecLog -Context $ctx -Area 'PassiveAssessment' -Message 'Starting passive assessment.'

    $report = Invoke-SecOperation -Context $ctx -Area 'PassiveAssessment' -FailureMessage 'Passive assessment failed.' -ScriptBlock {
        # Local inventory and network collection stay read-only and deterministic.
        [pscustomobject]@{
            Context           = $ctx
            Inventory         = Get-SecHostInventory
            InstalledSoftware = @(Get-SecInstalledSoftware)
            PassiveNetwork    = Get-SecPassiveNetworkSnapshot
            Safety            = [pscustomobject]@{
                DeniedCategories = @(Get-SecDeniedCategories)
            }
        }
    }

    $paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $report -BaseName 'passive-assessment'
    Write-SecLog -Context $ctx -Area 'PassiveAssessment' -Message 'Passive assessment completed.' -Data @{ reports = $paths }
    $report
}
catch {
    Write-Error "Failed to run passive assessment: $($_.Exception.Message)"
    exit 1
}
