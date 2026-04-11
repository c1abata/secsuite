[CmdletBinding()]
param([string]$OutputPath)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'modules\Core\Core.psm1') -Force
Import-Module (Join-Path $root 'modules\ADAudit\ADAudit.psm1') -Force

try {
    $ctx = New-SecSuiteRunContext -OutputPath $OutputPath
    Initialize-SecSuiteLogging -Context $ctx | Out-Null
    Write-SecLog -Context $ctx -Area 'EnvironmentCheck' -Message 'Starting environment validation.'

    $isAdministrator = $false
    try {
        $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $isAdministrator = $false
    }

    $result = [pscustomobject]@{
        SuiteName         = $ctx.SuiteName
        Version           = $ctx.Version
        Hostname          = $ctx.Hostname
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsAdministrator   = $isAdministrator
        ADModuleAvailable = (Test-SecAdModuleAvailable)
        OutputPath        = $ctx.OutputPath
        UtcStarted        = $ctx.UtcStarted
    }

    $paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $result -BaseName 'environment-check'
    Write-SecLog -Context $ctx -Area 'EnvironmentCheck' -Message 'Environment validation completed.' -Data @{ reports = $paths }
    $result
}
catch {
    Write-Error "Failed to validate the environment: $($_.Exception.Message)"
    exit 1
}
