[CmdletBinding()]
param([string]$OutputPath)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'Core' 'Core.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'ADAudit' 'ADAudit.psm1')) -Force
Import-Module (Join-Path (Join-Path $root 'modules') (Join-Path 'ThreatValidation' 'ThreatValidation.psm1')) -Force

try {
    $ctx = New-SecSuiteRunContext -OutputPath $OutputPath
    Initialize-SecSuiteLogging -Context $ctx | Out-Null
    Write-SecLog -Context $ctx -Area 'EnvironmentCheck' -Message 'Starting environment validation.'

    $isAdministrator = $false
    if ($IsWindows) {
        try {
            $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch {
            $isAdministrator = $false
        }
    }
    else {
        try {
            $isAdministrator = ((id -u) -eq '0')
        }
        catch {
            $isAdministrator = $false
        }
    }

    $nmap = Get-Command -Name nmap -ErrorAction SilentlyContinue

    $result = [pscustomobject]@{
        SuiteName = $ctx.SuiteName
        Version = $ctx.Version
        BrandStyle = $ctx.BrandStyle
        Hostname = $ctx.Hostname
        Platform = if ($IsWindows) { 'Windows' } else { 'Linux' }
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsAdministrator = $isAdministrator
        ADModuleAvailable = (Test-SecAdModuleAvailable)
        NmapAvailable = [bool]$nmap
        NmapPath = if ($nmap) { $nmap.Source } else { $null }
        SupportedThreatProfiles = @(Get-SecThreatProfileNames)
        OutputPath = $ctx.OutputPath
        UtcStarted = $ctx.UtcStarted
    }

    $paths = Export-SecSuiteReportSet -Context $ctx -ReportObject $result -BaseName 'environment-check'
    Write-SecLog -Context $ctx -Area 'EnvironmentCheck' -Message 'Environment validation completed.' -Data @{ reports = $paths }
    $result
}
catch {
    Write-Error "Failed to validate the environment: $($_.Exception.Message)"
    exit 1
}
