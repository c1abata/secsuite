[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$DomainController,
    [switch]$UseLdaps,
    [System.Management.Automation.PSCredential]$Credential
)

& (Join-Path $PSScriptRoot 'Invoke-ADAudit.ps1') @PSBoundParameters
