[CmdletBinding()]
param([string]$OutputPath)

& (Join-Path $PSScriptRoot 'Invoke-EnvironmentCheck.ps1') @PSBoundParameters
