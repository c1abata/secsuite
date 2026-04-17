[CmdletBinding()]
param([string]$OutputPath)

& (Join-Path $PSScriptRoot 'Invoke-PassiveAssessment.ps1') @PSBoundParameters
