[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$TargetsPath = './targets.txt',
    [string]$ExcludePath = './exclude.txt',
    [ValidateSet('VA','PT','VA-PT')][string]$AssessmentType = 'VA',
    [string]$AuthorizationPath,
    [string]$RulesOfEngagementPath,
    [string]$ScopePath,
    [string]$DataHandlingPath,
    [int]$RetentionDays = 365,
    [ValidateSet('NetworkEquipment','DomainControllerExposure','LinuxSurface','DatabaseExposure','WebApplication','IoTSurface','PrintInfrastructure','NasStorage','AccessControlSystems','HybridFullStack','ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
    [string]$Profile = 'HybridFullStack',
    [switch]$Execute
)

& (Join-Path $PSScriptRoot 'Invoke-ThreatValidation.ps1') @PSBoundParameters
