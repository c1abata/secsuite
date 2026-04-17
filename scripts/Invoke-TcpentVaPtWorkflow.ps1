[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateSet('VA','PT','VA-PT')][string]$AssessmentType = 'VA',
    [Parameter(Mandatory)][string]$AuthorizationPath,
    [Parameter(Mandatory)][string]$RulesOfEngagementPath,
    [Parameter(Mandatory)][string]$ScopePath,
    [Parameter(Mandatory)][string]$TargetsPath,
    [string]$ExcludePath,
    [string]$DataHandlingPath,
    [string]$TicketId,
    [string]$ClientName = 'AuthorizedClient',
    [ValidateSet('NetworkEquipment','DomainControllerExposure','LinuxSurface','DatabaseExposure','WebApplication','IoTSurface','PrintInfrastructure','NasStorage','AccessControlSystems','HybridFullStack','ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
    [string]$Profile = 'HybridFullStack',
    [int]$RetentionDays = 365,
    [switch]$ExecuteThreatValidation,
    [switch]$IncludeADAudit,
    [string]$DomainController,
    [switch]$UseLdaps,
    [System.Management.Automation.PSCredential]$Credential
)

& (Join-Path $PSScriptRoot 'Invoke-VaPtWorkflow.ps1') @PSBoundParameters
