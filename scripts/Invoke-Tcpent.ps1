[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('environment','passive','adaudit','threat','workflow','install-check','off')][string]$Action,
    [string]$OutputPath = './output',
    [string]$TargetsPath = './targets.txt',
    [string]$ExcludePath = './exclude.txt',
    [string]$AuthorizationPath,
    [string]$RulesOfEngagementPath,
    [string]$ScopePath,
    [string]$DataHandlingPath,
    [ValidateSet('VA','PT','VA-PT')][string]$AssessmentType = 'VA',
    [ValidateSet('NetworkEquipment','DomainControllerExposure','LinuxSurface','DatabaseExposure','WebApplication','IoTSurface','PrintInfrastructure','NasStorage','AccessControlSystems','HybridFullStack','ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
    [string]$Profile = 'HybridFullStack',
    [switch]$Execute,
    [switch]$ExecuteThreatValidation,
    [switch]$IncludeADAudit,
    [switch]$EnableLabOffense,
    [switch]$SkipLabConfirmation
)

switch ($Action) {
    'environment' {
        & (Join-Path $PSScriptRoot 'Invoke-TcpentEnvironmentCheck.ps1') -OutputPath $OutputPath
    }
    'passive' {
        & (Join-Path $PSScriptRoot 'Invoke-TcpentPassiveAssessment.ps1') -OutputPath $OutputPath
    }
    'adaudit' {
        & (Join-Path $PSScriptRoot 'Invoke-TcpentADAudit.ps1') -OutputPath $OutputPath
    }
    'threat' {
        & (Join-Path $PSScriptRoot 'Invoke-TcpentThreatValidation.ps1') `
            -OutputPath $OutputPath `
            -TargetsPath $TargetsPath `
            -ExcludePath $ExcludePath `
            -AssessmentType $AssessmentType `
            -AuthorizationPath $AuthorizationPath `
            -RulesOfEngagementPath $RulesOfEngagementPath `
            -ScopePath $ScopePath `
            -DataHandlingPath $DataHandlingPath `
            -Profile $Profile `
            -Execute:$Execute
    }
    'workflow' {
        & (Join-Path $PSScriptRoot 'Invoke-TcpentVaPtWorkflow.ps1') `
            -OutputPath $OutputPath `
            -AssessmentType $AssessmentType `
            -AuthorizationPath $AuthorizationPath `
            -RulesOfEngagementPath $RulesOfEngagementPath `
            -ScopePath $ScopePath `
            -TargetsPath $TargetsPath `
            -ExcludePath $ExcludePath `
            -DataHandlingPath $DataHandlingPath `
            -Profile $Profile `
            -ExecuteThreatValidation:$ExecuteThreatValidation `
            -IncludeADAudit:$IncludeADAudit
    }
    'install-check' {
        & (Join-Path $PSScriptRoot 'Invoke-TcpentInstallCheck.ps1') -OutputPath $OutputPath
    }
    'off' {
        & (Join-Path $PSScriptRoot 'Invoke-TcpentOffSuite.ps1') `
            -EnableLabOffense:$EnableLabOffense `
            -SkipLabConfirmation:$SkipLabConfirmation
    }
}
