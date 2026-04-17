Set-StrictMode -Version Latest

function Get-SecDeniedCategories {
    @(
        'Exploit',
        'BruteForce',
        'Spraying',
        'PasswordAttack',
        'CredentialStuffing',
        'Coercion',
        'LateralMovement',
        'RemoteExecution',
        'StateChange',
        'PrivilegeEscalation',
        'Persistence',
        'MalwareDrop',
        'DestructiveAction'
    )
}

function Get-SecAllowedCategories {
    @(
        'Inventory',
        'PassiveDiscovery',
        'ConfigurationReview',
        'ReadOnlyProtocolInspection',
        'ComplianceEvidenceCollection',
        'Reporting'
    )
}

function Assert-SecSafeAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [string]$Reason = 'Blocked by defensive policy.'
    )

    if (Get-SecDeniedCategories | Where-Object { $_ -eq $Category }) {
        throw "Denied category '$Category'. $Reason"
    }

    return $true
}

function Test-SecPassiveTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)

    -not [string]::IsNullOrWhiteSpace($ComputerName)
}

Export-ModuleMember -Function Get-SecDeniedCategories, Get-SecAllowedCategories, Assert-SecSafeAction, Test-SecPassiveTarget
