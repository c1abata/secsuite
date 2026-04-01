Set-StrictMode -Version Latest

function Get-SecDeniedCategories {
    @('Exploit','BruteForce','Spraying','PasswordAttack','Coercion','LateralMovement','RemoteExecution','StateChange')
}

function Assert-SecSafeAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Category,
        [string]$Reason = 'Blocked by defensive policy.'
    )
    if (Get-SecDeniedCategories | Where-Object { $_ -eq $Category }) {
        throw "Denied category '$Category'. $Reason"
    }
    $true
}

function Test-SecPassiveTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ComputerName)
    -not [string]::IsNullOrWhiteSpace($ComputerName)
}

Export-ModuleMember -Function Get-SecDeniedCategories, Assert-SecSafeAction, Test-SecPassiveTarget
