Set-StrictMode -Version Latest

function Test-SecReadableFile {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    $exists = $false
    $hasContent = $false

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $exists = Test-Path -LiteralPath $Path -PathType Leaf
    }

    if ($exists) {
        try {
            $hasContent = -not [string]::IsNullOrWhiteSpace((Get-Content -LiteralPath $Path -Raw -ErrorAction Stop))
        }
        catch {
            $hasContent = $false
        }
    }

    [pscustomobject]@{
        Name      = $Label
        Path      = $Path
        Exists    = $exists
        HasContent = $hasContent
        Status    = $(if ($exists -and $hasContent) { 'OK' } else { 'BLOCK' })
        Detail    = $(if ($exists -and $hasContent) { "$Label available." } else { "$Label missing or empty." })
    }
}

function New-SecEngagementRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('VA','PT','VA-PT','AD-AUDIT')][string]$AssessmentType,
        [Parameter(Mandatory)][string]$AuthorizationPath,
        [Parameter(Mandatory)][string]$RulesOfEngagementPath,
        [Parameter(Mandatory)][string]$ScopePath,
        [string]$DataHandlingPath,
        [string]$TicketId,
        [string]$ClientName = 'AuthorizedClient',
        [int]$RetentionDays = 365
    )

    [pscustomobject]@{
        AssessmentType      = $AssessmentType
        ClientName          = $ClientName
        TicketId            = $TicketId
        AuthorizationPath   = $AuthorizationPath
        RulesOfEngagementPath = $RulesOfEngagementPath
        ScopePath           = $ScopePath
        DataHandlingPath    = $DataHandlingPath
        RetentionDays       = $RetentionDays
        CollectedAtUtc      = (Get-Date).ToUniversalTime().ToString('o')
        Methodology         = 'Defensive, fail-closed, modular, deterministic'
    }
}

function Get-SecComplianceControlMatrix {
    [CmdletBinding()]
    param()

    @(
        [pscustomobject]@{ Control = 'Written authorization'; Standard = 'ISO/IEC 27001 A.5.31'; Objective = 'Ensure lawful and approved security testing.' }
        [pscustomobject]@{ Control = 'Rules of engagement'; Standard = 'NIST SP 800-115'; Objective = 'Define boundaries, timing, contacts and safe methods.' }
        [pscustomobject]@{ Control = 'Scope definition'; Standard = 'ISO/IEC 27001 A.5.9'; Objective = 'Limit evidence collection to approved assets.' }
        [pscustomobject]@{ Control = 'Evidence handling'; Standard = 'ISO/IEC 27001 A.5.33'; Objective = 'Protect logs, reports and collected data.' }
        [pscustomobject]@{ Control = 'Change prevention'; Standard = 'Microsoft Security Baseline'; Objective = 'Keep the workflow read-only unless explicitly approved.' }
    )
}

function Get-SecExecutionBoundaries {
    [CmdletBinding()]
    param()

    $denied = @(
        'Exploit',
        'BruteForce',
        'Spraying',
        'PasswordAttack',
        'Coercion',
        'LateralMovement',
        'RemoteExecution',
        'StateChange'
    )

    if (Get-Command -Name Get-SecDeniedCategories -ErrorAction SilentlyContinue) {
        $denied = @(Get-SecDeniedCategories)
    }

    [pscustomobject]@{
        AllowedActions = @(
            'Passive inventory',
            'Read-only Active Directory audit',
            'Safe nmap discovery profiles',
            'Deterministic reporting',
            'Compliance evidence collection'
        )
        DeniedCategories = $denied
        OperatingPrinciples = @(
            'Fail closed',
            'No offensive payloads',
            'Deterministic outputs',
            'Small readable modules',
            'Authorization before execution'
        )
    }
}

function Test-SecVaPtComplianceGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('VA','PT','VA-PT','AD-AUDIT')][string]$AssessmentType,
        [AllowEmptyString()][string]$AuthorizationPath,
        [AllowEmptyString()][string]$RulesOfEngagementPath,
        [AllowEmptyString()][string]$ScopePath,
        [string]$TargetsPath,
        [string]$DataHandlingPath,
        [int]$RetentionDays = 365,
        [switch]$ExecutionRequested
    )

    $checks = New-Object System.Collections.Generic.List[object]
    $checks.Add((Test-SecReadableFile -Path $AuthorizationPath -Label 'Authorization letter'))
    $checks.Add((Test-SecReadableFile -Path $RulesOfEngagementPath -Label 'Rules of engagement'))
    $checks.Add((Test-SecReadableFile -Path $ScopePath -Label 'Approved scope'))

    if ($DataHandlingPath) {
        $checks.Add((Test-SecReadableFile -Path $DataHandlingPath -Label 'Data handling procedure'))
    }

    if ($TargetsPath) {
        $checks.Add((Test-SecReadableFile -Path $TargetsPath -Label 'Targets list'))
    }

    $retentionCheck = [pscustomobject]@{
        Name       = 'Evidence retention'
        Path       = $null
        Exists     = $true
        HasContent = $true
        Status     = $(if ($RetentionDays -ge 30 -and $RetentionDays -le 3650) { 'OK' } else { 'BLOCK' })
        Detail     = "RetentionDays=$RetentionDays"
    }
    $checks.Add($retentionCheck)

    $hasBlocking = @($checks | Where-Object { $_.Status -eq 'BLOCK' }).Count -gt 0
    $status = if ($hasBlocking -and $ExecutionRequested) { 'Blocked' } elseif ($hasBlocking) { 'ReviewRequired' } else { 'Approved' }

    [pscustomobject]@{
        AssessmentType = $AssessmentType
        ExecutionRequested = [bool]$ExecutionRequested
        Status = $status
        Checks = $checks.ToArray()
        ControlMatrix = [object[]](Get-SecComplianceControlMatrix)
    }
}

Export-ModuleMember -Function Test-SecReadableFile, New-SecEngagementRecord, Get-SecComplianceControlMatrix, Get-SecExecutionBoundaries, Test-SecVaPtComplianceGate
