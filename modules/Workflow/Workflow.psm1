Set-StrictMode -Version Latest

function Test-SecReadableFile {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    $exists = $false
    $hasContent = $false
    $sizeBytes = 0
    $sha256 = $null

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $exists = Test-Path -LiteralPath $Path -PathType Leaf
    }

    if ($exists) {
        try {
            $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
            $hasContent = -not [string]::IsNullOrWhiteSpace($raw)
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            $sizeBytes = [int64]$item.Length
            $hashCmd = Get-Command -Name Get-SecFileSha256 -ErrorAction SilentlyContinue
            if ($hashCmd) {
                $sha256 = Get-SecFileSha256 -Path $Path
            }
        }
        catch {
            $hasContent = $false
        }
    }

    [pscustomobject]@{
        Name = $Label
        Path = $Path
        Exists = $exists
        HasContent = $hasContent
        SizeBytes = $sizeBytes
        Sha256 = $sha256
        Status = if ($exists -and $hasContent) { 'OK' } else { 'BLOCK' }
        Detail = if ($exists -and $hasContent) { "$Label available." } else { "$Label missing or empty." }
    }
}

function Test-SecTargetsFile {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{
            Name = 'Targets list syntax'
            Status = 'BLOCK'
            Detail = 'Targets path missing.'
            TargetCount = 0
            InvalidEntries = @()
        }
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{
            Name = 'Targets list syntax'
            Status = 'BLOCK'
            Detail = 'Targets file not found.'
            TargetCount = 0
            InvalidEntries = @()
        }
    }

    $targets = @()
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $item = $line.Trim()
        if (-not $item -or $item.StartsWith('#')) {
            continue
        }

        $targets += $item
    }

    $invalid = @($targets | Where-Object { $_ -match '[\*]' -or $_ -match '^0\.0\.0\.0/0$' })

    if ($targets.Count -eq 0) {
        return [pscustomobject]@{
            Name = 'Targets list syntax'
            Status = 'BLOCK'
            Detail = 'Targets list is empty.'
            TargetCount = 0
            InvalidEntries = @()
        }
    }

    if ($invalid.Count -gt 0) {
        return [pscustomobject]@{
            Name = 'Targets list syntax'
            Status = 'BLOCK'
            Detail = 'Targets list includes invalid wildcards or unrestricted range.'
            TargetCount = $targets.Count
            InvalidEntries = $invalid
        }
    }

    [pscustomobject]@{
        Name = 'Targets list syntax'
        Status = 'OK'
        Detail = 'Targets list syntax is valid.'
        TargetCount = $targets.Count
        InvalidEntries = @()
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
        AssessmentType = $AssessmentType
        ClientName = $ClientName
        TicketId = $TicketId
        AuthorizationPath = $AuthorizationPath
        RulesOfEngagementPath = $RulesOfEngagementPath
        ScopePath = $ScopePath
        DataHandlingPath = $DataHandlingPath
        RetentionDays = $RetentionDays
        CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        Methodology = 'TCPENT defensive, fail-closed, modular, deterministic'
        Lifecycle = @(
            'Preparation',
            'Scoping',
            'PassiveDiscovery',
            'Validation',
            'Analysis',
            'Reporting',
            'Closure'
        )
    }
}

function Get-SecComplianceControlMatrix {
    [CmdletBinding()]
    param()

    @(
        [pscustomobject]@{ Control='Written authorization'; Standard='ISO/IEC 27001 A.5.31'; Objective='Ensure lawful and approved security testing.' }
        [pscustomobject]@{ Control='Rules of engagement'; Standard='NIST SP 800-115'; Objective='Define boundaries, timing, contacts and safe methods.' }
        [pscustomobject]@{ Control='Scope definition'; Standard='ISO/IEC 27001 A.5.9'; Objective='Limit evidence collection to approved assets.' }
        [pscustomobject]@{ Control='Evidence handling'; Standard='ISO/IEC 27001 A.5.33'; Objective='Protect logs, reports and collected data.' }
        [pscustomobject]@{ Control='Traceable operations log'; Standard='NIS2 / DORA operational resilience'; Objective='Provide auditable trail and accountability.' }
        [pscustomobject]@{ Control='Change prevention'; Standard='Defensive baseline'; Objective='Keep workflow read-only and non-invasive.' }
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

    $allowed = @(
        'Passive inventory',
        'Read-only Active Directory audit',
        'Safe nmap discovery profiles',
        'Deterministic reporting',
        'Compliance evidence collection'
    )

    if (Get-Command -Name Get-SecAllowedCategories -ErrorAction SilentlyContinue) {
        $allowed = @(Get-SecAllowedCategories)
    }

    [pscustomobject]@{
        AllowedActions = $allowed
        DeniedCategories = $denied
        OperatingPrinciples = @(
            'Fail closed',
            'No offensive payloads',
            'Deterministic outputs',
            'Small readable modules',
            'Authorization before execution',
            'Chain-of-custody logging'
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

    $config = $null
    $importConfig = Get-Command -Name Import-SecSuiteConfig -ErrorAction SilentlyContinue
    if ($importConfig) {
        try {
            $config = Import-SecSuiteConfig
        }
        catch {
            $config = $null
        }
    }

    $checks = New-Object System.Collections.Generic.List[object]

    $checks.Add((Test-SecReadableFile -Path $AuthorizationPath -Label 'Authorization letter'))
    $checks.Add((Test-SecReadableFile -Path $RulesOfEngagementPath -Label 'Rules of engagement'))
    $checks.Add((Test-SecReadableFile -Path $ScopePath -Label 'Approved scope'))

    if ($TargetsPath) {
        $checks.Add((Test-SecReadableFile -Path $TargetsPath -Label 'Targets list'))
        $checks.Add((Test-SecTargetsFile -Path $TargetsPath))
    }
    else {
        $checks.Add([pscustomobject]@{
            Name = 'Targets list'
            Path = $null
            Exists = $false
            HasContent = $false
            Status = 'BLOCK'
            Detail = 'Targets path not provided.'
        })
    }

    if ($DataHandlingPath) {
        $checks.Add((Test-SecReadableFile -Path $DataHandlingPath -Label 'Data handling procedure'))
    }
    else {
        $checks.Add([pscustomobject]@{
            Name = 'Data handling procedure'
            Path = $null
            Exists = $false
            HasContent = $false
            Status = if ($ExecutionRequested) { 'REVIEW' } else { 'INFO' }
            Detail = if ($ExecutionRequested) { 'Data handling file missing: review required before execute.' } else { 'Optional in dry-run mode.' }
        })
    }

    $minRetention = if ($config -and $config.Compliance.MinRetentionDays) { [int]$config.Compliance.MinRetentionDays } else { 30 }
    $maxRetention = if ($config -and $config.Compliance.MaxRetentionDays) { [int]$config.Compliance.MaxRetentionDays } else { 3650 }

    $retentionStatus = if ($RetentionDays -ge $minRetention -and $RetentionDays -le $maxRetention) { 'OK' } else { 'BLOCK' }
    $checks.Add([pscustomobject]@{
        Name = 'Evidence retention'
        Path = $null
        Exists = $true
        HasContent = $true
        Status = $retentionStatus
        Detail = "RetentionDays=$RetentionDays, expected range=$minRetention..$maxRetention"
    })

    if ($ExecutionRequested -and $config -and $config.Compliance.RequireTicketIdForExecute) {
        $checks.Add([pscustomobject]@{
            Name = 'Ticket reference'
            Path = $null
            Exists = $false
            HasContent = $false
            Status = 'REVIEW'
            Detail = 'Ticket reference should be included for execute mode.'
        })
    }

    $blockCount = @($checks | Where-Object { $_.Status -eq 'BLOCK' }).Count
    $reviewCount = @($checks | Where-Object { $_.Status -eq 'REVIEW' }).Count

    $status = if ($blockCount -gt 0 -and $ExecutionRequested) {
        'Blocked'
    }
    elseif ($blockCount -gt 0 -or $reviewCount -gt 0) {
        'ReviewRequired'
    }
    else {
        'Approved'
    }

    [pscustomobject]@{
        AssessmentType = $AssessmentType
        ExecutionRequested = [bool]$ExecutionRequested
        Status = $status
        Checks = $checks.ToArray()
        BlockingChecks = @($checks | Where-Object { $_.Status -eq 'BLOCK' })
        ReviewChecks = @($checks | Where-Object { $_.Status -eq 'REVIEW' })
        ControlMatrix = [object[]](Get-SecComplianceControlMatrix)
        Boundaries = Get-SecExecutionBoundaries
    }
}

Export-ModuleMember -Function Test-SecReadableFile, Test-SecTargetsFile, New-SecEngagementRecord, Get-SecComplianceControlMatrix, Get-SecExecutionBoundaries, Test-SecVaPtComplianceGate
