Set-StrictMode -Version Latest

$stackMatrixModulePath = Join-Path (Join-Path $PSScriptRoot '..') (Join-Path 'StackMatrix' 'StackMatrix.psm1')
if (-not (Get-Command -Name Resolve-SecStackProfile -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $stackMatrixModulePath)) {
    Import-Module $stackMatrixModulePath -Force
}

function Get-SecTargetList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ExcludePath
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Target file not found: $Path"
    }

    $excluded = @{}
    if ($ExcludePath -and (Test-Path -LiteralPath $ExcludePath -PathType Leaf)) {
        foreach ($line in (Get-Content -LiteralPath $ExcludePath -ErrorAction Stop)) {
            $item = $line.Trim()
            if ($item -and -not $item.StartsWith('#')) {
                $excluded[$item.ToLowerInvariant()] = $true
            }
        }
    }

    $targets = foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $item = $line.Trim()
        if (-not $item -or $item.StartsWith('#')) {
            continue
        }

        if ($excluded.ContainsKey($item.ToLowerInvariant())) {
            continue
        }

        $item
    }

    $unique = @($targets | Sort-Object -Unique)
    if (-not $unique -or $unique.Count -eq 0) {
        throw 'The targets list is empty after normalization and exclusions.'
    }

    return $unique
}

function ConvertTo-SecShellCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $quotedArgs = foreach ($arg in $Arguments) {
        if ($arg -match '[\s"'']') {
            '"{0}"' -f ($arg -replace '"', '\\"')
        }
        else {
            $arg
        }
    }

    "{0} {1}" -f $Tool, ($quotedArgs -join ' ')
}

function Get-SecThreatProfileNames {
    [CmdletBinding()]
    param([switch]$IncludeAliases)

    if (-not (Get-Command -Name Get-SecStackProfileNames -ErrorAction SilentlyContinue)) {
        throw 'StackMatrix module is not loaded.'
    }

    Get-SecStackProfileNames -IncludeAliases:$IncludeAliases
}

function New-SecSafeNmapPlan {
    [CmdletBinding()]
    param(
        [ValidateSet('NetworkEquipment','DomainControllerExposure','LinuxSurface','DatabaseExposure','WebApplication','IoTSurface','PrintInfrastructure','NasStorage','AccessControlSystems','HybridFullStack','ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
        [string]$Profile = 'HybridFullStack',
        [Parameter(Mandatory)][string]$TargetFile,
        [string]$ExcludeFile,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [hashtable]$Config
    )

    if (-not (Test-Path -LiteralPath $TargetFile -PathType Leaf)) {
        throw "Target file not found: $TargetFile"
    }

    if ($ExcludeFile -and -not (Test-Path -LiteralPath $ExcludeFile -PathType Leaf)) {
        throw "Exclude file not found: $ExcludeFile"
    }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    $resolvedProfile = Resolve-SecStackProfile -Name $Profile
    $maxRetries = if ($Config -and $Config.MaxRetries -ge 0) { [int]$Config.MaxRetries } else { 2 }
    $hostTimeout = if ($Config -and $Config.HostTimeout) { [string]$Config.HostTimeout } else { '45s' }
    $timingTemplate = if ($Config -and $Config.TimingTemplate) { [string]$Config.TimingTemplate } else { 'T3' }
    $serviceVersion = $true
    if ($Config -and $Config.ContainsKey('ServiceVersionDetection')) {
        $serviceVersion = [bool]$Config.ServiceVersionDetection
    }

    $steps = New-Object System.Collections.Generic.List[object]

    foreach ($scanSet in @($resolvedProfile.ScanSets)) {
        $args = New-Object System.Collections.Generic.List[string]

        $null = $args.Add('-Pn')
        $null = $args.Add('--disable-arp-ping')
        $null = $args.Add('--reason')
        $null = $args.Add('--open')
        $null = $args.Add('-' + $timingTemplate)
        $null = $args.Add('--max-retries')
        $null = $args.Add([string]$maxRetries)
        $null = $args.Add('--host-timeout')
        $null = $args.Add($hostTimeout)

        if ($serviceVersion) {
            $null = $args.Add('-sV')
        }

        if ($scanSet.Transport -eq 'udp') {
            $null = $args.Add('-sU')
        }

        $null = $args.Add('-p')
        $null = $args.Add([string]$scanSet.Ports)

        if (-not [string]::IsNullOrWhiteSpace([string]$scanSet.Scripts)) {
            $null = $args.Add('--script')
            $null = $args.Add([string]$scanSet.Scripts)
        }

        foreach ($extra in @($scanSet.ExtraArgs)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$extra)) {
                $null = $args.Add([string]$extra)
            }
        }

        $null = $args.Add('-iL')
        $null = $args.Add($TargetFile)

        if ($ExcludeFile) {
            $null = $args.Add('--excludefile')
            $null = $args.Add($ExcludeFile)
        }

        $outputPrefix = Join-Path $OutputDirectory ([string]$scanSet.Name)
        $null = $args.Add('-oA')
        $null = $args.Add($outputPrefix)

        $argArray = @($args)

        $steps.Add([pscustomobject]@{
            Name = [string]$scanSet.Name
            Tool = 'nmap'
            Profile = [string]$resolvedProfile.Name
            Purpose = [string]$resolvedProfile.Description
            Protocol = [string]$scanSet.Transport
            Ports = [string]$scanSet.Ports
            Scripts = [string]$scanSet.Scripts
            OutputPrefix = $outputPrefix
            Arguments = $argArray
            Command = ConvertTo-SecShellCommand -Tool 'nmap' -Arguments $argArray
        })
    }

    return $steps.ToArray()
}

function Invoke-SecSafeScanPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Plan,
        [switch]$Execute,
        [object]$Context
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($step in $Plan) {
        $tool = Get-Command -Name $step.Tool -ErrorAction SilentlyContinue
        $canRun = $null -ne $tool

        if ($Execute -and $canRun) {
            $start = Get-Date

            if ($Context -and (Get-Command -Name Write-SecAuditEvent -ErrorAction SilentlyContinue)) {
                Write-SecAuditEvent -Context $Context -Area 'ThreatValidation' -Action $step.Name -Status Started -Data @{ command = $step.Command; profile = $step.Profile }
            }

            $output = & $tool.Source @($step.Arguments) 2>&1
            $exitCode = $LASTEXITCODE
            $durationMs = ((Get-Date) - $start).TotalMilliseconds

            $result = [pscustomobject]@{
                Name = $step.Name
                Profile = $step.Profile
                Ran = $true
                ExitCode = $exitCode
                Output = @($output | ForEach-Object { [string]$_ })
                Command = $step.Command
                DurationMs = $durationMs
                ToolPath = $tool.Source
                TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
            }

            if ($Context -and (Get-Command -Name Write-SecLog -ErrorAction SilentlyContinue)) {
                $level = if ($exitCode -eq 0) { 'INFO' } else { 'WARN' }
                Write-SecLog -Context $Context -Level $level -Area 'ThreatValidation' -Message "Scan step '$($step.Name)' completed." -Data @{ exitCode = $exitCode; durationMs = $durationMs; profile = $step.Profile }
            }

            if ($Context -and (Get-Command -Name Write-SecAuditEvent -ErrorAction SilentlyContinue)) {
                $status = if ($exitCode -eq 0) { 'Completed' } else { 'Failed' }
                Write-SecAuditEvent -Context $Context -Area 'ThreatValidation' -Action $step.Name -Status $status -DurationMs $durationMs -Data @{ exitCode = $exitCode; profile = $step.Profile }
            }

            $null = $results.Add($result)
        }
        else {
            if ($Context -and (Get-Command -Name Write-SecAuditEvent -ErrorAction SilentlyContinue)) {
                Write-SecAuditEvent -Context $Context -Area 'ThreatValidation' -Action $step.Name -Status Skipped -Data @{ reason = if ($Execute) { 'tool_not_found' } else { 'dry_run' }; command = $step.Command }
            }

            $null = $results.Add([pscustomobject]@{
                Name = $step.Name
                Profile = $step.Profile
                Ran = $false
                ExitCode = if ($canRun) { 0 } else { 127 }
                Output = @(
                    if ($Execute -and -not $canRun) {
                        "Tool '$($step.Tool)' not found on this host."
                    }
                    else {
                        'Dry-run mode enabled: command not executed.'
                    }
                )
                Command = $step.Command
                DurationMs = 0
                ToolPath = if ($canRun) { $tool.Source } else { $null }
                TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
            })
        }
    }

    return $results.ToArray()
}

function New-SecCoverageSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Profile)

    $resolved = Resolve-SecStackProfile -Name $Profile
    $matrix = @(Get-SecStackPortMatrix)

    $ports = New-Object System.Collections.Generic.List[int]
    foreach ($set in @($resolved.ScanSets)) {
        foreach ($p in ([string]$set.Ports -split ',')) {
            $parsed = 0
            if ([int]::TryParse($p.Trim(), [ref]$parsed)) {
                $null = $ports.Add($parsed)
            }
        }
    }

    $uniquePorts = @($ports | Sort-Object -Unique)
    $mappedRows = @($matrix | Where-Object { $uniquePorts -contains $_.Port })

    [pscustomobject]@{
        Profile = $resolved.Name
        Description = $resolved.Description
        CoveredPorts = $uniquePorts
        PortCount = $uniquePorts.Count
        CoveredServices = @($mappedRows | Select-Object -ExpandProperty Service -Unique)
        CoveredStacks = @($mappedRows | ForEach-Object { $_.Stack -split ',' } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    }
}

function New-SecThreatFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$ScanResults)

    $patterns = @(
        @{ Regex = '23/tcp\s+open'; Severity = 'High'; Title = 'Telnet service exposed'; Evidence = 'Port 23 open.' }
        @{ Regex = 'SMBv1|NT LM 0\.12'; Severity = 'High'; Title = 'Legacy SMB protocol indicator'; Evidence = 'SMBv1 indicator found.' }
        @{ Regex = 'TLSv1\.0|TLSv1\.1'; Severity = 'Medium'; Title = 'Legacy TLS protocol supported'; Evidence = 'TLS legacy protocol in scan output.' }
        @{ Regex = 'anonymous|public'; Severity = 'Medium'; Title = 'Anonymous or weak default access indicator'; Evidence = 'Anonymous/default indicator detected.' }
        @{ Regex = '6379/tcp\s+open'; Severity = 'High'; Title = 'Redis service exposed'; Evidence = 'Port 6379 open.' }
        @{ Regex = '2375/tcp\s+open'; Severity = 'Critical'; Title = 'Docker daemon clear-text endpoint exposed'; Evidence = 'Port 2375 open.' }
        @{ Regex = '9100/tcp\s+open'; Severity = 'Medium'; Title = 'Raw print service exposed'; Evidence = 'JetDirect port open.' }
        @{ Regex = '3389/tcp\s+open'; Severity = 'Medium'; Title = 'RDP service exposed'; Evidence = 'Port 3389 open.' }
        @{ Regex = '445/tcp\s+open'; Severity = 'Medium'; Title = 'SMB service exposed'; Evidence = 'Port 445 open.' }
    )

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($result in $ScanResults) {
        $blob = ($result.Output -join "`n")

        foreach ($pattern in $patterns) {
            if ($blob -match $pattern.Regex) {
                $findings.Add([pscustomobject]@{
                    Source = $result.Name
                    Profile = $result.Profile
                    Severity = $pattern.Severity
                    Title = $pattern.Title
                    Evidence = $pattern.Evidence
                    Command = $result.Command
                })
            }
        }

        if ($result.Ran -and $result.ExitCode -ne 0) {
            $findings.Add([pscustomobject]@{
                Source = $result.Name
                Profile = $result.Profile
                Severity = 'Medium'
                Title = 'Scan step returned non-zero exit code'
                Evidence = "ExitCode=$($result.ExitCode)"
                Command = $result.Command
            })
        }
    }

    @($findings | Sort-Object Source, Severity, Title -Unique)
}

Export-ModuleMember -Function Get-SecTargetList, Get-SecThreatProfileNames, New-SecSafeNmapPlan, Invoke-SecSafeScanPlan, New-SecCoverageSummary, New-SecThreatFindings
