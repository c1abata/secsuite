Set-StrictMode -Version Latest

function Get-SecTargetList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [string]$ExcludePath
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Target file not found: $Path"
    }

    $excluded = @{}
    if ($ExcludePath -and (Test-Path -LiteralPath $ExcludePath)) {
        foreach ($line in Get-Content -LiteralPath $ExcludePath -ErrorAction Stop) {
            $item = $line.Trim()
            if ($item -and -not $item.StartsWith('#')) {
                $excluded[$item.ToLowerInvariant()] = $true
            }
        }
    }

    $targets = foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
        $item = $line.Trim()
        if ($item -and -not $item.StartsWith('#') -and -not $excluded.ContainsKey($item.ToLowerInvariant())) {
            $item
        }
    }

    @($targets | Sort-Object -Unique)
}

function New-SecSafeNmapPlan {
    [CmdletBinding()]
    param(
        [ValidateSet('ResilienceSnmp','IdentityAccess','WindowsProtocol','UnixExposure','MssqlAudit','WebTlsBaseline')]
        [string]$Profile = 'ResilienceSnmp',
        [Parameter(Mandatory)] [string]$TargetFile,
        [string]$ExcludeFile,
        [Parameter(Mandatory)] [string]$OutputDirectory
    )

    $common = '-Pn --disable-arp-ping'
    $excludeArg = if ($ExcludeFile) { "--excludefile \"$ExcludeFile\"" } else { '' }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    switch ($Profile) {
        'ResilienceSnmp' {
            @(
                [pscustomobject]@{
                    Name    = 'SNMP_Resilience_Check'
                    Tool    = 'nmap'
                    Purpose = 'Verifica configurazioni SNMP esposte e community deboli in sola modalità discovery.'
                    Command = "nmap $common -sU -p 161 -sV --script \"snmp-info,snmp-interfaces,snmp-sysdescr,snmp-processes\" --script-args \"snmpcommunity=public,private\" -iL \"$TargetFile\" $excludeArg -oA \"$OutputDirectory/snmp_resilience\""
                }
            )
        }
        'IdentityAccess' {
            @(
                [pscustomobject]@{
                    Name    = 'AD_Identity_Baseline'
                    Tool    = 'nmap'
                    Purpose = 'Controlla cifratura RDP e segnali SMB legacy senza exploit.'
                    Command = "nmap $common -p 445,3389 -sV --script \"rdp-enum-encryption,rdp-ntlm-info,smb-security-mode,smb2-security-mode\" -iL \"$TargetFile\" $excludeArg -oA \"$OutputDirectory/identity_access\""
                }
            )
        }
        'WindowsProtocol' {
            @(
                [pscustomobject]@{
                    Name    = 'Windows_Safe_Protocol_Check'
                    Tool    = 'nmap'
                    Purpose = 'Rileva protocolli SMB deboli con script NSE in modalità non distruttiva.'
                    Command = "nmap $common -p 445 --script \"smb-protocols,smb-security-mode,smb2-capabilities\" --script-args \"unsafe=0\" -iL \"$TargetFile\" $excludeArg -oA \"$OutputDirectory/windows_protocol\""
                }
            )
        }
        'UnixExposure' {
            @(
                [pscustomobject]@{
                    Name    = 'Unix_Web_Exposure_Check'
                    Tool    = 'nmap'
                    Purpose = 'Controlla exposure web e metodi SSH permessi senza inviare payload.'
                    Command = "nmap $common -p 22,80,443,8080 -sV --script \"http-shellshock,http-methods,ssh-auth-methods\" --script-args \"unsafe=0\" -iL \"$TargetFile\" $excludeArg -oA \"$OutputDirectory/unix_exposure\""
                }
            )
        }
        'MssqlAudit' {
            @(
                [pscustomobject]@{
                    Name    = 'MSSQL_Safe_Audit'
                    Tool    = 'nmap'
                    Purpose = 'Audit SQL Server focalizzato su metadata, TLS e configurazioni visibili.'
                    Command = "nmap $common -p 1433 -sV --script \"ms-sql-info,ms-sql-ntlm-info,ssl-cert,ssl-enum-ciphers\" --script-args \"ms-sql-ntlm-info.auth=anonymous\" -iL \"$TargetFile\" $excludeArg -oA \"$OutputDirectory/mssql_audit\""
                }
            )
        }
        'WebTlsBaseline' {
            @(
                [pscustomobject]@{
                    Name    = 'Web_TLS_Baseline'
                    Tool    = 'nmap'
                    Purpose = 'Baseline web security headers e postura TLS in ottica NIS2/DORA.'
                    Command = "nmap $common -p 80,443 -sV --script \"http-security-headers,ssl-cert,ssl-enum-ciphers\" -iL \"$TargetFile\" $excludeArg -oA \"$OutputDirectory/web_tls\""
                }
            )
        }
    }
}

function Invoke-SecSafeScanPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]]$Plan,
        [switch]$Execute
    )

    $results = foreach ($step in $Plan) {
        $toolPath = Get-Command $step.Tool -ErrorAction SilentlyContinue
        $canRun = $null -ne $toolPath

        if ($Execute -and $canRun) {
            $output = & cmd.exe /c $step.Command 2>&1
            [pscustomobject]@{
                Name     = $step.Name
                Ran      = $true
                ExitCode = $LASTEXITCODE
                Output   = @($output)
                Command  = $step.Command
            }
        }
        else {
            [pscustomobject]@{
                Name     = $step.Name
                Ran      = $false
                ExitCode = if ($canRun) { 0 } else { 127 }
                Output   = @('Dry-run o tool non disponibile in questo host.')
                Command  = $step.Command
            }
        }
    }

    @($results)
}

function New-SecThreatFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]]$ScanResults)

    $patterns = @(
        @{ Regex = 'VULNERABLE|WEAK|deprecated|anonymous'; Severity = 'High'; Title = 'Segnale di configurazione debole o vulnerabile' },
        @{ Regex = 'TLSv1\.0|TLSv1\.1|SMBv1'; Severity = 'Medium'; Title = 'Protocollo legacy rilevato' },
        @{ Regex = 'open|exposed|enabled'; Severity = 'Low'; Title = 'Superficie esposta da validare con hardening' }
    )

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($result in $ScanResults) {
        $blob = ($result.Output -join "`n")
        foreach ($p in $patterns) {
            if ($blob -match $p.Regex) {
                $findings.Add([pscustomobject]@{
                    Source   = $result.Name
                    Severity = $p.Severity
                    Title    = $p.Title
                    Evidence = "Pattern: $($p.Regex)"
                })
            }
        }
    }

    @($findings | Sort-Object Source, Severity, Title -Unique)
}

Export-ModuleMember -Function Get-SecTargetList, New-SecSafeNmapPlan, Invoke-SecSafeScanPlan, New-SecThreatFindings
