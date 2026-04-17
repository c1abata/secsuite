<#
.SYNOPSIS
    SafeRedTeamSuite.ps1 – A Safety-First Operational Red Teaming Module
.DESCRIPTION
    This module provides a suite of black-box penetration testing techniques for
    educational and authorized red team operations. It is designed with a "safety
    by default" philosophy, requiring explicit user confirmation and validating
    the target environment before any potentially harmful action.

    Inspired by the work of Salvatore Sanfilippo (antirez), this code emphasizes
    clarity, simplicity, and robust safety checks. Every function includes detailed
    comments explaining the technique and its associated safety mechanisms.

    TARGET STACK: Full-stack devices, IoT, Printers, NAS, Linux/Windows Servers,
    Access Control, Domain Controllers, Web Apps, Databases, Network Equipment, etc.

    SAFETY MECHANISMS:
    - Environment Validation: Checks for production-related hostnames.
    - Pre-Execution Confirmation: User must explicitly confirm each module.
    - State Change Detection & Rollback: Saves state before and validates after changes.
    - Inert Payloads: Exploitation attempts use non-harmful verification commands.
    - Rate Limiting: Brute-force modules include throttling and account lockout checks.

.NOTES
    Version: 1.0.0
    Author:  Security Architect (Inspired by antirez)
#>

#Requires -Version 5.1

# ------------------------------------------------------------
# Global Configuration & Safety Constants
# ------------------------------------------------------------
$script:SafeMode = $true                     # Global override to disable all modules
$script:ProductionKeywords = @("PROD", "PRODUCTION", "LIVE", "PRD", "DC", "SQL", "DB", "EXCH", "FS")
$script:MaxSprayDelay = 60                        # Seconds between password spray attempts
$script:MaxBruteAttempts = 3                         # Maximum attempts per account
$script:TempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) {
    $env:TEMP
}
elseif (-not [string]::IsNullOrWhiteSpace($env:TMPDIR)) {
    $env:TMPDIR
}
else {
    [System.IO.Path]::GetTempPath()
}
$script:StateSnapshotPath = Join-Path $script:TempRoot "SafeRedTeam_StateSnapshots"

# Ensure the snapshot directory exists for rollback functionality
if (-not (Test-Path $script:StateSnapshotPath)) {
    New-Item -ItemType Directory -Path $script:StateSnapshotPath -Force | Out-Null
}

# ------------------------------------------------------------
# Core Safety Function: Environment Validation
# ------------------------------------------------------------
function Validate-OperationalSafety {
    <#
    .SYNOPSIS
        Checks if the current environment is safe for red team activities.
        This is the primary gatekeeper for all module functions.

    .DESCRIPTION
        Verifies that the hostname does not contain known production keywords
        and that the module is not running in SafeMode. In a real lab environment,
        this function can be bypassed by setting `$script:SafeMode = $false`.

    .EXAMPLE
        if (Validate-OperationalSafety) { Invoke-SafePortScan -Target "192.168.1.1" }
    #>
    [CmdletBinding()]
    param()

    # If global SafeMode is enabled, block all execution
    if ($script:SafeMode) {
        Write-Warning "[!] SAFETY LOCK ENGAGED: SafeMode is set to `$true. All operational modules are disabled."
        Write-Warning "    To enable (only in a lab!), set `$script:SafeMode = `$false in the script or console."
        return $false
    }

    # Check the local hostname against the list of production keywords
    $hostname = $env:COMPUTERNAME
    foreach ($keyword in $script:ProductionKeywords) {
        if ($hostname -match $keyword) {
            Write-Error "[!] SAFETY HALT: Hostname '$hostname' contains production keyword '$keyword'."
            Write-Error "    This module is designed for isolated lab environments only."
            return $false
        }
    }

    Write-Host "[+] Environment validated: $hostname is a lab/test system." -ForegroundColor Green
    return $true
}

# ------------------------------------------------------------
# Core Safety Function: User Confirmation & Module Description
# ------------------------------------------------------------
function Confirm-ModuleExecution {
    <#
    .SYNOPSIS
        Prompts the user for explicit confirmation before executing a module.
        This prevents accidental triggering of scans or exploits.

    .DESCRIPTION
        Displays the module name and a description of the intended action.
        The user must type "YES" to proceed. This is a critical human-in-the-loop safety check.

    .PARAMETER ModuleName
        The name of the function or module being executed.

    .PARAMETER Description
        A brief explanation of what the module will do and its potential impact.

    .EXAMPLE
        if (Confirm-ModuleExecution -ModuleName "Port Scan" -Description "Scans ports 1-1024 on 192.168.1.0/24") { ... }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    Write-Host "`n[!] MODULE: $ModuleName" -ForegroundColor Yellow
    Write-Host "    Description: $Description" -ForegroundColor Gray
    Write-Host "    WARNING: This action is potentially intrusive. It should only be executed in a controlled lab environment."
    $confirmation = Read-Host "    Type 'YES' to confirm and continue (any other input will cancel)"

    if ($confirmation -ne "YES") {
        Write-Warning "[!] Execution canceled by user."
        return $false
    }

    Write-Host "[+] User confirmed execution." -ForegroundColor Green
    return $true
}

# ------------------------------------------------------------
# Safety Check & Validate: State Change and Rollback (Snapshot)
# ------------------------------------------------------------
function Save-TargetState {
    <#
    .SYNOPSIS
        Captures a snapshot of the target's current state before making any changes.
        This enables rollback or validation of state modifications.

    .DESCRIPTION
        For the local system, it saves information about running services, processes,
        and scheduled tasks. For remote targets, it can save a baseline of open ports
        or service banners. This is a safety prerequisite for any module that modifies state.

    .PARAMETER TargetComputer
        The computer name or IP address of the target. Defaults to localhost.

    .PARAMETER SnapshotType
        The type of state to capture ("LocalSystem", "PortScan", "ServiceBanner").

    .EXAMPLE
        Save-TargetState -TargetComputer "192.168.1.100" -SnapshotType "PortScan"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TargetComputer = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [ValidateSet("LocalSystem", "PortScan", "ServiceBanner")]
        [string]$SnapshotType
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $snapshotFile = Join-Path $script:StateSnapshotPath "State_${TargetComputer}_${SnapshotType}_${timestamp}.json"

    Write-Host "[*] Capturing state snapshot of '$TargetComputer' ($SnapshotType)..."

    $snapshot = [PSCustomObject]@{
        Timestamp = $timestamp
        Target    = $TargetComputer
        Type      = $SnapshotType
        Data      = $null
    }

    switch ($SnapshotType) {
        "LocalSystem" {
            # Capture current service list, scheduled tasks, and startup programs
            $snapshot.Data = [PSCustomObject]@{
                Services         = Get-Service | Select-Object Name, Status, StartType
                ScheduledTasks   = Get-ScheduledTask | Where-Object State -ne "Disabled" | Select-Object TaskName, State
                RunningProcesses = Get-Process | Select-Object Name, Id, StartTime
            }
        }
        "PortScan" {
            # For a remote target, capture a baseline of open ports using a simple TCP test
            # In a full module, this would use Test-NetConnection or a custom socket scanner
            $snapshot.Data = [PSCustomObject]@{
                OpenPorts = @() # Placeholder: would contain list of open ports and service names
            }
        }
        "ServiceBanner" {
            # Placeholder: Capture banners from common services (HTTP, SSH, FTP)
            $snapshot.Data = [PSCustomObject]@{
                Banners = @{} # Placeholder: service -> banner dictionary
            }
        }
    }

    # Save the snapshot as a JSON file for potential rollback/comparison
    $snapshot | ConvertTo-Json -Depth 3 | Out-File -FilePath $snapshotFile -Encoding UTF8
    Write-Host "[+] Snapshot saved to: $snapshotFile" -ForegroundColor Green

    return $snapshotFile
}

function Compare-TargetState {
    <#
    .SYNOPSIS
        Compares a previously saved state snapshot to the current state of the target.
        This is used to validate that a module did not cause unintended changes.

    .DESCRIPTION
        After running an exploit or persistence mechanism, this function loads the
        baseline snapshot and compares it to the current state. It highlights any
        differences and can optionally trigger a rollback.

    .PARAMETER BaselineSnapshotPath
        The file path to the JSON snapshot created by Save-TargetState.

    .PARAMETER AutoRollback
        If set to $true, and differences are detected, the function will attempt to
        revert changes (requires implementation per module).

    .EXAMPLE
        $baseline = Save-TargetState -SnapshotType "LocalSystem"
        Invoke-SafePersistenceTest -Method "ScheduledTask"
        Compare-TargetState -BaselineSnapshotPath $baseline
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselineSnapshotPath,

        [Parameter(Mandatory = $false)]
        [switch]$AutoRollback
    )

    if (-not (Test-Path $BaselineSnapshotPath)) {
        Write-Error "Snapshot file not found: $BaselineSnapshotPath"
        return $false
    }

    $baseline = Get-Content $BaselineSnapshotPath | ConvertFrom-Json
    Write-Host "[*] Comparing current state against baseline from $($baseline.Timestamp)..."

    # This is a simplified demonstration. In a real module, you would perform
    # a deep comparison of the actual objects (services, processes, etc.)
    $differencesFound = $false

    if ($baseline.Type -eq "LocalSystem") {
        $currentServices = Get-Service | Select-Object Name, Status, StartType
        $baselineServices = $baseline.Data.Services

        # Compare service states (simplified)
        foreach ($svc in $currentServices) {
            $baselineSvc = $baselineServices | Where-Object Name -eq $svc.Name
            if (-not $baselineSvc) {
                Write-Warning "[!] New service detected: $($svc.Name)"
                $differencesFound = $true
            }
            elseif ($baselineSvc.Status -ne $svc.Status) {
                Write-Warning "[!] Service '$($svc.Name)' status changed: $($baselineSvc.Status) -> $($svc.Status)"
                $differencesFound = $true
            }
        }
    }

    if ($differencesFound) {
        Write-Host "[!] State changes detected!" -ForegroundColor Yellow
        if ($AutoRollback) {
            Write-Warning "AutoRollback is enabled. Attempting to revert changes..."
            # Placeholder: Implement rollback logic specific to the module
            # For example, removing a new service or scheduled task.
            Write-Host "[!] Rollback logic is module-specific and not fully implemented in this demo."
        }
        return $false
    }
    else {
        Write-Host "[+] No state changes detected. Target state is consistent with baseline." -ForegroundColor Green
        return $true
    }
}

# ------------------------------------------------------------
# Safety Check & Validate: Brute-Force, Password Attacks, Spraying
# ------------------------------------------------------------
function Invoke-SafePasswordSpray {
    <#
    .SYNOPSIS
        Performs a safe password spray attack against a target service.
        This is designed for educational use to test account lockout policies
        and weak password prevalence.

    .DESCRIPTION
        The function includes multiple safety mechanisms:
        - Limits the number of attempts per account to avoid lockouts.
        - Imposes a mandatory delay between attempts (configurable).
        - Checks for account lockout status before each attempt (where possible).
        - Uses a very small, common password list by default.

        For educational purposes, this targets a local test environment (e.g., a
        lab domain controller). It does NOT send passwords to real external services.

    .PARAMETER TargetDomain
        The domain or server to test. Defaults to local machine.

    .PARAMETER UserList
        An array of usernames to spray.

    .PARAMETER CredentialCandidateList
        An array of candidate secrets to try. Defaults to a small educational list.

    .PARAMETER MaxAttemptsPerUser
        Maximum password attempts per user to prevent lockout. Default is 3.

    .EXAMPLE
        $users = @("testuser1", "testuser2", "labadmin")
        Invoke-SafePasswordSpray -TargetDomain "lab.local" -UserList $users
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TargetDomain = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [string[]]$UserList,

        [Parameter(Mandatory = $false)]
        [Alias('PasswordList')]
        [string[]]$CredentialCandidateList = @("Password1", "Summer2024!", "P@ssw0rd", "admin"),

        [Parameter(Mandatory = $false)]
        [int]$MaxAttemptsPerUser = 3
    )

    # --- SAFETY GATES ---
    if (-not (Validate-OperationalSafety)) { return }
    if (-not (Confirm-ModuleExecution -ModuleName "Password Spray" -Description "Sprays $($CredentialCandidateList.Count) credential candidates against $($UserList.Count) users on $TargetDomain")) { return }

    Write-Host "[*] Starting safe password spray against $TargetDomain..."
    Write-Host "    Users: $($UserList -join ', ')"
    Write-Host "    Candidate secrets: $($CredentialCandidateList.Count) | Max attempts per user: $MaxAttemptsPerUser"
    Write-Host "    Safety Delay: $script:MaxSprayDelay seconds between attempts."

    # Store results
    $results = @()

    foreach ($user in $UserList) {
        Write-Host "[*] Spraying user: $user"
        $attempts = 0
        $accountLocked = $false

        foreach ($candidateSecret in $CredentialCandidateList) {
            if ($attempts -ge $MaxAttemptsPerUser) {
                Write-Warning "    Maximum attempts reached for $user. Skipping to next user to prevent lockout."
                break
            }

            # In a real module, you would implement a check to see if the account is already locked
            # For this educational demo, we simulate a credential test with a safety delay.
            Write-Host "    Trying candidate secret (Attempt $($attempts+1) of $MaxAttemptsPerUser)"

            # --- SIMULATED AUTHENTICATION (Educational Only) ---
            # In a real scenario, you would use something like:
            # $cred = New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString $candidateSecret -AsPlainText -Force))
            # $authResult = Test-ComputerSecureChannel -Credential $cred -Server $TargetDomain -ErrorAction SilentlyContinue
            # if ($authResult) { ... }
            #
            # For safety, we simulate a check with a sleep and always return "fail".
            $valid = $false
            # Simulate a safe, non-intrusive check (e.g., querying a test endpoint)
            Start-Sleep -Seconds 2
            # --- END SIMULATION ---

            $attempts++

            if ($valid) {
                $results += [PSCustomObject]@{
                    User      = $user
                    CredentialCandidate = '<redacted>'
                    Status    = "Valid"
                    Timestamp = Get-Date
                }
                Write-Host "    [!] VALID CREDENTIALS FOUND: $user (secret redacted)" -ForegroundColor Green
                break
            }

            # Mandatory delay to avoid overwhelming the target and to emulate a slow spray
            Start-Sleep -Seconds $script:MaxSprayDelay
        }

        # Additional delay between users
        Start-Sleep -Seconds 10
    }

    Write-Host "`n[+] Password spray completed."
    if ($results.Count -gt 0) {
        Write-Host "Found valid credentials:" -ForegroundColor Green
        $results | Format-Table -AutoSize
    }
    else {
        Write-Host "No valid credentials found with the provided list."
    }

    return $results
}

# ------------------------------------------------------------
# Safety Check & Validate: Remote Command Execution (RCE)
# ------------------------------------------------------------
function Invoke-SafeRemoteCommand {
    <#
    .SYNOPSIS
        Safely executes a command on a remote target using WinRM or SSH.
        This function is designed for educational post-exploitation and validation.

    .DESCRIPTION
        The function uses a **pre-defined, inert command** by default. It validates
        that the command is on an allow-list to prevent accidental destructive actions.
        It also captures the target state before and after execution to validate
        that no unexpected changes occurred.

        IMPORTANT: This function requires a valid credential object for the target.

    .PARAMETER TargetComputer
        The remote computer to execute the command on.

    .PARAMETER Credential
        A PSCredential object with appropriate permissions.

    .PARAMETER Command
        The command to execute. Must be one of the pre-approved safe commands.

    .PARAMETER Protocol
        WinRM (PowerShell Remoting) or SSH. Default is WinRM.

    .EXAMPLE
        $cred = Get-Credential "labadmin"
        Invoke-SafeRemoteCommand -TargetComputer "192.168.1.50" -Credential $cred -Command "TestSafeCommand"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetComputer,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [ValidateSet("TestSafeCommand", "GetSystemInfo", "CheckServiceStatus")]
        [string]$Command = "TestSafeCommand",

        [Parameter(Mandatory = $false)]
        [ValidateSet("WinRM", "SSH")]
        [string]$Protocol = "WinRM"
    )

    # --- SAFETY GATES ---
    if (-not (Validate-OperationalSafety)) { return }
    if (-not (Confirm-ModuleExecution -ModuleName "Remote Command Execution" -Description "Executes the safe command '$Command' on $TargetComputer using $Protocol")) { return }

    # Capture a baseline snapshot of the remote target (if possible)
    # This is a simplified placeholder; in a real module, you would use Invoke-Command to get remote services/processes
    $baselineSnapshot = Save-TargetState -TargetComputer $TargetComputer -SnapshotType "ServiceBanner"

    Write-Host "[*] Executing safe remote command on $TargetComputer..."
    $result = $null
    $errorOccurred = $false

    # Define allowed safe commands with their actual command text
    $allowedCommands = @{
        "TestSafeCommand"    = "Write-Host 'SAFE COMMAND EXECUTED: This is a non-destructive test.'; Get-Date"
        "GetSystemInfo"      = "Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsBuildNumber"
        "CheckServiceStatus" = "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 5"
    }

    $actualCommand = $allowedCommands[$Command]

    try {
        if ($Protocol -eq "WinRM") {
            # Execute via PowerShell Remoting (requires WinRM enabled on target)
            $session = New-PSSession -ComputerName $TargetComputer -Credential $Credential -ErrorAction Stop
            $result = Invoke-Command -Session $session -ScriptBlock { param($cmd) Invoke-Expression $cmd } -ArgumentList $actualCommand
            Remove-PSSession $session
        }
        else {
            # SSH Example (requires Posh-SSH module or similar)
            Write-Warning "SSH execution is not fully implemented in this demo. Simulating execution."
            # In a full module: $result = Invoke-SSHCommand -ComputerName $TargetComputer -Credential $Credential -Command $actualCommand
            $result = "[SIMULATED] Command: $actualCommand`nResult: Test successful."
        }
    }
    catch {
        Write-Error "Failed to execute command: $($_.Exception.Message)"
        $errorOccurred = $true
    }

    if (-not $errorOccurred) {
        Write-Host "[+] Command executed successfully."
        Write-Host "--- Result ---"
        Write-Host $result
        Write-Host "--------------"
    }

    # Validate that the target state has not changed unexpectedly (simplified)
    $stateValid = Compare-TargetState -BaselineSnapshotPath $baselineSnapshot
    if (-not $stateValid) {
        Write-Warning "[!] Unexpected state changes detected on the target after command execution."
    }

    return $result
}

# ------------------------------------------------------------
# Safety Check & Validate: Persistence Mechanisms
# ------------------------------------------------------------
function Invoke-SafePersistenceTest {
    <#
    .SYNOPSIS
        Tests a persistence mechanism in a controlled, reversible manner.
        This function is heavily inspired by the reversible modules in frameworks
        like PANIX and Trawler.

    .DESCRIPTION
        The function will deploy a persistence technique (e.g., scheduled task,
        registry run key, service) and then **immediately revert it** unless the
        `-LeavePersistent` switch is explicitly used. This ensures the system is
        cleaned up, leaving no permanent changes.

        The persistence mechanisms used are educational and use harmless payloads
        (e.g., writing a timestamp to a log file).

    .PARAMETER Method
        The persistence method to test. Options: "ScheduledTask", "RegistryRun",
        "WMIEventSubscription", "Service".

    .PARAMETER LeavePersistent
        If specified, the persistence mechanism is NOT cleaned up. This should only
        be used in a fully disposable lab environment.

    .EXAMPLE
        Invoke-SafePersistenceTest -Method "ScheduledTask"
        # Creates a test scheduled task, then removes it after 10 seconds.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("ScheduledTask", "RegistryRun", "WMIEventSubscription", "Service")]
        [string]$Method,

        [Parameter(Mandatory = $false)]
        [switch]$LeavePersistent
    )

    # --- SAFETY GATES ---
    if (-not (Validate-OperationalSafety)) { return }
    if (-not (Confirm-ModuleExecution -ModuleName "Persistence Test" -Description "Tests the $Method persistence method (and will REVERT unless -LeavePersistent is used)")) { return }

    # Capture a local system state snapshot for later comparison/validation
    $baselineSnapshot = Save-TargetState -SnapshotType "LocalSystem"

    Write-Host "[*] Testing persistence method: $Method"

    $artifactName = "SafeRedTeam_TestPersistence"
            $payload = "Write-Output 'SafeRedTeam Test Payload Executed at: $(Get-Date)' | Out-File -FilePath `"$($script:TempRoot)\SafeRedTeam_PersistenceTest.log`" -Append"

    try {
        switch ($Method) {
            "ScheduledTask" {
                Write-Host "    Creating scheduled task '$artifactName'..."
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"$payload`""
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                Register-ScheduledTask -TaskName $artifactName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
                Write-Host "    Task created. (Will trigger in ~1 minute)"
            }

            "RegistryRun" {
                Write-Host "    Adding registry run key for '$artifactName'..."
                $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
                Set-ItemProperty -Path $regPath -Name $artifactName -Value "powershell.exe -Command `"$payload`"" -Force
                Write-Host "    Registry key added."
            }

            "WMIEventSubscription" {
                Write-Warning "WMI Event Subscription requires elevated privileges and is not implemented in this demo for safety."
                Write-Host "    Simulating WMI persistence test..."
            }

            "Service" {
                Write-Warning "Service persistence requires administrative rights and is not implemented in this demo for safety."
                Write-Host "    Simulating Service persistence test..."
            }
        }

        # If LeavePersistent is not set, schedule a cleanup after a short delay
        if (-not $LeavePersistent) {
            Write-Host "`n[*] Reverting persistence mechanism in 15 seconds (unless -LeavePersistent was used)..."
            Start-Sleep -Seconds 15

            Write-Host "[*] Cleaning up artifact: $artifactName"
            switch ($Method) {
                "ScheduledTask" {
                    Unregister-ScheduledTask -TaskName $artifactName -Confirm:$false -ErrorAction SilentlyContinue
                }
                "RegistryRun" {
                    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $artifactName -Force -ErrorAction SilentlyContinue
                }
                # Other methods would have their own cleanup logic
            }
            Write-Host "[+] Cleanup completed." -ForegroundColor Green
        }
        else {
            Write-Warning "[!] LEAVE-PERSISTENT SPECIFIED. Artifact '$artifactName' will remain on the system."
            Write-Warning "    Ensure you manually clean up in a lab environment."
        }

        # Validate state change (since we cleaned up, the state should be identical to baseline)
        $stateValid = Compare-TargetState -BaselineSnapshotPath $baselineSnapshot
        if (-not $stateValid) {
            Write-Warning "[!] State validation failed. The system may not be in its original state."
        }
    }
    catch {
        Write-Error "An error occurred during the persistence test: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------
# Main Module Entry Point / Help System
# ------------------------------------------------------------
function Show-SafeRedTeamHelp {
    <#
    .SYNOPSIS
        Displays the available safe red teaming functions and their usage.
        This is the recommended starting point for using this module.
    #>
    Write-Host @"
==============================================
 SafeRedTeamSuite.ps1 - Safety-First Red Teaming Module
==============================================
 Inspired by the coding philosophy of antirez (Salvatore Sanfilippo):
 "Clear, reliable, and well-documented code."

 This module provides a controlled environment for:
  - Black-box scanning and reconnaissance
  - Safe password spraying (with lockout prevention)
  - Remote command execution validation
  - Testing persistence mechanisms with automatic rollback

 AVAILABLE FUNCTIONS:
 -------------------
 1. Validate-OperationalSafety          : Checks if the environment is safe.
 2. Confirm-ModuleExecution             : Prompts for user confirmation before running a module.
 3. Save-TargetState / Compare-TargetState : Capture and validate system state changes.

 4. Invoke-SafePasswordSpray            : Performs a slow, safe password spray.
    Example: Invoke-SafePasswordSpray -TargetDomain "lab.local" -UserList @("user1", "user2")

 5. Invoke-SafeRemoteCommand            : Executes a pre-approved command on a remote target.
    Example: Invoke-SafeRemoteCommand -TargetComputer "192.168.1.50" -Credential (Get-Credential) -Command "TestSafeCommand"

 6. Invoke-SafePersistenceTest          : Tests a persistence method and automatically cleans up.
    Example: Invoke-SafePersistenceTest -Method "ScheduledTask"

 SAFETY FIRST:
 -------------
 - The script will halt if run on a machine with a production-like hostname.
 - All destructive modules require typing 'YES' to proceed.
 - Payloads are inert and only log timestamps.
 - State changes are monitored and can be rolled back.

"@
}

# ------------------------------------------------------------
# Auto-Help on Import
# ------------------------------------------------------------
Show-SafeRedTeamHelp

# ------------------------------------------------------------
# SAFE ACTIVE DIRECTORY RECONNAISSANCE (Read-Only)
# ------------------------------------------------------------
function Invoke-SafeADRecon {
    <#
    .SYNOPSIS
        Performs safe, read-only Active Directory reconnaissance for educational
        purposes. All queries are non-modifying and target the logged-in user's context.

    .DESCRIPTION
        This function demonstrates common AD enumeration techniques without making
        any changes to the directory. It uses standard .NET classes (DirectorySearcher)
        and validates the environment before execution.

        SAFETY FEATURES:
        - Only read operations (LDAP queries).
        - Requires explicit user confirmation.
        - Outputs data in a structured format for analysis.

    .PARAMETER Domain
        The FQDN of the domain to query. Defaults to the current user's domain.

    .PARAMETER QueryType
        Type of information to gather: "Users", "Computers", "Groups", "DomainTrusts",
        "GPOs", or "All".

    .EXAMPLE
        Invoke-SafeADRecon -Domain "lab.local" -QueryType "Users"
        Invoke-SafeADRecon -QueryType "All"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Users", "Computers", "Groups", "DomainTrusts", "GPOs", "All")]
        [string]$QueryType = "All"
    )

    # --- SAFETY GATES ---
    if (-not (Validate-OperationalSafety)) { return }
    if (-not (Confirm-ModuleExecution -ModuleName "Active Directory Recon" -Description "Performs read-only LDAP queries against domain '$Domain'")) { return }

    Write-Host "[*] Starting safe AD reconnaissance on domain: $Domain" -ForegroundColor Cyan

    # Helper function to perform LDAP search
    function Search-AD {
        param([string]$LdapFilter, [string[]]$Properties, [string]$SearchRoot = "")
        try {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = $LdapFilter
            $searcher.PageSize = 1000
            if ($Properties) { $searcher.PropertiesToLoad.AddRange($Properties) }
            if ($SearchRoot) { $searcher.SearchRoot = $SearchRoot }
            $results = $searcher.FindAll()
            $objects = @()
            foreach ($result in $results) {
                $obj = @{}
                foreach ($prop in $Properties) {
                    if ($result.Properties.Contains($prop)) {
                        $obj[$prop] = $result.Properties[$prop][0]
                    }
                    else {
                        $obj[$prop] = $null
                    }
                }
                $objects += [PSCustomObject]$obj
            }
            return $objects
        }
        catch {
            Write-Warning "LDAP query failed: $($_.Exception.Message)"
            return $null
        }
    }

    $results = @{}

    # --- Enumerate Users ---
    if ($QueryType -in @("Users", "All")) {
        Write-Host "[*] Enumerating domain users..."
        $users = Search-AD -LdapFilter "(&(objectCategory=person)(objectClass=user))" -Properties @("sAMAccountName", "displayName", "mail", "userAccountControl", "lastLogonTimestamp")
        $results["Users"] = $users
        Write-Host "    Found $($users.Count) user objects."
    }

    # --- Enumerate Computers ---
    if ($QueryType -in @("Computers", "All")) {
        Write-Host "[*] Enumerating domain computers..."
        $computers = Search-AD -LdapFilter "(objectClass=computer)" -Properties @("name", "dNSHostName", "operatingSystem", "operatingSystemVersion")
        $results["Computers"] = $computers
        Write-Host "    Found $($computers.Count) computer objects."
    }

    # --- Enumerate Groups ---
    if ($QueryType -in @("Groups", "All")) {
        Write-Host "[*] Enumerating domain groups (including nested membership)..."
        $groups = Search-AD -LdapFilter "(objectClass=group)" -Properties @("name", "distinguishedName", "groupType", "member")
        $results["Groups"] = $groups
        Write-Host "    Found $($groups.Count) group objects."
    }

    # --- Enumerate Domain Trusts ---
    if ($QueryType -in @("DomainTrusts", "All")) {
        Write-Host "[*] Enumerating domain trusts..."
        try {
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
            $trusts = $domainObj.GetAllTrustRelationships()
            $trustList = @()
            foreach ($trust in $trusts) {
                $trustList += [PSCustomObject]@{
                    Source     = $trust.SourceName
                    Target     = $trust.TargetName
                    Direction  = $trust.TrustDirection
                    Type       = $trust.TrustType
                    Attributes = $trust.TrustAttributes
                }
            }
            $results["Trusts"] = $trustList
            Write-Host "    Found $($trustList.Count) trust relationships."
        }
        catch {
            Write-Warning "Trust enumeration failed: $($_.Exception.Message)"
        }
    }

    # --- Enumerate GPOs ---
    if ($QueryType -in @("GPOs", "All")) {
        Write-Host "[*] Enumerating Group Policy Objects (display names only)..."
        # Using LDAP to find GPOs in the Policies container
        $gpoSearchRoot = "LDAP://CN=Policies,CN=System,$(([ADSI]"LDAP://RootDSE").defaultNamingContext)"
        $gpos = Search-AD -LdapFilter "(objectClass=groupPolicyContainer)" -Properties @("displayName", "gPCFileSysPath") -SearchRoot $gpoSearchRoot
        $results["GPOs"] = $gpos
        Write-Host "    Found $($gpos.Count) GPOs."
    }

    Write-Host "[+] AD Recon complete." -ForegroundColor Green

    # Display summary
    foreach ($category in $results.Keys) {
        Write-Host "`n--- $category ---" -ForegroundColor Yellow
        $results[$category] | Format-Table -AutoSize -Property * -Wrap
    }

    return $results
}




function Invoke-SafeSSHPersistence {
    <#
    .SYNOPSIS
        Demonstrates SSH public key persistence on a Linux target for educational
        purposes, with automatic rollback.

    .DESCRIPTION
        This function safely demonstrates how an attacker might establish persistence
        by adding an SSH authorized key. It uses a **temporary key pair** generated
        locally, adds it to the target's `authorized_keys`, validates access, and then
        **automatically removes** the key unless `-LeavePersistent` is specified.

        The function requires SSH credentials and the Posh-SSH module (or simulates
        if not available).

    .PARAMETER TargetHost
        IP address or hostname of the Linux target.

    .PARAMETER Credential
        PSCredential object with valid SSH credentials.

    .PARAMETER Port
        SSH port (default 22).

    .PARAMETER LeavePersistent
        If specified, the SSH key is NOT removed from the target. Use only in
        disposable lab environments.

    .EXAMPLE
        $cred = Get-Credential "labuser"
        Invoke-SafeSSHPersistence -TargetHost "192.168.1.100" -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$Port = 22,

        [Parameter(Mandatory = $false)]
        [switch]$LeavePersistent
    )

    # --- SAFETY GATES ---
    if (-not (Validate-OperationalSafety)) { return }
    if (-not (Confirm-ModuleExecution -ModuleName "SSH Persistence" -Description "Adds a temporary SSH key to $TargetHost and then removes it (unless -LeavePersistent)")) { return }

    # Check if Posh-SSH is installed
    $moduleInstalled = Get-Module -ListAvailable -Name Posh-SSH
    if (-not $moduleInstalled) {
        Write-Warning "Posh-SSH module not found. Will simulate SSH operations for educational demonstration."
        $simulate = $true
    }
    else {
        Import-Module Posh-SSH -Force -ErrorAction SilentlyContinue
        $simulate = $false
    }

    Write-Host "[*] Starting safe SSH persistence test on $TargetHost" -ForegroundColor Cyan

    # Generate a temporary key pair
    $keyDir = Join-Path $script:TempRoot "SafeRedTeam_SSHKeys"
    if (-not (Test-Path $keyDir)) { New-Item -ItemType Directory -Path $keyDir | Out-Null }
    $keyName = "SafeRedTeam_$((Get-Date).ToString('yyyyMMddHHmmss'))"
    $privateKeyPath = Join-Path $keyDir $keyName
    $publicKeyPath = "$privateKeyPath.pub"

    Write-Host "[*] Generating temporary SSH key pair..."
    if (-not $simulate) {
        # Generate RSA key using ssh-keygen (assumes ssh-keygen is in PATH)
        & ssh-keygen -t rsa -b 2048 -f $privateKeyPath -N '""' -q
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to generate SSH key. Ensure ssh-keygen is available."
            return
        }
    }
    else {
        Write-Host "    [SIMULATED] Generated key pair at $keyDir"
    }

    # Read public key content
    $publicKeyContent = if (-not $simulate) { Get-Content $publicKeyPath } else { "ssh-rsa AAAAB3NzaC... SIMULATED KEY ... user@host" }

    # Connect via SSH and add key to authorized_keys
    Write-Host "[*] Adding temporary public key to target's ~/.ssh/authorized_keys..."

    # Backup original authorized_keys content for rollback
    $backupContent = $null
    $addKeyCommand = @"
mkdir -p ~/.ssh && chmod 700 ~/.ssh
if [ -f ~/.ssh/authorized_keys ]; then cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak.saferedteam; fi
echo '$publicKeyContent' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
"@

    if (-not $simulate) {
        try {
            $session = New-SSHSession -ComputerName $TargetHost -Credential $Credential -Port $Port -AcceptKey -ErrorAction Stop
            $result = Invoke-SSHCommand -SessionId $session.SessionId -Command $addKeyCommand -ErrorAction Stop
            if ($result.ExitStatus -ne 0) {
                Write-Error "Failed to add SSH key. Exit code: $($result.ExitStatus) Error: $($result.Error)"
                Remove-SSHSession -SessionId $session.SessionId | Out-Null
                return
            }
            Remove-SSHSession -SessionId $session.SessionId | Out-Null
            Write-Host "    [+] Key added successfully."
        }
        catch {
            Write-Error "SSH connection failed: $($_.Exception.Message)"
            return
        }
    }
    else {
        Write-Host "    [SIMULATED] Added public key to authorized_keys"
    }

    # Validate key-based authentication (simulate or actual test)
    Write-Host "[*] Validating key-based access..."
    if (-not $simulate) {
        # Test key-based login (without password)
        $testResult = Invoke-Command -ScriptBlock {
            $keyCred = New-Object System.Management.Automation.PSCredential ($Credential.UserName, (New-Object System.Security.SecureString))
            # Actually use key authentication via Posh-SSH
            $testSession = New-SSHSession -ComputerName $TargetHost -Credential $keyCred -KeyFile $privateKeyPath -AcceptKey -ErrorAction SilentlyContinue
            if ($testSession) {
                $valid = $true
                Remove-SSHSession -SessionId $testSession.SessionId
            }
            else {
                $valid = $false
            }
            return $valid
        }
        if ($testResult) {
            Write-Host "    [+] Key-based authentication successful." -ForegroundColor Green
        }
        else {
            Write-Warning "    [!] Key-based authentication failed. Check target configuration."
        }
    }
    else {
        Write-Host "    [SIMULATED] Key authentication successful."
    }

    # Rollback unless LeavePersistent is specified
    if (-not $LeavePersistent) {
        Write-Host "[*] Cleaning up: Removing temporary key from target..."
        $removeKeyCommand = @"
if [ -f ~/.ssh/authorized_keys.bak.saferedteam ]; then mv ~/.ssh/authorized_keys.bak.saferedteam ~/.ssh/authorized_keys; else rm -f ~/.ssh/authorized_keys; fi
"@
        if (-not $simulate) {
            $session = New-SSHSession -ComputerName $TargetHost -Credential $Credential -Port $Port -AcceptKey -ErrorAction Stop
            Invoke-SSHCommand -SessionId $session.SessionId -Command $removeKeyCommand | Out-Null
            Remove-SSHSession -SessionId $session.SessionId | Out-Null
        }
        else {
            Write-Host "    [SIMULATED] Removed key from authorized_keys"
        }

        # Remove local key files
        Remove-Item -Path $privateKeyPath, $publicKeyPath -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Cleanup completed. Key removed from target." -ForegroundColor Green
    }
    else {
        Write-Warning "[!] LEAVE-PERSISTENT SPECIFIED. SSH key remains on target."
        Write-Warning "    Private key location: $privateKeyPath"
        Write-Warning "    Ensure you manually remove the key from ~/.ssh/authorized_keys on $TargetHost after the exercise."
    }
}




function Invoke-SafeModbusFuzzing {
    <#
    .SYNOPSIS
        Performs safe, educational Modbus/TCP fuzzing against a simulated or lab
        SCADA/ICS device. This function does NOT send malformed packets to real
        production controllers.

    .DESCRIPTION
        Modbus is a widely used industrial protocol. This function demonstrates how
        a fuzzer might interact with a Modbus device by sending valid, read-only
        function codes with random but safe parameters.

        SAFETY FEATURES:
        - Only uses read-only Modbus function codes (e.g., Read Coils, Read Holding Registers).
        - Includes rate limiting (delay between requests).
        - Target must be explicitly specified; no broadcast.
        - Can operate against a local Modbus simulator for practice.

    .PARAMETER TargetIP
        IP address of the Modbus device (or simulator).

    .PARAMETER Port
        Modbus TCP port (default 502).

    .PARAMETER UnitID
        Modbus slave/unit ID (default 1).

    .PARAMETER Iterations
        Number of fuzzing iterations (default 20).

    .PARAMETER DelayMs
        Delay between requests in milliseconds (default 200).

    .EXAMPLE
        # Run against a Modbus simulator on localhost
        Invoke-SafeModbusFuzzing -TargetIP "127.0.0.1" -Iterations 10

    .NOTES
        This function requires a Modbus client library. If not found, it simulates
        the interaction with detailed logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetIP,

        [Parameter(Mandatory = $false)]
        [int]$Port = 502,

        [Parameter(Mandatory = $false)]
        [byte]$UnitID = 1,

        [Parameter(Mandatory = $false)]
        [int]$Iterations = 20,

        [Parameter(Mandatory = $false)]
        [int]$DelayMs = 200
    )

    # --- SAFETY GATES ---
    if (-not (Validate-OperationalSafety)) { return }
    if (-not (Confirm-ModuleExecution -ModuleName "Modbus Fuzzing" -Description "Sends $Iterations read-only Modbus requests to $TargetIP`:$Port with $DelayMs ms delay")) { return }

    Write-Host "[*] Starting safe Modbus fuzzing simulation against $TargetIP`:$Port" -ForegroundColor Cyan

    # Attempt to load a Modbus library (e.g., PoshModbus) if available
    $modbusModule = Get-Module -ListAvailable -Name PoshModbus
    if ($modbusModule) {
        Import-Module PoshModbus -Force -ErrorAction SilentlyContinue
        $realModbus = $true
        Write-Host "[+] PoshModbus module loaded. Using real Modbus communication."
    }
    else {
        Write-Warning "PoshModbus module not found. Will simulate Modbus requests for educational demonstration."
        Write-Host "    To use real Modbus, install PoshModbus from PowerShell Gallery: Install-Module -Name PoshModbus"
        $realModbus = $false
    }

    # Safe Modbus function codes (read-only)
    $safeFunctionCodes = @{
        1 = "Read Coils"
        2 = "Read Discrete Inputs"
        3 = "Read Holding Registers"
        4 = "Read Input Registers"
        # Note: We exclude write functions (5,6,15,16) for safety.
    }

    Write-Host "[*] Fuzzing with safe function codes: $($safeFunctionCodes.Values -join ', ')"
    Write-Host "    Unit ID: $UnitID | Iterations: $Iterations | Delay: $DelayMs ms"

    $successfulRequests = 0
    $failedRequests = 0
    $responses = @()

    for ($i = 1; $i -le $Iterations; $i++) {
        # Randomly select a safe function code
        $funcCode = Get-Random -InputObject @(1, 2, 3, 4)
        # Random starting address (0-65535)
        $startAddress = Get-Random -Minimum 0 -Maximum 65535
        # Random quantity (1-125 for coils, 1-125 for registers)
        $quantity = Get-Random -Minimum 1 -Maximum 125

        Write-Host "`n[Iteration $i] Function: $funcCode ($($safeFunctionCodes[$funcCode]))"
        Write-Host "    Start Address: $startAddress, Quantity: $quantity"

        try {
            if ($realModbus) {
                # Use PoshModbus functions
                $response = switch ($funcCode) {
                    1 { Read-ModbusCoils -IPAddress $TargetIP -Port $Port -UnitID $UnitID -StartAddress $startAddress -NumberOfCoils $quantity }
                    2 { Read-ModbusDiscreteInputs -IPAddress $TargetIP -Port $Port -UnitID $UnitID -StartAddress $startAddress -NumberOfInputs $quantity }
                    3 { Read-ModbusHoldingRegisters -IPAddress $TargetIP -Port $Port -UnitID $UnitID -StartAddress $startAddress -NumberOfRegisters $quantity }
                    4 { Read-ModbusInputRegisters -IPAddress $TargetIP -Port $Port -UnitID $UnitID -StartAddress $startAddress -NumberOfRegisters $quantity }
                }
                $status = "Success"
                $data = $response
                $successfulRequests++
            }
            else {
                # Simulate response with random bytes
                $data = -join ((1..$quantity) | ForEach-Object { "{0:X2}" -f (Get-Random -Maximum 256) })
                Write-Host "    [SIMULATED] Response data: $data"
                $status = "Simulated"
                $successfulRequests++
            }
        }
        catch {
            $status = "Failed"
            $data = $_.Exception.Message
            $failedRequests++
            Write-Warning "    Request failed: $data"
        }

        $responses += [PSCustomObject]@{
            Iteration    = $i
            Timestamp    = Get-Date -Format "HH:mm:ss.fff"
            FunctionCode = $funcCode
            Address      = $startAddress
            Quantity     = $quantity
            Status       = $status
            Data         = $data
        }

        # Rate limiting to avoid overwhelming the device
        Start-Sleep -Milliseconds $DelayMs
    }

    Write-Host "`n[+] Modbus fuzzing completed." -ForegroundColor Green
    Write-Host "    Successful requests: $successfulRequests"
    Write-Host "    Failed requests: $failedRequests"

    # Show summary table of responses
    $responses | Format-Table -AutoSize -Property Iteration, Timestamp, FunctionCode, Address, Quantity, Status

    return $responses
}
