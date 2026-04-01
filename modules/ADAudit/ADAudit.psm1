Set-StrictMode -Version Latest

function Test-SecAdModuleAvailable {
    [CmdletBinding()]
    param()
    [bool](Get-Module -ListAvailable -Name ActiveDirectory)
}

function Get-SecADSummary {
    [CmdletBinding()]
    param([hashtable]$Config)

    if (-not (Test-SecAdModuleAvailable)) {
        return [pscustomobject]@{
            Available = $false
            Message   = 'ActiveDirectory module not available on this host.'
        }
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = Get-ADDomain
    $forest = Get-ADForest
    $privilegedGroups = if ($Config -and $Config.PrivilegedGroups) { $Config.PrivilegedGroups } else { @('Domain Admins','Enterprise Admins','Schema Admins') }

    $memberships = foreach ($group in $privilegedGroups) {
        try {
            Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                Select-Object @{n='Group';e={$group}}, Name, SamAccountName, objectClass
        }
        catch {
            [pscustomobject]@{ Group = $group; Name = $null; SamAccountName = $null; objectClass = 'Unavailable' }
        }
    }

    $pwdPolicy = Get-ADDefaultDomainPasswordPolicy
    $inactiveDays = if ($Config -and $Config.InactiveUserDays) { [int]$Config.InactiveUserDays } else { 90 }
    $inactiveSince = (Get-Date).AddDays(-$inactiveDays)
    $inactiveUsers = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $inactiveSince } -Properties LastLogonDate,PasswordNotRequired,DoesNotRequirePreAuth,ServicePrincipalName,TrustedForDelegation,TrustedToAuthForDelegation -ErrorAction SilentlyContinue |
        Select-Object Name, SamAccountName, LastLogonDate, PasswordNotRequired, DoesNotRequirePreAuth, ServicePrincipalName, TrustedForDelegation, TrustedToAuthForDelegation

    $serviceAccounts = Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties ServicePrincipalName,PasswordLastSet,TrustedForDelegation -ErrorAction SilentlyContinue |
        Select-Object Name, SamAccountName, ServicePrincipalName, PasswordLastSet, TrustedForDelegation

    $computers = Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate,TrustedForDelegation -ErrorAction SilentlyContinue |
        Select-Object Name, OperatingSystem, LastLogonDate, TrustedForDelegation

    $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue |
        Select-Object Name, Direction, ForestTransitive, IntraForest, SelectiveAuthentication, SIDFilteringForestAware

    [pscustomobject]@{
        Available             = $true
        DNSRoot               = $domain.DNSRoot
        DomainMode            = $domain.DomainMode.ToString()
        ForestMode            = $forest.ForestMode.ToString()
        DomainControllers     = @($domain.ReplicaDirectoryServers)
        PrivilegedMemberships = @($memberships)
        PasswordPolicy        = [pscustomobject]@{
            MinPasswordLength = $pwdPolicy.MinPasswordLength
            ComplexityEnabled = $pwdPolicy.ComplexityEnabled
            LockoutThreshold  = $pwdPolicy.LockoutThreshold
            MaxPasswordAge    = $pwdPolicy.MaxPasswordAge.ToString()
        }
        InactiveUsers         = @($inactiveUsers)
        ServiceAccounts       = @($serviceAccounts)
        Computers             = @($computers)
        Trusts                = @($trusts)
    }
}

function New-SecADFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$AuditData)

    $findings = New-Object System.Collections.Generic.List[object]

    if (-not $AuditData.Available) {
        $findings.Add([pscustomobject]@{ Id='AD-000'; Severity='Info'; Title='AD module not available'; Detail=$AuditData.Message })
        return @($findings)
    }

    if ($AuditData.PasswordPolicy.MinPasswordLength -lt 12) {
        $findings.Add([pscustomobject]@{ Id='AD-001'; Severity='Medium'; Title='Min password length below 12'; Detail="Configured value: $($AuditData.PasswordPolicy.MinPasswordLength)" })
    }

    if (-not $AuditData.PasswordPolicy.ComplexityEnabled) {
        $findings.Add([pscustomobject]@{ Id='AD-002'; Severity='High'; Title='Password complexity disabled'; Detail='Default domain password policy reports ComplexityEnabled = false.' })
    }

    foreach ($u in @($AuditData.InactiveUsers | Where-Object { $_.PasswordNotRequired })) {
        $findings.Add([pscustomobject]@{ Id='AD-003'; Severity='High'; Title='User with PasswordNotRequired'; Detail=$u.SamAccountName })
    }

    foreach ($u in @($AuditData.InactiveUsers | Where-Object { $_.DoesNotRequirePreAuth })) {
        $findings.Add([pscustomobject]@{ Id='AD-004'; Severity='High'; Title='User without Kerberos pre-auth'; Detail=$u.SamAccountName })
    }

    foreach ($u in @($AuditData.ServiceAccounts | Where-Object { $_.TrustedForDelegation })) {
        $findings.Add([pscustomobject]@{ Id='AD-005'; Severity='High'; Title='Service account trusted for delegation'; Detail=$u.SamAccountName })
    }

    foreach ($c in @($AuditData.Computers | Where-Object { $_.TrustedForDelegation })) {
        $findings.Add([pscustomobject]@{ Id='AD-006'; Severity='High'; Title='Computer trusted for delegation'; Detail=$c.Name })
    }

    foreach ($t in @($AuditData.Trusts | Where-Object { -not $_.SelectiveAuthentication })) {
        $findings.Add([pscustomobject]@{ Id='AD-007'; Severity='Medium'; Title='Trust without selective authentication'; Detail=$t.Name })
    }

    @($findings)
}

Export-ModuleMember -Function Test-SecAdModuleAvailable, Get-SecADSummary, New-SecADFindings
