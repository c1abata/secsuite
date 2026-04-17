Set-StrictMode -Version Latest

function Test-SecAdModuleAvailable {
    [CmdletBinding()]
    param()
    [bool](Get-Module -ListAvailable -Name ActiveDirectory)
}

if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
    function global:Resolve-DnsName {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter()][ValidateSet('A','AAAA','NS')][string]$Type = 'A'
        )

        try {
            $entry = [System.Net.Dns]::GetHostEntry($Name)
        }
        catch {
            return @()
        }

        if ($Type -eq 'NS') {
            if ([string]::IsNullOrWhiteSpace($entry.HostName)) {
                return @()
            }

            return [pscustomobject]@{
                NameHost = $entry.HostName.TrimEnd('.')
            }
        }

        $family = if ($Type -eq 'AAAA') {
            [System.Net.Sockets.AddressFamily]::InterNetworkV6
        }
        else {
            [System.Net.Sockets.AddressFamily]::InterNetwork
        }

        return @(
            $entry.AddressList |
                Where-Object { $_.AddressFamily -eq $family } |
                ForEach-Object {
                    [pscustomobject]@{
                        NameHost  = $entry.HostName
                        IPAddress = $_.IPAddressToString
                    }
                }
        )
    }
}

function ConvertFrom-SecLargeInteger {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Value)

    if ($null -eq $Value) { return $null }

    try {
        $raw = [int64]$Value
        if ($raw -le 0) { return $null }
        [DateTime]::FromFileTimeUtc($raw)
    }
    catch {
        $null
    }
}

function ConvertTo-SecDomainDn {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DomainFqdn)

    ($DomainFqdn.Split('.') | ForEach-Object { "DC=$($_)" }) -join ','
}

function New-SecLdapConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][int]$Port,
        [Parameter()][switch]$UseLdaps,
        [Parameter()][System.Management.Automation.PSCredential]$Credential,
        [Parameter()][ValidateSet('Negotiate','Basic','Ntlm','Kerberos')][string]$AuthType = 'Negotiate'
    )

    Add-Type -AssemblyName System.DirectoryServices.Protocols

    $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server, $Port, $false, $false)
    $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
    $connection.Timeout = [TimeSpan]::FromSeconds(20)
    $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::$AuthType

    if ($Credential) {
        $connection.Credential = $Credential.GetNetworkCredential()
    }

    if ($UseLdaps) {
        $connection.SessionOptions.SecureSocketLayer = $true
    }

    $connection.SessionOptions.ProtocolVersion = 3
    $connection.Bind()
    $connection
}

function Get-SecLdapEntries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][string]$BaseDn,
        [Parameter(Mandatory)][string]$Filter,
        [Parameter(Mandatory)][string[]]$Properties,
        [Parameter()][System.DirectoryServices.Protocols.SearchScope]$Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    )

    $request = [System.DirectoryServices.Protocols.SearchRequest]::new($BaseDn, $Filter, $Scope, $Properties)
    $response = $Connection.SendRequest($request)
    @($response.Entries)
}

function Get-SecLdapSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter()][string]$DomainController,
        [Parameter()][System.Management.Automation.PSCredential]$Credential,
        [Parameter()][switch]$UseLdaps
    )

    $server = if ($DomainController) { $DomainController } elseif ($Config.DomainController) { [string]$Config.DomainController } else { throw 'DomainController is required in non-domain-joined mode.' }
    $port = if ($UseLdaps -or $Config.UseLdaps) { 636 } else { 389 }
    $authType = if ($Config.LdapAuthType) { [string]$Config.LdapAuthType } else { 'Negotiate' }
    $inactiveDays = if ($Config.InactiveUserDays) { [int]$Config.InactiveUserDays } else { 90 }

    $conn = New-SecLdapConnection -Server $server -Port $port -UseLdaps:($UseLdaps -or $Config.UseLdaps) -Credential $Credential -AuthType $authType

    try {
        $rootDse = Get-SecLdapEntries -Connection $conn -BaseDn '' -Filter '(objectClass=*)' -Properties @('defaultNamingContext','dnsHostName','domainFunctionality','forestFunctionality') -Scope Base
        if (-not $rootDse) {
            throw 'Unable to read RootDSE from LDAP server.'
        }

        $defaultNamingContext = [string]$rootDse[0].Attributes['defaultNamingContext'][0]
        $domainFqdn = ($defaultNamingContext -split ',' | ForEach-Object { ($_ -replace '^DC=','') }) -join '.'

        $users = Get-SecLdapEntries -Connection $conn -BaseDn $defaultNamingContext -Filter '(&(objectCategory=person)(objectClass=user))' -Properties @('sAMAccountName','displayName','userAccountControl','lastLogonTimestamp','servicePrincipalName')
        $computers = Get-SecLdapEntries -Connection $conn -BaseDn $defaultNamingContext -Filter '(objectClass=computer)' -Properties @('name','operatingSystem','userAccountControl','lastLogonTimestamp')
        $groups = Get-SecLdapEntries -Connection $conn -BaseDn $defaultNamingContext -Filter '(objectClass=group)' -Properties @('sAMAccountName','member')
        $trusts = Get-SecLdapEntries -Connection $conn -BaseDn $defaultNamingContext -Filter '(objectClass=trustedDomain)' -Properties @('name','trustDirection','trustAttributes')

        $inactiveSince = (Get-Date).AddDays(-$inactiveDays)
        $inactiveUsers = foreach ($entry in $users) {
            $sam = [string]$entry.Attributes['sAMAccountName'][0]
            if ([string]::IsNullOrWhiteSpace($sam)) { continue }

            $uac = if ($entry.Attributes['userAccountControl']) { [int]$entry.Attributes['userAccountControl'][0] } else { 0 }
            $lastLogon = if ($entry.Attributes['lastLogonTimestamp']) { ConvertFrom-SecLargeInteger -Value $entry.Attributes['lastLogonTimestamp'][0] } else { $null }

            if ($lastLogon -and $lastLogon -ge $inactiveSince) { continue }

            [pscustomobject]@{
                Name                  = [string]$entry.Attributes['displayName'][0]
                SamAccountName        = $sam
                LastLogonDate         = $lastLogon
                PasswordNotRequired   = [bool]($uac -band 0x20)
                DoesNotRequirePreAuth = [bool]($uac -band 0x400000)
                ServicePrincipalName  = @($entry.Attributes['servicePrincipalName'])
                TrustedForDelegation  = [bool]($uac -band 0x80000)
                TrustedToAuthForDelegation = [bool]($uac -band 0x1000000)
            }
        }

        $serviceAccounts = foreach ($entry in $users) {
            if (-not $entry.Attributes['servicePrincipalName']) { continue }
            $uac = if ($entry.Attributes['userAccountControl']) { [int]$entry.Attributes['userAccountControl'][0] } else { 0 }
            [pscustomobject]@{
                Name                 = [string]$entry.Attributes['displayName'][0]
                SamAccountName       = [string]$entry.Attributes['sAMAccountName'][0]
                ServicePrincipalName = @($entry.Attributes['servicePrincipalName'])
                PasswordLastSet      = $null
                TrustedForDelegation = [bool]($uac -band 0x80000)
            }
        }

        $computerRows = foreach ($entry in $computers) {
            $uac = if ($entry.Attributes['userAccountControl']) { [int]$entry.Attributes['userAccountControl'][0] } else { 0 }
            [pscustomobject]@{
                Name                 = [string]$entry.Attributes['name'][0]
                OperatingSystem      = [string]$entry.Attributes['operatingSystem'][0]
                LastLogonDate        = if ($entry.Attributes['lastLogonTimestamp']) { ConvertFrom-SecLargeInteger -Value $entry.Attributes['lastLogonTimestamp'][0] } else { $null }
                TrustedForDelegation = [bool]($uac -band 0x80000)
            }
        }

        $trustRows = foreach ($entry in $trusts) {
            $trustAttr = if ($entry.Attributes['trustAttributes']) { [int]$entry.Attributes['trustAttributes'][0] } else { 0 }
            [pscustomobject]@{
                Name                    = [string]$entry.Attributes['name'][0]
                Direction               = if ($entry.Attributes['trustDirection']) { [int]$entry.Attributes['trustDirection'][0] } else { $null }
                ForestTransitive        = [bool]($trustAttr -band 0x8)
                IntraForest             = [bool]($trustAttr -band 0x20)
                SelectiveAuthentication = [bool]($trustAttr -band 0x400)
                SIDFilteringForestAware = [bool]($trustAttr -band 0x40)
            }
        }

        $privilegedGroups = if ($Config.PrivilegedGroups) { @($Config.PrivilegedGroups) } else { @('Domain Admins','Enterprise Admins','Schema Admins') }
        $membershipRows = foreach ($gName in $privilegedGroups) {
            $group = $groups | Where-Object { [string]$_.Attributes['sAMAccountName'][0] -eq $gName } | Select-Object -First 1
            if (-not $group) {
                [pscustomobject]@{ Group = $gName; Name = $null; SamAccountName = $null; objectClass = 'Unavailable' }
                continue
            }

            foreach ($memberDn in @($group.Attributes['member'])) {
                $memberName = ([string]$memberDn -split ',')[0] -replace '^CN='
                [pscustomobject]@{ Group = $gName; Name = $memberName; SamAccountName = $memberName; objectClass = 'Unknown' }
            }
        }

        $attackGraph = New-SecADAttackGraph -Users $users -Groups $groups

        [pscustomobject]@{
            Available             = $true
            CollectionMode        = 'Ldap'
            DNSRoot               = $domainFqdn
            DomainMode            = [string]$rootDse[0].Attributes['domainFunctionality'][0]
            ForestMode            = [string]$rootDse[0].Attributes['forestFunctionality'][0]
            DomainControllers     = @($server)
            PrivilegedMemberships = @($membershipRows)
            PasswordPolicy        = [pscustomobject]@{
                MinPasswordLength = $null
                ComplexityEnabled = $null
                LockoutThreshold  = $null
                MaxPasswordAge    = 'NotCollectedViaLDAP'
            }
            InactiveUsers         = @($inactiveUsers)
            ServiceAccounts       = @($serviceAccounts)
            Computers             = @($computerRows)
            Trusts                = @($trustRows)
            AttackPaths           = @($attackGraph)
            ExposureScore         = Get-SecADExposureScore -InactiveUsers $inactiveUsers -ServiceAccounts $serviceAccounts -Computers $computerRows -Trusts $trustRows
        }
    }
    finally {
        if ($conn) { $conn.Dispose() }
    }
}

function New-SecADAttackGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Users,
        [Parameter(Mandatory)]$Groups
    )

    $edges = New-Object System.Collections.Generic.List[object]

    foreach ($group in $Groups) {
        $gName = [string]$group.Attributes['sAMAccountName'][0]
        if ([string]::IsNullOrWhiteSpace($gName)) { continue }

        foreach ($memberDn in @($group.Attributes['member'])) {
            $memberName = ([string]$memberDn -split ',')[0] -replace '^CN='
            $edges.Add([pscustomobject]@{
                Source     = $memberName
                Target     = $gName
                Relation   = 'MemberOf'
                RiskWeight = if ($gName -match 'Admin') { 5 } else { 1 }
            })
        }
    }

    @($edges | Select-Object -First 5000)
}

function Get-SecADExposureScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InactiveUsers,
        [Parameter(Mandatory)]$ServiceAccounts,
        [Parameter(Mandatory)]$Computers,
        [Parameter(Mandatory)]$Trusts
    )

    $score = 0
    $score += (@($InactiveUsers | Where-Object { $_.PasswordNotRequired }).Count * 8)
    $score += (@($InactiveUsers | Where-Object { $_.DoesNotRequirePreAuth }).Count * 10)
    $score += (@($ServiceAccounts | Where-Object { $_.TrustedForDelegation }).Count * 12)
    $score += (@($Computers | Where-Object { $_.TrustedForDelegation }).Count * 10)
    $score += (@($Trusts | Where-Object { -not $_.SelectiveAuthentication }).Count * 7)

    $rating = if ($score -ge 80) { 'Critical' } elseif ($score -ge 40) { 'High' } elseif ($score -ge 20) { 'Medium' } else { 'Low' }

    [pscustomobject]@{
        Score  = $score
        Rating = $rating
    }
}

function Write-SecADTelemetry {
    [CmdletBinding()]
    param(
        [Parameter()][object]$Context,
        [Parameter(Mandatory)][ValidateSet('DEBUG','INFO','WARN','ERROR')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [Parameter()][hashtable]$Data
    )

    if (-not $Context) { return }

    $writeLog = Get-Command -Name Write-SecLog -ErrorAction SilentlyContinue
    if ($writeLog) {
        Write-SecLog -Context $Context -Level $Level -Area 'ADAudit' -Message $Message -Data $Data
    }
}

function Invoke-SecADSecurityChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter()][string]$DomainController,
        [Parameter()][System.Management.Automation.PSCredential]$Credential,
        [Parameter()][switch]$UnauthenticatedOnly,
        [Parameter()][switch]$AuthenticatedOnly,
        [Parameter()][object]$Context
    )

    $targetServer = if ([string]::IsNullOrWhiteSpace($DomainController)) { $Domain } else { $DomainController }
    $domainDn = ConvertTo-SecDomainDn -DomainFqdn $Domain
    $startedAt = (Get-Date).ToUniversalTime()

    $report = [ordered]@{
        Domain = $Domain
        DomainController = $targetServer
        StartedAtUtc = $startedAt.ToString('o')
        UnauthenticatedChecks = @()
        AuthenticatedChecks = @()
        Errors = @()
    }

    Write-SecADTelemetry -Context $Context -Level INFO -Message 'Extended AD security checks started.' -Data @{
        domain = $Domain
        domainController = $targetServer
        unauthenticatedOnly = [bool]$UnauthenticatedOnly
        authenticatedOnly = [bool]$AuthenticatedOnly
        hasCredential = [bool]$Credential
    }

    if (-not $AuthenticatedOnly) {
        $unauth = New-Object System.Collections.Generic.List[object]

        try {
            $dnsServers = Resolve-DnsName -Name $Domain -Type NS -ErrorAction Stop | Select-Object -ExpandProperty NameHost -Unique
            $null = $unauth.Add([pscustomobject]@{ Check='DNS namespace discovery'; Status='OK'; Details=@($dnsServers) })
        }
        catch {
            $null = $unauth.Add([pscustomobject]@{ Check='DNS namespace discovery'; Status='WARN'; Details=@('NS records not discovered from current host.') })
        }

        try {
            $ldapConn = New-SecLdapConnection -Server $targetServer -Port 389 -AuthType Negotiate
            $root = Get-SecLdapEntries -Connection $ldapConn -BaseDn '' -Filter '(objectClass=*)' -Properties @('defaultNamingContext') -Scope Base
            $isReachable = $null -ne $root -and @($root).Count -gt 0
            $null = $unauth.Add([pscustomobject]@{
                Check = 'LDAP endpoint reachability'
                Status = if ($isReachable) { 'OK' } else { 'WARN' }
                Details = @("Target: $targetServer:389")
            })
        }
        catch {
            $null = $unauth.Add([pscustomobject]@{ Check='LDAP endpoint reachability'; Status='WARN'; Details=@('LDAP service unreachable or blocked from current source.') })
        }
        finally {
            if ($ldapConn) { $ldapConn.Dispose() }
        }

        try {
            $commonUsers = @('administrator','guest','krbtgt')
            $foundUsers = @()
            $searchConn = New-SecLdapConnection -Server $targetServer -Port 389 -AuthType Negotiate
            foreach ($user in $commonUsers) {
                $filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$user))"
                $entry = Get-SecLdapEntries -Connection $searchConn -BaseDn $domainDn -Filter $filter -Properties @('distinguishedName')
                if (@($entry).Count -gt 0) { $foundUsers += $user }
            }

            if ($foundUsers.Count -gt 0) {
                    $null = $unauth.Add([pscustomobject]@{ Check='Common principal enumeration'; Status='WARN'; Details=@("Discovered accounts: $($foundUsers -join ', ')") })
                }
                else {
                    $null = $unauth.Add([pscustomobject]@{ Check='Common principal enumeration'; Status='OK'; Details=@('No common principals resolved with current technique.') })
                }
            }
        catch {
            $null = $unauth.Add([pscustomobject]@{ Check='Common principal enumeration'; Status='INFO'; Details=@('Enumeration skipped because LDAP query was not possible.') })
        }
        finally {
            if ($searchConn) { $searchConn.Dispose() }
        }

        $report.UnauthenticatedChecks = $unauth.ToArray()
    }

    if (-not $UnauthenticatedOnly) {
        $auth = New-Object System.Collections.Generic.List[object]

        if (-not $Credential) {
            $null = $auth.Add([pscustomobject]@{ Check='Authenticated checks'; Status='INFO'; Details=@('No credentials provided. Authenticated checks skipped.') })
        }
        else {
            try {
                $summary = Get-SecLdapSummary -Config @{ DomainController = $targetServer; UseLdaps = $false; LdapAuthType = 'Negotiate'; InactiveUserDays = 90; PrivilegedGroups = @('Domain Admins','Enterprise Admins') } -DomainController $targetServer -Credential $Credential

                $pwdMin = $summary.PasswordPolicy.MinPasswordLength
                $null = $auth.Add([pscustomobject]@{
                    Check='Password policy baseline'
                    Status= if ($null -eq $pwdMin -or $pwdMin -ge 12) { 'OK' } else { 'WARN' }
                    Details=@("Min password length: $pwdMin","Complexity enabled: $($summary.PasswordPolicy.ComplexityEnabled)")
                })

                $kerberoastCount = @($summary.ServiceAccounts).Count
                $null = $auth.Add([pscustomobject]@{
                    Check='Kerberoastable service accounts'
                    Status= if ($kerberoastCount -gt 0) { 'WARN' } else { 'OK' }
                    Details=@("Accounts with SPN: $kerberoastCount")
                })

                $asRepCount = @($summary.InactiveUsers | Where-Object { $_.DoesNotRequirePreAuth }).Count
                $null = $auth.Add([pscustomobject]@{
                    Check='AS-REP roast exposure'
                    Status= if ($asRepCount -gt 0) { 'WARN' } else { 'OK' }
                    Details=@("Users without pre-auth: $asRepCount")
                })

                $delegationCount = @($summary.Computers | Where-Object { $_.TrustedForDelegation }).Count
                $null = $auth.Add([pscustomobject]@{
                    Check='Unconstrained delegation'
                    Status= if ($delegationCount -gt 0) { 'WARN' } else { 'OK' }
                    Details=@("Computers trusted for delegation: $delegationCount")
                })
            }
            catch {
                $message = "Authenticated checks failed: $($_.Exception.Message)"
                $null = $auth.Add([pscustomobject]@{ Check='Authenticated checks'; Status='ERROR'; Details=@($message) })
                $report.Errors += $message
            }
        }

        $report.AuthenticatedChecks = $auth.ToArray()
    }

    $report.CompletedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    Write-SecADTelemetry -Context $Context -Level INFO -Message 'Extended AD security checks completed.' -Data @{
        unauthCount = @($report.UnauthenticatedChecks).Count
        authCount = @($report.AuthenticatedChecks).Count
        errorCount = @($report.Errors).Count
    }
    [pscustomobject]$report
}

function Get-SecADSummary {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [string]$DomainController,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$UseLdaps
    )

    $mode = if ($Config -and $Config.ConnectionMode) { [string]$Config.ConnectionMode } else { 'Auto' }

    if ($mode -eq 'Ldap' -or $DomainController) {
        return Get-SecLdapSummary -Config $Config -DomainController $DomainController -Credential $Credential -UseLdaps:$UseLdaps
    }

    if (-not (Test-SecAdModuleAvailable)) {
        return [pscustomobject]@{
            Available = $false
            Message   = 'ActiveDirectory module not available on this host. Set ADAudit.ConnectionMode=Ldap and provide a domain controller.'
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
        CollectionMode        = 'ActiveDirectoryModule'
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
        AttackPaths           = @()
        ExposureScore         = Get-SecADExposureScore -InactiveUsers $inactiveUsers -ServiceAccounts $serviceAccounts -Computers $computers -Trusts $trusts
    }
}

function New-SecADFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$AuditData)

    $findings = New-Object System.Collections.Generic.List[object]

    if (-not $AuditData.Available) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-000'; Severity='Info'; Title='AD module not available'; Detail=$AuditData.Message })
        return $findings.ToArray()
    }

    if ($null -ne $AuditData.PasswordPolicy.MinPasswordLength -and $AuditData.PasswordPolicy.MinPasswordLength -lt 12) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-001'; Severity='Medium'; Title='Min password length below 12'; Detail="Configured value: $($AuditData.PasswordPolicy.MinPasswordLength)" })
    }

    if ($null -ne $AuditData.PasswordPolicy.ComplexityEnabled -and -not $AuditData.PasswordPolicy.ComplexityEnabled) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-002'; Severity='High'; Title='Password complexity disabled'; Detail='Default domain password policy reports ComplexityEnabled = false.' })
    }

    foreach ($u in @($AuditData.InactiveUsers | Where-Object { $_.PasswordNotRequired })) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-003'; Severity='High'; Title='User with PasswordNotRequired'; Detail=$u.SamAccountName })
    }

    foreach ($u in @($AuditData.InactiveUsers | Where-Object { $_.DoesNotRequirePreAuth })) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-004'; Severity='High'; Title='User without Kerberos pre-auth'; Detail=$u.SamAccountName })
    }

    foreach ($u in @($AuditData.ServiceAccounts | Where-Object { $_.TrustedForDelegation })) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-005'; Severity='High'; Title='Service account trusted for delegation'; Detail=$u.SamAccountName })
    }

    foreach ($c in @($AuditData.Computers | Where-Object { $_.TrustedForDelegation })) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-006'; Severity='High'; Title='Computer trusted for delegation'; Detail=$c.Name })
    }

    foreach ($t in @($AuditData.Trusts | Where-Object { -not $_.SelectiveAuthentication })) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-007'; Severity='Medium'; Title='Trust without selective authentication'; Detail=$t.Name })
    }

    if ($AuditData.ExposureScore -and $AuditData.ExposureScore.Score -ge 40) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-008'; Severity='High'; Title='High AD exposure score'; Detail="Score: $($AuditData.ExposureScore.Score) - Rating: $($AuditData.ExposureScore.Rating)" })
    }

    if (@($AuditData.AttackPaths).Count -gt 0) {
        $null = $findings.Add([pscustomobject]@{ Id='AD-009'; Severity='Info'; Title='Attack path graph available'; Detail="Edges collected: $(@($AuditData.AttackPaths).Count)" })
    }

    $findings.ToArray()
}

Export-ModuleMember -Function Test-SecAdModuleAvailable, Get-SecADSummary, New-SecADFindings, Get-SecADExposureScore, New-SecADAttackGraph, Invoke-SecADSecurityChecks
