Set-StrictMode -Version Latest

function Get-SecStackPortMatrix {
    [CmdletBinding()]
    param()

    @(
        [pscustomobject]@{ Port = 22; Protocol = 'tcp'; Service = 'SSH'; Stack = 'Linux, NetworkEquipment'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 23; Protocol = 'tcp'; Service = 'Telnet'; Stack = 'IoT, NetworkEquipment'; Risk = 'High' }
        [pscustomobject]@{ Port = 53; Protocol = 'tcp/udp'; Service = 'DNS'; Stack = 'DomainController, NetworkEquipment'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 80; Protocol = 'tcp'; Service = 'HTTP'; Stack = 'WebApp, IoT, AccessControl'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 88; Protocol = 'tcp'; Service = 'Kerberos'; Stack = 'DomainController'; Risk = 'High' }
        [pscustomobject]@{ Port = 111; Protocol = 'tcp'; Service = 'RPCBind'; Stack = 'Linux, NAS'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 123; Protocol = 'udp'; Service = 'NTP'; Stack = 'NetworkEquipment'; Risk = 'Low' }
        [pscustomobject]@{ Port = 135; Protocol = 'tcp'; Service = 'MSRPC'; Stack = 'DomainController, Windows'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 139; Protocol = 'tcp'; Service = 'NetBIOS'; Stack = 'NAS, DomainController'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 1433; Protocol = 'tcp'; Service = 'MSSQL'; Stack = 'Database'; Risk = 'High' }
        [pscustomobject]@{ Port = 1521; Protocol = 'tcp'; Service = 'Oracle'; Stack = 'Database'; Risk = 'High' }
        [pscustomobject]@{ Port = 161; Protocol = 'udp'; Service = 'SNMP'; Stack = 'IoT, Print, NetworkEquipment'; Risk = 'High' }
        [pscustomobject]@{ Port = 389; Protocol = 'tcp'; Service = 'LDAP'; Stack = 'DomainController, AccessControl'; Risk = 'High' }
        [pscustomobject]@{ Port = 443; Protocol = 'tcp'; Service = 'HTTPS'; Stack = 'WebApp, AccessControl, NAS'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 445; Protocol = 'tcp'; Service = 'SMB'; Stack = 'DomainController, NAS'; Risk = 'High' }
        [pscustomobject]@{ Port = 515; Protocol = 'tcp'; Service = 'LPD'; Stack = 'Print'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 631; Protocol = 'tcp'; Service = 'IPP'; Stack = 'Print'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 636; Protocol = 'tcp'; Service = 'LDAPS'; Stack = 'DomainController'; Risk = 'High' }
        [pscustomobject]@{ Port = 2049; Protocol = 'tcp'; Service = 'NFS'; Stack = 'NAS, Linux'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 2375; Protocol = 'tcp'; Service = 'Docker'; Stack = 'Linux'; Risk = 'High' }
        [pscustomobject]@{ Port = 3306; Protocol = 'tcp'; Service = 'MySQL'; Stack = 'Database'; Risk = 'High' }
        [pscustomobject]@{ Port = 3389; Protocol = 'tcp'; Service = 'RDP'; Stack = 'DomainController, Windows'; Risk = 'High' }
        [pscustomobject]@{ Port = 47808; Protocol = 'udp'; Service = 'BACnet'; Stack = 'AccessControl, IoT'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 5432; Protocol = 'tcp'; Service = 'PostgreSQL'; Stack = 'Database'; Risk = 'High' }
        [pscustomobject]@{ Port = 5683; Protocol = 'udp'; Service = 'CoAP'; Stack = 'IoT'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 6379; Protocol = 'tcp'; Service = 'Redis'; Stack = 'Database'; Risk = 'High' }
        [pscustomobject]@{ Port = 8080; Protocol = 'tcp'; Service = 'HTTP-alt'; Stack = 'WebApp, NAS, IoT'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 8443; Protocol = 'tcp'; Service = 'HTTPS-alt'; Stack = 'WebApp, AccessControl'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 9100; Protocol = 'tcp'; Service = 'JetDirect'; Stack = 'Print'; Risk = 'Medium' }
        [pscustomobject]@{ Port = 10001; Protocol = 'tcp'; Service = 'Controller management'; Stack = 'AccessControl'; Risk = 'Medium' }
    )
}

function Get-SecStackProfiles {
    [CmdletBinding()]
    param()

    @(
        [pscustomobject]@{
            Name = 'NetworkEquipment'
            Aliases = @('ResilienceSnmp')
            Description = 'Switch/router/firewall surface and SNMP exposure in read-only mode.'
            ScanSets = @(
                [pscustomobject]@{ Name='network_equipment_tcp'; Transport='tcp'; Ports='22,23,80,443,8080,8291'; Scripts='banner,ssh2-enum-algos,http-title,ssl-cert'; ExtraArgs=@() }
                [pscustomobject]@{ Name='network_equipment_udp'; Transport='udp'; Ports='161,162,123,514'; Scripts='snmp-info,snmp-sysdescr,ntp-info'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'DomainControllerExposure'
            Aliases = @('IdentityAccess','WindowsProtocol')
            Description = 'AD/domain controller baseline exposure checks without exploitation.'
            ScanSets = @(
                [pscustomobject]@{ Name='domain_controller_tcp'; Transport='tcp'; Ports='53,88,135,389,445,464,636,3268,3269,3389'; Scripts='dns-service-discovery,ldap-rootdse,smb-security-mode,smb2-security-mode,rdp-enum-encryption,ssl-cert'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'LinuxSurface'
            Aliases = @('UnixExposure')
            Description = 'Linux and Unix workload exposure: management, NFS, web and service endpoints.'
            ScanSets = @(
                [pscustomobject]@{ Name='linux_surface_tcp'; Transport='tcp'; Ports='22,80,111,443,2049,2375,2376,3306,5432,5900,6379,8080'; Scripts='banner,ssh2-enum-algos,http-title,http-security-headers,ssl-cert'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'DatabaseExposure'
            Aliases = @('MssqlAudit')
            Description = 'Database stack discovery for MSSQL, Oracle, MySQL, PostgreSQL and Redis.'
            ScanSets = @(
                [pscustomobject]@{ Name='database_exposure_tcp'; Transport='tcp'; Ports='1433,1521,3306,5432,6379,27017'; Scripts='ms-sql-info,mysql-info,pgsql-info,redis-info,ssl-cert,banner'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'WebApplication'
            Aliases = @('WebTlsBaseline')
            Description = 'Web and TLS baseline for internet-facing and internal applications.'
            ScanSets = @(
                [pscustomobject]@{ Name='web_application_tcp'; Transport='tcp'; Ports='80,443,8080,8443'; Scripts='http-title,http-security-headers,http-methods,ssl-cert,ssl-enum-ciphers'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'IoTSurface'
            Aliases = @()
            Description = 'IoT and embedded protocol exposure assessment in safe mode.'
            ScanSets = @(
                [pscustomobject]@{ Name='iot_surface_tcp'; Transport='tcp'; Ports='23,80,443,1883,8080,8883'; Scripts='banner,http-title,ssl-cert'; ExtraArgs=@() }
                [pscustomobject]@{ Name='iot_surface_udp'; Transport='udp'; Ports='161,1900,5683,47808'; Scripts='snmp-info,bacnet-info'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'PrintInfrastructure'
            Aliases = @()
            Description = 'Printer and print server exposure across LPD/IPP/JetDirect.'
            ScanSets = @(
                [pscustomobject]@{ Name='print_infrastructure_tcp'; Transport='tcp'; Ports='515,631,9100,80,443'; Scripts='ipp-enum,http-title,ssl-cert,banner'; ExtraArgs=@() }
                [pscustomobject]@{ Name='print_infrastructure_udp'; Transport='udp'; Ports='161'; Scripts='snmp-info'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'NasStorage'
            Aliases = @()
            Description = 'NAS exposure baseline for SMB, NFS and management interfaces.'
            ScanSets = @(
                [pscustomobject]@{ Name='nas_storage_tcp'; Transport='tcp'; Ports='139,445,2049,5000,5001,8080,8443'; Scripts='smb-security-mode,smb2-security-mode,nfs-showmount,http-title,ssl-cert'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'AccessControlSystems'
            Aliases = @()
            Description = 'Access control and building automation endpoint exposure review.'
            ScanSets = @(
                [pscustomobject]@{ Name='access_control_tcp'; Transport='tcp'; Ports='80,443,8443,9000,10001'; Scripts='http-title,ssl-cert,banner'; ExtraArgs=@() }
                [pscustomobject]@{ Name='access_control_udp'; Transport='udp'; Ports='161,47808'; Scripts='snmp-info,bacnet-info'; ExtraArgs=@() }
            )
        }
        [pscustomobject]@{
            Name = 'HybridFullStack'
            Aliases = @()
            Description = 'Unified full-stack baseline across infrastructure, identity, apps and data services.'
            ScanSets = @(
                [pscustomobject]@{ Name='fullstack_tcp'; Transport='tcp'; Ports='22,23,53,80,88,111,135,139,389,443,445,515,631,636,1433,1521,2049,2375,3306,3389,5432,6379,8080,8443,9100,10001'; Scripts='banner,http-title,http-security-headers,ssl-cert,ssl-enum-ciphers,smb-security-mode,smb2-security-mode,ssh2-enum-algos,ldap-rootdse'; ExtraArgs=@() }
                [pscustomobject]@{ Name='fullstack_udp'; Transport='udp'; Ports='53,67,68,69,123,161,162,500,514,1900,47808'; Scripts='snmp-info,ntp-info,bacnet-info'; ExtraArgs=@() }
            )
        }
    )
}

function Get-SecStackProfileNames {
    [CmdletBinding()]
    param([switch]$IncludeAliases)

    $profiles = @(Get-SecStackProfiles)

    if (-not $IncludeAliases) {
        return @($profiles | ForEach-Object { $_.Name } | Sort-Object -Unique)
    }

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($profile in $profiles) {
        $null = $names.Add([string]$profile.Name)
        foreach ($alias in @($profile.Aliases)) {
            $null = $names.Add([string]$alias)
        }
    }

    @($names | Sort-Object -Unique)
}

function Resolve-SecStackProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    foreach ($profile in @(Get-SecStackProfiles)) {
        if ($profile.Name -eq $Name) {
            return $profile
        }

        if (@($profile.Aliases) -contains $Name) {
            return $profile
        }
    }

    $valid = (Get-SecStackProfileNames -IncludeAliases) -join ', '
    throw "Unknown profile '$Name'. Valid profiles: $valid"
}

Export-ModuleMember -Function Get-SecStackPortMatrix, Get-SecStackProfiles, Get-SecStackProfileNames, Resolve-SecStackProfile
