Set-StrictMode -Version Latest

function Get-SecPassiveNetworkSnapshot {
    [CmdletBinding()]
    param()

    if ($IsWindows) {
        $ipConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, RouteMetric, ifIndex
        $arp = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object ifIndex, IPAddress, LinkLayerAddress, State
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess

        return [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
            Platform = 'Windows'
            Interfaces = @($ipConfig)
            Routes = @($routes)
            Neighbors = @($arp)
            TcpListeners = @($listeners)
        }
    }

    $interfaces = @()
    $routes = @()
    $neighbors = @()
    $listeners = @()

    $ipCmd = Get-Command -Name ip -ErrorAction SilentlyContinue
    if ($ipCmd) {
        try {
            $interfaces = @((& $ipCmd.Source -j address 2>$null | ConvertFrom-Json -ErrorAction Stop) | ForEach-Object {
                [pscustomobject]@{
                    Interface = $_.ifname
                    State = $_.operstate
                    Address = $_.address
                    IPv4 = @($_.addr_info | Where-Object { $_.family -eq 'inet' } | ForEach-Object { $_.local })
                    IPv6 = @($_.addr_info | Where-Object { $_.family -eq 'inet6' } | ForEach-Object { $_.local })
                }
            })
        }
        catch {
            $interfaces = @()
        }

        try {
            $routes = @((& $ipCmd.Source route 2>$null | ForEach-Object {
                [pscustomobject]@{ Raw = $_ }
            }))
        }
        catch {
            $routes = @()
        }

        try {
            $neighbors = @((& $ipCmd.Source neigh 2>$null | ForEach-Object {
                [pscustomobject]@{ Raw = $_ }
            }))
        }
        catch {
            $neighbors = @()
        }
    }

    $ssCmd = Get-Command -Name ss -ErrorAction SilentlyContinue
    if ($ssCmd) {
        try {
            $listeners = @((& $ssCmd.Source -H -lntu 2>$null | ForEach-Object {
                [pscustomobject]@{ Raw = $_ }
            }))
        }
        catch {
            $listeners = @()
        }
    }

    [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Platform = 'Linux'
        Interfaces = $interfaces
        Routes = $routes
        Neighbors = $neighbors
        TcpListeners = $listeners
    }
}

function Invoke-SecPassiveHttpProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$TimeoutSec = 3
    )

    try {
        $response = Invoke-WebRequest -Uri $Uri -Method Head -TimeoutSec $TimeoutSec -SkipHttpErrorCheck -ErrorAction Stop
        [pscustomobject]@{
            Uri = $Uri
            StatusCode = $response.StatusCode
            Server = $response.Headers['Server']
            PoweredBy = $response.Headers['X-Powered-By']
            StrictTransportSecurity = $response.Headers['Strict-Transport-Security']
            Success = $true
        }
    }
    catch {
        [pscustomobject]@{
            Uri = $Uri
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

Export-ModuleMember -Function Get-SecPassiveNetworkSnapshot, Invoke-SecPassiveHttpProbe
