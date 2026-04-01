Set-StrictMode -Version Latest

function Get-SecPassiveNetworkSnapshot {
    [CmdletBinding()]
    param()

    $ipConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, RouteMetric, ifIndex
    $arp = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object ifIndex, IPAddress, LinkLayerAddress, State
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess

    [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Interfaces   = @($ipConfig)
        Routes       = @($routes)
        Neighbors    = @($arp)
        TcpListeners = @($listeners)
    }
}

function Invoke-SecPassiveHttpProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [int]$TimeoutSec = 3
    )

    try {
        $response = Invoke-WebRequest -Uri $Uri -Method Head -TimeoutSec $TimeoutSec -SkipHttpErrorCheck -ErrorAction Stop
        [pscustomobject]@{
            Uri        = $Uri
            StatusCode = $response.StatusCode
            Server     = $response.Headers['Server']
            PoweredBy  = $response.Headers['X-Powered-By']
            StrictTransportSecurity = $response.Headers['Strict-Transport-Security']
            Success    = $true
        }
    }
    catch {
        [pscustomobject]@{
            Uri     = $Uri
            Success = $false
            Error   = $_.Exception.Message
        }
    }
}

Export-ModuleMember -Function Get-SecPassiveNetworkSnapshot, Invoke-SecPassiveHttpProbe
