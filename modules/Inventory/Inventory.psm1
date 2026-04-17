Set-StrictMode -Version Latest

function Get-SecHostInventory {
    [CmdletBinding()]
    param()

    if ($IsWindows) {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        $nics = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress

        return [pscustomobject]@{
            Platform = 'Windows'
            Hostname = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            OSCaption = $os.Caption
            OSVersion = $os.Version
            BuildNumber = $os.BuildNumber
            Manufacturer = $cs.Manufacturer
            Model = $cs.Model
            BIOSVersion = ($bios.SMBIOSBIOSVersion -join ', ')
            LastBootUpTime = $os.LastBootUpTime
            Kernel = $null
            NetworkAdapters = @($nics)
        }
    }

    $osRelease = @{}
    if (Test-Path -LiteralPath '/etc/os-release') {
        foreach ($line in (Get-Content -LiteralPath '/etc/os-release' -ErrorAction SilentlyContinue)) {
            if ($line -notmatch '=') {
                continue
            }

            $parts = $line.Split('=', 2)
            $key = $parts[0]
            $value = $parts[1].Trim('"')
            $osRelease[$key] = $value
        }
    }

    $interfaces = @()
    $ipCmd = Get-Command -Name ip -ErrorAction SilentlyContinue
    if ($ipCmd) {
        try {
            $interfaces = @((& $ipCmd.Source -j address 2>$null | ConvertFrom-Json -ErrorAction Stop) | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.ifname
                    State = $_.operstate
                    MacAddress = $_.address
                    Addresses = @($_.addr_info | ForEach-Object { $_.local })
                }
            })
        }
        catch {
            $interfaces = @()
        }
    }

    $kernel = ''
    try {
        $kernel = (& uname -sr) -join ' '
    }
    catch {
        $kernel = ''
    }

    [pscustomobject]@{
        Platform = 'Linux'
        Hostname = if ($env:HOSTNAME) { $env:HOSTNAME } else { [System.Net.Dns]::GetHostName() }
        Domain = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { $null }
        OSCaption = if ($osRelease.PRETTY_NAME) { $osRelease.PRETTY_NAME } else { 'Linux' }
        OSVersion = if ($osRelease.VERSION_ID) { $osRelease.VERSION_ID } else { $null }
        BuildNumber = $null
        Manufacturer = $null
        Model = $null
        BIOSVersion = $null
        LastBootUpTime = $null
        Kernel = $kernel
        NetworkAdapters = $interfaces
    }
}

function Get-SecInstalledSoftware {
    [CmdletBinding()]
    param()

    if ($IsWindows) {
        $pathA = 'HKLM:' + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
        $pathB = 'HKLM:' + '\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'

        $items = foreach ($path in @($pathA, $pathB)) {
            if (Test-Path -LiteralPath $path) {
                Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName } |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            }
        }

        return @($items)
    }

    $dpkg = Get-Command -Name dpkg-query -ErrorAction SilentlyContinue
    if ($dpkg) {
        try {
            $rows = & $dpkg.Source -W -f='${binary:Package}\t${Version}\t${Maintainer}\n'
            return @($rows | ForEach-Object {
                $cols = $_ -split "`t"
                [pscustomobject]@{
                    DisplayName = if ($cols.Count -gt 0) { $cols[0] } else { $null }
                    DisplayVersion = if ($cols.Count -gt 1) { $cols[1] } else { $null }
                    Publisher = if ($cols.Count -gt 2) { $cols[2] } else { $null }
                    InstallDate = $null
                }
            })
        }
        catch {
            return @()
        }
    }

    $rpm = Get-Command -Name rpm -ErrorAction SilentlyContinue
    if ($rpm) {
        try {
            $rows = & $rpm.Source -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n'
            return @($rows | ForEach-Object {
                $cols = $_ -split "`t"
                [pscustomobject]@{
                    DisplayName = if ($cols.Count -gt 0) { $cols[0] } else { $null }
                    DisplayVersion = if ($cols.Count -gt 1) { $cols[1] } else { $null }
                    Publisher = if ($cols.Count -gt 2) { $cols[2] } else { $null }
                    InstallDate = $null
                }
            })
        }
        catch {
            return @()
        }
    }

    @()
}

Export-ModuleMember -Function Get-SecHostInventory, Get-SecInstalledSoftware
