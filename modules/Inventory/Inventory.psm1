Set-StrictMode -Version Latest

function Get-SecHostInventory {
    [CmdletBinding()]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $nics = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress

    [pscustomobject]@{
        Hostname        = $env:COMPUTERNAME
        Domain          = $env:USERDOMAIN
        OSCaption       = $os.Caption
        OSVersion       = $os.Version
        BuildNumber     = $os.BuildNumber
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        BIOSVersion     = ($bios.SMBIOSBIOSVersion -join ', ')
        LastBootUpTime  = $os.LastBootUpTime
        NetworkAdapters = @($nics)
    }
}

function Get-SecInstalledSoftware {
    [CmdletBinding()]
    param()

    $pathA = 'HKLM:' + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
    $pathB = 'HKLM:' + '\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'

    foreach ($path in @($pathA, $pathB)) {
        if (Test-Path $path) {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }
    }
}

Export-ModuleMember -Function Get-SecHostInventory, Get-SecInstalledSoftware
