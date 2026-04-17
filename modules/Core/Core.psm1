Set-StrictMode -Version Latest

function Get-SecSuiteRoot {
    (Resolve-Path (Join-Path (Join-Path $PSScriptRoot '..') '..')).Path
}

function Get-SecHostName {
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        return $env:COMPUTERNAME
    }

    if (-not [string]::IsNullOrWhiteSpace($env:HOSTNAME)) {
        return $env:HOSTNAME
    }

    try {
        return [System.Net.Dns]::GetHostName()
    }
    catch {
        return 'unknown-host'
    }
}

function Get-SecCurrentUserName {
    [CmdletBinding()]
    param()

    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
            return $env:USERNAME
        }

        if (-not [string]::IsNullOrWhiteSpace($env:USER)) {
            return $env:USER
        }

        return 'unknown-user'
    }
}

function Get-SecSha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$InputText)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
        $hash = $sha.ComputeHash($bytes)
        -join ($hash | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $sha.Dispose()
    }
}

function Get-SecFileSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Cannot hash missing file: $Path"
    }

    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Import-SecSuiteConfig {
    [CmdletBinding()]
    param()

    $configPath = Join-Path (Get-SecSuiteRoot) (Join-Path 'config' 'suite.config.psd1')
    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "Config file not found: $configPath"
    }

    Import-PowerShellDataFile -Path $configPath
}

function New-SecSuiteRunContext {
    [CmdletBinding()]
    param([string]$OutputPath)

    $config = Import-SecSuiteConfig
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = $config.DefaultOutputPath
    }

    $resolvedOutput = Resolve-SecPath -Path $OutputPath -CreateDirectory

    [pscustomobject]@{
        SuiteName  = $config.SuiteName
        Version    = $config.Version
        Hostname   = Get-SecHostName
        UserName   = Get-SecCurrentUserName
        UtcStarted = (Get-Date).ToUniversalTime().ToString('o')
        OutputPath = $resolvedOutput
        SessionId  = ([guid]::NewGuid()).Guid
        Config     = $config
        BrandStyle = $config.BrandStyle
    }
}

function Resolve-SecPath {
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$ExpectFile,
        [switch]$ExpectDirectory,
        [switch]$Optional,
        [switch]$CreateDirectory
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($Optional) {
            return $null
        }

        throw 'A required path parameter is empty or missing.'
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
    }
    catch {
        throw "Invalid path '$Path'. $($_.Exception.Message)"
    }

    if ($CreateDirectory) {
        if (-not (Test-Path -LiteralPath $fullPath)) {
            New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
        }
        elseif (-not (Test-Path -LiteralPath $fullPath -PathType Container)) {
            throw "Expected directory but found a non-directory item: $fullPath"
        }

        return (Resolve-Path -LiteralPath $fullPath).Path
    }

    if (-not (Test-Path -LiteralPath $fullPath)) {
        if ($Optional) {
            return $null
        }

        throw "Path not found: $fullPath"
    }

    if ($ExpectFile -and -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Expected a file path but found a different item type: $fullPath"
    }

    if ($ExpectDirectory -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "Expected a directory path but found a different item type: $fullPath"
    }

    (Resolve-Path -LiteralPath $fullPath).Path
}

function Add-SecHashChainEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$EventType,
        [Parameter(Mandatory)][object]$Payload
    )

    if (-not $Context.HashChainPath) {
        return
    }

    $prevHash = if ($Context.PSObject.Properties.Name -contains 'LastHash' -and -not [string]::IsNullOrWhiteSpace($Context.LastHash)) {
        $Context.LastHash
    }
    else {
        'GENESIS'
    }

    $payloadJson = $Payload | ConvertTo-Json -Depth 12 -Compress
    $hash = Get-SecSha256Hex -InputText ("{0}|{1}|{2}" -f $prevHash, $EventType, $payloadJson)

    $entry = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
        eventType = $EventType
        sessionId = $Context.SessionId
        previousHash = $prevHash
        hash = $hash
        payload = $Payload
    }

    Add-Content -LiteralPath $Context.HashChainPath -Value ($entry | ConvertTo-Json -Depth 12 -Compress) -Encoding UTF8
    $Context | Add-Member -NotePropertyName LastHash -NotePropertyValue $hash -Force
}

function Initialize-SecSuiteLogging {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $logPath = Join-Path $Context.OutputPath $Context.Config.LogFileName
    $jsonLogPath = Join-Path $Context.OutputPath $Context.Config.LogJsonFileName
    $auditTrailPath = Join-Path $Context.OutputPath $Context.Config.AuditTrailFileName
    $hashChainPath = Join-Path $Context.OutputPath $Context.Config.HashChainFileName

    foreach ($path in @($logPath, $jsonLogPath, $auditTrailPath, $hashChainPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -Path $path -ItemType File -Force | Out-Null
        }
    }

    $Context | Add-Member -NotePropertyName LogPath -NotePropertyValue $logPath -Force
    $Context | Add-Member -NotePropertyName JsonLogPath -NotePropertyValue $jsonLogPath -Force
    $Context | Add-Member -NotePropertyName AuditTrailPath -NotePropertyValue $auditTrailPath -Force
    $Context | Add-Member -NotePropertyName HashChainPath -NotePropertyValue $hashChainPath -Force
    $Context | Add-Member -NotePropertyName LastHash -NotePropertyValue '' -Force

    Write-SecLog -Context $Context -Level 'INFO' -Area 'Core' -Message 'Logging initialized.'
    $Context
}

function Write-SecLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [ValidateSet('DEBUG','INFO','WARN','ERROR')][string]$Level = 'INFO',
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString('o')
    $line = "[{0}] [{1}] [{2}] {3}" -f $timestamp, $Level, $Area, $Message
    Add-Content -LiteralPath $Context.LogPath -Value $line -Encoding UTF8

    $payload = [ordered]@{
        timestamp = $timestamp
        level = $Level
        area = $Area
        message = $Message
        sessionId = $Context.SessionId
        hostname = $Context.Hostname
        userName = $Context.UserName
    }

    if ($Data) {
        $payload.data = $Data
    }

    Add-Content -LiteralPath $Context.JsonLogPath -Value ($payload | ConvertTo-Json -Depth 12 -Compress) -Encoding UTF8
    Add-SecHashChainEntry -Context $Context -EventType 'log' -Payload $payload
}

function Write-SecAuditEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Action,
        [ValidateSet('Started','Completed','Failed','Skipped')][string]$Status,
        [double]$DurationMs,
        [hashtable]$Data
    )

    $entry = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
        sessionId = $Context.SessionId
        area = $Area
        action = $Action
        status = $Status
        durationMs = $DurationMs
        hostname = $Context.Hostname
        userName = $Context.UserName
    }

    if ($Data) {
        $entry.data = $Data
    }

    Add-Content -LiteralPath $Context.AuditTrailPath -Value ($entry | ConvertTo-Json -Depth 12 -Compress) -Encoding UTF8
    Add-SecHashChainEntry -Context $Context -EventType 'audit' -Payload $entry
}

function Write-SecSuiteJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    $InputObject | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
    Get-Item -LiteralPath $Path
}

function Invoke-SecOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$FailureMessage = 'Operation failed.'
    )

    $start = Get-Date
    Write-SecAuditEvent -Context $Context -Area $Area -Action 'operation' -Status Started

    try {
        $result = & $ScriptBlock
        $duration = ((Get-Date) - $start).TotalMilliseconds
        Write-SecAuditEvent -Context $Context -Area $Area -Action 'operation' -Status Completed -DurationMs $duration
        return $result
    }
    catch {
        $duration = ((Get-Date) - $start).TotalMilliseconds
        Write-SecLog -Context $Context -Level 'ERROR' -Area $Area -Message $FailureMessage -Data @{ error = $_.Exception.Message }
        Write-SecAuditEvent -Context $Context -Area $Area -Action 'operation' -Status Failed -DurationMs $duration -Data @{ error = $_.Exception.Message }
        throw
    }
}

function ConvertTo-SecXmlString {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    $json = $InputObject | ConvertTo-Json -Depth 12
    $xml = New-Object System.Xml.XmlDocument
    $decl = $xml.CreateXmlDeclaration('1.0', 'utf-8', $null)
    [void]$xml.AppendChild($decl)

    $root = $xml.CreateElement('TcpentReport')
    [void]$xml.AppendChild($root)

    $data = $xml.CreateCDATASection($json)
    [void]$root.AppendChild($data)

    $xml.OuterXml
}

function ConvertTo-SecHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [string]$Title = 'TCPENT Report'
    )

    $pretty = $InputObject | ConvertTo-Json -Depth 12
    $encoded = [System.Net.WebUtility]::HtmlEncode($pretty)

    @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>$Title</title>
<style>
body { font-family: "JetBrains Mono", "Fira Code", Consolas, monospace; margin: 20px; background: #0f1217; color: #f2f4f8; }
h1 { margin-bottom: 6px; }
.small { color: #98a2b3; font-size: 12px; }
pre { background: #151b23; border: 1px solid #273142; padding: 16px; overflow-x: auto; line-height: 1.4; }
</style>
</head>
<body>
<h1>$Title</h1>
<p class="small">Generated at $((Get-Date).ToUniversalTime().ToString('o'))</p>
<pre>$encoded</pre>
</body>
</html>
"@
}

function Get-SecHeadlessBrowserCommand {
    [CmdletBinding()]
    param()

    $windowsCandidates = @(
        "$env:ProgramFiles (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "$env:ProgramFiles\\Microsoft\\Edge\\Application\\msedge.exe",
        "$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.exe"
    )

    foreach ($candidate in $windowsCandidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    foreach ($cmd in @('microsoft-edge','google-chrome','chromium','chromium-browser')) {
        $found = Get-Command -Name $cmd -ErrorAction SilentlyContinue
        if ($found) {
            return $found.Source
        }
    }

    return $null
}

function Export-SecSuiteReportSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$ReportObject,
        [Parameter(Mandatory)][string]$BaseName
    )

    $jsonPath = Join-Path $Context.OutputPath "$BaseName.json"
    $xmlPath = Join-Path $Context.OutputPath "$BaseName.xml"
    $htmlPath = Join-Path $Context.OutputPath "$BaseName.html"
    $pdfPath = Join-Path $Context.OutputPath "$BaseName.pdf"
    $manifestPath = Join-Path $Context.OutputPath "$BaseName.manifest.json"

    Write-SecSuiteJson -InputObject $ReportObject -Path $jsonPath | Out-Null
    (ConvertTo-SecXmlString -InputObject $ReportObject) | Set-Content -LiteralPath $xmlPath -Encoding UTF8
    (ConvertTo-SecHtml -InputObject $ReportObject -Title $BaseName) | Set-Content -LiteralPath $htmlPath -Encoding UTF8

    $browser = Get-SecHeadlessBrowserCommand
    if ($browser) {
        try {
            & $browser --headless --disable-gpu "--print-to-pdf=$pdfPath" $htmlPath | Out-Null
            Write-SecLog -Context $Context -Area 'Reporting' -Message 'PDF export attempted.' -Data @{ browser = $browser; output = $pdfPath }
        }
        catch {
            Write-SecLog -Context $Context -Level 'WARN' -Area 'Reporting' -Message 'PDF export failed.' -Data @{ error = $_.Exception.Message; browser = $browser }
        }
    }
    else {
        Write-SecLog -Context $Context -Level 'WARN' -Area 'Reporting' -Message 'PDF export skipped: no supported browser found.'
    }

    $reportPaths = [ordered]@{
        Json = $jsonPath
        Xml = $xmlPath
        Html = $htmlPath
        Pdf = if (Test-Path -LiteralPath $pdfPath) { $pdfPath } else { $null }
    }

    if ($Context.Config.Reports.EmitManifest) {
        $manifest = [ordered]@{
            suite = $Context.SuiteName
            version = $Context.Version
            sessionId = $Context.SessionId
            generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            files = @()
        }

        foreach ($entry in $reportPaths.GetEnumerator()) {
            if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
                continue
            }

            $manifest.files += [pscustomobject]@{
                type = $entry.Key
                path = $entry.Value
                sha256 = Get-SecFileSha256 -Path $entry.Value
                sizeBytes = (Get-Item -LiteralPath $entry.Value).Length
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        $reportPaths.Manifest = $manifestPath
    }

    [pscustomobject]$reportPaths
}

function New-TcpentRunContext {
    [CmdletBinding()]
    param([string]$OutputPath)

    New-SecSuiteRunContext -OutputPath $OutputPath
}

Export-ModuleMember -Function Get-SecSuiteRoot, Get-SecHostName, Get-SecCurrentUserName, Get-SecSha256Hex, Get-SecFileSha256, Import-SecSuiteConfig, Resolve-SecPath, New-SecSuiteRunContext, Initialize-SecSuiteLogging, Write-SecLog, Write-SecAuditEvent, Write-SecSuiteJson, Invoke-SecOperation, ConvertTo-SecXmlString, ConvertTo-SecHtml, Export-SecSuiteReportSet, New-TcpentRunContext
