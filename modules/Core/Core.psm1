Set-StrictMode -Version Latest

function Get-SecSuiteRoot {
    (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
}

function Import-SecSuiteConfig {
    $configPath = Join-Path (Get-SecSuiteRoot) 'config\\suite.config.psd1'
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

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $resolvedOutput = (Resolve-Path $OutputPath).Path
    [pscustomobject]@{
        SuiteName  = $config.SuiteName
        Version    = $config.Version
        Hostname   = $env:COMPUTERNAME
        UserName   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        UtcStarted = (Get-Date).ToUniversalTime().ToString('o')
        OutputPath = $resolvedOutput
        SessionId  = ([guid]::NewGuid()).Guid
        Config     = $config
    }
}

function Initialize-SecSuiteLogging {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $logPath = Join-Path $Context.OutputPath $Context.Config.LogFileName
    $jsonLogPath = Join-Path $Context.OutputPath $Context.Config.LogJsonFileName

    if (-not (Test-Path -LiteralPath $logPath)) { New-Item -Path $logPath -ItemType File -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $jsonLogPath)) { New-Item -Path $jsonLogPath -ItemType File -Force | Out-Null }

    $Context | Add-Member -NotePropertyName LogPath -NotePropertyValue $logPath -Force
    $Context | Add-Member -NotePropertyName JsonLogPath -NotePropertyValue $jsonLogPath -Force
    Write-SecLog -Context $Context -Level 'INFO' -Area 'Core' -Message 'Logging initialized.'
    $Context
}

function Write-SecLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [ValidateSet('DEBUG','INFO','WARN','ERROR')] [string]$Level = 'INFO',
        [Parameter(Mandatory)] [string]$Area,
        [Parameter(Mandatory)] [string]$Message,
        [hashtable]$Data
    )

    $ts = (Get-Date).ToUniversalTime().ToString('o')
    $line = "[{0}] [{1}] [{2}] {3}" -f $ts, $Level, $Area, $Message
    Add-Content -LiteralPath $Context.LogPath -Value $line -Encoding UTF8

    $payload = [ordered]@{
        timestamp = $ts
        level = $Level
        area = $Area
        message = $Message
        sessionId = $Context.SessionId
        hostname = $Context.Hostname
    }
    if ($Data) { $payload.data = $Data }
    Add-Content -LiteralPath $Context.JsonLogPath -Value (($payload | ConvertTo-Json -Depth 8 -Compress)) -Encoding UTF8
}

function Write-SecSuiteJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$InputObject,
        [Parameter(Mandatory)] [string]$Path
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    $InputObject | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
    Get-Item -LiteralPath $Path
}

function ConvertTo-SecXmlString {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    $json = $InputObject | ConvertTo-Json -Depth 10
    $xml = New-Object System.Xml.XmlDocument
    $decl = $xml.CreateXmlDeclaration('1.0','utf-8',$null)
    $xml.AppendChild($decl) | Out-Null
    $root = $xml.CreateElement('SecSuiteReport')
    $xml.AppendChild($root) | Out-Null
    $data = $xml.CreateCDATASection($json)
    $root.AppendChild($data) | Out-Null
    $xml.OuterXml
}

function ConvertTo-SecHtml {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject,[string]$Title='SecSuite Report')

    $pretty = $InputObject | ConvertTo-Json -Depth 10
    @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>$Title</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; }
h1, h2 { margin-bottom: 8px; }
pre { background: #f4f4f4; padding: 16px; border: 1px solid #ddd; overflow-x: auto; }
.small { color: #666; font-size: 12px; }
</style>
</head>
<body>
<h1>$Title</h1>
<p class="small">Generated at $(Get-Date -Format s) UTC</p>
<pre>$([System.Web.HttpUtility]::HtmlEncode($pretty))</pre>
</body>
</html>
"@
}

function Export-SecSuiteReportSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$ReportObject,
        [Parameter(Mandatory)] [string]$BaseName
    )

    $jsonPath = Join-Path $Context.OutputPath "$BaseName.json"
    $xmlPath  = Join-Path $Context.OutputPath "$BaseName.xml"
    $htmlPath = Join-Path $Context.OutputPath "$BaseName.html"
    $pdfPath  = Join-Path $Context.OutputPath "$BaseName.pdf"

    Write-SecSuiteJson -InputObject $ReportObject -Path $jsonPath | Out-Null
    (ConvertTo-SecXmlString -InputObject $ReportObject) | Set-Content -LiteralPath $xmlPath -Encoding UTF8
    (ConvertTo-SecHtml -InputObject $ReportObject -Title $BaseName) | Set-Content -LiteralPath $htmlPath -Encoding UTF8

    $edge = @(
        "$env:ProgramFiles (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "$env:ProgramFiles\\Microsoft\\Edge\\Application\\msedge.exe",
        "$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($edge) {
        & $edge --headless --disable-gpu "--print-to-pdf=$pdfPath" $htmlPath | Out-Null
        Write-SecLog -Context $Context -Area 'Reporting' -Message 'PDF export attempted.' -Data @{ browser = $edge; output = $pdfPath }
    }
    else {
        Write-SecLog -Context $Context -Level 'WARN' -Area 'Reporting' -Message 'PDF export skipped: no supported headless browser found.'
    }

    [pscustomobject]@{
        Json = $jsonPath
        Xml  = $xmlPath
        Html = $htmlPath
        Pdf  = (Test-Path $pdfPath) ? $pdfPath : $null
    }
}

Export-ModuleMember -Function Get-SecSuiteRoot, Import-SecSuiteConfig, New-SecSuiteRunContext, Initialize-SecSuiteLogging, Write-SecLog, Write-SecSuiteJson, ConvertTo-SecXmlString, ConvertTo-SecHtml, Export-SecSuiteReportSet
