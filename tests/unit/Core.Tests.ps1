BeforeAll {
    Import-Module "$PSScriptRoot/../../modules/Core/Core.psm1" -Force
}

Describe 'Core logging and reporting' {
    It 'creates run context and log files' {
        $tmp = Join-Path $TestDrive 'out'
        $ctx = New-SecSuiteRunContext -OutputPath $tmp
        Initialize-SecSuiteLogging -Context $ctx | Out-Null
        Test-Path $ctx.LogPath | Should -BeTrue
        Test-Path $ctx.JsonLogPath | Should -BeTrue
        Test-Path $ctx.AuditTrailPath | Should -BeTrue
        Test-Path $ctx.HashChainPath | Should -BeTrue
    }

    It 'exports json xml html and manifest reports' {
        $tmp = Join-Path $TestDrive 'out2'
        $ctx = New-SecSuiteRunContext -OutputPath $tmp
        Initialize-SecSuiteLogging -Context $ctx | Out-Null
        $paths = Export-SecSuiteReportSet -Context $ctx -ReportObject ([pscustomobject]@{ Name = 'demo' }) -BaseName 'demo'
        Test-Path $paths.Json | Should -BeTrue
        Test-Path $paths.Xml | Should -BeTrue
        Test-Path $paths.Html | Should -BeTrue
        Test-Path $paths.Manifest | Should -BeTrue
    }
}
