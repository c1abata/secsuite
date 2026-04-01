BeforeAll {
    Import-Module "$PSScriptRoot\..\..\modules\ThreatValidation\ThreatValidation.psm1" -Force
}

Describe 'ThreatValidation module shape tests' {
    It 'exports plan builder' {
        (Get-Command New-SecSafeNmapPlan -ErrorAction Stop).Name | Should -Be 'New-SecSafeNmapPlan'
    }

    It 'creates plan with no-arp flag by default' {
        $plan = New-SecSafeNmapPlan -Profile IdentityAccess -TargetFile '.\targets.txt' -ExcludeFile '.\exclude.txt' -OutputDirectory $TestDrive
        $plan[0].Command | Should -Match '--disable-arp-ping'
    }

    It 'parses target list and applies exclude file' {
        $targets = Join-Path $TestDrive 'targets.txt'
        $exclude = Join-Path $TestDrive 'exclude.txt'
        @('10.0.0.1','10.0.0.2','#comment') | Set-Content -LiteralPath $targets
        @('10.0.0.2') | Set-Content -LiteralPath $exclude
        $list = Get-SecTargetList -Path $targets -ExcludePath $exclude
        $list | Should -Contain '10.0.0.1'
        $list | Should -Not -Contain '10.0.0.2'
    }
}
