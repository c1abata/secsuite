BeforeAll {
    Import-Module "$PSScriptRoot/../../modules/StackMatrix/StackMatrix.psm1" -Force
}

Describe 'StackMatrix profile catalog' {
    It 'resolves legacy alias to canonical profile' {
        $profile = Resolve-SecStackProfile -Name 'MssqlAudit'
        $profile.Name | Should -Be 'DatabaseExposure'
    }

    It 'contains full stack profile and scan sets' {
        $profile = Resolve-SecStackProfile -Name 'HybridFullStack'
        $profile.ScanSets.Count | Should -BeGreaterThan 1
    }

    It 'returns matrix with known ports' {
        $matrix = Get-SecStackPortMatrix
        @($matrix | Where-Object Port -eq 445).Count | Should -BeGreaterThan 0
    }
}
