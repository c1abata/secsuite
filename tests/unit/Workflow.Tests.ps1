BeforeAll {
    Import-Module "$PSScriptRoot/../../modules/Core/Core.psm1" -Force
    Import-Module "$PSScriptRoot/../../modules/Safety/Safety.psm1" -Force
    Import-Module "$PSScriptRoot/../../modules/Workflow/Workflow.psm1" -Force
}

Describe 'Workflow compliance gate' {
    It 'blocks execution when legal artifacts are missing' {
        $result = Test-SecVaPtComplianceGate -AssessmentType VA -ExecutionRequested

        $result.Status | Should -Be 'Blocked'
        @($result.Checks | Where-Object Status -eq 'BLOCK').Count | Should -BeGreaterThan 0
    }

    It 'approves execution when required artifacts exist' {
        $authorization = Join-Path $TestDrive 'authorization.txt'
        $roe = Join-Path $TestDrive 'roe.txt'
        $scope = Join-Path $TestDrive 'scope.txt'
        $targets = Join-Path $TestDrive 'targets.txt'
        $dataHandling = Join-Path $TestDrive 'data-handling.txt'

        'authorized assessment' | Set-Content -LiteralPath $authorization
        'approved boundaries' | Set-Content -LiteralPath $roe
        '10.0.0.0/24' | Set-Content -LiteralPath $scope
        '10.0.0.10' | Set-Content -LiteralPath $targets
        'encrypted evidence and retention policy' | Set-Content -LiteralPath $dataHandling

        $result = Test-SecVaPtComplianceGate -AssessmentType PT -AuthorizationPath $authorization -RulesOfEngagementPath $roe -ScopePath $scope -TargetsPath $targets -DataHandlingPath $dataHandling -ExecutionRequested

        $result.Status | Should -Be 'Approved'
    }
}

Describe 'Workflow boundaries' {
    It 'inherits denied categories from the safety policy' {
        $boundaries = Get-SecExecutionBoundaries

        $boundaries.DeniedCategories | Should -Contain 'Exploit'
        $boundaries.AllowedActions | Should -Contain 'Inventory'
    }
}
