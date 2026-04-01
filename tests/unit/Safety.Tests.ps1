BeforeAll {
    Import-Module "$PSScriptRoot\..\..\modules\Safety\Safety.psm1" -Force
}

Describe 'Safety guardrails' {
    It 'denies exploit operations' {
        { Assert-SecSafeAction -Category 'Exploit' } | Should -Throw
    }

    It 'denies remote execution operations' {
        { Assert-SecSafeAction -Category 'RemoteExecution' } | Should -Throw
    }

    It 'accepts a passive category name not on deny list' {
        { Assert-SecSafeAction -Category 'Inventory' } | Should -Not -Throw
    }
}
