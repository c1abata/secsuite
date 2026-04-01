BeforeAll {
    Import-Module "$PSScriptRoot\..\..\modules\PassiveNetwork\PassiveNetwork.psm1" -Force
}

Describe 'PassiveNetwork module shape tests' {
    It 'exports passive snapshot function' {
        (Get-Command Get-SecPassiveNetworkSnapshot -ErrorAction Stop).Name | Should -Be 'Get-SecPassiveNetworkSnapshot'
    }

    It 'exports passive http probe function' {
        (Get-Command Invoke-SecPassiveHttpProbe -ErrorAction Stop).Name | Should -Be 'Invoke-SecPassiveHttpProbe'
    }
}
