BeforeAll {
    Import-Module "$PSScriptRoot\..\..\modules\Inventory\Inventory.psm1" -Force
}

Describe 'Inventory module shape tests' {
    It 'exports host inventory function' {
        (Get-Command Get-SecHostInventory -ErrorAction Stop).Name | Should -Be 'Get-SecHostInventory'
    }

    It 'exports installed software function' {
        (Get-Command Get-SecInstalledSoftware -ErrorAction Stop).Name | Should -Be 'Get-SecInstalledSoftware'
    }
}
