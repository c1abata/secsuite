BeforeAll {
    Import-Module "$PSScriptRoot\..\..\modules\ADAudit\ADAudit.psm1" -Force
}

Describe 'AD findings engine' {
    It 'emits findings from weak mocked data' {
        $audit = [pscustomobject]@{
            Available = $true
            PasswordPolicy = [pscustomobject]@{
                MinPasswordLength = 8
                ComplexityEnabled = $false
            }
            InactiveUsers = @(
                [pscustomobject]@{ SamAccountName='user1'; PasswordNotRequired=$true; DoesNotRequirePreAuth=$false },
                [pscustomobject]@{ SamAccountName='user2'; PasswordNotRequired=$false; DoesNotRequirePreAuth=$true }
            )
            ServiceAccounts = @([pscustomobject]@{ SamAccountName='svc1'; TrustedForDelegation=$true })
            Computers = @([pscustomobject]@{ Name='srv1'; TrustedForDelegation=$true })
            Trusts = @([pscustomobject]@{ Name='trust1'; SelectiveAuthentication=$false })
        }
        $findings = New-SecADFindings -AuditData $audit
        @($findings).Count | Should -BeGreaterThan 0
    }
}
