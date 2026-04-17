BeforeAll {
    Import-Module "$PSScriptRoot/../../modules/ADAudit/ADAudit.psm1" -Force
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
                [pscustomobject]@{ SamAccountName = 'user1'; PasswordNotRequired = $true; DoesNotRequirePreAuth = $false },
                [pscustomobject]@{ SamAccountName = 'user2'; PasswordNotRequired = $false; DoesNotRequirePreAuth = $true }
            )
            ServiceAccounts = @([pscustomobject]@{ SamAccountName = 'svc1'; TrustedForDelegation = $true })
            Computers = @([pscustomobject]@{ Name = 'srv1'; TrustedForDelegation = $true })
            Trusts = @([pscustomobject]@{ Name = 'trust1'; SelectiveAuthentication = $false })
            AttackPaths = @([pscustomobject]@{ Source = 'user1'; Target = 'Domain Admins'; Relation = 'MemberOf'; RiskWeight = 5 })
            ExposureScore = [pscustomobject]@{ Score = 60; Rating = 'High' }
        }

        $findings = New-SecADFindings -AuditData $audit
        @($findings).Count | Should -BeGreaterThan 0
        (@($findings | Where-Object Id -eq 'AD-008').Count) | Should -Be 1
        (@($findings | Where-Object Id -eq 'AD-009').Count) | Should -Be 1
    }
}

Describe 'AD exposure scoring' {
    It 'returns a numeric score and rating' {
        $score = Get-SecADExposureScore -InactiveUsers @([pscustomobject]@{ PasswordNotRequired = $true; DoesNotRequirePreAuth = $true }) -ServiceAccounts @([pscustomobject]@{ TrustedForDelegation = $true }) -Computers @([pscustomobject]@{ TrustedForDelegation = $false }) -Trusts @([pscustomobject]@{ SelectiveAuthentication = $false })

        $score.Score | Should -BeGreaterThan 0
        $score.Rating | Should -Not -BeNullOrEmpty
    }
}

Describe 'Extended AD security checks' {
    It 'returns structured output when only unauthenticated checks are requested' {
        Mock Resolve-DnsName {
            @(
                [pscustomobject]@{ NameHost = 'dc01.contoso.local' }
            )
        }

        Mock New-SecLdapConnection -ModuleName ADAudit {
            $conn = [pscustomobject]@{}
            $conn | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
            $conn
        }

        Mock Get-SecLdapEntries -ModuleName ADAudit {
            @([pscustomobject]@{ Attributes = @{ defaultNamingContext = @('DC=contoso,DC=local') } })
        }

        $result = Invoke-SecADSecurityChecks -Domain 'contoso.local' -UnauthenticatedOnly

        $result.Domain | Should -Be 'contoso.local'
        @($result.UnauthenticatedChecks).Count | Should -BeGreaterThan 0
        @($result.AuthenticatedChecks).Count | Should -Be 0
    }
}
