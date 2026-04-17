@{
    Severity = @('Error','Warning')
    Rules = @{
        PSAvoidUsingWriteHost = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments = @{ Enable = $true }
        PSAvoidUsingPlainTextForPassword = @{ Enable = $true }
        PSUseConsistentWhitespace = @{ Enable = $true }
        PSUseConsistentIndentation = @{ Enable = $true }
    }
    ExcludeRules = @(
        'PSAvoidGlobalVars'
    )
}
