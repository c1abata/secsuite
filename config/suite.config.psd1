@{
    SuiteName = 'TCPENT'
    Version = '0.1.0'
    BrandStyle = 'antirez'

    DefaultOutputPath = './output'

    LogFileName = 'execution.log'
    LogJsonFileName = 'execution.ndjson'
    AuditTrailFileName = 'operations.ndjson'
    HashChainFileName = 'hashchain.ndjson'

    Reports = @{
        EmitJson = $true
        EmitXml  = $true
        EmitHtml = $true
        EmitPdf  = $true
        EmitManifest = $true
    }

    ADAudit = @{
        ConnectionMode = 'Auto'
        DomainController = ''
        UseLdaps = $true
        LdapAuthType = 'Negotiate'
        PrivilegedGroups = @(
            'Administrators',
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Group Policy Creator Owners',
            'Account Operators',
            'Server Operators',
            'Backup Operators',
            'Print Operators'
        )
        InactiveUserDays = 90
    }

    ThreatValidation = @{
        DefaultProfile = 'HybridFullStack'
        MaxRetries = 2
        HostTimeout = '45s'
        ServiceVersionDetection = $true
        TimingTemplate = 'T3'
    }

    Workflow = @{
        DefaultAssessmentType = 'VA'
        DefaultRetentionDays = 365
        RequireAuthorizationEvidence = $true
        RequireRulesOfEngagement = $true
        RequireScopeEvidence = $true
        RequireTargets = $true
        RequireDataHandlingForExecute = $true
        AllowedAssessmentTypes = @(
            'VA',
            'PT',
            'VA-PT',
            'AD-AUDIT'
        )
    }

    Compliance = @{
        Frameworks = @('ISO27001','NIST-SP-800-115','NIS2','DORA')
        MinRetentionDays = 30
        MaxRetentionDays = 3650
        RequireTicketIdForExecute = $false
    }
}
