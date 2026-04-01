@{
    SuiteName = 'SecSuite'
    Version = '0.2.0'
    DefaultOutputPath = '.\\output'
    LogFileName = 'execution.log'
    LogJsonFileName = 'execution.ndjson'
    Reports = @{
        EmitJson = $true
        EmitXml  = $true
        EmitHtml = $true
        EmitPdf  = $true
    }
    ADAudit = @{
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
}
