# Windows 11 preparation

## Required software
- PowerShell 7
- RSAT Active Directory module when AD audit is needed
- Pester 5 for local tests
- Microsoft Edge or Google Chrome if PDF export is required

## Suggested steps
1. Update Windows 11 fully.
2. Install PowerShell 7.
3. Install Pester with `Install-Module Pester -Scope CurrentUser`.
4. Install RSAT AD tools if the host is used for domain auditing.
5. Run the suite from a dedicated directory with standard user rights unless local inspection needs elevation.
