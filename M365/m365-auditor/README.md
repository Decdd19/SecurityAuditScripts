# M365 / Exchange Online Security Auditor

Audits Microsoft 365 tenant security posture for common misconfigurations affecting SMB environments.

## Checks

| Check | Finding Type | CIS Control | Risk |
|-------|-------------|-------------|------|
| No MFA-enforcing Conditional Access policy | `NoMfaCaPolicy` | CIS 6 | CRITICAL |
| CA MFA policy in report-only mode | `CaPolicyReportOnly` | CIS 6 | HIGH |
| Legacy authentication not blocked | `LegacyAuthNotBlocked` | CIS 4 | HIGH |
| Mailbox auto-forwarding to external address | `ExternalMailboxForwarding` | CIS 9 | HIGH |
| Inbox rule forwarding externally | `ExternalInboxForwardRule` | CIS 9 | HIGH |
| Unrestricted OAuth app user consent | `UnrestrictedOAuthConsent` | CIS 16 | HIGH |

## Prerequisites

Install required PowerShell modules on a Windows machine with admin access:

```powershell
Install-Module Az -Scope CurrentUser -Force
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
```

Connect before running:

```powershell
Connect-AzAccount
Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All"
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
```

## Usage

```powershell
# Default — all formats, auto-detect tenant domain
.\m365_auditor.ps1

# Specify tenant domain explicitly (required when UPN doesn't match primary domain)
.\m365_auditor.ps1 -TenantDomain contoso.com

# JSON only
.\m365_auditor.ps1 -TenantDomain contoso.com -Format json

# Pipe to exec summary
python3 tools/exec_summary.py --input-dir ./reports/client-2026-01-01/
```

## Output

| File | Description |
|------|-------------|
| `m365_report.json` | Machine-readable findings (import into exec_summary) |
| `m365_report.csv` | Spreadsheet export |
| `m365_report.html` | Standalone HTML report |

## Required Permissions

| Module | Permission | Purpose |
|--------|-----------|---------|
| Microsoft.Graph | `Policy.Read.All` | Read CA policies, auth policy |
| Microsoft.Graph | `Application.Read.All` | Read OAuth app registrations |
| Exchange Online | `View-Only Recipients` | Read mailbox forwarding settings |
| Exchange Online | `View-Only Configuration` | Read inbox rules |

## Running Tests

```powershell
Invoke-Pester ./tests/m365_auditor.Tests.ps1 -Output Detailed
```
