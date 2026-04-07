# Entra Password Policy Auditor

Audits Entra ID tenant-level password policy settings.

## Requirements

- PowerShell 7+
- `Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Beta.Identity.DirectoryManagement`
- `Connect-MgGraph -Scopes 'Policy.Read.All','Directory.Read.All'`

## Usage

```powershell
.\entrapwd_auditor.ps1
.\entrapwd_auditor.ps1 -Format json
.\entrapwd_auditor.ps1 -Output client_entrapwd -Format all
```

## Findings

| ID | FindingType | Severity | Description |
|----|-------------|----------|-------------|
| EP-01 | PasswordExpiryEnabled | MEDIUM | Domain password expiry still set — drives weak predictable passwords |
| EP-02 | SsprDisabled | HIGH | Self-service password reset disabled — users must call helpdesk |
| EP-03 | SmartLockoutPermissive | MEDIUM | Lockout threshold > 10 or duration < 60s |
| EP-04 | SecurityDefaultsDisabled | HIGH | Security defaults off with no confirmed Conditional Access replacement |
| EP-05 | CustomBannedPasswordsAbsent | LOW | No custom banned password list configured |

## Output

Produces `entrapwd_report.json`, `entrapwd_report.csv`, `entrapwd_report.html`.
