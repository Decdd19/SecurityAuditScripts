# teams-auditor

Audits Microsoft Teams guest access, external federation, and meeting policies.

## Checks

| ID | Finding | Severity |
|----|---------|----------|
| TM-01 | External access open to all domains | HIGH |
| TM-02 | Guest access enabled with unrestricted permissions | MEDIUM |
| TM-03 | Guests can create or delete channels | MEDIUM |
| TM-04 | Anonymous users can bypass meeting lobby | HIGH |
| TM-05 | Meeting recordings have no expiry | MEDIUM |
| TM-06 | Third-party app installs permitted | MEDIUM |

## Requirements

- MicrosoftTeams module: `Install-Module MicrosoftTeams`
- Teams admin or Global admin role

## Usage

```powershell
.\teams_auditor.ps1 -TenantDomain contoso.com
.\teams_auditor.ps1 -TenantDomain contoso.com -Format json
```

## Output

Produces `teams_report.json`, `teams_report.csv`, `teams_report.html`.
