# intune-auditor

Audits Intune device compliance policies and Conditional Access device enforcement.

## Checks

| ID | Finding | Severity |
|----|---------|----------|
| IN-01 | Platform missing compliance policy (Windows/iOS/Android/macOS) | HIGH |
| IN-02 | Compliance grace period exceeds 24 hours | HIGH |
| IN-03 | No Conditional Access policy enforces device compliance | CRITICAL |
| IN-04 | Non-compliant managed devices accessing M365 | HIGH |
| IN-05 | Windows MDM auto-enrollment not configured | MEDIUM |

## Requirements

- Microsoft.Graph module: `Install-Module Microsoft.Graph`
- Scopes: `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `Policy.Read.All`
- Intune administrator or Global reader role
- **M365 licence:** Requires M365 Business Premium, E3+Intune, or EMS E3/E5. On unlicensed tenants the script emits an `IntuneNotLicensed` INFO finding and exits cleanly.

## Usage

```powershell
.\intune_auditor.ps1 -TenantDomain contoso.com
.\intune_auditor.ps1 -TenantDomain contoso.com -Format json
```

## Output

Produces `intune_report.json`, `intune_report.csv`, `intune_report.html`.
