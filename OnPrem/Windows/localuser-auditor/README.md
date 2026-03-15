# Windows Local User Auditor

Audits local user accounts, group memberships, registry security settings, and service configuration on standalone Windows machines.

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- Run as local administrator
- No additional modules required

## Usage

```powershell
# Full audit — writes localuser_report.json, .csv, .html
.\localuser_auditor.ps1

# HTML report only
.\localuser_auditor.ps1 -Format html -Output my_report

# Print JSON to terminal
.\localuser_auditor.ps1 -Format stdout
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Output` | `localuser_report` | Output file prefix |
| `-Format` | `all` | `json` \| `csv` \| `html` \| `all` \| `stdout` |

## Checks

| Finding | Score | Severity | Description |
|---------|-------|----------|-------------|
| `ClearTextPasswordInRegistry` | 10 | CRITICAL | AutoLogon `DefaultPassword` stored in registry |
| `LocalUserNoPassword` | 9 | CRITICAL | Enabled local user account requires no password |
| `AutologinEnabled` | 9 | CRITICAL | `AutoAdminLogon` registry key enables automatic login |
| `WDigestAuthEnabled` | 8 | CRITICAL | WDigest authentication caches credentials in plaintext |
| `GuestAccountEnabled` | 8 | CRITICAL | Built-in Guest account is enabled |
| `LapsNotDetected` | 7 | HIGH | LAPS (Local Administrator Password Solution) not found |
| `NtlmV1Enabled` | 7 | HIGH | LmCompatibilityLevel below 3 allows NTLMv1 |
| `LocalAdminPasswordNeverExpires` | 7 | HIGH | Local admin account password set to never expire |
| `RemoteRegistryEnabled` | 6 | HIGH | Remote Registry service is running |
| `ExcessiveLocalAdmins` | 6 | HIGH | More than 3 non-built-in accounts in Administrators group |
| `AdministratorAccountDefaultName` | 5 | MEDIUM | Built-in Administrator account has not been renamed |
| `StaleLocalUser` | 4 | MEDIUM | Enabled local user with no login in 90+ days |

## Output Files

All files are written with owner-only permissions.

- `localuser_report.json` — machine-readable full report
- `localuser_report.csv` — one row per finding
- `localuser_report.html` — colour-coded HTML summary

## Running Tests

```powershell
Install-Module Pester -MinimumVersion 5.0 -Force -Scope CurrentUser
Invoke-Pester .\tests\localuser_auditor.Tests.ps1 -Output Detailed
```
