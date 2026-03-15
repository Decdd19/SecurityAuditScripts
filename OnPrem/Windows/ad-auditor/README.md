# Active Directory Auditor

Audits Active Directory domain health: stale accounts, Kerberoastable/AS-REP roastable users, password policy weaknesses, delegation misconfigurations, and privileged group hygiene.

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- RSAT ActiveDirectory module:
  ```powershell
  # Windows 10/11
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  # Windows Server
  Install-WindowsFeature RSAT-AD-PowerShell
  ```
- Domain-joined machine
- Domain user account with read access to Active Directory (standard user is sufficient for most checks)

## Usage

```powershell
# Full audit — writes ad_report.json, .csv, .html
.\ad_auditor.ps1

# HTML report only
.\ad_auditor.ps1 -Format html -Output my_ad_report

# Print JSON to terminal
.\ad_auditor.ps1 -Format stdout
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Output` | `ad_report` | Output file prefix |
| `-Format` | `all` | `json` \| `csv` \| `html` \| `all` \| `stdout` |
| `-AllTargets` | (switch) | Reserved for future remote scanning |

## Checks

| Finding | Score | Severity | Description |
|---------|-------|----------|-------------|
| `UserPasswordNotRequired` | 9 | CRITICAL | Enabled user account has PasswordNotRequired flag set |
| `KerberoastableAccount` | 8 | CRITICAL | User account with an SPN — susceptible to Kerberoasting |
| `ASREPRoastableAccount` | 8 | CRITICAL | User with Kerberos pre-authentication disabled |
| `TrustUnconstrained` | 9 | CRITICAL | Computer account with unconstrained delegation |
| `DomainAdminPasswordAge` | 7 | HIGH | Domain Admin password older than 90 days |
| `DomainAdminStale` | 7 | HIGH | Domain Admin with no login in 30+ days |
| `WeakDomainPasswordPolicy` | 7 | HIGH | Default domain password policy too weak (len<12 or max age>90d) |
| `AdminCountFlagOrphan` | 6 | HIGH | User has adminCount=1 but is not in a privileged group |
| `ExcessiveDomainAdmins` | 6 | HIGH | More than 5 members in Domain Admins group |
| `UserPasswordNeverExpires` | 6 | HIGH | Enabled user account with password set to never expire |
| `StaleUser` | 5 | MEDIUM | Enabled user with no login in 90+ days |
| `ProtectedUsersEmpty` | 5 | MEDIUM | Protected Users security group has no members |
| `NoFineGrainedPolicyForAdmins` | 5 | MEDIUM | No fine-grained password policy targeting admin accounts |
| `StaleComputer` | 4 | MEDIUM | Computer account with no login in 90+ days |
| `RecycleBinDisabled` | 3 | MEDIUM | AD Recycle Bin optional feature is not enabled |

## Output Files

- `ad_report.json` — machine-readable full report
- `ad_report.csv` — one row per finding
- `ad_report.html` — colour-coded HTML summary

## Running Tests

```powershell
Install-Module Pester -MinimumVersion 5.0 -Force -Scope CurrentUser
Invoke-Pester .\tests\ad_auditor.Tests.ps1 -Output Detailed
```
