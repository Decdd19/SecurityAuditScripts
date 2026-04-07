# M365 Security Audit Scripts

PowerShell scripts for auditing Microsoft 365 tenant security posture — Conditional Access, Exchange Online, SharePoint, Teams, Intune, and Defender for Endpoint.

---

## Prerequisites

Each auditor uses different modules. Install what you need:

| Auditor | Module(s) | Connect command |
|---------|-----------|----------------|
| `m365-auditor` | `Microsoft.Graph`, `ExchangeOnlineManagement` | `Connect-MgGraph` + `Connect-ExchangeOnline` |
| `sharepoint-auditor` | `Microsoft.Online.SharePoint.PowerShell` | `Connect-SPOService -Url https://<tenant>-admin.sharepoint.com` |
| `teams-auditor` | `MicrosoftTeams` | `Connect-MicrosoftTeams` |
| `intune-auditor` | `Microsoft.Graph` | `Connect-MgGraph` |
| `exchange-auditor` | `ExchangeOnlineManagement`, `Microsoft.Graph` | `Connect-ExchangeOnline` + `Connect-MgGraph` |
| `mde-auditor` | `Microsoft.Graph` | `Connect-MgGraph` |

### Graph scopes needed

```powershell
Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All","User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All","RoleManagement.Read.Directory","DeviceManagementManagedDevices.Read.All","DeviceManagementConfiguration.Read.All"
```

> You can scope this down per-auditor — see the table below.

### Quick install

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force
Install-Module MicrosoftTeams -Scope CurrentUser -Force
```

---

## Orchestrator

Use `Run-Audit.ps1` at the repo root to run all M365 auditors at once:

```powershell
.\Run-Audit.ps1 -Client "Acme Corp" -M365
.\Run-Audit.ps1 -Client "Acme Corp" -All -Open   # Azure + M365 + Windows
```

---

## Scripts & Checks

### m365-auditor

Core M365 tenant security checks. Requires `Microsoft.Graph` + `ExchangeOnlineManagement`.

| ID | Finding | Severity |
|----|---------|----------|
| — | No MFA-enforcing Conditional Access policy | CRITICAL |
| — | CA MFA policy in report-only mode | HIGH |
| — | Legacy authentication not blocked by CA | HIGH |
| — | Mailbox auto-forwarding to external address | HIGH |
| — | Inbox rule forwarding externally | HIGH |
| — | Unrestricted OAuth app user consent | HIGH |
| — | Users with no MFA method registered | MEDIUM–HIGH |
| — | Privileged admin role member enumeration | MEDIUM |
| — | Guest / external users stale >90 days | LOW–MEDIUM |

```powershell
.\m365_auditor.ps1 -TenantDomain contoso.com
.\m365_auditor.ps1 -TenantDomain contoso.com -Format json
```

### sharepoint-auditor

Audits SharePoint Online and OneDrive external sharing. Requires SPO Management Shell.

| ID | Finding | Severity |
|----|---------|----------|
| SP-01 | Tenant allows anonymous ("Anyone") sharing | CRITICAL |
| SP-02 | Anonymous links have no expiry | HIGH |
| SP-03 | Sites more permissive than tenant default | HIGH |
| SP-04 | OneDrive external sharing unrestricted | HIGH |
| SP-05 | Default sharing link type is anonymous | CRITICAL |
| SP-06 | External sharing not restricted to allowed domains | MEDIUM |

```powershell
.\sharepoint_auditor.ps1 -TenantDomain contoso.com
```

### teams-auditor

Audits Microsoft Teams federation, guest access, and meeting policies. Requires `MicrosoftTeams`.

| ID | Finding | Severity |
|----|---------|----------|
| TM-01 | External access open to all domains | HIGH |
| TM-02 | Guest access enabled with unrestricted permissions | MEDIUM |
| TM-03 | Guests can create or delete channels | MEDIUM |
| TM-04 | Anonymous users can bypass meeting lobby | HIGH |
| TM-05 | Meeting recordings have no expiry | MEDIUM |
| TM-06 | Third-party app installs permitted | MEDIUM |

```powershell
.\teams_auditor.ps1 -TenantDomain contoso.com
```

### intune-auditor

Audits Intune device compliance and Conditional Access enforcement. Requires `Microsoft.Graph` with `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `Policy.Read.All`. Requires M365 Business Premium, E3+Intune, or EMS E3/E5 — exits cleanly with an INFO finding on unlicensed tenants.

| ID | Finding | Severity |
|----|---------|----------|
| IN-01 | Platform missing compliance policy (Windows/iOS/Android/macOS) | HIGH |
| IN-02 | Compliance grace period exceeds 24 hours | HIGH |
| IN-03 | No Conditional Access policy enforces device compliance | CRITICAL |
| IN-04 | Non-compliant managed devices accessing M365 | HIGH |
| IN-05 | Windows MDM auto-enrollment not configured | MEDIUM |

```powershell
.\intune_auditor.ps1 -TenantDomain contoso.com
```

### exchange-auditor

Audits Exchange Online transport rules, delegation, and audit logging. Requires `ExchangeOnlineManagement` + `Microsoft.Graph`.

| ID | Finding | Severity |
|----|---------|----------|
| EX-01 | Transport rule forwards mail to external domain | CRITICAL |
| EX-02 | Transport rule bypasses spam/malware filtering | CRITICAL |
| EX-03 | Remote domain allows automatic forwarding | CRITICAL |
| EX-04 | FullAccess mailbox delegation to non-admin account | MEDIUM |
| EX-05 | Shared mailbox sign-in not blocked | HIGH |
| EX-06 | Per-mailbox audit logging disabled | HIGH |
| EX-07 | Admin audit logging disabled | HIGH |
| EX-08 | SMTP AUTH enabled on individual mailbox | HIGH |

```powershell
.\exchange_auditor.ps1 -TenantDomain contoso.com
```

### mde-auditor

Audits Defender for Endpoint device posture via Microsoft Graph. Requires M365 Business Premium or MDE Plan 1/2 licence. Requires `Microsoft.Graph` with `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`.

| ID | Finding | Severity |
|----|---------|----------|
| MDE-01 | Windows device not onboarded to Defender for Endpoint | CRITICAL |
| MDE-02 | Real-time protection disabled | HIGH |
| MDE-03 | BitLocker not enabled on Windows device | HIGH |
| MDE-04 | Tamper protection disabled | HIGH |
| MDE-05 | No antivirus scan in >7 days | MEDIUM |

```powershell
.\mde_auditor.ps1
.\mde_auditor.ps1 -TenantDomain contoso.com -Format all
```

---

## Common Usage

All scripts accept the same flags:

```powershell
.\<auditor>.ps1 -TenantDomain contoso.com      # Specify tenant domain
.\<auditor>.ps1 -Format html                    # HTML only
.\<auditor>.ps1 -Format json                    # JSON only
.\<auditor>.ps1 -Format all                     # JSON + CSV + HTML (default)
.\<auditor>.ps1 -Format stdout                  # Print JSON to terminal
.\<auditor>.ps1 -Output my_report              # Custom file prefix
```

---

## Running Tests

```powershell
Invoke-Pester M365/ -Recurse -Output Detailed
```

Tests use module stubs — no live M365 connection required.
