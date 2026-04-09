# M365 Security Audit Scripts

PowerShell scripts for auditing Microsoft 365 tenant security posture — Conditional Access, Exchange Online, SharePoint, Teams, Intune, and Defender for Endpoint.

---

## Prerequisites

### 1 — Install PowerShell 7

**Linux (Ubuntu/Debian via snap):**
```bash
snap install powershell --classic
```

**macOS:**
```bash
brew install --cask powershell
```

**Windows:** PowerShell 7 is pre-installed on modern systems. Download from [aka.ms/powershell](https://aka.ms/powershell) if needed.

---

### 2 — Install Required Modules

All M365 auditors use Microsoft Graph and/or Exchange Online Management. Run once in a `pwsh` session:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber

# Verify
$required = @(
    'Microsoft.Graph.Authentication','Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.Governance','Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'ExchangeOnlineManagement'
)
$required | ForEach-Object {
    $m = Get-Module -ListAvailable -Name $_ | Select-Object -First 1
    if ($m) { Write-Host "OK  $_ $($m.Version)" } else { Write-Host "MISSING $_" }
}
```

---

### 3 — Authenticate

One Graph authentication prompt is required. The token is cached to disk (~1 hour lifetime) so you will only be prompted on the first run of the day or after token expiry.

```powershell
Connect-MgGraph -Scopes `
    'User.Read.All','Directory.Read.All','Policy.Read.All',
    'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All',
    'Organization.Read.All','OnPremDirectorySynchronization.Read.All',
    'RoleManagement.Read.Directory','UserAuthenticationMethod.Read.All','AuditLog.Read.All'
```

> Exchange Online auditors (`m365-auditor`, `exchange-auditor`) connect to Exchange automatically using the cached Graph token — no separate `Connect-ExchangeOnline` step is needed when running via the orchestrator.

---

## Running All M365 Auditors (Recommended)

Use the wrapper script at the repo root to authenticate and run all auditors in one command:

```bash
# From repo root (Linux/macOS)
/snap/bin/pwsh -NoProfile -File run-my-audit.ps1
```

The `run-my-audit.ps1` script handles both `Connect-AzAccount` and `Connect-MgGraph`, then runs `Run-Audit.ps1 -Azure -M365`.

To run M365 alone or combined with Azure:

```powershell
# From repo root (inside a pwsh session after auth)
.\Run-Audit.ps1 -Client "Client Name" -M365
.\Run-Audit.ps1 -Client "Client Name" -Azure -M365 -Open   # recommended: full cloud audit
.\Run-Audit.ps1 -Client "Client Name" -Azure -M365 -Quick  # top-priority auditors only
```

Each auditor produces **JSON + CSV + HTML** output per pillar, plus a consolidated executive summary HTML.

---

## Per-Auditor Module Requirements

| Auditor | Modules | Graph scopes |
|---------|---------|-------------|
| `m365-auditor` | `Microsoft.Graph`, `ExchangeOnlineManagement` | `Policy.Read.All`, `Directory.Read.All`, `User.Read.All`, `AuditLog.Read.All` |
| `sharepoint-auditor` | `Microsoft.Graph` | `Sites.Read.All`, `Directory.Read.All` |
| `teams-auditor` | `Microsoft.Graph` | `Directory.Read.All` |
| `intune-auditor` | `Microsoft.Graph` | `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `Policy.Read.All` |
| `exchange-auditor` | `ExchangeOnlineManagement`, `Microsoft.Graph` | `User.Read.All` |
| `mde-auditor` | `Microsoft.Graph` | `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All` |

> Intune and MDE auditors require M365 Business Premium or an E3/E5 + Intune/MDE add-on licence. On unlicensed tenants they exit cleanly and the report shows "Not Applicable" rather than a failure.

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
```

### sharepoint-auditor

Audits SharePoint Online and OneDrive external sharing via Microsoft Graph.

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

Audits Microsoft Teams federation, guest access, and meeting policies via Microsoft Graph.

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

Audits Intune device compliance and Conditional Access enforcement. Requires M365 Business Premium, E3+Intune, or EMS E3/E5. Reports "Not Applicable" on unlicensed tenants.

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

Audits Exchange Online transport rules, delegation, and audit logging.

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

Audits Defender for Endpoint device posture via Microsoft Graph. Requires M365 Business Premium or MDE Plan 1/2.

| ID | Finding | Severity |
|----|---------|----------|
| MDE-01 | Windows device not onboarded to Defender for Endpoint | CRITICAL |
| MDE-02 | Real-time protection disabled | HIGH |
| MDE-03 | BitLocker not enabled on Windows device | HIGH |
| MDE-04 | Tamper protection disabled | HIGH |
| MDE-05 | No antivirus scan in >7 days | MEDIUM |

```powershell
.\mde_auditor.ps1 -TenantDomain contoso.com
```

---

## Individual Script Usage

All scripts accept the same flags:

```powershell
.\<auditor>.ps1 -TenantDomain contoso.com   # Specify tenant domain
.\<auditor>.ps1 -Format html                 # HTML only
.\<auditor>.ps1 -Format json                 # JSON only
.\<auditor>.ps1 -Format all                  # JSON + CSV + HTML (default)
.\<auditor>.ps1 -Format stdout               # Print JSON to terminal
.\<auditor>.ps1 -Output my_report            # Custom file prefix
```

---

## Output

Each run produces (with `-Format all`, the default):

| Format | File | Contents |
|--------|------|----------|
| JSON | `<prefix>.json` | Machine-readable findings with severity and CIS control mapping |
| CSV | `<prefix>.csv` | One row per finding, importable to Excel/SIEM |
| HTML | `<prefix>.html` | Colour-coded per-pillar report with summary cards |

The orchestrator (`Run-Audit.ps1`) additionally generates `exec_summary.html` — a single consolidated executive report across all pillars.

All output files are created with owner-only permissions (mode 600).

---

## Running Tests

```powershell
Invoke-Pester M365/ -Recurse -Output Detailed
```

Tests use module stubs — no live M365 connection required.
