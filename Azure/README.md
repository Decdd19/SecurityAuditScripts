# Azure Security Audit Scripts

PowerShell scripts for auditing Azure infrastructure security posture.

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

Run once in a `pwsh` session:

```powershell
# Core Az modules
Install-Module Az -Scope CurrentUser -Force -AllowClobber

# Microsoft Graph modules
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
Install-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -Scope CurrentUser -Force -AllowClobber

# Verify all required modules are present
$required = @(
    'Az.Accounts','Az.Monitor','Az.Storage','Az.Network','Az.Resources',
    'Az.Security','Az.KeyVault','Az.RecoveryServices',
    'Microsoft.Graph.Authentication','Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.Governance','Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Beta.Identity.DirectoryManagement'
)
$required | ForEach-Object {
    $m = Get-Module -ListAvailable -Name $_ | Select-Object -First 1
    if ($m) { Write-Host "OK  $_ $($m.Version)" } else { Write-Host "MISSING $_" }
}
```

---

### 3 — Authenticate

Two authentication prompts are required — one for Azure Resource Manager, one for Microsoft Graph. Both token caches are saved to disk (~1 hour lifetime), so you will only be prompted on the first run of the day or after token expiry.

> **Linux note:** On Linux, each auditor script runs in an isolated child process. Depending on whether MSAL's token cache can be shared across processes (requires libsecret / GNOME keyring or a writable `~/.local/share/.IdentityService/` path), you may see 2–4 additional browser prompts during the run. This is a known limitation of the multi-process architecture on Linux and does not affect Windows, where DPAPI-based token caching is cross-process reliable. The prompts are harmless — just authenticate and the run continues.

```powershell
# Azure Resource Manager (required for all Az.* auditors)
Connect-AzAccount

# Microsoft Graph (required for Entra, hybrid, entrapwd, subscription auditors)
Connect-MgGraph -Scopes `
    'User.Read.All','Directory.Read.All','Policy.Read.All',
    'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All',
    'Organization.Read.All','OnPremDirectorySynchronization.Read.All',
    'RoleManagement.Read.Directory','UserAuthenticationMethod.Read.All','AuditLog.Read.All'
```

---

## Running All Azure Auditors (Recommended)

Use the wrapper script at the repo root to authenticate and run all auditors in a single command:

```bash
# From repo root
/snap/bin/pwsh -NoProfile -File run-my-audit.ps1
```

The `run-my-audit.ps1` script handles both auth prompts, then invokes `Run-Audit.ps1 -Azure`.

To run Azure + M365 together:

```powershell
# From repo root (inside a pwsh session after auth)
.\Run-Audit.ps1 -Client "Client Name" -Azure -M365 -Open
.\Run-Audit.ps1 -Client "Client Name" -Azure -M365 -AllSubscriptions
.\Run-Audit.ps1 -Client "Client Name" -Azure -M365 -Quick   # top-priority auditors only
```

Each auditor produces **JSON + CSV + HTML** output per pillar, plus a consolidated executive summary HTML.

---

## Per-Auditor Module Requirements

| Auditor | Az modules | Graph modules |
|---------|-----------|---------------|
| `keyvault-auditor` | `Az.Accounts`, `Az.KeyVault` | — |
| `storage-auditor` | `Az.Accounts`, `Az.Storage` | — |
| `nsg-auditor` | `Az.Accounts`, `Az.Network` | — |
| `activitylog-auditor` | `Az.Accounts`, `Az.Monitor` | — |
| `subscription-auditor` | `Az.Accounts`, `Az.Resources`, `Az.Security` | `Authentication`, `Identity.Governance`, `Users` |
| `entra-auditor` | `Az.Accounts`, `Az.Resources` | `Authentication`, `Users` |
| `entrapwd-auditor` | — | `Authentication`, `Identity.SignIns`, `Identity.DirectoryManagement`, `Beta.Identity.DirectoryManagement` |
| `hybrid-auditor` | — | `Authentication`, `Identity.DirectoryManagement` |
| `defender-auditor` | `Az.Accounts`, `Az.Security` | — |
| `policy-auditor` | `Az.Accounts`, `Az.Resources` | — |
| `backup-auditor` | `Az.Accounts`, `Az.RecoveryServices` | — |

> Graph module names are prefixed with `Microsoft.Graph.` — e.g. `Authentication` = `Microsoft.Graph.Authentication`.

---

## Scripts

| Script | Azure Service | AWS Equivalent |
|--------|--------------|----------------|
| `entra-auditor/entra_auditor.ps1` | Entra ID users, guest access, app credentials, custom roles | iam-privilege-mapper |
| `entrapwd-auditor/entrapwd_auditor.ps1` | Entra ID password policy — expiry, SSPR, smart lockout, security defaults, banned passwords | — |
| `hybrid-auditor/hybrid_auditor.ps1` | Hybrid Identity (AAD Connect) — sync staleness, PHS, password writeback, accidental-delete protection, seamless SSO | — |
| `storage-auditor/storage_auditor.ps1` | Storage Accounts | s3-auditor |
| `activitylog-auditor/activitylog_auditor.ps1` | Diagnostic Settings / Activity Logs | cloudtrail-auditor |
| `nsg-auditor/nsg_auditor.ps1` | Network Security Groups | sg-auditor |
| `subscription-auditor/subscription_auditor.ps1` | Subscription posture, PIM, Global Admin hygiene | root-auditor |
| `keyvault-auditor/keyvault_auditor.ps1` | Key Vault RBAC, soft delete, expiring secrets/certs/keys | — |
| `defender-auditor/defender_auditor.ps1` | Defender for Cloud plans, secure score, security contacts | securityhub-auditor |
| `policy-auditor/azpolicy_auditor.ps1` | Azure Policy assignments, compliance state, exemptions | — |
| `backup-auditor/azbackup_auditor.ps1` | Azure Backup vault coverage, retention, redundancy | backup-auditor |

---

## Individual Script Usage

All scripts share the same interface:

```powershell
.\nsg_auditor.ps1                          # Audit current subscription, all output formats
.\nsg_auditor.ps1 -AllSubscriptions        # Audit all accessible subscriptions
.\nsg_auditor.ps1 -Format html             # HTML output only
.\nsg_auditor.ps1 -Format json             # JSON only
.\nsg_auditor.ps1 -Output my_report        # Custom output file prefix
.\nsg_auditor.ps1 -Format stdout           # Print JSON to console
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
Invoke-Pester Azure/ -Recurse
```
