# Azure Security Audit Scripts

PowerShell scripts for auditing Azure infrastructure security posture.

---

## Prerequisites

```powershell
# Install all Az modules needed across auditors
Install-Module Az.Accounts, Az.Resources, Az.Network, Az.Storage, Az.Monitor, Az.Security, Az.KeyVault -Scope CurrentUser

# Authenticate
Connect-AzAccount
```

### Per-Auditor Module Requirements

Some auditors need additional modules beyond the base Az install:

| Auditor | Extra modules | Graph scopes needed |
|---------|--------------|---------------------|
| `entra-auditor` | `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users` | `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory` |
| `entrapwd-auditor` | `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Beta.Identity.DirectoryManagement` | `Policy.Read.All`, `Directory.Read.All` |
| `hybrid-auditor` | `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.DirectoryManagement` | `Organization.Read.All`, `OnPremDirectorySynchronization.Read.All` |
| `subscription-auditor` | `Az.Security`, `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.Governance` | `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory` |
| `activitylog-auditor` | `Az.Monitor` (+ optional `Az.OperationalInsights` for LA workspace retention) | — |
| `storage-auditor` | `Az.Storage` | — |
| `nsg-auditor` | `Az.Network` | — |
| `keyvault-auditor` | `Az.KeyVault` | — |
| `defender-auditor` | `Az.Security`, `Az.Resources` | — |
| `policy-auditor` | `Az.Resources` | — |
| `backup-auditor` | `Az.RecoveryServices` | — |

```powershell
# For auditors using Microsoft Graph — connect after Connect-AzAccount:
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","RoleManagement.Read.Directory","Policy.Read.All","Directory.Read.All","Organization.Read.All","OnPremDirectorySynchronization.Read.All"
```

---

## Orchestrator

Use `Run-Audit.ps1` at the repo root to run all Azure auditors in one command:

```powershell
.\Run-Audit.ps1 -Client "Acme Corp" -Azure
.\Run-Audit.ps1 -Client "Acme Corp" -Azure -AllSubscriptions -Open
```

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

## Usage

All scripts share the same interface:

```powershell
.\nsg_auditor.ps1                          # Audit current subscription, all formats
.\nsg_auditor.ps1 -AllSubscriptions        # Audit all accessible subscriptions
.\nsg_auditor.ps1 -Format html             # HTML output only
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
| HTML | `<prefix>.html` | Colour-coded report with summary cards |

All output files are created with owner-only permissions (mode 600).

---

## Running Tests

```powershell
Invoke-Pester Azure/ -Recurse
```
