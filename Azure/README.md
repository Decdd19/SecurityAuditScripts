# Azure Security Audit Scripts

PowerShell scripts for auditing Azure infrastructure security posture.

---

## Prerequisites

```powershell
# Install core Az modules
Install-Module Az.Accounts, Az.Resources, Az.Network, Az.Storage, Az.Monitor, Az.Security, Az.KeyVault -Scope CurrentUser

# Install Graph modules (required by entra-auditor and subscription-auditor)
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance -Scope CurrentUser

# Authenticate
Connect-AzAccount

# For entra-auditor and subscription-auditor, also authenticate to Graph:
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","RoleManagement.Read.Directory"
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
