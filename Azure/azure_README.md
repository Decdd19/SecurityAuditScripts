# Azure Security Audit Scripts

PowerShell scripts for auditing Azure infrastructure security posture. Azure equivalents
of the AWS audit scripts in this repository.

## Prerequisites

```powershell
# Install Az modules
Install-Module Az.Accounts, Az.Resources, Az.Network, Az.Storage, Az.Monitor, Az.Security -Scope CurrentUser

# Install Graph modules (required by entra_auditor and subscription_auditor)
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance -Scope CurrentUser

# Authenticate
Connect-AzAccount
# For entra_auditor and subscription_auditor, also:
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","RoleManagement.Read.Directory"
```

## Scripts

| Script | Azure Service | AWS Equivalent |
|--------|--------------|----------------|
| `nsg-auditor/nsg_auditor.ps1` | Network Security Groups | sg-auditor |
| `storage-auditor/storage_auditor.ps1` | Storage Accounts | s3-auditor |
| `activitylog-auditor/activitylog_auditor.ps1` | Diagnostic Settings / Activity Logs | cloudtrail-auditor |
| `subscription-auditor/subscription_auditor.ps1` | Subscriptions & Tenant Posture | root-auditor |
| `entra-auditor/entra_auditor.ps1` | Entra ID & RBAC | iam-privilege-mapper |

## Usage

All scripts share the same interface:

```powershell
.\nsg_auditor.ps1                          # Audit current subscription, all formats
.\nsg_auditor.ps1 -AllSubscriptions        # Audit all accessible subscriptions
.\nsg_auditor.ps1 -Format html             # HTML output only
.\nsg_auditor.ps1 -Output my_report        # Custom output file prefix
.\nsg_auditor.ps1 -Format stdout           # Print JSON to console
```

## Output

Each run produces (with `-Format all`, the default):
- `<prefix>.json` — machine-readable findings
- `<prefix>.csv` — spreadsheet-compatible flat rows
- `<prefix>.html` — colour-coded HTML report with summary cards

All output files are created with owner-only permissions.

## Running Tests

```powershell
Invoke-Pester Azure/ -Recurse
```
