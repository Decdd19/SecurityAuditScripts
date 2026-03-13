# Azure Security Audit Scripts — Design Spec

**Date:** 2026-03-13
**Status:** Approved
**Author:** Declan / Claude

---

## Overview

Create Azure equivalents of the existing AWS security audit scripts in this repository. Five standalone PowerShell scripts, each targeting a distinct Azure security domain, mirroring the structure, style, and CLI interface of the existing `AWS/` scripts.

---

## Repository Structure

```
SecurityAuditScripts/
├── AWS/                              (existing)
└── Azure/
    ├── azure_README.md
    ├── entra-auditor/
    │   └── entra_auditor.ps1
    ├── storage-auditor/
    │   └── storage_auditor.ps1
    ├── activitylog-auditor/
    │   └── activitylog_auditor.ps1
    ├── nsg-auditor/
    │   └── nsg_auditor.ps1
    └── subscription-auditor/
        └── subscription_auditor.ps1
```

Each script is self-contained with no shared module dependencies, keeping them CloudShell-friendly.

---

## Scripts

### 1. `entra_auditor.ps1` — Entra ID & RBAC
**Azure equivalent of:** `iam-privilege-mapper`
**Modules:** `Az.Accounts`, `Az.Resources`, `Microsoft.Graph.Users`, `Microsoft.Graph.Authentication`

> **Note:** MFA registration state for Entra ID users is exposed via Microsoft Graph (`Get-MgUserAuthenticationMethod`), not via `Az.*` modules. This script requires both Az and Graph modules. The script checks for both on startup.

**Audits:**
- Users without MFA registered (`Get-MgUserAuthenticationMethod` — requires `UserAuthenticationMethod.Read.All`)
- Guest users assigned privileged RBAC roles
- Service principals with Owner/Contributor permanently assigned at subscription scope
- App registrations with stale secrets or certificates (>90 days old, via `Get-AzADAppCredential`)
- Privilege escalation paths via dangerous RBAC role combinations (see table below)
- Custom roles with overly permissive actions (`*/write`, `*/delete`, `*`)

**Privilege escalation combos to flag:**

| Combo | Risk |
|-------|------|
| `User Access Administrator` + `Contributor` | Can grant self Owner rights |
| `Managed Identity Contributor` + `Contributor` | Can create managed identity, assign to controlled resource |
| `Role Based Access Control Administrator` (any scope) | Can modify own role assignments |
| `Owner` assigned to a service principal with no owner tracking | Unmonitored privileged SP |
| Any role with `Microsoft.Authorization/*/write` | Can modify RBAC assignments |

---

### 2. `storage_auditor.ps1` — Storage Accounts
**Azure equivalent of:** `s3-auditor`
**Modules:** `Az.Accounts`, `Az.Storage`

**Audits:**
- Public blob access enabled on containers (`AllowBlobPublicAccess = true`)
- Customer-managed keys (CMK) not configured — all Azure storage is encrypted by default; flags accounts using Microsoft-managed keys only (MEDIUM) and those without infrastructure double-encryption (LOW/informational)
- Access keys enabled (vs Entra-only authentication enforced via `allowSharedKeyAccess`)
- Soft delete disabled for blobs and/or containers
- Versioning disabled
- No diagnostic logging configured on storage accounts
- No SAS expiry policy enforced on the storage account

---

### 3. `activitylog_auditor.ps1` — Diagnostic Settings & Activity Logs
**Azure equivalent of:** `cloudtrail-auditor`
**Modules:** `Az.Accounts`, `Az.Monitor`

> **Note:** `Az.OperationalInsights` is not required. Destination workspace existence is verified by checking the diagnostic setting's `workspaceId` property. Log Analytics workspace retention is read via `Get-AzOperationalInsightsWorkspace` only if a workspace destination is found — treat as optional/best-effort.

**Audits:**
- Subscriptions with no Activity Log diagnostic setting configured
- Logs not forwarded to any destination (Log Analytics, Storage Account, or Event Hub)
- Log retention under 90 days:
  - Storage account destination: `retentionPolicy.days` on the diagnostic setting
  - Log Analytics destination: `retentionInDays` on the workspace (`Get-AzOperationalInsightsWorkspace`)
  - Event Hub: no native retention audit surface — flag as "retention unverifiable" (LOW)
- Key administrative categories not captured: `Administrative`, `Security`, `Policy`, `Alert`
- No Activity Log alerts configured for critical operations: role assignment changes, policy assignment changes, resource group deletions (`Get-AzActivityLogAlert`)

---

### 4. `nsg_auditor.ps1` — Network Security Groups
**Azure equivalent of:** `sg-auditor`
**Modules:** `Az.Accounts`, `Az.Network`

**Audits:**
- Inbound rules open to `0.0.0.0/0` or `::/0`
- Dangerous ports exposed to the internet (source = `*`, `0.0.0.0/0`, or `Internet` tag):
  SSH (22), Telnet (23), FTP (21), RDP (3389), WinRM (5985/5986), SMB (445),
  SQL Server (1433), MySQL (3306), PostgreSQL (5432), MongoDB (27017),
  Redis (6379), Elasticsearch (9200/9300), Docker (2375), etcd (2379),
  LDAP/LDAPS (389/636), VNC (5900), NFS (2049)
- NSGs not associated with any subnet or NIC (orphaned)
- NSGs where no custom deny rules exist for any dangerous port above (relies purely on built-in `DenyAllInbound` at priority 65500 — weak posture, flagged MEDIUM)

> **Note:** Azure NSGs have no "allow all" default rule — the built-in default is `DenyAllInbound` (65500). This script does NOT flag that rule. The weak-posture check above flags NSGs that have no explicit denies for high-risk ports, relying entirely on the catch-all default.

---

### 5. `subscription_auditor.ps1` — Subscription & Tenant Posture
**Azure equivalent of:** `root-auditor`
**Modules:** `Az.Accounts`, `Az.Resources`, `Az.Security`, `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.Governance`

> **Note:** Global Administrator MFA status and PIM usage require Microsoft Graph. This script requires both Az and Graph modules. The script checks for both on startup.

**Audits:**
- Global Administrator count (via `Get-MgRoleManagementDirectoryRoleAssignment` filtered by role definition ID `62e90394-69f5-4237-9190-012177145e10` — requires `RoleManagement.Read.Directory`)
- Global Administrator MFA status (`Get-MgUserAuthenticationMethod` — requires Graph, `UserAuthenticationMethod.Read.All`)
- Permanent Owner/Contributor assignments on human user accounts at subscription scope (PIM eligible assignments excluded — detects PIM absence indirectly via `Get-MgRoleManagementDirectoryRoleEligibilitySchedule`)
- Microsoft Defender for Cloud not enabled at Standard/P2 tier (`Get-AzSecurityPricing`)
- No resource locks on resource groups (`Get-AzResourceLock`)
- No budget alerts configured on subscriptions (`Get-AzConsumptionBudget`)

---

## CLI Interface

All scripts share the same parameter interface:

```powershell
param(
    [string]$Output,           # Output file prefix (default: <scriptname>_report)
    [string]$Format = "all",   # json | csv | html | all | stdout
    [switch]$AllSubscriptions  # Scan all accessible subscriptions (default: current context only)
)
```

---

## Authentication

Scripts use the active Az PowerShell context (`Connect-AzAccount` already run by the user). No credential parameters — matches Azure CloudShell usage pattern.

Scripts that require Microsoft Graph (`entra_auditor.ps1`, `subscription_auditor.ps1`) also call `Connect-MgGraph` with the required scopes if not already connected:
- `entra_auditor.ps1`: `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`
- `subscription_auditor.ps1`: `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`

On startup, each script:
1. Checks required modules are installed and prints a clear error if not
2. Verifies an active Az context exists
3. Enumerates target subscriptions (current or all, based on `-AllSubscriptions`)

---

## Output Formats

| Format | Description |
|--------|-------------|
| `json` | Machine-readable structured findings |
| `csv`  | Flat rows, spreadsheet-compatible |
| `html` | Human-readable report with summary cards and colour-coded findings table |
| `all`  | Generates all three simultaneously |
| `stdout` | JSON to console |

**Terminal summary:** On completion, each script prints a structured summary block to the terminal (matching the `╔══╗` style of the AWS scripts), regardless of `-Format`. Includes: total resources scanned, findings by severity, and top 3 critical findings.

**HTML report includes:**
- Header with script name, tenant ID, timestamp
- Summary cards: total findings, counts by severity, key metrics
- Findings table: resource name, finding, severity badge, recommendation
- Colour coding: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green

**File permissions:** Output files created with restricted permissions (owner read/write only).

---

## Severity Scoring

Numeric 1–10 scale, consistent with existing AWS scripts:

| Label    | Score | Colour |
|----------|-------|--------|
| CRITICAL | 8–10  | Red    |
| HIGH     | 6–7   | Orange |
| MEDIUM   | 3–5   | Yellow |
| LOW      | 1–2   | Green  |

---

## Non-Goals

- No write operations — all scripts are strictly read-only (`Get-*`, `Read-*` cmdlets only)
- No shared module — each script is fully self-contained
- No authentication handling beyond verifying active context — assumes `Connect-AzAccount` (and `Connect-MgGraph` where needed) has been run
- No Bicep/ARM analysis — infrastructure-as-code scanning is out of scope

---

## Dependencies

| Module | Used by | Purpose |
|--------|---------|---------|
| `Az.Accounts` | All | Authentication and subscription enumeration |
| `Az.Resources` | entra, subscription | RBAC, resource groups, resource locks, app registrations |
| `Az.Network` | nsg | NSG rules and associations |
| `Az.Storage` | storage | Storage account and container configuration |
| `Az.Monitor` | activitylog | Diagnostic settings and activity log alerts |
| `Az.Security` | subscription | Defender for Cloud pricing/status |
| `Microsoft.Graph.Authentication` | entra, subscription | Graph API authentication |
| `Microsoft.Graph.Users` | entra | MFA registration state per user |
| `Microsoft.Graph.Identity.Governance` | subscription | PIM eligible role assignments |
