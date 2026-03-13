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
**Az modules:** `Az.Accounts`, `Az.Resources`

**Audits:**
- Users without MFA enabled
- Guest users assigned privileged roles
- Service principals with Owner/Contributor at subscription scope
- App registrations with stale secrets or certificates (>90 days old)
- Privilege escalation paths via dangerous RBAC role combinations
- Custom roles with overly permissive actions (`*/write`, `*/delete`, `*`)

---

### 2. `storage_auditor.ps1` — Storage Accounts
**Azure equivalent of:** `s3-auditor`
**Az modules:** `Az.Accounts`, `Az.Storage`

**Audits:**
- Public blob access enabled on containers
- Storage accounts not using encryption or using Microsoft-managed keys only
- Access keys enabled (vs Entra-only authentication)
- Soft delete and versioning disabled
- No diagnostic logging configured on storage accounts
- Shared Access Signatures with no expiry policy enforced

---

### 3. `activitylog_auditor.ps1` — Diagnostic Settings & Activity Logs
**Azure equivalent of:** `cloudtrail-auditor`
**Az modules:** `Az.Accounts`, `Az.Monitor`, `Az.OperationalInsights`

**Audits:**
- Subscriptions with no Activity Log diagnostic setting configured
- Logs not being forwarded to Log Analytics workspace, Storage Account, or Event Hub
- Log retention period under 90 days
- Key administrative operation categories not captured (Write, Delete, Action)
- No alerts configured for critical operations (role assignments, policy changes, resource deletions)

---

### 4. `nsg_auditor.ps1` — Network Security Groups
**Azure equivalent of:** `sg-auditor`
**Az modules:** `Az.Accounts`, `Az.Network`

**Audits:**
- Inbound rules open to `0.0.0.0/0` or `::/0`
- Dangerous ports exposed to the internet: SSH (22), RDP (3389), SQL Server (1433), MySQL (3306), MongoDB (27017), Redis (6379), Elasticsearch (9200/9300), PostgreSQL (5432), WinRM (5985/5986)
- NSGs not associated with any subnet or NIC (orphaned)
- Default "allow all" rules not overridden by higher-priority deny rules

---

### 5. `subscription_auditor.ps1` — Subscription & Tenant Posture
**Azure equivalent of:** `root-auditor`
**Az modules:** `Az.Accounts`, `Az.Resources`, `Az.Security`

**Audits:**
- Global Administrator count and MFA status
- Subscription Owners (flags human users; ideally should be service principals or PIM-managed)
- Absence of Privileged Identity Management (PIM) usage
- Microsoft Defender for Cloud not enabled at Standard tier
- No resource locks on critical/production resources
- No budget alerts configured on subscriptions

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

On startup, each script:
1. Checks required Az modules are installed and prints a clear error if not
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
- No authentication handling — assumes `Connect-AzAccount` has been run
- No Bicep/ARM analysis — infrastructure-as-code scanning is out of scope

---

## Dependencies

| Module | Purpose |
|--------|---------|
| `Az.Accounts` | Authentication and subscription enumeration |
| `Az.Resources` | RBAC, resource groups, resource locks |
| `Az.Network` | NSG rules and associations |
| `Az.Storage` | Storage account and container configuration |
| `Az.Monitor` | Diagnostic settings and activity log alerts |
| `Az.Security` | Defender for Cloud status |
| `Az.OperationalInsights` | Log Analytics workspace queries |
