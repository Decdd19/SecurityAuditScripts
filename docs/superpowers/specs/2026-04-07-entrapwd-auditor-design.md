# Entra Password Policy Auditor — Design Spec

**Date:** 2026-04-07
**Scope:** New Azure auditor — tenant-level password policy checks
**Location:** `Azure/entrapwd-auditor/`

---

## Goal

A standalone PowerShell script that checks Entra ID tenant-level password policy settings and flags the most common Irish SMB findings: password expiry still enabled, SSPR disabled, smart lockout too permissive, security defaults off, and no custom banned password list.

Per-user checks (stale passwords, last password change) are intentionally out of scope — those belong in `entra_auditor.ps1` which already iterates users.

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Output` | `string` | `entrapwd_report` | Output file prefix |
| `-Format` | `string` | `all` | `json \| csv \| html \| all \| stdout` |

No `-AllSubscriptions` — password policy is tenant-scoped, not per-subscription.

---

## Finding Types

| ID | FindingType | Severity | Score | CIS Control |
|----|-------------|----------|-------|-------------|
| EP-01 | `PasswordExpiryEnabled` | MEDIUM | 4 | CIS 5.2 |
| EP-02 | `SsprDisabled` | HIGH | 6 | CIS 5.2 |
| EP-03 | `SmartLockoutPermissive` | MEDIUM | 4 | CIS 5.2 |
| EP-04 | `SecurityDefaultsDisabled` | HIGH | 7 | CIS 5.2 |
| EP-05 | `CustomBannedPasswordsAbsent` | LOW | 2 | CIS 5.2 |

**EP-01 rationale:** Microsoft and NIST SP 800-63B recommend removing password expiry when MFA is enforced. Flag any domain with `PasswordValidityPeriodInDays` set to a non-null, non-zero value.

**EP-03 thresholds:** Flag if `lockoutThreshold > 10` (too many attempts before lockout) or `lockoutDurationInSeconds < 60` (unlocks too quickly).

---

## Architecture

### Stub block

If Graph cmdlets are not available (Pester environment), define no-op stubs. Pester Mocks override per-test:

```powershell
if (-not (Get-Command -Name 'Get-MgDomain' -ErrorAction SilentlyContinue)) {
    function Get-MgDomain { @() }
    function Get-MgBetaDirectorySetting { @() }
    function Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy { $null }
    function Invoke-MgGraphRequest { param($Uri, $Method) @{} }
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext { $null }
}
```

### Required modules

`Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Beta.Identity.DirectoryManagement`

### Audit functions

#### `Get-PasswordExpiryFindings → [PSCustomObject[]]`

Calls `Get-MgDomain`. For each domain where `PasswordValidityPeriodInDays` is not null and not 0, emits an EP-01 finding. Domain name included in finding for actionability.

#### `Get-SsprFindings → [PSCustomObject[]]`

Calls `Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'`. Flags if `value[0].defaultUserRolePermissions.allowedToUseSSPR -eq $false`.

#### `Get-SmartLockoutFindings → [PSCustomObject[]]`

Calls `Get-MgBetaDirectorySetting`. Finds the entry with `DisplayName -eq 'Password Rule Settings'`. Reads `lockoutThreshold` and `lockoutDurationInSeconds` from the `Values` array. Flags if threshold > 10 or duration < 60. If settings not found (not yet configured), no finding — absence means defaults apply (threshold=10, duration=60s, which are acceptable).

#### `Get-SecurityDefaultsFindings → [PSCustomObject[]]`

Calls `Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy`. Flags if `IsEnabled -eq $false`.

#### `Get-CustomBannedPasswordFindings → [PSCustomObject[]]`

Uses same directory settings as `Get-SmartLockoutFindings`. Flags if `enableBannedPasswordCheck -eq $false` or `banPasswordList` is null/empty.

### Finding shape

```powershell
[PSCustomObject]@{
    FindingType    = 'PasswordExpiryEnabled'
    Domain         = 'contoso.com'          # domain name or 'tenant' for policy-level
    Detail         = 'contoso.com: 90 days' # human-readable detail
    Severity       = 'MEDIUM'
    CisControl     = 'CIS 5.2'
    Score          = 4
    Recommendation = '...'
}
```

### Output layer

`ConvertTo-EntrapwdJsonReport` / `ConvertTo-EntrapwdCsvReport` / `ConvertTo-EntrapwdHtmlReport`

JSON schema:

```json
{
  "generated_at": "...",
  "tenant_id": "...",
  "summary": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 1 },
  "findings": [ ... ]
}
```

---

## Testing Strategy (~15 Pester tests)

### `Describe 'Get-PasswordExpiryFindings'`
- Domain with `PasswordValidityPeriodInDays = 90` → EP-01 MEDIUM finding
- Domain with `PasswordValidityPeriodInDays = $null` → no finding
- Multiple domains, only expiry-enabled ones flagged

### `Describe 'Get-SsprFindings'`
- `allowedToUseSSPR = $false` → EP-02 HIGH finding
- `allowedToUseSSPR = $true` → no finding

### `Describe 'Get-SmartLockoutFindings'`
- `lockoutThreshold = 15` → EP-03 MEDIUM finding
- `lockoutDurationInSeconds = 30` → EP-03 MEDIUM finding
- `lockoutThreshold = 5, lockoutDurationInSeconds = 120` → no finding
- Settings not found → no finding (graceful)

### `Describe 'Get-SecurityDefaultsFindings'`
- `IsEnabled = $false` → EP-04 HIGH finding
- `IsEnabled = $true` → no finding

### `Describe 'Get-CustomBannedPasswordFindings'`
- `enableBannedPasswordCheckOnPremises = $false` → EP-05 LOW finding
- `banPasswordList` empty → EP-05 LOW finding
- Both configured → no finding

### `Describe 'ConvertTo-EntrapwdJsonReport'`
- Emits `generated_at`, `tenant_id`, `summary`, `findings` fields
- Summary counts match findings array

---

## Integration

- Add `entrapwd_report.json` to `KNOWN_PATTERNS` and `AZURE_WINDOWS_PATTERNS` in `tools/exec_summary.py`
- Add `"entrapwd": "Entra Password Policy"` to `PILLAR_LABELS`
- Add `"entrapwd": "Azure/entrapwd-auditor/entrapwd_auditor.ps1"` to `AZURE_PS1` in `audit.py`
- Add entry to `$AzureAuditors` in `Run-Audit.ps1`
- Update root `README.md`: directory tree + auditor table

---

## Out of Scope

- Per-user last password change date (belongs in `entra_auditor.ps1`)
- Conditional Access policy enumeration
- Password writeback configuration
- On-premises AD password sync health
