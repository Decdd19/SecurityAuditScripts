# Entra Password Policy Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone PowerShell auditor that checks Entra ID tenant-level password policy settings and produces JSON/CSV/HTML findings reports.

**Architecture:** Five focused audit functions (one per finding type) backed by Microsoft Graph API calls. A stub block allows Pester 5 to mock all external cmdlets. Output layer follows the same JSON schema used by all other auditors in the repo. Wired into `Run-Audit.ps1`, `exec_summary.py`, and `audit.py`.

**Tech Stack:** PowerShell 7+, Pester 5, Microsoft.Graph.Beta.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `Azure/entrapwd-auditor/entrapwd_auditor.ps1` | Create | All audit functions, output layer, main block |
| `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1` | Create | ~15 Pester tests for all functions |
| `Azure/entrapwd-auditor/README.md` | Create | Usage, requirements, findings table |
| `tools/exec_summary.py` | Modify | Add `entrapwd_report.json` to KNOWN_PATTERNS, AZURE_WINDOWS_PATTERNS, PILLAR_LABELS |
| `audit.py` | Modify | Add `"entrapwd"` entry to WINDOWS_PS1 |
| `Run-Audit.ps1` | Modify | Add entry to `$AzureAuditors` |
| `tests/test_audit.py` | Modify | Update WINDOWS_PS1 count (17 → add entrapwd) |

---

## Task 1: Scaffold — directory, test file, script stub

**Files:**
- Create: `Azure/entrapwd-auditor/entrapwd_auditor.ps1`
- Create: `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p /path/to/SecurityAuditScripts/Azure/entrapwd-auditor/tests
```

- [ ] **Step 2: Create the test file with BeforeAll stub block**

Create `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1`:

```powershell
# Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1
BeforeAll {
    # Stub all Graph cmdlets so the script loads without real modules installed.
    # Individual It blocks override with Mock as needed.
    function Get-MgDomain { @() }
    function Get-MgBetaDirectorySetting { @() }
    function Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy { $null }
    function Invoke-MgGraphRequest { param($Uri, $Method) @{} }
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext { $null }

    . "$PSScriptRoot/../entrapwd_auditor.ps1"
}
```

- [ ] **Step 3: Create the script with stub block and severity helpers only**

Create `Azure/entrapwd-auditor/entrapwd_auditor.ps1`:

```powershell
<#
.SYNOPSIS
    Audits Entra ID tenant-level password policy settings.
.DESCRIPTION
    Read-only audit of password expiry, SSPR, smart lockout, security defaults,
    and custom banned password configuration. No -AllSubscriptions needed —
    password policy is tenant-scoped, not per-subscription.
.PARAMETER Output
    Output file prefix (default: entrapwd_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.EXAMPLE
    .\entrapwd_auditor.ps1
    .\entrapwd_auditor.ps1 -Format json
#>
param(
    [string]$Output = 'entrapwd_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all'
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Graph stubs — overridden by real modules at runtime; Pester Mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-MgDomain' -ErrorAction SilentlyContinue)) {
    function Get-MgDomain { @() }
    function Get-MgBetaDirectorySetting { @() }
    function Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy { $null }
    function Invoke-MgGraphRequest { param($Uri, $Method) @{} }
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext { $null }
}

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
function Get-SeverityLabel {
    param([int]$Score)
    if ($Score -ge 8) { return 'CRITICAL' }
    if ($Score -ge 6) { return 'HIGH' }
    if ($Score -ge 3) { return 'MEDIUM' }
    return 'LOW'
}

function Get-SeverityColour {
    param([string]$Severity)
    switch ($Severity) {
        'CRITICAL' { return '#dc3545' }
        'HIGH'     { return '#fd7e14' }
        'MEDIUM'   { return '#ffc107' }
        'LOW'      { return '#28a745' }
        default    { return '#6c757d' }
    }
}

# ---------------------------------------------------------------------------
# File permission helper
# ---------------------------------------------------------------------------
function Set-RestrictedPermissions {
    param([string]$Path)
    if ($IsLinux -or $IsMacOS) {
        & chmod 600 $Path
    } else {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
    }
}

# ---------------------------------------------------------------------------
# Main — skipped when dot-sourced (Pester dot-sources with '.')
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host 'entrapwd_auditor.ps1 — stub, audit functions not yet implemented'
    exit 0
}
```

- [ ] **Step 4: Verify script loads without errors**

```bash
/path/to/pwsh -Command ". './Azure/entrapwd-auditor/entrapwd_auditor.ps1'; Write-Host 'OK'"
```

Expected: `OK` with no errors.

- [ ] **Step 5: Run Pester — confirm 0 tests (scaffold only)**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 0, Failed: 0`

- [ ] **Step 6: Commit scaffold**

```bash
git add Azure/entrapwd-auditor/
git commit -m "test(entrapwd): scaffold test file and script stub"
```

---

## Task 2: Get-PasswordExpiryFindings (EP-01)

**Files:**
- Modify: `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1` — add Describe block
- Modify: `Azure/entrapwd-auditor/entrapwd_auditor.ps1` — add function

- [ ] **Step 1: Add failing tests for Get-PasswordExpiryFindings**

Append to `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1` (before the final closing line):

```powershell
# ---------------------------------------------------------------------------
# Get-PasswordExpiryFindings
# ---------------------------------------------------------------------------
Describe 'Get-PasswordExpiryFindings' {
    It 'emits EP-01 MEDIUM finding when domain has expiry set' {
        Mock Get-MgDomain {
            @([PSCustomObject]@{ Id = 'contoso.com'; PasswordValidityPeriodInDays = 90 })
        }
        $findings = Get-PasswordExpiryFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'PasswordExpiryEnabled'
        $findings[0].Severity    | Should -Be 'MEDIUM'
        $findings[0].Domain      | Should -Be 'contoso.com'
        $findings[0].Score       | Should -Be 4
    }

    It 'emits no finding when PasswordValidityPeriodInDays is null' {
        Mock Get-MgDomain {
            @([PSCustomObject]@{ Id = 'contoso.com'; PasswordValidityPeriodInDays = $null })
        }
        $findings = Get-PasswordExpiryFindings
        $findings | Should -BeNullOrEmpty
    }

    It 'only flags expiry-enabled domains when multiple domains exist' {
        Mock Get-MgDomain {
            @(
                [PSCustomObject]@{ Id = 'a.com'; PasswordValidityPeriodInDays = 90   }
                [PSCustomObject]@{ Id = 'b.com'; PasswordValidityPeriodInDays = $null }
            )
        }
        $findings = Get-PasswordExpiryFindings
        $findings | Should -HaveCount 1
        $findings[0].Domain | Should -Be 'a.com'
    }
}
```

- [ ] **Step 2: Run tests — confirm 3 failures**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 0, Failed: 3` — `Get-PasswordExpiryFindings` not found.

- [ ] **Step 3: Implement Get-PasswordExpiryFindings**

Add after the `Set-RestrictedPermissions` function in `entrapwd_auditor.ps1` (before the Main block):

```powershell
# ---------------------------------------------------------------------------
# Audit functions
# ---------------------------------------------------------------------------
function Get-PasswordExpiryFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $domains = @(Get-MgDomain)
    foreach ($domain in $domains) {
        if ($null -ne $domain.PasswordValidityPeriodInDays -and $domain.PasswordValidityPeriodInDays -ne 0) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'PasswordExpiryEnabled'
                Domain         = $domain.Id
                Detail         = "$($domain.Id): $($domain.PasswordValidityPeriodInDays) days"
                Severity       = 'MEDIUM'
                CisControl     = 'CIS 5.2'
                Score          = 4
                Recommendation = "Disable password expiry: Azure Portal → Microsoft Entra ID → Password reset → Properties → Password expiry policy. NIST SP 800-63B recommends removing expiry when MFA is enforced — frequent rotation drives weak, predictable passwords."
            })
        }
    }
    return $findings
}
```

- [ ] **Step 4: Run tests — confirm 3 pass**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 3, Failed: 0`

- [ ] **Step 5: Commit**

```bash
git add Azure/entrapwd-auditor/
git commit -m "feat(entrapwd): add Get-PasswordExpiryFindings (EP-01)"
```

---

## Task 3: Get-SsprFindings (EP-02)

**Files:**
- Modify: `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1`
- Modify: `Azure/entrapwd-auditor/entrapwd_auditor.ps1`

- [ ] **Step 1: Add failing tests for Get-SsprFindings**

Append to the test file:

```powershell
# ---------------------------------------------------------------------------
# Get-SsprFindings
# ---------------------------------------------------------------------------
Describe 'Get-SsprFindings' {
    It 'emits EP-02 HIGH finding when SSPR is disabled' {
        Mock Invoke-MgGraphRequest {
            @{ defaultUserRolePermissions = @{ allowedToUseSSPR = $false } }
        }
        $findings = Get-SsprFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'SsprDisabled'
        $findings[0].Severity    | Should -Be 'HIGH'
        $findings[0].Score       | Should -Be 6
    }

    It 'emits no finding when SSPR is enabled' {
        Mock Invoke-MgGraphRequest {
            @{ defaultUserRolePermissions = @{ allowedToUseSSPR = $true } }
        }
        $findings = Get-SsprFindings
        $findings | Should -BeNullOrEmpty
    }
}
```

- [ ] **Step 2: Run tests — confirm 2 failures**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 3, Failed: 2`

- [ ] **Step 3: Implement Get-SsprFindings**

Add after `Get-PasswordExpiryFindings`:

```powershell
function Get-SsprFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $policy = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -Method GET
        $allowedToUseSSPR = $policy.defaultUserRolePermissions.allowedToUseSSPR
        if ($allowedToUseSSPR -eq $false) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'SsprDisabled'
                Domain         = 'tenant'
                Detail         = 'Self-service password reset is disabled for all users'
                Severity       = 'HIGH'
                CisControl     = 'CIS 5.2'
                Score          = 6
                Recommendation = "Enable SSPR: Azure Portal → Microsoft Entra ID → Password reset → Properties → Self-service password reset enabled → All. Configure at least 2 authentication methods (mobile app, email, phone)."
            })
        }
    } catch {
        Write-Warning "Could not check SSPR policy: $_"
    }
    return $findings
}
```

- [ ] **Step 4: Run tests — confirm 5 pass**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 5, Failed: 0`

- [ ] **Step 5: Commit**

```bash
git add Azure/entrapwd-auditor/
git commit -m "feat(entrapwd): add Get-SsprFindings (EP-02)"
```

---

## Task 4: Get-SmartLockoutFindings (EP-03)

**Files:**
- Modify: `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1`
- Modify: `Azure/entrapwd-auditor/entrapwd_auditor.ps1`

- [ ] **Step 1: Add failing tests for Get-SmartLockoutFindings**

Append to the test file:

```powershell
# ---------------------------------------------------------------------------
# Get-SmartLockoutFindings
# ---------------------------------------------------------------------------
Describe 'Get-SmartLockoutFindings' {
    It 'emits EP-03 MEDIUM finding when lockoutThreshold exceeds 10' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'lockoutThreshold';         Value = '15' }
                    [PSCustomObject]@{ Name = 'lockoutDurationInSeconds'; Value = '60' }
                )
            })
        }
        $findings = Get-SmartLockoutFindings
        $f = $findings | Where-Object { $_.Detail -match 'threshold' }
        $f              | Should -Not -BeNullOrEmpty
        $f.FindingType  | Should -Be 'SmartLockoutPermissive'
        $f.Severity     | Should -Be 'MEDIUM'
    }

    It 'emits EP-03 MEDIUM finding when lockoutDurationInSeconds is under 60' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'lockoutThreshold';         Value = '10' }
                    [PSCustomObject]@{ Name = 'lockoutDurationInSeconds'; Value = '30' }
                )
            })
        }
        $findings = Get-SmartLockoutFindings
        $f = $findings | Where-Object { $_.Detail -match 'duration' }
        $f             | Should -Not -BeNullOrEmpty
        $f.FindingType | Should -Be 'SmartLockoutPermissive'
    }

    It 'emits no finding when threshold and duration are within bounds' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'lockoutThreshold';         Value = '5'   }
                    [PSCustomObject]@{ Name = 'lockoutDurationInSeconds'; Value = '120' }
                )
            })
        }
        $findings = Get-SmartLockoutFindings
        $findings | Should -BeNullOrEmpty
    }

    It 'emits no finding when password rule settings are not configured' {
        Mock Get-MgBetaDirectorySetting { @() }
        $findings = Get-SmartLockoutFindings
        $findings | Should -BeNullOrEmpty
    }
}
```

- [ ] **Step 2: Run tests — confirm 4 failures**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 5, Failed: 4`

- [ ] **Step 3: Implement Get-SmartLockoutFindings**

Add after `Get-SsprFindings`:

```powershell
function Get-SmartLockoutFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $settings   = @(Get-MgBetaDirectorySetting)
        $pwdSettings = $settings | Where-Object { $_.DisplayName -eq 'Password Rule Settings' }
        if (-not $pwdSettings) { return $findings }

        $values = @{}
        foreach ($v in $pwdSettings.Values) { $values[$v.Name] = $v.Value }

        $threshold = [int]($values['lockoutThreshold']         ?? 10)
        $duration  = [int]($values['lockoutDurationInSeconds'] ?? 60)

        if ($threshold -gt 10) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'SmartLockoutPermissive'
                Domain         = 'tenant'
                Detail         = "Lockout threshold: $threshold (recommended: ≤10)"
                Severity       = 'MEDIUM'
                CisControl     = 'CIS 5.2'
                Score          = 4
                Recommendation = "Reduce smart lockout threshold: Azure Portal → Microsoft Entra ID → Security → Authentication methods → Password protection → Lockout threshold → set to 10 or lower."
            })
        }
        if ($duration -lt 60) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'SmartLockoutPermissive'
                Domain         = 'tenant'
                Detail         = "Lockout duration: ${duration}s (recommended: ≥60s)"
                Severity       = 'MEDIUM'
                CisControl     = 'CIS 5.2'
                Score          = 4
                Recommendation = "Increase smart lockout duration: Azure Portal → Microsoft Entra ID → Security → Authentication methods → Password protection → Lockout duration in seconds → set to 60 or higher."
            })
        }
    } catch {
        Write-Warning "Could not check smart lockout settings: $_"
    }
    return $findings
}
```

- [ ] **Step 4: Run tests — confirm 9 pass**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 9, Failed: 0`

- [ ] **Step 5: Commit**

```bash
git add Azure/entrapwd-auditor/
git commit -m "feat(entrapwd): add Get-SmartLockoutFindings (EP-03)"
```

---

## Task 5: Get-SecurityDefaultsFindings + Get-CustomBannedPasswordFindings (EP-04, EP-05)

**Files:**
- Modify: `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1`
- Modify: `Azure/entrapwd-auditor/entrapwd_auditor.ps1`

- [ ] **Step 1: Add failing tests for both functions**

Append to the test file:

```powershell
# ---------------------------------------------------------------------------
# Get-SecurityDefaultsFindings
# ---------------------------------------------------------------------------
Describe 'Get-SecurityDefaultsFindings' {
    It 'emits EP-04 HIGH finding when security defaults are disabled' {
        Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
            [PSCustomObject]@{ IsEnabled = $false }
        }
        $findings = Get-SecurityDefaultsFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'SecurityDefaultsDisabled'
        $findings[0].Severity    | Should -Be 'HIGH'
        $findings[0].Score       | Should -Be 7
    }

    It 'emits no finding when security defaults are enabled' {
        Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
            [PSCustomObject]@{ IsEnabled = $true }
        }
        $findings = Get-SecurityDefaultsFindings
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-CustomBannedPasswordFindings
# ---------------------------------------------------------------------------
Describe 'Get-CustomBannedPasswordFindings' {
    It 'emits EP-05 LOW finding when banned password check is disabled' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'enableBannedPasswordCheckOnPremises'; Value = 'false'   }
                    [PSCustomObject]@{ Name = 'banPasswordList';                     Value = 'contoso' }
                )
            })
        }
        $findings = Get-CustomBannedPasswordFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'CustomBannedPasswordsAbsent'
        $findings[0].Severity    | Should -Be 'LOW'
        $findings[0].Score       | Should -Be 2
    }

    It 'emits EP-05 LOW finding when banned password list is empty' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'enableBannedPasswordCheckOnPremises'; Value = 'true' }
                    [PSCustomObject]@{ Name = 'banPasswordList';                     Value = ''     }
                )
            })
        }
        $findings = Get-CustomBannedPasswordFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'CustomBannedPasswordsAbsent'
    }

    It 'emits no finding when banned password check is enabled with a list' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'enableBannedPasswordCheckOnPremises'; Value = 'true'          }
                    [PSCustomObject]@{ Name = 'banPasswordList';                     Value = 'contoso,acme'  }
                )
            })
        }
        $findings = Get-CustomBannedPasswordFindings
        $findings | Should -BeNullOrEmpty
    }
}
```

- [ ] **Step 2: Run tests — confirm 5 failures**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 9, Failed: 5`

- [ ] **Step 3: Implement Get-SecurityDefaultsFindings**

Add after `Get-SmartLockoutFindings`:

```powershell
function Get-SecurityDefaultsFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        if ($policy -and $policy.IsEnabled -eq $false) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'SecurityDefaultsDisabled'
                Domain         = 'tenant'
                Detail         = 'Security defaults are disabled'
                Severity       = 'HIGH'
                CisControl     = 'CIS 5.2'
                Score          = 7
                Recommendation = "Enable security defaults or replace with Conditional Access: Azure Portal → Microsoft Entra ID → Properties → Manage security defaults → Enable. If using Conditional Access, ensure equivalent policies cover MFA for all users, blocking legacy auth, and protecting privileged access."
            })
        }
    } catch {
        Write-Warning "Could not check security defaults: $_"
    }
    return $findings
}
```

- [ ] **Step 4: Implement Get-CustomBannedPasswordFindings**

Add after `Get-SecurityDefaultsFindings`:

```powershell
function Get-CustomBannedPasswordFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $settings    = @(Get-MgBetaDirectorySetting)
        $pwdSettings = $settings | Where-Object { $_.DisplayName -eq 'Password Rule Settings' }

        if (-not $pwdSettings) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'CustomBannedPasswordsAbsent'
                Domain         = 'tenant'
                Detail         = 'Password protection settings not configured'
                Severity       = 'LOW'
                CisControl     = 'CIS 5.2'
                Score          = 2
                Recommendation = "Configure custom banned passwords: Azure Portal → Microsoft Entra ID → Security → Authentication methods → Password protection → Enable custom banned passwords → add organisation-specific terms (company name, product names, locations)."
            })
            return $findings
        }

        $values = @{}
        foreach ($v in $pwdSettings.Values) { $values[$v.Name] = $v.Value }

        $checkEnabled = $values['enableBannedPasswordCheckOnPremises']
        $banList      = $values['banPasswordList']

        if ($checkEnabled -eq 'false' -or [string]::IsNullOrWhiteSpace($banList)) {
            $detail = if ($checkEnabled -eq 'false') {
                'Custom banned password check disabled'
            } else {
                'Custom banned password list is empty'
            }
            $findings.Add([PSCustomObject]@{
                FindingType    = 'CustomBannedPasswordsAbsent'
                Domain         = 'tenant'
                Detail         = $detail
                Severity       = 'LOW'
                CisControl     = 'CIS 5.2'
                Score          = 2
                Recommendation = "Configure custom banned passwords: Azure Portal → Microsoft Entra ID → Security → Authentication methods → Password protection → Enable custom banned passwords → add organisation-specific terms (company name, product names, locations)."
            })
        }
    } catch {
        Write-Warning "Could not check custom banned password settings: $_"
    }
    return $findings
}
```

- [ ] **Step 5: Run tests — confirm 14 pass**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 14, Failed: 0`

- [ ] **Step 6: Commit**

```bash
git add Azure/entrapwd-auditor/
git commit -m "feat(entrapwd): add Get-SecurityDefaultsFindings (EP-04) and Get-CustomBannedPasswordFindings (EP-05)"
```

---

## Task 6: Output layer + ConvertTo-EntrapwdJsonReport tests + main block

**Files:**
- Modify: `Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1`
- Modify: `Azure/entrapwd-auditor/entrapwd_auditor.ps1`

- [ ] **Step 1: Add failing tests for ConvertTo-EntrapwdJsonReport**

Append to the test file:

```powershell
# ---------------------------------------------------------------------------
# ConvertTo-EntrapwdJsonReport
# ---------------------------------------------------------------------------
Describe 'ConvertTo-EntrapwdJsonReport' {
    It 'emits generated_at, tenant_id, summary, and findings fields' {
        $f = [PSCustomObject]@{
            FindingType = 'SsprDisabled'; Domain = 'tenant'
            Detail = 'SSPR disabled'; Severity = 'HIGH'
            CisControl = 'CIS 5.2'; Score = 6; Recommendation = 'Enable SSPR'
        }
        $report = ConvertTo-EntrapwdJsonReport -Findings @($f) -TenantId 'test-tenant-id'
        $report.generated_at | Should -Not -BeNullOrEmpty
        $report.tenant_id    | Should -Be 'test-tenant-id'
        $report.summary      | Should -Not -BeNullOrEmpty
        $report.findings     | Should -HaveCount 1
    }

    It 'summary counts match findings array' {
        $findings = @(
            [PSCustomObject]@{ FindingType='SecurityDefaultsDisabled'; Domain='tenant'; Detail='x'; Severity='HIGH';   CisControl='CIS 5.2'; Score=7; Recommendation='x' }
            [PSCustomObject]@{ FindingType='SsprDisabled';             Domain='tenant'; Detail='x'; Severity='HIGH';   CisControl='CIS 5.2'; Score=6; Recommendation='x' }
            [PSCustomObject]@{ FindingType='PasswordExpiryEnabled';    Domain='a.com';  Detail='x'; Severity='MEDIUM'; CisControl='CIS 5.2'; Score=4; Recommendation='x' }
        )
        $report = ConvertTo-EntrapwdJsonReport -Findings $findings -TenantId 'x'
        $report.summary.CRITICAL | Should -Be 0
        $report.summary.HIGH     | Should -Be 2
        $report.summary.MEDIUM   | Should -Be 1
        $report.summary.LOW      | Should -Be 0
    }
}
```

- [ ] **Step 2: Run tests — confirm 2 failures**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 14, Failed: 2`

- [ ] **Step 3: Replace the Main stub in entrapwd_auditor.ps1 with the full output layer + main block**

Replace everything from `# ---------------------------------------------------------------------------` (the Main block comment) to the end of the file with:

```powershell
# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function ConvertTo-EntrapwdJsonReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [string]$TenantId = ''
    )
    $summary = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($summary.ContainsKey($f.Severity)) { $summary[$f.Severity]++ } }
    return [PSCustomObject]@{
        generated_at = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
        tenant_id    = $TenantId
        summary      = $summary
        findings     = $Findings
    }
}

function ConvertTo-EntrapwdCsvReport {
    param([Parameter(Mandatory)][array]$Findings)
    $Findings | Select-Object `
        @{N='Domain';       E={$_.Domain}},
        @{N='FindingType';  E={$_.FindingType}},
        @{N='Detail';       E={$_.Detail}},
        Severity, Score, CisControl, Recommendation |
        ConvertTo-Csv -NoTypeInformation
}

function ConvertTo-EntrapwdHtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [string]$TenantId  = '',
        [string]$ScannedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $Findings) {
        $colour = Get-SeverityColour $f.Severity
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Domain))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Detail))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td><div class='rem-text'>&#8627; $([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</div></td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Entra Password Policy Audit Report</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}
  .header h1{margin:0;font-size:1.8em}
  .header p{margin:5px 0 0;opacity:0.8}
  .content{padding:24px 32px}
  .summary{display:flex;gap:16px;margin-bottom:24px}
  .card{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 2px 8px rgba(0,0,0,0.08);min-width:120px;text-align:center}
  .card .num{font-size:2em;font-weight:bold}.card .lbl{color:#666;font-size:.85em}
  table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:10px;text-align:left}
  td{padding:8px 10px;border-bottom:1px solid #dee2e6}tr:hover{background:#f1f3f5}
  .rem-text{display:block;font-size:0.78em;color:#555;padding-left:12px;font-style:italic;margin-top:4px}
</style></head><body>
<div class='header'>
<h1>Entra Password Policy Audit Report</h1>
<p>Tenant: $TenantId &nbsp;|&nbsp; Generated: $ScannedAt</p>
</div>
<div class='content'>
<div class='summary'>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
</div>
<table><thead><tr>
  <th>Finding</th><th>Domain</th><th>Detail</th><th>Severity</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table>
</div></body></html>
"@
}

function Write-TerminalSummary {
    param([array]$Findings, [string]$TenantId)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║     ENTRA PASSWORD POLICY AUDIT COMPLETE         ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Tenant  : $($TenantId.PadRight(38))║" -ForegroundColor Cyan
    Write-Host "║  Total findings: $($Findings.Count.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Main — skipped when dot-sourced (Pester dot-sources with '.')
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Beta.Identity.DirectoryManagement'
    )
    foreach ($mod in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Error "Required module '$mod' is not installed. Run: Install-Module $mod"
            exit 1
        }
    }

    try { $null = Get-MgContext -ErrorAction Stop } catch {
        Connect-MgGraph -Scopes @(
            'Policy.Read.All',
            'Directory.Read.All'
        ) -NoWelcome
    }

    $tenantId    = (Get-MgContext).TenantId ?? 'unknown'
    $timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host "Scanning tenant: $tenantId" -ForegroundColor Gray

    foreach ($fn in @(
        { Get-PasswordExpiryFindings },
        { Get-SsprFindings },
        { Get-SmartLockoutFindings },
        { Get-SecurityDefaultsFindings },
        { Get-CustomBannedPasswordFindings }
    )) {
        $result = & $fn
        if ($result) { $allFindings.AddRange([PSCustomObject[]]@($result)) }
    }

    $reportData = ConvertTo-EntrapwdJsonReport -Findings $allFindings -TenantId $tenantId

    switch ($Format) {
        'json'   {
            $reportData | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
            Set-RestrictedPermissions "$Output.json"
            Write-Host "JSON report: $Output.json"
        }
        'csv'    {
            ConvertTo-EntrapwdCsvReport $allFindings | Out-File "$Output.csv" -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            Write-Host "CSV report: $Output.csv"
        }
        'html'   {
            ConvertTo-EntrapwdHtmlReport -Findings $allFindings -TenantId $tenantId -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "HTML report: $Output.html"
        }
        'all'    {
            $reportData | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
            Set-RestrictedPermissions "$Output.json"
            ConvertTo-EntrapwdCsvReport $allFindings | Out-File "$Output.csv" -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            ConvertTo-EntrapwdHtmlReport -Findings $allFindings -TenantId $tenantId -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $allFindings -TenantId $tenantId
}
```

- [ ] **Step 4: Run tests — confirm 16 pass**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 16, Failed: 0`

- [ ] **Step 5: Commit**

```bash
git add Azure/entrapwd-auditor/
git commit -m "feat(entrapwd): add output layer, HTML/CSV/JSON reports, main block"
```

---

## Task 7: README + wire into exec_summary.py, audit.py, Run-Audit.ps1

**Files:**
- Create: `Azure/entrapwd-auditor/README.md`
- Modify: `tools/exec_summary.py` (lines 44, 95, 133)
- Modify: `audit.py` (line 188)
- Modify: `Run-Audit.ps1` (line 128, after `entra` entry)
- Modify: `tests/test_audit.py` (WINDOWS_PS1 count)

- [ ] **Step 1: Create README.md**

Create `Azure/entrapwd-auditor/README.md`:

```markdown
# Entra Password Policy Auditor

Audits Entra ID tenant-level password policy settings.

## Requirements

- PowerShell 7+
- `Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Beta.Identity.DirectoryManagement`
- `Connect-MgGraph -Scopes 'Policy.Read.All','Directory.Read.All'`

## Usage

```powershell
.\entrapwd_auditor.ps1
.\entrapwd_auditor.ps1 -Format json
.\entrapwd_auditor.ps1 -Output client_entrapwd -Format all
```

## Findings

| ID | FindingType | Severity | Description |
|----|-------------|----------|-------------|
| EP-01 | PasswordExpiryEnabled | MEDIUM | Domain password expiry still set — drives weak predictable passwords |
| EP-02 | SsprDisabled | HIGH | Self-service password reset disabled — users must call helpdesk |
| EP-03 | SmartLockoutPermissive | MEDIUM | Lockout threshold > 10 or duration < 60s |
| EP-04 | SecurityDefaultsDisabled | HIGH | Security defaults off with no confirmed Conditional Access replacement |
| EP-05 | CustomBannedPasswordsAbsent | LOW | No custom banned password list configured |

## Output

Produces `entrapwd_report.json`, `entrapwd_report.csv`, `entrapwd_report.html`.
```

- [ ] **Step 2: Add entrapwd_report.json to KNOWN_PATTERNS in exec_summary.py**

In `tools/exec_summary.py`, find line 44 (`"entra_report.json",`) and add the new entry after it:

```python
    "entra_report.json",
    "entrapwd_report.json",
```

- [ ] **Step 3: Add entrapwd_report.json to AZURE_WINDOWS_PATTERNS in exec_summary.py**

In `tools/exec_summary.py`, find line 95 (`"entra_report.json",`) and add after it:

```python
    "entra_report.json",
    "entrapwd_report.json",
```

- [ ] **Step 4: Add entrapwd to PILLAR_LABELS in exec_summary.py**

In `tools/exec_summary.py`, find line 133 (`"entra": "Azure Entra ID",`) and add after it:

```python
    "entra": "Azure Entra ID",
    "entrapwd": "Entra Password Policy",
```

- [ ] **Step 5: Add entrapwd to WINDOWS_PS1 in audit.py**

In `audit.py`, find line 187 (`"entra":        "Azure/entra-auditor/entra_auditor.ps1",`) and add after it:

```python
    "entra":        "Azure/entra-auditor/entra_auditor.ps1",
    "entrapwd":     "Azure/entrapwd-auditor/entrapwd_auditor.ps1",
```

- [ ] **Step 6: Add entrapwd entry to $AzureAuditors in Run-Audit.ps1**

In `Run-Audit.ps1`, find:
```powershell
    @{ Name = 'entra';        Script = 'Azure\entra-auditor\entra_auditor.ps1';               Prefix = 'entra_report';        AllSubs = $true  }
```

Add after it:
```powershell
    @{ Name = 'entrapwd';     Script = 'Azure\entrapwd-auditor\entrapwd_auditor.ps1';          Prefix = 'entrapwd_report';     AllSubs = $false }
```

Note: `AllSubs = $false` — password policy is tenant-scoped, not per-subscription.

- [ ] **Step 7: Update WINDOWS_PS1 count in test_audit.py**

In `tests/test_audit.py`, find the test that asserts the count of WINDOWS_PS1 entries. It currently expects 16. Update it to 17:

```python
assert len(WINDOWS_PS1) == 17
```

- [ ] **Step 8: Run Python test suite — confirm all pass**

```bash
python3 -m pytest tests/test_audit.py -q
```

Expected: all tests pass.

- [ ] **Step 9: Run Pester — confirm 16 still pass**

```bash
/path/to/pwsh -Command "Invoke-Pester -Path Azure/entrapwd-auditor/tests -Output Minimal"
```

Expected: `Tests Passed: 16, Failed: 0`

- [ ] **Step 10: Commit**

```bash
git add Azure/entrapwd-auditor/README.md tools/exec_summary.py audit.py Run-Audit.ps1 tests/test_audit.py
git commit -m "feat(entrapwd): wire into exec_summary, audit.py, Run-Audit.ps1; add README"
```

---

## pwsh path note

On this machine, PowerShell 7 is at `/home/declan/bin/pwsh`. All `pwsh` commands in this plan should use that path:

```bash
/home/declan/bin/pwsh -Command "Invoke-Pester ..."
```
