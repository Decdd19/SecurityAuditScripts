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

function Get-SmartLockoutFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $settings    = @(Get-MgBetaDirectorySetting)
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

# ---------------------------------------------------------------------------
# Main — skipped when dot-sourced (Pester dot-sources with '.')
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host 'entrapwd_auditor.ps1 — stub, audit functions not yet implemented'
    exit 0
}
