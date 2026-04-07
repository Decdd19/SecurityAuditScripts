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

# ---------------------------------------------------------------------------
# Main — skipped when dot-sourced (Pester dot-sources with '.')
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host 'entrapwd_auditor.ps1 — stub, audit functions not yet implemented'
    exit 0
}
