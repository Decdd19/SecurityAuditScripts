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

        $checkEnabled = $values['enableBannedPasswordCheck']
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

    $mgCtx = $null; try { $mgCtx = Get-MgContext } catch { }
    if (-not $mgCtx) {
        if ($env:AUDIT_TENANT_ID) {
            Connect-MgGraph -TenantId $env:AUDIT_TENANT_ID -NoWelcome
        } else {
            Connect-MgGraph -Scopes 'Policy.Read.All','Directory.Read.All' -NoWelcome
        }
        $mgCtx = $null; try { $mgCtx = Get-MgContext } catch { }
    }
    $tenantId    = if ($mgCtx) { $mgCtx.TenantId } else { 'unknown' }
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
