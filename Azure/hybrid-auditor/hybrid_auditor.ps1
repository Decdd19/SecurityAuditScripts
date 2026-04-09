<#
.SYNOPSIS
    Audits Hybrid Identity (Azure AD Connect / Entra Connect) security posture.
.DESCRIPTION
    Read-only audit of on-premises directory sync configuration via Microsoft Graph:
    - HA-01: Stale or broken directory sync (last sync >3h or never) — CRITICAL
    - HA-02: Password Hash Sync not enabled (resilience risk vs PTA-only) — MEDIUM
    - HA-03: Password writeback disabled (SSPR cannot reset on-prem accounts) — MEDIUM
    - HA-04: Accidental deletion prevention disabled — HIGH
    - HA-05: Seamless Single Sign-On not enabled — LOW

    Cloud-only tenants (no on-prem sync) receive a single INFO finding and exit cleanly.
.PARAMETER Output
    Output file prefix (default: hybrid_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.EXAMPLE
    .\hybrid_auditor.ps1
    .\hybrid_auditor.ps1 -Format json
#>
param(
    [string]$Output = 'hybrid_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all'
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Graph stubs — overridden by real modules; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-MgOrganization' -ErrorAction SilentlyContinue)) {
    function Connect-MgGraph      { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext        { $null }
    function Get-MgOrganization   { @() }
    function Invoke-MgGraphRequest { param($Uri, $Method) @{ value = @() } }
}
if (-not (Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue)) {
    function Get-AzContext { @{ Tenant = @{ Id = '' }; Account = @{ Id = '' } } }
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
        'INFO'     { return '#17a2b8' }
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
# Cloud-only guard — returns INFO finding if no on-prem sync is configured
# Returns empty list when sync is enabled (caller continues with checks)
# ---------------------------------------------------------------------------
function Get-HybridCloudOnlyGuard {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $org = @(Get-MgOrganization) | Select-Object -First 1

    if ($null -eq $org -or $org.OnPremisesSyncEnabled -ne $true) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'CloudOnlyTenant'
            Resource       = 'tenant'
            Score          = 0
            Severity       = 'LOW'
            CisControl     = 'N/A'
            Recommendation = 'This tenant has no on-premises directory sync configured. ' +
                             'Hybrid Identity checks (AAD Connect sync status, PHS, password writeback) are not applicable. ' +
                             'If on-premises Active Directory exists, consider enabling Entra Connect for unified identity management.'
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# HA-01: Directory sync freshness
# ---------------------------------------------------------------------------
function Get-HybridSyncStatusFindings {
    $findings   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $org        = @(Get-MgOrganization) | Select-Object -First 1
    $threshold  = (Get-Date).AddHours(-3)
    $lastSync   = $org.OnPremisesLastSyncDateTime

    $isStale = ($null -eq $lastSync) -or ([datetime]$lastSync -lt $threshold)

    if ($isStale) {
        $lastSyncStr = if ($null -eq $lastSync) { 'never' } else { [datetime]$lastSync | Get-Date -Format 'o' }
        $findings.Add([PSCustomObject]@{
            FindingType    = 'SyncStale'
            Resource       = 'tenant'
            Score          = 9
            Severity       = 'CRITICAL'
            CisControl     = 'CIS 5'
            Recommendation = "Directory sync has not completed in over 3 hours (last: $lastSyncStr). " +
                             "Investigate the Entra Connect server: check the Synchronization Service Manager for errors, " +
                             "verify network connectivity to Entra ID, and review the Application event log on the sync server. " +
                             "Stale sync means on-prem account changes (new hires, terminations, password resets) are not reflected in Entra."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# HA-02, HA-03, HA-05: Sync feature flags (PHS, password writeback, seamless SSO)
# ---------------------------------------------------------------------------
function Get-HybridSyncFeatureFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $resp = $null
    try {
        $resp = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization' -Method GET -ErrorAction Stop
    } catch {
        Write-Warning "Could not retrieve sync configuration: $_"
        return $findings
    }

    $syncConfig = if ($resp.value -and $resp.value.Count -gt 0) { $resp.value[0] } else { $null }
    if ($null -eq $syncConfig) { return $findings }

    $features = $syncConfig.features

    # HA-02: Password Hash Sync
    if ($features.passwordHashSyncEnabled -ne $true) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'PasswordHashSyncDisabled'
            Resource       = 'tenant'
            Score          = 5
            Severity       = 'MEDIUM'
            CisControl     = 'CIS 5'
            Recommendation = 'Enable Password Hash Synchronisation (PHS) in Entra Connect: ' +
                             'Open the Entra Connect wizard → Customise synchronisation options → ' +
                             'enable Password hash synchronization. PHS provides a resilient fallback ' +
                             'if Pass-Through Authentication agents go offline, and enables leaked credential detection.'
        })
    }

    # HA-03: Password writeback
    if ($features.passwordWritebackEnabled -ne $true) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'PasswordWritebackDisabled'
            Resource       = 'tenant'
            Score          = 5
            Severity       = 'MEDIUM'
            CisControl     = 'CIS 5'
            Recommendation = 'Enable password writeback in Entra Connect: ' +
                             'Open the Entra Connect wizard → Optional features → Password writeback → enable. ' +
                             'Without writeback, self-service password reset (SSPR) cannot update on-premises AD passwords, ' +
                             'leaving users locked out after a cloud-side reset.'
        })
    }

    # HA-05: Seamless SSO
    if ($features.seamlessSsoEnabled -ne $true) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'SeamlessSsoNotEnabled'
            Resource       = 'tenant'
            Score          = 2
            Severity       = 'LOW'
            CisControl     = 'CIS 5'
            Recommendation = 'Enable Seamless Single Sign-On in Entra Connect: ' +
                             'Open the Entra Connect wizard → Optional features → Single sign-on → enable, ' +
                             'then configure intranet zone Group Policy to allow automatic Kerberos authentication. ' +
                             'Seamless SSO eliminates re-authentication prompts for domain-joined devices on the corporate network.'
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# HA-04: Accidental deletion prevention
# ---------------------------------------------------------------------------
function Get-HybridSyncConfigFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $resp = $null
    try {
        $resp = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization' -Method GET -ErrorAction Stop
    } catch {
        Write-Warning "Could not retrieve sync configuration: $_"
        return $findings
    }

    $syncConfig = if ($resp.value -and $resp.value.Count -gt 0) { $resp.value[0] } else { $null }
    if ($null -eq $syncConfig) { return $findings }

    $accDelPrev = $syncConfig.configuration.accidentalDeletionPrevention

    if ($null -eq $accDelPrev -or $accDelPrev.enabled -ne $true) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'AccidentalDeletionPreventionDisabled'
            Resource       = 'tenant'
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 11'
            Recommendation = 'Enable accidental deletion prevention in Entra Connect: ' +
                             'Open the Entra Connect wizard → Optional features → Accidental delete prevention → enable ' +
                             'and set an appropriate threshold (recommend 200–500 objects). ' +
                             'Without this, a bulk delete or misconfigured OU scope could wipe thousands of cloud accounts silently.'
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------
function ConvertTo-HybridJsonReport {
    param([array]$Findings, [string]$TenantId = '')
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    return @{
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        tenant_id    = $TenantId
        summary      = @{
            total_findings = $Findings.Count
            critical       = $counts.CRITICAL
            high           = $counts.HIGH
            medium         = $counts.MEDIUM
            low            = $counts.LOW
        }
        findings     = @($Findings | ForEach-Object {
            @{
                finding_type   = $_.FindingType
                resource       = if ($null -ne $_.Resource) { $_.Resource } else { '' }
                risk_level     = $_.Severity
                severity_score = $_.Score
                cis_control    = $_.CisControl
                recommendation = $_.Recommendation
            }
        })
    }
}

function ConvertTo-HybridCsvReport {
    param([array]$Findings, [string]$Path)
    if ($Findings.Count -eq 0) { return }
    $Findings | ForEach-Object {
        [PSCustomObject]@{
            finding_type   = $_.FindingType
            resource       = if ($null -ne $_.Resource) { $_.Resource } else { '' }
            risk_level     = $_.Severity
            severity_score = $_.Score
            cis_control    = $_.CisControl
            recommendation = $_.Recommendation
        }
    } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function ConvertTo-HybridHtmlReport {
    param([array]$Findings, [string]$TenantId)
    $rows = ''
    foreach ($f in ($Findings | Sort-Object Score -Descending)) {
        $colour   = Get-SeverityColour $f.Severity
        $resource = if ($null -ne $f.Resource) { [System.Web.HttpUtility]::HtmlEncode($f.Resource) } else { '&mdash;' }
        $rec      = [System.Web.HttpUtility]::HtmlEncode($f.Recommendation)
        $rows += "<tr>
          <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
          <td><code>$resource</code></td>
          <td><span style='background:$colour;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em'>$($f.Severity)</span></td>
          <td style='font-size:0.85em'>$([System.Web.HttpUtility]::HtmlEncode($f.CisControl))</td>
          <td style='font-size:0.82em;color:#555;font-style:italic'>$rec</td>
        </tr>`n"
    }
    $noFindings    = if ($Findings.Count -eq 0) { "<tr><td colspan='5' style='text-align:center;color:#888'>No findings — hybrid identity configuration appears compliant.</td></tr>" } else { '' }
    $tenantDisplay = if ($TenantId) { [System.Web.HttpUtility]::HtmlEncode($TenantId) } else { 'N/A' }
    $ts            = (Get-Date).ToUniversalTime().ToString('o')
    return @"
<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><title>Hybrid Identity Security Audit</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}.header h1{margin:0;font-size:1.8em}.header p{margin:5px 0 0;opacity:0.8}
  .section{padding:20px 32px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
  td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
  .footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style></head>
<body>
<div class="header"><h1>Hybrid Identity Security Audit</h1><p>Tenant: $tenantDisplay &nbsp;|&nbsp; Generated: $ts</p></div>
<div class="section"><table>
  <thead><tr><th>Type</th><th>Resource</th><th>Risk</th><th>CIS</th><th>Recommendation</th></tr></thead>
  <tbody>$rows$noFindings</tbody>
</table></div>
<div class="footer">Hybrid Identity (Entra Connect) Security Audit &nbsp;|&nbsp; For internal use only</div>
</body></html>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ctx      = Get-AzContext
$tenantId = if ($ctx -and $ctx.Tenant) { $ctx.Tenant.Id } else { '' }

Write-Host "Hybrid Identity Auditor"
Write-Host "Tenant ID: $tenantId"

Connect-MgGraph -Scopes 'Organization.Read.All','OnPremDirectorySynchronization.Read.All' -NoWelcome

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "[1/4] Checking for cloud-only tenant..."
$guardFindings = @(Get-HybridCloudOnlyGuard)
if ($guardFindings.Count -gt 0) {
    $guardFindings | ForEach-Object { $allFindings.Add($_) }
    Write-Host "  → Cloud-only tenant detected. Hybrid checks skipped."
} else {
    Write-Host "[2/4] Checking sync status..."
    Get-HybridSyncStatusFindings | ForEach-Object { $allFindings.Add($_) }

    Write-Host "[3/4] Checking sync feature flags..."
    Get-HybridSyncFeatureFindings | ForEach-Object { $allFindings.Add($_) }

    Write-Host "[4/4] Checking sync configuration..."
    Get-HybridSyncConfigFindings | ForEach-Object { $allFindings.Add($_) }
}

$findings = @($allFindings)
Write-Host "Findings: $($findings.Count)"

switch ($Format) {
    'stdout' { $findings | Format-Table FindingType, Resource, Severity, CisControl, Recommendation -Wrap }
    'json' {
        $r = ConvertTo-HybridJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        Write-Host "JSON report: $Output.json"
    }
    'csv' {
        ConvertTo-HybridCsvReport -Findings $findings -Path "$Output.csv"
        Write-Host "CSV report: $Output.csv"
    }
    'html' {
        $html = ConvertTo-HybridHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "HTML report: $Output.html"
    }
    'all' {
        $r = ConvertTo-HybridJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        ConvertTo-HybridCsvReport -Findings $findings -Path "$Output.csv"
        $html = ConvertTo-HybridHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
    }
}
