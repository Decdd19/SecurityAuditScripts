<#
.SYNOPSIS
    Audits Intune device compliance policies and Conditional Access device enforcement.
.DESCRIPTION
    Read-only audit of Intune posture:
    - IN-01: Platform missing compliance policy
    - IN-02: Compliance grace period > 24h
    - IN-03: No CA policy enforcing device compliance
    - IN-04: Non-compliant managed devices accessing M365
    - IN-05: Windows MDM auto-enrollment not configured
.PARAMETER Output
    Output file prefix (default: intune_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER TenantDomain
    Primary tenant domain (e.g. contoso.com)
.EXAMPLE
    .\intune_auditor.ps1 -TenantDomain contoso.com
#>
param(
    [string]$Output       = 'intune_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format       = 'all',
    [string]$TenantDomain = ''
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Graph / Az stubs
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-MgDeviceManagementDeviceCompliancePolicy' -ErrorAction SilentlyContinue)) {
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext   { $null }
    function Get-MgDeviceManagementDeviceCompliancePolicy { @() }
    function Get-MgDeviceManagementManagedDevice          { param([switch]$All) @() }
    function Get-MgIdentityConditionalAccessPolicy        { @() }
    function Get-MgDeviceManagementDeviceEnrollmentConfiguration { @() }
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
        default    { return '#6c757d' }
    }
}

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
# IN-01, IN-02: Compliance policies — coverage and grace period
# ---------------------------------------------------------------------------
function Get-IntuneCompliancePolicyFindings {
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $policies  = @(Get-MgDeviceManagementDeviceCompliancePolicy)

    $platformMap = @{
        'windows' = '#microsoft.graph.windows10CompliancePolicy'
        'iOS'     = '#microsoft.graph.iosCompliancePolicy'
        'android' = '#microsoft.graph.androidCompliancePolicy'
        'macOS'   = '#microsoft.graph.macOSCompliancePolicy'
    }

    foreach ($platform in $platformMap.Keys) {
        $type   = $platformMap[$platform]
        $match  = @($policies | Where-Object { $_.'@odata.type' -eq $type })
        if ($match.Count -eq 0) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'MissingCompliancePolicy'
                Resource       = $platform
                Score          = 7
                Severity       = 'HIGH'
                CisControl     = 'CIS 1'
                Recommendation = "Create a device compliance policy for $platform in Intune: " +
                                 "Intune admin centre → Devices → Compliance → Create policy → " +
                                 "Platform: $platform → configure minimum requirements."
            })
        }
    }

    # IN-02: Grace period > 24h (1440 minutes) on any policy
    foreach ($policy in $policies) {
        if ($null -ne $policy.GracePeriodInMinutes -and $policy.GracePeriodInMinutes -gt 1440) {
            $policyName = if ($policy.PSObject.Properties['DisplayName'] -and $policy.DisplayName) { $policy.DisplayName } else { $policy.'@odata.type' }
            $findings.Add([PSCustomObject]@{
                FindingType    = 'ComplianceGracePeriodTooLong'
                Resource       = $policyName
                Score          = 6
                Severity       = 'HIGH'
                CisControl     = 'CIS 1'
                Recommendation = "Reduce the compliance grace period to 24 hours or less for '$policyName': " +
                                 "Intune admin centre → Devices → Compliance → select policy → " +
                                 "Actions for noncompliance → reduce grace period to 1 day."
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# IN-03, IN-04: CA device enforcement and non-compliant devices
# ---------------------------------------------------------------------------
function Get-IntuneDeviceAccessFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # IN-03: No CA policy requires device compliance
    $policies = @(Get-MgIdentityConditionalAccessPolicy)
    $deviceCompliancePolicies = @($policies | Where-Object {
        $_.State -eq 'enabled' -and
        $null -ne $_.GrantControls -and
        $_.GrantControls.BuiltInControls -contains 'compliantDevice'
    })
    if ($deviceCompliancePolicies.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'NoCaDeviceComplianceEnforcement'
            Resource       = 'tenant'
            Score          = 8
            Severity       = 'CRITICAL'
            CisControl     = 'CIS 1'
            Recommendation = "Create a Conditional Access policy requiring device compliance: " +
                             "Entra admin centre → Protection → Conditional Access → New policy → " +
                             "Users: All → Cloud apps: All → Grant: Require device to be marked as compliant → Enable."
        })
    }

    # IN-04: Non-compliant managed devices
    $devices = @(Get-MgDeviceManagementManagedDevice -All)
    $nonCompliant = @($devices | Where-Object { $_.ComplianceState -in @('noncompliant', 'error', 'unknown') })
    if ($nonCompliant.Count -gt 0) {
        $resourceList = ($nonCompliant | Select-Object -First 10 | ForEach-Object { $_.DeviceName }) -join ', '
        $findings.Add([PSCustomObject]@{
            FindingType    = 'UnmanagedDevicesAccessingM365'
            Resource       = $resourceList
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 1'
            Recommendation = "Remediate $($nonCompliant.Count) non-compliant device(s). Review in: " +
                             "Intune admin centre → Devices → All devices → filter by Compliance: Not compliant. " +
                             "Ensure Conditional Access blocks non-compliant devices until remediated."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# IN-05: Windows MDM auto-enrollment
# ---------------------------------------------------------------------------
function Get-IntuneEnrollmentFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $configs  = @(Get-MgDeviceManagementDeviceEnrollmentConfiguration)

    $autoEnroll = @($configs | Where-Object {
        $_.'@odata.type' -eq '#microsoft.graph.windowsAutoEnrollmentConfiguration'
    })

    if ($autoEnroll.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'WindowsAutoEnrollmentNotConfigured'
            Resource       = 'tenant'
            Score          = 5
            Severity       = 'MEDIUM'
            CisControl     = 'CIS 1'
            Recommendation = "Enable Windows MDM auto-enrollment to ensure all domain-joined Windows devices " +
                             "are managed: Intune admin centre → Devices → Enroll devices → " +
                             "Windows enrollment → Automatic enrollment → MDM user scope: All (or selected group)."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------
function ConvertTo-IntuneJsonReport {
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

function ConvertTo-IntuneCsvReport {
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

function ConvertTo-IntuneHtmlReport {
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
    $noFindings    = if ($Findings.Count -eq 0) { "<tr><td colspan='5' style='text-align:center;color:#888'>No findings — tenant appears compliant.</td></tr>" } else { '' }
    $tenantDisplay = if ($TenantId) { [System.Web.HttpUtility]::HtmlEncode($TenantId) } else { 'N/A' }
    $ts            = (Get-Date).ToUniversalTime().ToString('o')
    return @"
<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><title>Intune Security Audit</title>
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
<div class="header"><h1>Intune Device Compliance Audit</h1><p>Tenant: $tenantDisplay &nbsp;|&nbsp; Generated: $ts</p></div>
<div class="section"><table>
  <thead><tr><th>Type</th><th>Resource</th><th>Risk</th><th>CIS</th><th>Recommendation</th></tr></thead>
  <tbody>$rows$noFindings</tbody>
</table></div>
<div class="footer">Intune Security Audit &nbsp;|&nbsp; For internal use only</div>
</body></html>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ctx      = Get-AzContext
$tenantId = if ($ctx -and $ctx.Tenant) { $ctx.Tenant.Id } else { '' }

Write-Host "Intune Device Compliance Auditor"
Write-Host "Tenant ID: $tenantId"

# ---------------------------------------------------------------------------
# License gate — Intune requires M365 Business Premium or E3+Intune add-on.
# On unlicensed tenants Graph returns 403; catch it and emit a single INFO
# finding so exec_summary gets a valid report rather than a crash.
# ---------------------------------------------------------------------------
try {
    Get-MgDeviceManagementDeviceCompliancePolicy -Top 1 -ErrorAction Stop | Out-Null
} catch {
    if ($_.Exception.Message -match '403|Forbidden|Unauthorized|AccessDenied') {
        Write-Warning "Intune not licensed on this tenant — skipping IN-01 through IN-05."
        $noLicense = [PSCustomObject]@{
            FindingType    = 'IntuneNotLicensed'
            Severity       = 'INFO'
            Resource       = if ($TenantDomain) { $TenantDomain } else { $tenantId }
            Detail         = 'Microsoft Intune is not provisioned on this tenant. Intune requires M365 Business Premium or an E3/E5 + Intune add-on licence.'
            Recommendation = 'Consider upgrading to M365 Business Premium to enable device compliance and Conditional Access enforcement.'
            CisControl     = 'CIS 1'
            Score          = 0
        }
        $findings = @($noLicense)
        switch ($Format) {
            'stdout' { $findings | Format-Table FindingType, Resource, Severity, Recommendation -Wrap }
            'json' {
                $r = @{ findings = $findings; tenant_id = $tenantId; generated_at = (Get-Date).ToUniversalTime().ToString('o') }
                $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
                Set-RestrictedPermissions "$Output.json"
                Write-Host "JSON report: $Output.json"
            }
            'csv' { ConvertTo-IntuneCsvReport -Findings $findings -Path "$Output.csv" }
            default {
                $r = @{ findings = $findings; tenant_id = $tenantId; generated_at = (Get-Date).ToUniversalTime().ToString('o') }
                $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
                Set-RestrictedPermissions "$Output.json"
                ConvertTo-IntuneCsvReport -Findings $findings -Path "$Output.csv"
                $html = ConvertTo-IntuneHtmlReport -Findings $findings -TenantId $tenantId
                $html | Out-File "$Output.html" -Encoding UTF8
                Set-RestrictedPermissions "$Output.html"
                Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
            }
        }
        exit 0
    }
    throw
}

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "[1/3] Checking compliance policies..."
Get-IntuneCompliancePolicyFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[2/3] Checking device access and CA enforcement..."
Get-IntuneDeviceAccessFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[3/3] Checking Windows MDM auto-enrollment..."
Get-IntuneEnrollmentFindings | ForEach-Object { $allFindings.Add($_) }

$findings = @($allFindings)
Write-Host "Findings: $($findings.Count)"

switch ($Format) {
    'stdout' { $findings | Format-Table FindingType, Resource, Severity, CisControl, Recommendation -Wrap }
    'json' {
        $r = ConvertTo-IntuneJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        Write-Host "JSON report: $Output.json"
    }
    'csv' {
        ConvertTo-IntuneCsvReport -Findings $findings -Path "$Output.csv"
        Write-Host "CSV report: $Output.csv"
    }
    'html' {
        $html = ConvertTo-IntuneHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "HTML report: $Output.html"
    }
    'all' {
        $r = ConvertTo-IntuneJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        ConvertTo-IntuneCsvReport -Findings $findings -Path "$Output.csv"
        $html = ConvertTo-IntuneHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
    }
}
