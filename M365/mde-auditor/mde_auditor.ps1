<#
.SYNOPSIS
    Audits Microsoft Defender for Endpoint (MDE) device security posture.
.DESCRIPTION
    Read-only audit of MDE endpoint protection via Microsoft Graph:
    - MDE-01: Devices not onboarded to Defender for Endpoint (onboardingStatus ≠ onboarded) — CRITICAL
    - MDE-02: Devices with real-time protection disabled (antivirusStatus ≠ monitored) — HIGH
    - MDE-03: Devices without BitLocker encryption (isEncrypted = false) — HIGH
    - MDE-04: Devices with tamper protection disabled — HIGH
    - MDE-05: Devices with no antivirus scan in the last 7 days — MEDIUM
.PARAMETER Output
    Output file prefix (default: mde_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER TenantDomain
    Primary tenant domain (e.g. contoso.com)
.EXAMPLE
    .\mde_auditor.ps1 -TenantDomain contoso.com
    .\mde_auditor.ps1 -TenantDomain contoso.com -Format json
#>
param(
    [string]$Output       = 'mde_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format       = 'all',
    [string]$TenantDomain = ''
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Graph / Az stubs — overridden by real modules; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-MgDeviceManagementManagedDevice' -ErrorAction SilentlyContinue)) {
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext   { $null }
    function Get-MgDeviceManagementManagedDevice { param([switch]$All) @() }
    function Get-MgDeviceManagementManagedDeviceWindowsProtectionState { param($ManagedDeviceId) $null }
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
# MDE-01: Devices not onboarded to Defender for Endpoint
# ---------------------------------------------------------------------------
function Get-MdeOnboardingFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $devices  = @(Get-MgDeviceManagementManagedDevice -All)

    $notOnboarded = @($devices | Where-Object {
        $_.OperatingSystem -eq 'Windows' -and
        $null -ne $_.OnboardingStatus -and
        $_.OnboardingStatus -ne 'onboarded'
    })

    if ($notOnboarded.Count -gt 0) {
        $resourceList = ($notOnboarded | Select-Object -First 10 | ForEach-Object { $_.DeviceName }) -join ', '
        $findings.Add([PSCustomObject]@{
            FindingType    = 'DeviceNotOnboardedToMde'
            Resource       = $resourceList
            Score          = 9
            Severity       = 'CRITICAL'
            CisControl     = 'CIS 10'
            Recommendation = "Onboard $($notOnboarded.Count) device(s) to Microsoft Defender for Endpoint: " +
                             "Security.microsoft.com → Settings → Endpoints → Onboarding → " +
                             "select deployment method → follow onboarding package instructions. " +
                             "Devices: $resourceList."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# MDE-03: Devices not encrypted with BitLocker
# ---------------------------------------------------------------------------
function Get-MdeEncryptionFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $devices  = @(Get-MgDeviceManagementManagedDevice -All)

    $unencrypted = @($devices | Where-Object {
        $_.OperatingSystem -eq 'Windows' -and
        $_.IsEncrypted -eq $false
    })

    if ($unencrypted.Count -gt 0) {
        $resourceList = ($unencrypted | Select-Object -First 10 | ForEach-Object { $_.DeviceName }) -join ', '
        $findings.Add([PSCustomObject]@{
            FindingType    = 'DeviceNotEncrypted'
            Resource       = $resourceList
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 10'
            Recommendation = "Enable BitLocker on $($unencrypted.Count) unencrypted device(s): " +
                             "Intune admin centre → Endpoint security → Disk encryption → " +
                             "Create policy → Windows → BitLocker → assign to affected devices. " +
                             "Affected: $resourceList."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# MDE-02, MDE-04, MDE-05: Real-time protection, tamper protection, scan age
# (fetches windowsProtectionState per Windows device)
# ---------------------------------------------------------------------------
function Get-MdeProtectionStateFindings {
    $findings     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $devices      = @(Get-MgDeviceManagementManagedDevice -All | Where-Object { $_.OperatingSystem -eq 'Windows' })
    $staleThreshold = (Get-Date).AddDays(-7)

    $rtpOff     = [System.Collections.Generic.List[string]]::new()
    $tamperOff  = [System.Collections.Generic.List[string]]::new()
    $staleScan  = [System.Collections.Generic.List[string]]::new()

    foreach ($device in $devices) {
        $wps = $null
        try {
            $wps = Get-MgDeviceManagementManagedDeviceWindowsProtectionState -ManagedDeviceId $device.Id -ErrorAction SilentlyContinue
        } catch { }

        if ($null -eq $wps) { continue }

        # MDE-02: Real-time protection
        if ($wps.RealTimeProtectionEnabled -eq $false) {
            $rtpOff.Add($device.DeviceName)
        }

        # MDE-04: Tamper protection
        if ($wps.TamperProtectionEnabled -eq $false) {
            $tamperOff.Add($device.DeviceName)
        }

        # MDE-05: Scan age — flag if null (never scanned) or older than 7 days
        $lastScan = $wps.AntiVirusScanLastReportedDateTime
        if ($null -eq $lastScan -or $lastScan -lt $staleThreshold) {
            $staleScan.Add($device.DeviceName)
        }
    }

    if ($rtpOff.Count -gt 0) {
        $r = ($rtpOff | Select-Object -First 10) -join ', '
        $findings.Add([PSCustomObject]@{
            FindingType    = 'RtpDisabled'
            Resource       = $r
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 10'
            Recommendation = "Enable real-time protection on $($rtpOff.Count) device(s): " +
                             "Ensure Microsoft Defender Antivirus is not disabled by policy or third-party AV. " +
                             "Check via Security.microsoft.com → Devices → select device → Security posture. " +
                             "Affected: $r."
        })
    }

    if ($tamperOff.Count -gt 0) {
        $r = ($tamperOff | Select-Object -First 10) -join ', '
        $findings.Add([PSCustomObject]@{
            FindingType    = 'TamperProtectionDisabled'
            Resource       = $r
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 10'
            Recommendation = "Enable tamper protection on $($tamperOff.Count) device(s): " +
                             "Security.microsoft.com → Settings → Endpoints → Advanced features → " +
                             "Tamper Protection → On. Or enforce via Intune: Endpoint security → " +
                             "Antivirus → Windows Antivirus policy → Tamper Protection: Enabled. " +
                             "Affected: $r."
        })
    }

    if ($staleScan.Count -gt 0) {
        $r = ($staleScan | Select-Object -First 10) -join ', '
        $findings.Add([PSCustomObject]@{
            FindingType    = 'StaleAntiVirusScan'
            Resource       = $r
            Score          = 5
            Severity       = 'MEDIUM'
            CisControl     = 'CIS 10'
            Recommendation = "$($staleScan.Count) device(s) have not completed an antivirus scan in >7 days " +
                             "(or have never been scanned). Trigger a scan via: " +
                             "Security.microsoft.com → Devices → select device → Run antivirus scan. " +
                             "Investigate connectivity and sensor health. Affected: $r."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------
function ConvertTo-MdeJsonReport {
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

function ConvertTo-MdeCsvReport {
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

function ConvertTo-MdeHtmlReport {
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
    $noFindings    = if ($Findings.Count -eq 0) { "<tr><td colspan='5' style='text-align:center;color:#888'>No findings — all devices appear compliant.</td></tr>" } else { '' }
    $tenantDisplay = if ($TenantId) { [System.Web.HttpUtility]::HtmlEncode($TenantId) } else { 'N/A' }
    $ts            = (Get-Date).ToUniversalTime().ToString('o')
    return @"
<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><title>Defender for Endpoint Security Audit</title>
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
<div class="header"><h1>Defender for Endpoint Security Audit</h1><p>Tenant: $tenantDisplay &nbsp;|&nbsp; Generated: $ts</p></div>
<div class="section"><table>
  <thead><tr><th>Type</th><th>Resource</th><th>Risk</th><th>CIS</th><th>Recommendation</th></tr></thead>
  <tbody>$rows$noFindings</tbody>
</table></div>
<div class="footer">Defender for Endpoint Security Audit &nbsp;|&nbsp; For internal use only</div>
</body></html>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ctx      = Get-AzContext
$tenantId = if ($ctx -and $ctx.Tenant) { $ctx.Tenant.Id } else { '' }

Write-Host "Defender for Endpoint Auditor"
Write-Host "Tenant ID: $tenantId"

Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All' -NoWelcome

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "[1/3] Checking MDE onboarding status..."
Get-MdeOnboardingFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[2/3] Checking device encryption..."
Get-MdeEncryptionFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[3/3] Checking protection state (RTP, tamper, scan age)..."
Get-MdeProtectionStateFindings | ForEach-Object { $allFindings.Add($_) }

$findings = @($allFindings)
Write-Host "Findings: $($findings.Count)"

switch ($Format) {
    'stdout' { $findings | Format-Table FindingType, Resource, Severity, CisControl, Recommendation -Wrap }
    'json' {
        $r = ConvertTo-MdeJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        Write-Host "JSON report: $Output.json"
    }
    'csv' {
        ConvertTo-MdeCsvReport -Findings $findings -Path "$Output.csv"
        Write-Host "CSV report: $Output.csv"
    }
    'html' {
        $html = ConvertTo-MdeHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "HTML report: $Output.html"
    }
    'all' {
        $r = ConvertTo-MdeJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        ConvertTo-MdeCsvReport -Findings $findings -Path "$Output.csv"
        $html = ConvertTo-MdeHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
    }
}
