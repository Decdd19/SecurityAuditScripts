<#
.SYNOPSIS
    Audits Windows LAPS deployment and password management across Active Directory.
.DESCRIPTION
    Read-only audit of Local Administrator Password Solution (LAPS) coverage in
    Active Directory. Checks for both Legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS
    (msLAPS-Password) schema attributes, measures deployment coverage across domain
    computers, and identifies expired LAPS-managed passwords.
.PARAMETER Output
    Output file prefix (default: laps_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.EXAMPLE
    .\laps_auditor.ps1
    .\laps_auditor.ps1 -Format html
    .\laps_auditor.ps1 -Output 'laps_audit_2024' -Format json
#>
param(
    [string]$Output = 'laps_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all'
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# ActiveDirectory module stubs -- overridden by real module at runtime
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-ADObject' -ErrorAction SilentlyContinue)) {
    function Get-ADObject { param($Filter, $SearchBase, $Properties) @() }
}
if (-not (Get-Command -Name 'Get-ADComputer' -ErrorAction SilentlyContinue)) {
    function Get-ADComputer { param($Filter, $Properties) @() }
}
if (-not (Get-Command -Name 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
    function Get-ADDomain { @{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' } }
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
# Output helpers
# ---------------------------------------------------------------------------
function Write-JsonReport {
    param([Parameter(Mandatory)][hashtable]$ReportData, [string]$Path)
    $ReportData | ConvertTo-Json -Depth 10 | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function Write-CsvReport {
    param([Parameter(Mandatory)][array]$Findings, [string]$Path)
    $Findings | Select-Object FindingType, Resource, Severity, Score, Description, Recommendation |
        ConvertTo-Csv -NoTypeInformation | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function Write-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [hashtable]$Summary = @{},
        [string]$Path
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $Findings) {
        $colour = Get-SeverityColour $f.Severity
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Description))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    $coveragePct = if ($Summary.coverage_pct) { $Summary.coverage_pct } else { 'N/A' }
    $managed     = if ($Summary.laps_managed)  { $Summary.laps_managed }  else { 0 }
    $total       = if ($Summary.total_computers) { $Summary.total_computers } else { 0 }
    $scannedAt   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'

    $html = @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Windows LAPS Audit Report</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
.header{background:#1a1a2e;color:#fff;padding:30px 40px}
.header h1{margin:0;font-size:1.8em}.header p{margin:5px 0 0;opacity:0.8}
.cards{display:flex;gap:16px;flex-wrap:wrap;padding:20px 40px}
.card{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 2px 8px rgba(0,0,0,0.08);min-width:130px;text-align:center}
.val{font-size:2em;font-weight:bold}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
.footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style></head><body>
<div class='header'><h1>Windows LAPS Audit Report</h1>
<p>Domain: $($Summary.hostname) | Generated: $scannedAt</p>
</div>
<div class='cards'>
  <div class='card'><div class='val'>$total</div><div>Total Computers</div></div>
  <div class='card'><div class='val'>$managed</div><div>LAPS Managed</div></div>
  <div class='card'><div class='val'>$coveragePct%</div><div>Coverage</div></div>
  <div class='card'><div class='val' style='color:#dc3545'>$($counts.CRITICAL)</div><div>CRITICAL</div></div>
  <div class='card'><div class='val' style='color:#fd7e14'>$($counts.HIGH)</div><div>HIGH</div></div>
  <div class='card'><div class='val' style='color:#ffc107'>$($counts.MEDIUM)</div><div>MEDIUM</div></div>
  <div class='card'><div class='val' style='color:#28a745'>$($counts.LOW)</div><div>LOW</div></div>
</div>
<div style='padding:0 40px 20px'>
<table><thead><tr>
  <th>Finding</th><th>Resource</th><th>Detail</th>
  <th>Severity</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table>
</div>
<div class='footer'>Windows LAPS Audit Report | Generated $scannedAt</div>
</body></html>
"@
    $html | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

# ---------------------------------------------------------------------------
# Main audit function
# ---------------------------------------------------------------------------
function Get-LapsFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $domain   = Get-ADDomain
    $schemaDN = "CN=Schema,CN=Configuration,$($domain.DistinguishedName)"

    # ------------------------------------------------------------------
    # 1. Legacy LAPS schema check (ms-Mcs-AdmPwd)
    # ------------------------------------------------------------------
    $legacySchema = @(Get-ADObject -Filter { name -eq 'ms-Mcs-AdmPwd' } -SearchBase $schemaDN)
    $legacyPresent = $legacySchema.Count -gt 0

    if (-not $legacyPresent) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'LapsNotInstalled'
            Resource       = 'AD Schema'
            Severity       = 'HIGH'
            Score          = 7
            Description    = 'Legacy LAPS schema attribute not found - LAPS not installed'
            Recommendation = 'Install Legacy LAPS MSI on a domain controller to extend the schema with ms-Mcs-AdmPwd, then deploy the LAPS CSE via Group Policy to manage local admin passwords.'
        })
    }

    # ------------------------------------------------------------------
    # 2. Windows LAPS schema check (msLAPS-Password)
    # ------------------------------------------------------------------
    $windowsSchema = @(Get-ADObject -Filter { name -eq 'msLAPS-Password' } -SearchBase $schemaDN)
    $windowsLapsPresent = $windowsSchema.Count -gt 0

    if (-not $windowsLapsPresent) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'WindowsLapsNotPresent'
            Resource       = 'AD Schema'
            Severity       = 'MEDIUM'
            Score          = 5
            Description    = 'Windows LAPS (built-in) schema attribute not present'
            Recommendation = 'Update domain controllers to Windows Server 2025 or apply the April 2023 update to Server 2019/2022 to enable built-in Windows LAPS with encrypted password storage and automatic rotation.'
        })
    }

    # ------------------------------------------------------------------
    # 3. LAPS coverage across domain computers
    # ------------------------------------------------------------------
    $now = Get-Date
    $computers = @(Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime')
    $total   = $computers.Count
    $managed = 0
    $expired = 0

    foreach ($computer in $computers) {
        $legacyExpiry  = $computer.'ms-Mcs-AdmPwdExpirationTime'
        $windowsExpiry = $computer.'msLAPS-PasswordExpirationTime'
        $hasLaps       = ($null -ne $legacyExpiry) -or ($null -ne $windowsExpiry)

        if ($hasLaps) {
            $managed++

            # ----------------------------------------------------------
            # 4. Expired LAPS password check
            # ----------------------------------------------------------
            $isExpired = $false
            if ($null -ne $legacyExpiry -and $legacyExpiry -lt $now) {
                $isExpired = $true
            }
            if ($null -ne $windowsExpiry -and $windowsExpiry -lt $now) {
                $isExpired = $true
            }
            if ($isExpired) {
                $expired++
            }
        }
    }

    $coveragePct = if ($total -gt 0) { [math]::Round(($managed / $total) * 100, 1) } else { 0 }

    if ($total -gt 0 -and $coveragePct -lt 80) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'LowLapsCoverage'
            Resource       = 'Domain Computers'
            Severity       = 'HIGH'
            Score          = 7
            Description    = "Only $coveragePct% of computers have LAPS managed passwords ($managed/$total)"
            Recommendation = 'Deploy LAPS Group Policy to all workstations and servers. Ensure the LAPS CSE is installed on target machines and that GPO permissions allow password updates to Active Directory.'
        })
    }

    if ($expired -gt 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'ExpiredLapsPasswords'
            Resource       = 'Domain Computers'
            Severity       = 'MEDIUM'
            Score          = 5
            Description    = "$expired computer(s) have expired LAPS passwords"
            Recommendation = 'Investigate why LAPS password rotation is failing on these computers. Common causes include network connectivity issues, LAPS CSE not installed, or Group Policy processing failures.'
        })
    }

    # Compute overall risk
    $overallRisk = 'LOW'
    if ($findings | Where-Object { $_.Severity -eq 'CRITICAL' }) { $overallRisk = 'CRITICAL' }
    elseif ($findings | Where-Object { $_.Severity -eq 'HIGH' }) { $overallRisk = 'HIGH' }
    elseif ($findings | Where-Object { $_.Severity -eq 'MEDIUM' }) { $overallRisk = 'MEDIUM' }

    $summaryData = @{
        hostname        = $env:COMPUTERNAME
        total_computers = $total
        laps_managed    = $managed
        coverage_pct    = $coveragePct
        overall_risk    = $overallRisk
    }

    return @{
        findings = $findings
        summary  = $summaryData
    }
}

# ---------------------------------------------------------------------------
# Terminal summary
# ---------------------------------------------------------------------------
function Write-TerminalSummary {
    param([array]$Findings, [hashtable]$Summary)

    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    Write-Host ''
    Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host '     WINDOWS LAPS AUDIT COMPLETE                      ' -ForegroundColor Cyan
    Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  Total computers : $($Summary.total_computers)"       -ForegroundColor Cyan
    Write-Host "  LAPS managed    : $($Summary.laps_managed)"          -ForegroundColor Cyan
    Write-Host "  Coverage        : $($Summary.coverage_pct)%"         -ForegroundColor Cyan
    Write-Host "  Overall risk    : $($Summary.overall_risk)"          -ForegroundColor Cyan
    Write-Host "  Findings        : $($Findings.Count)"                -ForegroundColor Cyan
    Write-Host "  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)" -ForegroundColor Cyan
    Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Main -- skipped when dot-sourced (InvocationName is '.' when dot-sourced)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $result    = Get-LapsFindings
    $findings  = @($result.findings)
    $summary   = $result.summary

    $reportData = @{
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        summary      = $summary
        findings     = $findings
    }

    switch ($Format) {
        'json' {
            Write-JsonReport -ReportData $reportData -Path "$Output.json"
            Write-Host "JSON report: $Output.json"
        }
        'csv' {
            Write-CsvReport -Findings $findings -Path "$Output.csv"
            Write-Host "CSV report: $Output.csv"
        }
        'html' {
            Write-HtmlReport -Findings $findings -Summary $summary -Path "$Output.html"
            Write-Host "HTML report: $Output.html"
        }
        'all' {
            Write-JsonReport -ReportData $reportData -Path "$Output.json"
            Write-CsvReport -Findings $findings -Path "$Output.csv"
            Write-HtmlReport -Findings $findings -Summary $summary -Path "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $findings -Summary $summary
}
