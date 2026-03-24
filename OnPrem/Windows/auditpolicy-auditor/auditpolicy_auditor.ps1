<#
.SYNOPSIS
    Audits Windows audit policy configuration against security baselines.
.DESCRIPTION
    Read-only audit of Windows audit policy subcategories using auditpol.exe.
    Checks that critical subcategories are set to capture Success and/or Failure
    events as required by CIS and security baselines. Missing audit policies mean
    attacker activity (logons, privilege use, process execution) goes undetected.
.PARAMETER Output
    Output file prefix (default: auditpolicy_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.EXAMPLE
    .\auditpolicy_auditor.ps1
    .\auditpolicy_auditor.ps1 -Format html
#>
param(
    [string]$Output = 'auditpolicy_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all'
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# auditpol stub — overridden at runtime; Pester mocks this function
# ---------------------------------------------------------------------------
function Invoke-Auditpol {
    # Returns CSV lines from: auditpol.exe /get /category:* /r
    $result = & auditpol.exe /get /category:* /r 2>&1
    return $result
}

# ---------------------------------------------------------------------------
# Required audit subcategories
# Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
# ---------------------------------------------------------------------------
$REQUIRED_SUBCATEGORIES = @(
    # [Subcategory, RequiredSetting, Severity, Reason]
    @{ Name='Logon';                  Required='Success and Failure'; Score=4; Reason='Track logon events — brute force, lateral movement' }
    @{ Name='Logoff';                 Required='Success';             Score=2; Reason='Track session ends — required for correlation' }
    @{ Name='Account Lockout';        Required='Failure';             Score=3; Reason='Detect brute force attacks' }
    @{ Name='Special Logon';          Required='Success';             Score=3; Reason='Track administrator logons and privilege use' }
    @{ Name='Credential Validation';  Required='Success and Failure'; Score=3; Reason='Detect credential stuffing and NTLM usage' }
    @{ Name='Kerberos Authentication Service'; Required='Failure';    Score=3; Reason='Detect Kerberos attacks (AS-REP roasting)' }
    @{ Name='Kerberos Service Ticket Operations'; Required='Failure'; Score=3; Reason='Detect Kerberoasting and ticket abuse' }
    @{ Name='Process Creation';       Required='Success';             Score=4; Reason='Track all processes — malware execution detection' }
    @{ Name='Audit Policy Change';    Required='Success';             Score=3; Reason='Detect tampering with audit settings' }
    @{ Name='Authentication Policy Change'; Required='Success';       Score=2; Reason='Track domain policy changes' }
    @{ Name='Sensitive Privilege Use';Required='Success and Failure'; Score=3; Reason='Detect privilege abuse (SeDebugPrivilege etc.)' }
    @{ Name='Security System Extension'; Required='Success';          Score=2; Reason='Track driver and service installation' }
    @{ Name='User Account Management';Required='Success and Failure'; Score=3; Reason='Track account creation, deletion, modification' }
    @{ Name='Security Group Management'; Required='Success';          Score=2; Reason='Track group membership changes' }
    @{ Name='Object Access';          Required='Failure';             Score=2; Reason='Detect access violations on sensitive objects' }
)

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
function Get-SeverityLabel {
    param([int]$Score)
    if ($Score -ge 8) { return 'CRITICAL' }
    if ($Score -ge 5) { return 'HIGH' }
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
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'Allow'
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
    }
}

# ---------------------------------------------------------------------------
# Audit logic
# ---------------------------------------------------------------------------
function Get-AuditPolicyMap {
    <#
    Parse auditpol /get /category:* /r CSV output.
    Returns hashtable: SubcategoryName → InclusionSetting
    #>
    $lines = Invoke-Auditpol
    $map   = @{}
    $header = $true
    foreach ($line in $lines) {
        if ($header) { $header = $false; continue }  # skip header row
        $parts = $line -split ','
        if ($parts.Count -ge 5) {
            $subcategory = $parts[2].Trim().Trim('"')
            $setting     = $parts[4].Trim().Trim('"')
            if ($subcategory) { $map[$subcategory] = $setting }
        }
    }
    return $map
}

function Test-AuditSubcategory {
    param([string]$Current, [string]$Required)
    # Acceptable if current includes the required events
    $c = $Current.ToLower()
    $r = $Required.ToLower()
    if ($r -eq 'success and failure') {
        return ($c -eq 'success and failure')
    }
    if ($r -eq 'success') {
        return ($c -eq 'success' -or $c -eq 'success and failure')
    }
    if ($r -eq 'failure') {
        return ($c -eq 'failure' -or $c -eq 'success and failure')
    }
    return $false
}

function Invoke-AuditPolicyAudit {
    $policyMap = Get-AuditPolicyMap
    $findings  = [System.Collections.Generic.List[object]]::new()
    $hostname  = $env:COMPUTERNAME
    $totalScore = 0

    foreach ($req in $REQUIRED_SUBCATEGORIES) {
        $current = $policyMap[$req.Name]
        if ($null -eq $current) { $current = 'No Auditing' }

        $compliant = Test-AuditSubcategory -Current $current -Required $req.Required
        $itemScore = if ($compliant) { 0 } else { $req.Score }
        $totalScore += $itemScore

        $flags = [System.Collections.Generic.List[string]]::new()
        $rems  = [System.Collections.Generic.List[string]]::new()

        if ($compliant) {
            $flags.Add("✅ $($req.Name): $current")
            $rems.Add('')
        } else {
            $prefix = if ($req.Score -ge 4) { '❌' } elseif ($req.Score -ge 3) { '⚠️' } else { 'ℹ️' }
            $flags.Add("$prefix $($req.Name): '$current' (required: $($req.Required)) — $($req.Reason)")
            $rems.Add("auditpol.exe /set /subcategory:`"$($req.Name)`" /success:enable /failure:enable")
        }

        $findings.Add([ordered]@{
            subcategory     = $req.Name
            current_setting = $current
            required        = $req.Required
            compliant       = $compliant
            severity_score  = $itemScore
            risk_level      = Get-SeverityLabel -Score $itemScore
            flags           = @($flags)
            remediations    = @($rems)
        })
    }

    $clampedScore = [Math]::Min($totalScore, 10)
    $overallRisk  = Get-SeverityLabel -Score $clampedScore

    $summary = @{
        hostname         = $hostname
        total_checks     = $findings.Count
        compliant        = @($findings | Where-Object { $_.compliant }).Count
        non_compliant    = @($findings | Where-Object { -not $_.compliant }).Count
        overall_score    = $clampedScore
        overall_risk     = $overallRisk
    }

    return [PSCustomObject]@{
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        summary      = $summary
        findings     = @($findings)
    }
}

# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------
function Write-JsonReport {
    param([PSCustomObject]$Report, [string]$Path)
    $Report | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
    Set-RestrictedPermissions -Path $Path
}

function Write-CsvReport {
    param([PSCustomObject]$Report, [string]$Path)
    $rows = $Report.findings | ForEach-Object {
        [PSCustomObject]@{
            subcategory     = $_.subcategory
            current_setting = $_.current_setting
            required        = $_.required
            compliant       = $_.compliant
            severity_score  = $_.severity_score
            risk_level      = $_.risk_level
            flags           = ($_.flags -join ' | ')
            remediations    = ($_.remediations -join ' | ')
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Set-RestrictedPermissions -Path $Path
}

function Write-HtmlReport {
    param([PSCustomObject]$Report, [string]$Path)
    $s = $Report.summary
    $colour = Get-SeverityColour -Severity $s.overall_risk

    $rows = ''
    foreach ($f in ($Report.findings | Sort-Object severity_score -Descending)) {
        $fc     = Get-SeverityColour -Severity $f.risk_level
        $tick   = if ($f.compliant) { '✅' } else { '❌' }
        $flagsH = ($f.flags | ForEach-Object { [System.Web.HttpUtility]::HtmlEncode($_) }) -join '<br>'
        $rows  += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($f.subcategory))</td>"
        $rows  += "<td>$([System.Web.HttpUtility]::HtmlEncode($f.current_setting))</td>"
        $rows  += "<td>$([System.Web.HttpUtility]::HtmlEncode($f.required))</td>"
        $rows  += "<td>$tick</td>"
        $rows  += "<td style='color:$fc;font-weight:bold'>$([System.Web.HttpUtility]::HtmlEncode($f.risk_level))</td>"
        $rows  += "<td style='font-size:0.85em'>$flagsH</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Audit Policy Report</title>
<style>
  body{font-family:Arial,sans-serif;margin:24px;background:#f8f9fa}
  h1{color:#212529}
  .card{background:#fff;border-radius:8px;padding:20px 28px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:24px;display:inline-block;min-width:140px;text-align:center}
  .val{font-size:2em;font-weight:bold}
  .cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}
  th{background:#343a40;color:#fff;padding:10px 12px;text-align:left}
  td{padding:8px 12px;border-bottom:1px solid #dee2e6;vertical-align:top}
  .footer{margin-top:16px;color:#6c757d;font-size:0.85em}
</style>
</head>
<body>
<h1>📋 Windows Audit Policy Report</h1>
<div class="cards">
  <div class="card"><div class="val" style="color:$colour">$([System.Web.HttpUtility]::HtmlEncode($s.overall_risk))</div>Overall Risk</div>
  <div class="card"><div class="val">$($s.total_checks)</div>Checks</div>
  <div class="card"><div class="val" style="color:#28a745">$($s.compliant)</div>Compliant</div>
  <div class="card"><div class="val" style="color:#dc3545">$($s.non_compliant)</div>Non-Compliant</div>
</div>
<table>
<tr><th>Subcategory</th><th>Current</th><th>Required</th><th>OK</th><th>Risk</th><th>Flags</th></tr>
$rows
</table>
<div class="footer">Generated: $([System.Web.HttpUtility]::HtmlEncode($Report.generated_at)) | Windows Audit Policy Auditor | Host: $([System.Web.HttpUtility]::HtmlEncode($s.hostname))</div>
</body>
</html>
"@
    $html | Set-Content -Path $Path -Encoding UTF8
    Set-RestrictedPermissions -Path $Path
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $report = Invoke-AuditPolicyAudit

    if ($Format -eq 'stdout') {
        $report | ConvertTo-Json -Depth 10
        exit 0
    }

    if ($Format -in 'json','all') { Write-JsonReport  -Report $report -Path "$Output.json" }
    if ($Format -in 'csv','all')  { Write-CsvReport   -Report $report -Path "$Output.csv"  }
    if ($Format -in 'html','all') { Write-HtmlReport  -Report $report -Path "$Output.html" }
}
