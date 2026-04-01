<#
.SYNOPSIS
    Audits Windows Firewall configuration for security compliance.
.DESCRIPTION
    Read-only audit of Windows Firewall profiles and rules. Flags disabled
    profiles, permissive default actions, missing logging, and dangerous
    inbound rules such as RDP, WinRM, and SMB open to all remote addresses.
.PARAMETER Output
    Output file prefix (default: winfirewall_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.EXAMPLE
    .\winfirewall_auditor.ps1
    .\winfirewall_auditor.ps1 -Format html
    .\winfirewall_auditor.ps1 -Output my_report -Format csv
#>
param(
    [string]$Output = 'winfirewall_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all'
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# NetSecurity module stubs — overridden by real cmdlets at runtime;
# Pester Mocks these during testing
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-NetFirewallRule' -ErrorAction SilentlyContinue)) {
    function Get-NetFirewallRule {
        param(
            [string]$Direction,
            $Enabled,
            $Action
        )
        @()
    }
    function Get-NetFirewallPortFilter {
        param($AssociatedNetFirewallRule)
        [PSCustomObject]@{ LocalPort = 'Any'; Protocol = 'Any' }
    }
    function Get-NetFirewallAddressFilter {
        param($AssociatedNetFirewallRule)
        [PSCustomObject]@{ RemoteAddress = 'Any' }
    }
    function Get-NetFirewallProfile {
        @()
    }
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
# Main audit function
# ---------------------------------------------------------------------------
function Get-FirewallFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ------------------------------------------------------------------
    # Profile-level checks
    # ------------------------------------------------------------------
    $profiles = @(Get-NetFirewallProfile)

    foreach ($profile in $profiles) {
        # 1. FirewallProfileDisabled — profile not enabled
        if ($profile.Enabled -eq $false) {
            $score = 9
            $findings.Add([PSCustomObject]@{
                FindingType     = 'FirewallProfileDisabled'
                Profile         = $profile.Name
                RuleName        = ''
                Port            = ''
                Score           = $score
                Severity        = (Get-SeverityLabel $score)
                Recommendation  = "Enable the Windows Firewall for the '$($profile.Name)' profile. A disabled firewall profile leaves the host completely unprotected by host-based packet filtering."
            })
        }

        # 2. InboundDefaultAllow — inbound default action is Allow
        if ($profile.DefaultInboundAction -eq 'Allow') {
            $score = 8
            $findings.Add([PSCustomObject]@{
                FindingType     = 'InboundDefaultAllow'
                Profile         = $profile.Name
                RuleName        = ''
                Port            = ''
                Score           = $score
                Severity        = (Get-SeverityLabel $score)
                Recommendation  = "Set the default inbound action to 'Block' for the '$($profile.Name)' profile. An allow-by-default inbound posture permits all unsolicited inbound connections unless explicitly blocked."
            })
        }

        # 3. OutboundDefaultAllow — outbound default action is Allow
        if ($profile.DefaultOutboundAction -eq 'Allow') {
            $score = 2
            $findings.Add([PSCustomObject]@{
                FindingType     = 'OutboundDefaultAllow'
                Profile         = $profile.Name
                RuleName        = ''
                Port            = ''
                Score           = $score
                Severity        = (Get-SeverityLabel $score)
                Recommendation  = "Consider setting the default outbound action to 'Block' for the '$($profile.Name)' profile and creating explicit allow rules for required outbound traffic to limit blast radius on compromise."
            })
        }

        # 4. NoLogDroppedPackets — dropped packets are not being logged
        if ($profile.LogBlocked -eq $false) {
            $score = 4
            $findings.Add([PSCustomObject]@{
                FindingType     = 'NoLogDroppedPackets'
                Profile         = $profile.Name
                RuleName        = ''
                Port            = ''
                Score           = $score
                Severity        = (Get-SeverityLabel $score)
                Recommendation  = "Enable logging of dropped packets for the '$($profile.Name)' profile. Without this, blocked connection attempts are invisible to defenders and forensic investigators."
            })
        }
    }

    # ------------------------------------------------------------------
    # Rule-level checks — enumerate enabled inbound Allow rules
    # ------------------------------------------------------------------
    $inboundAllowRules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow)

    $allowAllCount = 0

    foreach ($rule in $inboundAllowRules) {
        $portFilter    = Get-NetFirewallPortFilter    -AssociatedNetFirewallRule $rule.Name
        $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule.Name

        $localPort     = $portFilter.LocalPort
        $protocol      = $portFilter.Protocol
        $remoteAddress = $addressFilter.RemoteAddress

        # Track rules open to any remote address for the TooManyAllowAllRules check
        if ($remoteAddress -eq 'Any') {
            $allowAllCount++
        }

        # 5. RDPOpenToAll — RDP (3389) inbound open to all remote addresses
        if ($localPort -eq '3389' -and $remoteAddress -eq 'Any') {
            $score = 10
            $findings.Add([PSCustomObject]@{
                FindingType     = 'RDPOpenToAll'
                Profile         = $rule.Profile
                RuleName        = $rule.Name
                Port            = '3389'
                Score           = $score
                Severity        = (Get-SeverityLabel $score)
                Recommendation  = "Restrict the RDP firewall rule '$($rule.Name)' to specific trusted IP addresses or subnets. RDP exposed to all remote addresses is the leading vector for ransomware and brute-force attacks."
            })
        }

        # 6. WinRMOpenToAll — WinRM (5985/5986) inbound open to all remote addresses
        if (($localPort -eq '5985' -or $localPort -eq '5986') -and $remoteAddress -eq 'Any') {
            $score = 9
            $findings.Add([PSCustomObject]@{
                FindingType     = 'WinRMOpenToAll'
                Profile         = $rule.Profile
                RuleName        = $rule.Name
                Port            = $localPort
                Score           = $score
                Severity        = (Get-SeverityLabel $score)
                Recommendation  = "Restrict the WinRM firewall rule '$($rule.Name)' to specific management hosts. WinRM open to all remote addresses allows remote command execution from any network location."
            })
        }

        # 7. SMBOpenToAll — SMB (445) inbound open to all, outside Domain profile
        if ($localPort -eq '445' -and $remoteAddress -eq 'Any' -and $rule.Profile -ne 'Domain') {
            $score = 9
            $findings.Add([PSCustomObject]@{
                FindingType     = 'SMBOpenToAll'
                Profile         = $rule.Profile
                RuleName        = $rule.Name
                Port            = '445'
                Score           = $score
                Severity        = (Get-SeverityLabel $score)
                Recommendation  = "Restrict or disable the SMB firewall rule '$($rule.Name)' on non-Domain profiles. SMB open to all remote addresses on Public/Private profiles exposes the host to lateral movement and ransomware propagation."
            })
        }

        # 8. ICMPEchoPublicOpen — ICMP echo inbound on Public profile open to all
        $isIcmpProtocol = ($protocol -eq 'ICMPv4' -or $protocol -eq 'ICMPv6')
        $isPublicProfile = ($rule.Profile -eq 'Public' -or $rule.Profile -like '*Public*')
        if ($isIcmpProtocol -and $isPublicProfile -and $remoteAddress -eq 'Any') {
            $score = 2
            $findings.Add([PSCustomObject]@{
                FindingType     = 'ICMPEchoPublicOpen'
                Profile         = $rule.Profile
                RuleName        = $rule.Name
                Port            = $protocol
                Score           = $score
                Severity        = (Get-SeverityLabel $score)
                Recommendation  = "Consider restricting ICMP echo replies on the Public profile. While low severity, allowing ICMP echo from any address on Public networks aids host discovery by adversaries."
            })
        }
    }

    # 9. TooManyAllowAllRules — more than 10 enabled inbound Allow rules open to Any
    if ($allowAllCount -gt 10) {
        $score = 5
        $findings.Add([PSCustomObject]@{
            FindingType     = 'TooManyAllowAllRules'
            Profile         = 'Any'
            RuleName        = ''
            Port            = ''
            Score           = $score
            Severity        = (Get-SeverityLabel $score)
            Recommendation  = "Review and reduce the $allowAllCount inbound Allow rules with RemoteAddress='Any'. Excess permissive rules indicate firewall policy bloat and increase the attack surface. Restrict each rule to the minimum required source addresses."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [string]$Hostname  = $env:COMPUTERNAME,
        [string]$ScannedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $Findings) {
        $colour   = Get-SeverityColour $f.Severity
        $resource = if ($f.RuleName) { $f.RuleName } elseif ($f.Profile) { $f.Profile } else { 'N/A' }
        $portCell = if ($f.Port) { $f.Port } else { '—' }
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($portCell))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Windows Firewall Audit Report</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}
  .header h1{margin:0;font-size:1.8em}
  .header p{margin:5px 0 0;opacity:0.8}
  .summary{display:flex;gap:20px;padding:20px 40px;flex-wrap:wrap}
  .card{background:#fff;border-radius:8px;padding:20px 30px;flex:1;min-width:140px;box-shadow:0 2px 8px rgba(0,0,0,0.08);text-align:center}
  .card .num{font-size:2.5em;font-weight:bold}.card .lbl{color:#666;font-size:.85em;margin-top:4px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
  td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
  code{background:#ecf0f1;padding:2px 5px;border-radius:3px;font-size:0.85em}
  .footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style></head><body>
<div class='header'>
<h1>Windows Firewall Audit Report</h1>
<p>Host: $([System.Web.HttpUtility]::HtmlEncode($Hostname)) &nbsp;|&nbsp; Generated: $ScannedAt</p>
</div>
<div class='summary'>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
</div>
<table><thead><tr>
  <th>Profile/Rule</th><th>Finding</th><th>Severity</th>
  <th>Port</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
}

function ConvertTo-CsvReport {
    param([Parameter(Mandatory)][array]$Findings)
    $Findings | Select-Object `
        FindingType,
        Profile,
        RuleName,
        Port,
        Score,
        Severity,
        Recommendation |
        ConvertTo-Csv -NoTypeInformation
}

function Write-TerminalSummary {
    param([array]$Findings)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $top3 = $Findings | Sort-Object Score -Descending | Select-Object -First 3

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║      WINDOWS FIREWALL AUDIT COMPLETE             ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Host           : $($env:COMPUTERNAME.PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  Total findings : $($Findings.Count.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    if ($top3) {
        Write-Host '║  Top findings:                                   ║' -ForegroundColor Cyan
        foreach ($f in $top3) {
            $detail = if ($f.RuleName) { $f.RuleName } else { $f.Profile }
            $line   = "  [$($f.Severity)] $($f.FindingType): $detail"
            Write-Host "║  $($line.PadRight(47))║" -ForegroundColor Cyan
        }
    }
    Write-Host '╚══════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Main — skipped when dot-sourced (InvocationName is '.' when dot-sourced)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    # Check that the NetSecurity module is available
    if (-not (Get-Module -ListAvailable -Name 'NetSecurity')) {
        Write-Warning "Module 'NetSecurity' is not available on this system. Firewall cmdlets may not return real data."
    }

    $allFindings = Get-FirewallFindings

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $reportData = @{
        generated_at = $timestamp
        hostname     = $env:COMPUTERNAME
        findings     = $allFindings
        summary      = @{
            total    = $allFindings.Count
            critical = @($allFindings | Where-Object Severity -eq 'CRITICAL').Count
            high     = @($allFindings | Where-Object Severity -eq 'HIGH').Count
            medium   = @($allFindings | Where-Object Severity -eq 'MEDIUM').Count
            low      = @($allFindings | Where-Object Severity -eq 'LOW').Count
        }
    }

    switch ($Format) {
        'json'   {
            $reportData | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
            Set-RestrictedPermissions "$Output.json"
            Write-Host "JSON report: $Output.json"
        }
        'csv'    {
            ConvertTo-CsvReport $allFindings | Out-File "$Output.csv" -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            Write-Host "CSV report: $Output.csv"
        }
        'html'   {
            ConvertTo-HtmlReport -Findings $allFindings -Hostname $env:COMPUTERNAME -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "HTML report: $Output.html"
        }
        'all'    {
            $reportData | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
            Set-RestrictedPermissions "$Output.json"
            ConvertTo-CsvReport $allFindings | Out-File "$Output.csv" -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            ConvertTo-HtmlReport -Findings $allFindings -Hostname $env:COMPUTERNAME -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $allFindings
}
