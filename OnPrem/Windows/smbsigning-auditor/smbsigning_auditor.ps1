<#
.SYNOPSIS
    Audits SMB signing configuration on Windows server and client.
.DESCRIPTION
    Read-only audit of SMB signing settings. Checks whether the server
    requires SMB signing (RequireSecuritySignature) and whether the client
    has SMB signing enabled and required. Missing server-side enforcement
    allows NTLM relay attacks.
.PARAMETER Output
    Output file prefix (default: smbsigning_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.EXAMPLE
    .\smbsigning_auditor.ps1
    .\smbsigning_auditor.ps1 -Format html
    .\smbsigning_auditor.ps1 -Output smb_report -Format json
#>
param(
    [string]$Output = 'smbsigning_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all'
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# SMB cmdlet stubs — overridden by real module at runtime; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-SmbServerConfiguration' -ErrorAction SilentlyContinue)) {
    function Get-SmbServerConfiguration {
        [PSCustomObject]@{
            RequireSecuritySignature = $false
            EnableSecuritySignature  = $false
        }
    }
}
if (-not (Get-Command -Name 'Get-SmbClientConfiguration' -ErrorAction SilentlyContinue)) {
    function Get-SmbClientConfiguration {
        [PSCustomObject]@{
            RequireSecuritySignature = $false
            EnableSecuritySignature  = $false
        }
    }
}

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
function Get-SmbSigningStatus {
    $server = Get-SmbServerConfiguration
    $client = Get-SmbClientConfiguration

    return [PSCustomObject]@{
        ServerRequireSignature = [bool]$server.RequireSecuritySignature
        ServerEnableSignature  = [bool]$server.EnableSecuritySignature
        ClientRequireSignature = [bool]$client.RequireSecuritySignature
        ClientEnableSignature  = [bool]$client.EnableSecuritySignature
    }
}

function Get-Score {
    param([PSCustomObject]$Status)
    $score = 0
    if (-not $Status.ServerRequireSignature) { $score += 5 }
    if (-not $Status.ServerEnableSignature)  { $score += 2 }
    if (-not $Status.ClientRequireSignature) { $score += 2 }
    if (-not $Status.ClientEnableSignature)  { $score += 1 }
    return [Math]::Min($score, 10)
}

function Get-Flags {
    param([PSCustomObject]$Status)
    $flags = [System.Collections.Generic.List[string]]::new()
    $rems  = [System.Collections.Generic.List[string]]::new()

    if (-not $Status.ServerRequireSignature) {
        $flags.Add('❌ Server SMB signing not required — NTLM relay risk')
        $rems.Add('Set-SmbServerConfiguration -RequireSecuritySignature $true -Force')
    }
    if (-not $Status.ServerEnableSignature -and $Status.ServerRequireSignature) {
        $flags.Add('⚠️ Server SMB signing required but not enabled (inconsistent)')
        $rems.Add('Set-SmbServerConfiguration -EnableSecuritySignature $true -Force')
    }
    if (-not $Status.ClientRequireSignature) {
        $flags.Add('⚠️ Client SMB signing not required — relay attacks possible from client')
        $rems.Add('Set-SmbClientConfiguration -RequireSecuritySignature $true -Force')
    }
    if (-not $Status.ClientEnableSignature) {
        $flags.Add('ℹ️ Client SMB signing not enabled')
        $rems.Add('Set-SmbClientConfiguration -EnableSecuritySignature $true -Force')
    }
    if ($flags.Count -eq 0) {
        $flags.Add('✅ SMB signing required on both server and client')
        $rems.Add('')
    }
    return $flags, $rems
}

function Invoke-SmbSigningAudit {
    $status  = Get-SmbSigningStatus
    $score   = Get-Score -Status $status
    $severity = Get-SeverityLabel -Score $score
    $flagsRems = Get-Flags -Status $status
    $flags   = $flagsRems[0]
    $rems    = $flagsRems[1]
    $hostname = $env:COMPUTERNAME

    $finding = [ordered]@{
        hostname                = $hostname
        server_require_signing  = $status.ServerRequireSignature
        server_enable_signing   = $status.ServerEnableSignature
        client_require_signing  = $status.ClientRequireSignature
        client_enable_signing   = $status.ClientEnableSignature
        severity_score          = $score
        risk_level              = $severity
        flags                   = @($flags)
        remediations            = @($rems)
    }

    $summary = @{
        hostname               = $hostname
        server_require_signing = $status.ServerRequireSignature
        client_require_signing = $status.ClientRequireSignature
        risk_level             = $severity
        severity_score         = $score
    }

    return [PSCustomObject]@{
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        summary      = $summary
        findings     = @($finding)
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
            hostname               = $_.hostname
            server_require_signing = $_.server_require_signing
            server_enable_signing  = $_.server_enable_signing
            client_require_signing = $_.client_require_signing
            client_enable_signing  = $_.client_enable_signing
            severity_score         = $_.severity_score
            risk_level             = $_.risk_level
            flags                  = ($_.flags -join ' | ')
            remediations           = ($_.remediations -join ' | ')
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Set-RestrictedPermissions -Path $Path
}

function Write-HtmlReport {
    param([PSCustomObject]$Report, [string]$Path)
    $f       = $Report.findings[0]
    $colour  = Get-SeverityColour -Severity $f.risk_level
    $flagsHtml = ($f.flags | ForEach-Object { [System.Web.HttpUtility]::HtmlEncode($_) }) -join '<br>'

    $yesNo = { param($v) if ($v) { '✅ Yes' } else { '❌ No' } }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SMB Signing Audit Report</title>
<style>
  body{font-family:Arial,sans-serif;margin:24px;background:#f8f9fa}
  h1{color:#212529}
  .card{background:#fff;border-radius:8px;padding:20px 28px;box-shadow:0 1px 4px rgba(0,0,0,.1);max-width:600px;margin-bottom:24px}
  .score{font-size:2.5em;font-weight:bold;color:$colour}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}
  th{background:#343a40;color:#fff;padding:10px 12px;text-align:left}
  td{padding:8px 12px;border-bottom:1px solid #dee2e6;vertical-align:top}
  .footer{margin-top:16px;color:#6c757d;font-size:0.85em}
</style>
</head>
<body>
<h1>🔐 SMB Signing Audit Report</h1>
<div class="card">
  <div>Host: <strong>$([System.Web.HttpUtility]::HtmlEncode($f.hostname))</strong></div>
  <div class="score">$([System.Web.HttpUtility]::HtmlEncode($f.risk_level)) &nbsp; ($($f.severity_score)/10)</div>
</div>
<table>
  <tr><th>Check</th><th>Status</th></tr>
  <tr><td>Server: SMB signing required</td><td>$(& $yesNo $f.server_require_signing)</td></tr>
  <tr><td>Server: SMB signing enabled</td><td>$(& $yesNo $f.server_enable_signing)</td></tr>
  <tr><td>Client: SMB signing required</td><td>$(& $yesNo $f.client_require_signing)</td></tr>
  <tr><td>Client: SMB signing enabled</td><td>$(& $yesNo $f.client_enable_signing)</td></tr>
</table>
<h2>Findings</h2>
<p>$flagsHtml</p>
<div class="footer">Generated: $([System.Web.HttpUtility]::HtmlEncode($Report.generated_at)) | SMB Signing Auditor</div>
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
    $report = Invoke-SmbSigningAudit

    if ($Format -eq 'stdout') {
        $report | ConvertTo-Json -Depth 10
        exit 0
    }

    if ($Format -in 'json','all') { Write-JsonReport  -Report $report -Path "$Output.json" }
    if ($Format -in 'csv','all')  { Write-CsvReport   -Report $report -Path "$Output.csv"  }
    if ($Format -in 'html','all') { Write-HtmlReport  -Report $report -Path "$Output.html" }
}
