<#
.SYNOPSIS
    Audits BitLocker encryption status on all fixed drives.
.DESCRIPTION
    Read-only audit of BitLocker drive encryption using Get-BitLockerVolume.
    Checks protection status, encryption method strength, and key protector types
    on all fixed (non-removable) drives. Unencrypted drives and weak encryption
    methods are flagged for remediation.
.PARAMETER Output
    Output file prefix (default: bitlocker_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.EXAMPLE
    .\bitlocker_auditor.ps1
    .\bitlocker_auditor.ps1 -Format html
    .\bitlocker_auditor.ps1 -Output bl_report -Format json
#>
param(
    [string]$Output = 'bitlocker_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all'
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# BitLocker cmdlet stubs — overridden at runtime; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-BitLockerVolume' -ErrorAction SilentlyContinue)) {
    function Get-BitLockerVolume {
        @()
    }
}
if (-not (Get-Command -Name 'Get-Volume' -ErrorAction SilentlyContinue)) {
    function Get-Volume {
        @()
    }
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Encryption methods considered strong (XTS-AES preferred)
$STRONG_METHODS = @('XtsAes256','XtsAes128','Aes256')
# Weak methods — AES128 is below current NIST guidance
$WEAK_METHODS   = @('Aes128','TripleDes')

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
function Get-DriveFindings {
    param([object]$Volume)

    $mountPoint       = $Volume.MountPoint
    $volumeStatus     = $Volume.VolumeStatus        # e.g. FullyEncrypted, FullyDecrypted
    $protectionStatus = $Volume.ProtectionStatus    # On, Off
    $encryptionMethod = $Volume.EncryptionMethod    # XtsAes256, Aes128, None, etc.
    $keyProtectors    = @($Volume.KeyProtector | ForEach-Object { $_.KeyProtectorType })

    $score = 0
    $flags = [System.Collections.Generic.List[string]]::new()
    $rems  = [System.Collections.Generic.List[string]]::new()

    # Not encrypted / protection off
    if ($protectionStatus -ne 'On' -or $volumeStatus -eq 'FullyDecrypted' -or $volumeStatus -eq 'NotDecrypted') {
        $score += 8
        $flags.Add("❌ Drive $mountPoint is not encrypted (BitLocker protection is Off)")
        $rems.Add("Enable-BitLocker -MountPoint `"$mountPoint`" -EncryptionMethod XtsAes256 -UsedSpaceOnly `$false")
    } elseif ($encryptionMethod -in $WEAK_METHODS) {
        $score += 4
        $flags.Add("⚠️ Drive $mountPoint uses weak encryption method: $encryptionMethod (prefer XtsAes256)")
        $rems.Add("Re-encrypt with stronger method: manage-bde -on $mountPoint -EncryptionMethod XtsAes256 (requires decrypt first)")
    } elseif ($encryptionMethod -notin $STRONG_METHODS -and $encryptionMethod -ne 'None') {
        $score += 2
        $flags.Add("ℹ️ Drive $mountPoint encryption method: $encryptionMethod (verify this meets policy)")
        $rems.Add("Review encryption method policy and consider re-encrypting with XtsAes256")
    }

    # No TPM protector
    if ($protectionStatus -eq 'On' -and 'Tpm' -notin $keyProtectors -and 'TpmPin' -notin $keyProtectors -and 'TpmNetworkKey' -notin $keyProtectors) {
        $score += 2
        $flags.Add("⚠️ Drive $mountPoint has no TPM key protector (password-only is less secure)")
        $rems.Add("Add a TPM protector: Add-BitLockerKeyProtector -MountPoint `"$mountPoint`" -TpmProtector")
    }

    # No recovery key / recovery password
    if ($protectionStatus -eq 'On' -and 'RecoveryPassword' -notin $keyProtectors -and 'RecoveryKey' -notin $keyProtectors) {
        $score += 1
        $flags.Add("ℹ️ Drive $mountPoint has no recovery password protector")
        $rems.Add("Add a recovery password: Add-BitLockerKeyProtector -MountPoint `"$mountPoint`" -RecoveryPasswordProtector")
    }

    if ($flags.Count -eq 0) {
        $flags.Add("✅ Drive ${mountPoint}: BitLocker on, strong encryption (${encryptionMethod})")
        $rems.Add('')
    }

    return [ordered]@{
        mount_point       = $mountPoint
        protection_status = $protectionStatus
        volume_status     = $volumeStatus
        encryption_method = $encryptionMethod
        key_protectors    = $keyProtectors
        severity_score    = [Math]::Min($score, 10)
        risk_level        = Get-SeverityLabel -Score ([Math]::Min($score, 10))
        flags             = @($flags)
        remediations      = @($rems)
    }
}

function Invoke-BitLockerAudit {
    $hostname = $env:COMPUTERNAME
    $volumes  = Get-BitLockerVolume
    $findings = [System.Collections.Generic.List[object]]::new()

    if (-not $volumes -or @($volumes).Count -eq 0) {
        # No volumes returned — likely not running as admin or BitLocker not available
        $findings.Add([ordered]@{
            mount_point       = 'N/A'
            protection_status = 'Unknown'
            volume_status     = 'Unknown'
            encryption_method = 'Unknown'
            key_protectors    = @()
            severity_score    = 5
            risk_level        = 'HIGH'
            flags             = @('⚠️ No BitLocker volumes found — run as administrator or BitLocker may not be enabled')
            remediations      = @('Run as administrator. Install BitLocker feature if not present: Install-WindowsFeature BitLocker -IncludeManagementTools')
        })
    } else {
        foreach ($vol in $volumes) {
            $findings.Add((Get-DriveFindings -Volume $vol))
        }
    }

    $maxScore = ($findings | ForEach-Object { $_.severity_score } | Measure-Object -Maximum).Maximum
    if ($null -eq $maxScore) { $maxScore = 0 }
    $overallRisk = Get-SeverityLabel -Score $maxScore

    $summary = @{
        hostname       = $hostname
        total_drives   = $findings.Count
        encrypted      = @($findings | Where-Object { $_.protection_status -eq 'On' }).Count
        not_encrypted  = @($findings | Where-Object { $_.protection_status -ne 'On' }).Count
        overall_score  = $maxScore
        overall_risk   = $overallRisk
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
            mount_point       = $_.mount_point
            protection_status = $_.protection_status
            volume_status     = $_.volume_status
            encryption_method = $_.encryption_method
            key_protectors    = ($_.key_protectors -join ',')
            severity_score    = $_.severity_score
            risk_level        = $_.risk_level
            flags             = ($_.flags -join ' | ')
            remediations      = ($_.remediations -join ' | ')
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Set-RestrictedPermissions -Path $Path
}

function Write-HtmlReport {
    param([PSCustomObject]$Report, [string]$Path)
    $s      = $Report.summary
    $colour = Get-SeverityColour -Severity $s.overall_risk

    $rows = ''
    foreach ($f in ($Report.findings | Sort-Object severity_score -Descending)) {
        $fc     = Get-SeverityColour -Severity $f.risk_level
        $flagsH = ($f.flags | ForEach-Object { [System.Web.HttpUtility]::HtmlEncode($_) }) -join '<br>'
        $rows  += "<tr>"
        $rows  += "<td>$([System.Web.HttpUtility]::HtmlEncode($f.mount_point))</td>"
        $rows  += "<td>$([System.Web.HttpUtility]::HtmlEncode($f.protection_status))</td>"
        $rows  += "<td>$([System.Web.HttpUtility]::HtmlEncode($f.encryption_method))</td>"
        $rows  += "<td style='color:$fc;font-weight:bold'>$([System.Web.HttpUtility]::HtmlEncode($f.risk_level))</td>"
        $rows  += "<td>$([System.Web.HttpUtility]::HtmlEncode($f.severity_score))</td>"
        $rows  += "<td style='font-size:0.85em'>$flagsH</td>"
        $rows  += "</tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BitLocker Audit Report</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}
  .header h1{margin:0;font-size:1.8em}
  .cards{display:flex;gap:16px;flex-wrap:wrap;padding:20px 40px}
  .card{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 2px 8px rgba(0,0,0,0.08);min-width:130px;text-align:center}
  .val{font-size:2em;font-weight:bold}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
  td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
  .footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style>
</head>
<body>
<div class='header'><h1>🔒 BitLocker Audit Report</h1></div>
<div class="cards">
  <div class="card"><div class="val" style="color:$colour">$([System.Web.HttpUtility]::HtmlEncode($s.overall_risk))</div>Overall Risk</div>
  <div class="card"><div class="val">$($s.total_drives)</div>Drives</div>
  <div class="card"><div class="val" style="color:#28a745">$($s.encrypted)</div>Encrypted</div>
  <div class="card"><div class="val" style="color:#dc3545">$($s.not_encrypted)</div>Not Encrypted</div>
</div>
<table>
<tr><th>Drive</th><th>Protection</th><th>Encryption Method</th><th>Risk</th><th>Score</th><th>Flags</th></tr>
$rows
</table>
<div class="footer">Generated: $([System.Web.HttpUtility]::HtmlEncode($Report.generated_at)) | BitLocker Auditor | Host: $([System.Web.HttpUtility]::HtmlEncode($s.hostname))</div>
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
    $report = Invoke-BitLockerAudit

    if ($Format -eq 'stdout') {
        $report | ConvertTo-Json -Depth 10
        exit 0
    }

    if ($Format -in 'json','all') { Write-JsonReport  -Report $report -Path "$Output.json" }
    if ($Format -in 'csv','all')  { Write-CsvReport   -Report $report -Path "$Output.csv"  }
    if ($Format -in 'html','all') { Write-HtmlReport  -Report $report -Path "$Output.html" }
}
