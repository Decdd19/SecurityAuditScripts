<#
.SYNOPSIS
    Audits Windows local user accounts and related security configuration.
.DESCRIPTION
    Read-only audit of Windows local user hygiene and registry-based security settings.
    Flags guest account exposure, users without passwords, excessive local administrators,
    stale accounts, autologin configuration, credential caching weaknesses, and missing LAPS.
.PARAMETER Output
    Output file prefix (default: localuser_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.EXAMPLE
    .\localuser_auditor.ps1
    .\localuser_auditor.ps1 -Format html
    .\localuser_auditor.ps1 -Output my_report -Format csv
#>
param(
    [string]$Output = 'localuser_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all'
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# LocalUser / registry stubs — overridden by real modules at runtime; Pester Mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue)) {
    function Get-LocalUser { param($Name) @() }
    function Get-LocalGroup { @() }
    function Get-LocalGroupMember { param($Group) @() }
    function Get-Service { param($Name, [switch]$ErrorAction) $null }
    function Get-ItemProperty { param($Path, $Name, [switch]$ErrorAction) $null }
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
# Audit function
# ---------------------------------------------------------------------------
function Get-LocalUserFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ------------------------------------------------------------------
    # 1. GuestAccountEnabled — Guest account exists and is enabled
    # ------------------------------------------------------------------
    try {
        $guestUser = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guestUser -and $guestUser.Enabled -eq $true) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'GuestAccountEnabled'
                UserName       = 'Guest'
                GroupName      = ''
                Detail         = 'The built-in Guest account is enabled.'
                Score          = 8
                Severity       = (Get-SeverityLabel 8)
                Recommendation = "Disable the built-in Guest account: Disable-LocalUser -Name 'Guest'"
            })
        }
    } catch {
        Write-Warning "Could not check Guest account status: $_"
    }

    # ------------------------------------------------------------------
    # 2. LocalUserNoPassword — Enabled user with no password required
    # ------------------------------------------------------------------
    try {
        $allUsers = @(Get-LocalUser)
        foreach ($user in $allUsers) {
            if ($user.Enabled -eq $true -and $user.PasswordRequired -eq $false) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'LocalUserNoPassword'
                    UserName       = $user.Name
                    GroupName      = ''
                    Detail         = "User '$($user.Name)' does not require a password and is enabled."
                    Score          = 9
                    Severity       = (Get-SeverityLabel 9)
                    Recommendation = "Require a password for '$($user.Name)': Set-LocalUser -Name '$($user.Name)' -PasswordRequired `$true"
                })
            }
        }
    } catch {
        Write-Warning "Could not enumerate local users for password check: $_"
    }

    # ------------------------------------------------------------------
    # 3. LocalAdminPasswordNeverExpires — Admin group members with non-expiring password
    # ------------------------------------------------------------------
    try {
        $adminMembers = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
        foreach ($member in $adminMembers) {
            $memberName = $member.Name
            # Only check accounts that are actual local users (skip domain accounts, SIDs)
            $localUser = $null
            try {
                $shortName = $memberName -replace '^.*\\', ''
                $localUser = Get-LocalUser -Name $shortName -ErrorAction SilentlyContinue
            } catch { }

            if ($localUser -and $localUser.Enabled -eq $true -and $localUser.PasswordExpires -eq $false) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'LocalAdminPasswordNeverExpires'
                    UserName       = $localUser.Name
                    GroupName      = 'Administrators'
                    Detail         = "Administrator '$($localUser.Name)' has a password that never expires."
                    Score          = 7
                    Severity       = (Get-SeverityLabel 7)
                    Recommendation = "Configure a password expiration policy for '$($localUser.Name)' or enforce LAPS for local administrator accounts."
                })
            }
        }
    } catch {
        Write-Warning "Could not check admin password expiry: $_"
    }

    # ------------------------------------------------------------------
    # 4. ExcessiveLocalAdmins — More than 3 non-built-in members in Administrators
    # ------------------------------------------------------------------
    try {
        $adminMembers = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
        $nonBuiltIn = @($adminMembers | Where-Object {
            $_.Name -notlike '*\Administrator' -and
            $_.Name -notmatch '(?i)^Administrator$' -and
            $_.Name -notlike 'BUILTIN\*'
        })
        if ($nonBuiltIn.Count -gt 3) {
            $memberList = ($nonBuiltIn | ForEach-Object { $_.Name }) -join ', '
            $findings.Add([PSCustomObject]@{
                FindingType    = 'ExcessiveLocalAdmins'
                UserName       = ''
                GroupName      = 'Administrators'
                Detail         = "$($nonBuiltIn.Count) non-built-in members in Administrators group: $memberList"
                Score          = 6
                Severity       = (Get-SeverityLabel 6)
                Recommendation = 'Reduce the number of local administrators to the minimum required. Review each member and remove unnecessary accounts.'
            })
        }
    } catch {
        Write-Warning "Could not enumerate Administrators group members: $_"
    }

    # ------------------------------------------------------------------
    # 5. AdministratorAccountDefaultName — Built-in Administrator is enabled
    # ------------------------------------------------------------------
    try {
        $builtInAdmin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
        if ($builtInAdmin -and $builtInAdmin.Enabled -eq $true) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'AdministratorAccountDefaultName'
                UserName       = 'Administrator'
                GroupName      = ''
                Detail         = "The built-in 'Administrator' account is enabled with its default name."
                Score          = 5
                Severity       = (Get-SeverityLabel 5)
                Recommendation = "Rename and/or disable the built-in Administrator account to reduce attack surface: Rename-LocalUser -Name 'Administrator' -NewName '<custom_name>'"
            })
        }
    } catch {
        Write-Warning "Could not check built-in Administrator account: $_"
    }

    # ------------------------------------------------------------------
    # 6. StaleLocalUser — Enabled users with LastLogon older than 90 days
    # ------------------------------------------------------------------
    try {
        $allUsers = @(Get-LocalUser)
        $threshold = (Get-Date).AddDays(-90)
        foreach ($user in $allUsers) {
            if ($user.Enabled -eq $true -and
                $null -ne $user.LastLogon -and
                $user.LastLogon -lt $threshold) {
                $daysSince = [int]((Get-Date) - $user.LastLogon).TotalDays
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'StaleLocalUser'
                    UserName       = $user.Name
                    GroupName      = ''
                    Detail         = "User '$($user.Name)' last logged in $daysSince days ago ($(($user.LastLogon).ToString('yyyy-MM-dd')))."
                    Score          = 4
                    Severity       = (Get-SeverityLabel 4)
                    Recommendation = "Disable or remove the stale account '$($user.Name)': Disable-LocalUser -Name '$($user.Name)'"
                })
            }
        }
    } catch {
        Write-Warning "Could not check for stale local users: $_"
    }

    # ------------------------------------------------------------------
    # 7. AutologinEnabled — Registry AutoAdminLogon = '1'
    # ------------------------------------------------------------------
    try {
        $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $winlogonKey = Get-ItemProperty -Path $winlogonPath -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue
        if ($null -ne $winlogonKey -and $winlogonKey.AutoAdminLogon -eq '1') {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'AutologinEnabled'
                UserName       = ''
                GroupName      = ''
                Detail         = "Automatic logon is enabled via registry key AutoAdminLogon=1 at $winlogonPath"
                Score          = 9
                Severity       = (Get-SeverityLabel 9)
                Recommendation = "Disable automatic logon: set AutoAdminLogon to '0' or remove it from HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            })
        }
    } catch {
        Write-Warning "Could not check AutoAdminLogon registry value: $_"
    }

    # ------------------------------------------------------------------
    # 8. ClearTextPasswordInRegistry — DefaultPassword is non-null/non-empty
    # ------------------------------------------------------------------
    try {
        $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $defaultPwdKey = Get-ItemProperty -Path $winlogonPath -Name 'DefaultPassword' -ErrorAction SilentlyContinue
        if ($null -ne $defaultPwdKey -and
            $null -ne $defaultPwdKey.DefaultPassword -and
            $defaultPwdKey.DefaultPassword -ne '') {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'ClearTextPasswordInRegistry'
                UserName       = ''
                GroupName      = ''
                Detail         = "A clear-text password is stored in the registry at $winlogonPath (DefaultPassword)."
                Score          = 10
                Severity       = (Get-SeverityLabel 10)
                Recommendation = "Remove the DefaultPassword registry value immediately: Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword'"
            })
        }
    } catch {
        Write-Warning "Could not check DefaultPassword registry value: $_"
    }

    # ------------------------------------------------------------------
    # 9. WDigestAuthEnabled — UseLogonCredential = 1 enables plain-text caching
    # ------------------------------------------------------------------
    try {
        $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
        $wdigestKey = Get-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -ErrorAction SilentlyContinue
        if ($null -ne $wdigestKey -and $wdigestKey.UseLogonCredential -eq 1) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'WDigestAuthEnabled'
                UserName       = ''
                GroupName      = ''
                Detail         = "WDigest authentication is enabled (UseLogonCredential=1), causing credentials to be cached in plain text in LSASS memory."
                Score          = 8
                Severity       = (Get-SeverityLabel 8)
                Recommendation = "Disable WDigest credential caching: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0"
            })
        }
    } catch {
        Write-Warning "Could not check WDigest registry value: $_"
    }

    # ------------------------------------------------------------------
    # 10. NtlmV1Enabled — LmCompatibilityLevel < 3 (or absent, defaulting to 0)
    # ------------------------------------------------------------------
    try {
        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $lsaKey = Get-ItemProperty -Path $lsaPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
        $lmLevel = if ($null -ne $lsaKey -and $null -ne $lsaKey.LmCompatibilityLevel) {
            $lsaKey.LmCompatibilityLevel
        } else {
            0  # absent = default 0, which allows NTLMv1
        }
        if ($lmLevel -lt 3) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'NtlmV1Enabled'
                UserName       = ''
                GroupName      = ''
                Detail         = "LmCompatibilityLevel is $lmLevel (< 3), allowing NTLMv1 and LM authentication which are cryptographically weak."
                Score          = 7
                Severity       = (Get-SeverityLabel 7)
                Recommendation = "Set LmCompatibilityLevel to at least 5 (NTLMv2 only): Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5"
            })
        }
    } catch {
        Write-Warning "Could not check LmCompatibilityLevel registry value: $_"
    }

    # ------------------------------------------------------------------
    # 11. RemoteRegistryEnabled — RemoteRegistry service is running
    # ------------------------------------------------------------------
    try {
        $remoteRegSvc = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
        if ($null -ne $remoteRegSvc -and $remoteRegSvc.Status -eq 'Running') {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'RemoteRegistryEnabled'
                UserName       = ''
                GroupName      = ''
                Detail         = "The RemoteRegistry service is currently running, allowing remote registry access."
                Score          = 6
                Severity       = (Get-SeverityLabel 6)
                Recommendation = "Stop and disable the RemoteRegistry service unless explicitly required: Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled"
            })
        }
    } catch {
        Write-Warning "Could not check RemoteRegistry service status: $_"
    }

    # ------------------------------------------------------------------
    # 12. LapsNotDetected — No LAPS indicators found
    # ------------------------------------------------------------------
    try {
        $allUsers = @(Get-LocalUser)
        $lapsUserPresent = @($allUsers | Where-Object { $_.Name -like '*LAPS*' }).Count -gt 0
        $lapsRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
        $lapsRegKey = Get-ItemProperty -Path $lapsRegPath -ErrorAction SilentlyContinue
        $lapsRegPresent = $null -ne $lapsRegKey

        if (-not $lapsUserPresent -and -not $lapsRegPresent) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'LapsNotDetected'
                UserName       = ''
                GroupName      = ''
                Detail         = 'No indicators of Local Administrator Password Solution (LAPS) were found on this system.'
                Score          = 7
                Severity       = (Get-SeverityLabel 7)
                Recommendation = 'Deploy Microsoft LAPS (or Windows LAPS built into Windows Server 2022/Windows 11) to enforce unique, rotating local administrator passwords.'
            })
        }
    } catch {
        Write-Warning "Could not check for LAPS indicators: $_"
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
        $resource = if ($f.UserName -ne '') { $f.UserName } elseif ($f.GroupName -ne '') { $f.GroupName } else { 'System' }
        $finding  = $f.FindingType
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($finding))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Detail))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Score))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Windows Local User Audit Report</title>
<style>
  body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}
  h1{color:#333}.summary{display:flex;gap:16px;margin-bottom:24px}
  .card{background:#fff;border-radius:6px;padding:16px 24px;box-shadow:0 1px 4px rgba(0,0,0,.1);min-width:120px;text-align:center}
  .card .num{font-size:2em;font-weight:bold}.card .lbl{color:#666;font-size:.85em}
  table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.1)}
  th{background:#343a40;color:#fff;padding:10px;text-align:left}
  td{padding:8px 10px;border-bottom:1px solid #dee2e6}tr:hover{background:#f1f3f5}
  .meta{color:#666;font-size:.85em;margin-bottom:16px}
</style></head><body>
<h1>Windows Local User Audit Report</h1>
<p class='meta'>Host: $Hostname &nbsp;|&nbsp; Generated: $ScannedAt</p>
<div class='summary'>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
</div>
<table><thead><tr>
  <th>Username/Group</th><th>Finding</th>
  <th>Detail</th><th>Severity</th><th>Score</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
}

function ConvertTo-CsvReport {
    param([Parameter(Mandatory)][array]$Findings)
    $Findings | Select-Object `
        @{N='FindingType';     E={$_.FindingType}},
        @{N='UserName';        E={$_.UserName}},
        @{N='GroupName';       E={$_.GroupName}},
        @{N='Detail';          E={$_.Detail}},
        @{N='Score';           E={$_.Score}},
        @{N='Severity';        E={$_.Severity}},
        @{N='Recommendation';  E={$_.Recommendation}} |
        ConvertTo-Csv -NoTypeInformation
}

function Write-TerminalSummary {
    param([array]$Findings, [string]$Hostname = $env:COMPUTERNAME)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $top3 = $Findings | Sort-Object Score -Descending | Select-Object -First 3

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║     WINDOWS LOCAL USER AUDIT COMPLETE            ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Hostname       : $($Hostname.PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  Total findings : $($Findings.Count.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    if ($top3) {
        Write-Host '║  Top findings:                                   ║' -ForegroundColor Cyan
        foreach ($f in $top3) {
            $name = if ($f.UserName -ne '') { $f.UserName } elseif ($f.GroupName -ne '') { $f.GroupName } else { $f.FindingType }
            $line = "  [$($f.Severity)] ${name}: $($f.FindingType)"
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
    $allFindings = Get-LocalUserFindings

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $reportData = @{
        generated_at = $timestamp
        hostname     = $env:COMPUTERNAME
        findings     = $allFindings
        summary      = @{
            total    = $allFindings.Count
            critical = ($allFindings | Where-Object Severity -eq 'CRITICAL').Count
            high     = ($allFindings | Where-Object Severity -eq 'HIGH').Count
            medium   = ($allFindings | Where-Object Severity -eq 'MEDIUM').Count
            low      = ($allFindings | Where-Object Severity -eq 'LOW').Count
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

    Write-TerminalSummary -Findings $allFindings -Hostname $env:COMPUTERNAME
}
