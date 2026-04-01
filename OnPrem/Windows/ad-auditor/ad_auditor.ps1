<#
.SYNOPSIS
    Audits on-premises Active Directory security posture.
.DESCRIPTION
    Read-only audit of Active Directory identity hygiene and configuration.
    Flags accounts with insecure password settings, stale accounts, Kerberoastable
    and AS-REP roastable accounts, excessive privileged group membership, weak
    password policies, unconstrained delegation, and misconfigured AD features.
.PARAMETER Output
    Output file prefix (default: ad_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllTargets
    Scan all available targets in the forest.
.EXAMPLE
    .\ad_auditor.ps1
    .\ad_auditor.ps1 -AllTargets -Format html
#>
param(
    [string]$Output = 'ad_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format = 'all',
    [switch]$AllTargets
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# ActiveDirectory module stubs — overridden by real module at runtime
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-ADUser' -ErrorAction SilentlyContinue)) {
    function Get-ADUser { param($Filter, $Properties, $SearchBase, $Identity) @() }
    function Get-ADComputer { param($Filter, $Properties) @() }
    function Get-ADGroupMember { param($Identity, [switch]$Recursive) @() }
    function Get-ADDomain { @{ DistinguishedName = 'DC=contoso,DC=com'; DomainMode = 'Windows2016Domain' } }
    function Get-ADDefaultDomainPasswordPolicy { [PSCustomObject]@{ MinPasswordLength = 14; MaxPasswordAge = [TimeSpan]::FromDays(60); ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false } }
    function Get-ADFineGrainedPasswordPolicy { param($Filter) @() }
    function Get-ADObject { param($Filter, $Properties, $SearchBase) @() }
    function Get-ADForest { [PSCustomObject]@{ Name = 'contoso.com' } }
    function Get-ADOptionalFeature { param($Filter) @() }
    function Get-ADTrust { param($Filter) @() }
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
function ConvertTo-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [string]$DomainName = '',
        [string]$ScannedAt  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $Findings) {
        $colour   = Get-SeverityColour $f.Severity
        $resource = if ($f.UserName)     { $f.UserName     } `
               elseif ($f.ComputerName) { $f.ComputerName } `
               elseif ($f.GroupName)    { $f.GroupName    } `
               else                     { 'N/A'           }
        $detail   = if ($f.Detail) { $f.Detail } else { $f.FindingType }
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($detail))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Active Directory Audit Report</title>
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
<h1>Active Directory Audit Report</h1>
<p>Domain: $DomainName &nbsp;|&nbsp; Generated: $ScannedAt</p>
</div>
<div class='summary'>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
</div>
<table><thead><tr>
  <th>Finding</th><th>Resource</th><th>Detail</th>
  <th>Severity</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
}

function ConvertTo-CsvReport {
    param([Parameter(Mandatory)][array]$Findings)
    $Findings | Select-Object `
        @{N='FindingType';      E={$_.FindingType}},
        @{N='Resource';         E={ if ($_.UserName) { $_.UserName } elseif ($_.ComputerName) { $_.ComputerName } elseif ($_.GroupName) { $_.GroupName } else { '' } }},
        @{N='Detail';           E={$_.Detail}},
        Severity, Score, Recommendation |
        ConvertTo-Csv -NoTypeInformation
}

function Write-TerminalSummary {
    param([array]$Findings, [int]$UsersScanned, [string]$DomainName = '')
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $top3 = $Findings | Sort-Object Score -Descending | Select-Object -First 3

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║      ACTIVE DIRECTORY AUDIT COMPLETE             ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Domain        : $($DomainName.PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  Users scanned : $($UsersScanned.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  Total findings: $($Findings.Count.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    if ($top3) {
        Write-Host '║  Top findings:                                   ║' -ForegroundColor Cyan
        foreach ($f in $top3) {
            $name = if ($f.PSObject.Properties['UserName'] -and $f.UserName) { $f.UserName } `
                    elseif ($f.PSObject.Properties['ComputerName'] -and $f.ComputerName) { $f.ComputerName } `
                    else { $f.FindingType }
            $line = "  [$($f.Severity)] ${name}: $($f.FindingType)"
            Write-Host "║  $($line.PadRight(47))║" -ForegroundColor Cyan
        }
    }
    Write-Host '╚══════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Main audit function
# ---------------------------------------------------------------------------
function Get-ADFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now      = Get-Date

    # ------------------------------------------------------------------
    # 1. UserPasswordNeverExpires — enabled users with PasswordNeverExpires
    # ------------------------------------------------------------------
    $neverExpireUsers = @(Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordNeverExpires)
    foreach ($user in $neverExpireUsers) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'UserPasswordNeverExpires'
            UserName       = $user.SamAccountName
            ComputerName   = $null
            GroupName      = $null
            Detail         = "User '$($user.SamAccountName)' has PasswordNeverExpires set to true."
            Score          = 6
            Severity       = (Get-SeverityLabel 6)
            Recommendation = "Configure a password expiry policy for '$($user.SamAccountName)'. Enable the PasswordNeverExpires=false setting and enforce regular password rotation via Group Policy."
        })
    }

    # ------------------------------------------------------------------
    # 2. UserPasswordNotRequired — enabled users where password is not required
    # ------------------------------------------------------------------
    $noPasswordUsers = @(Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } -Properties PasswordNotRequired)
    foreach ($user in $noPasswordUsers) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'UserPasswordNotRequired'
            UserName       = $user.SamAccountName
            ComputerName   = $null
            GroupName      = $null
            Detail         = "User '$($user.SamAccountName)' has PasswordNotRequired set to true, allowing blank passwords."
            Score          = 9
            Severity       = (Get-SeverityLabel 9)
            Recommendation = "Immediately disable the PasswordNotRequired flag for '$($user.SamAccountName)' and require a strong password. Audit how this flag was set."
        })
    }

    # ------------------------------------------------------------------
    # 3. StaleUser — enabled users with LastLogonDate > 90 days ago
    # ------------------------------------------------------------------
    $staleCutoff  = $now.AddDays(-90)
    $enabledUsers = @(Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate)
    foreach ($user in $enabledUsers) {
        if ($null -ne $user.LastLogonDate -and $user.LastLogonDate -lt $staleCutoff) {
            $daysSince = [int]($now - $user.LastLogonDate).TotalDays
            $findings.Add([PSCustomObject]@{
                FindingType    = 'StaleUser'
                UserName       = $user.SamAccountName
                ComputerName   = $null
                GroupName      = $null
                Detail         = "User '$($user.SamAccountName)' has not logged in for $daysSince days (last logon: $($user.LastLogonDate))."
                Score          = 5
                Severity       = (Get-SeverityLabel 5)
                Recommendation = "Disable or remove stale account '$($user.SamAccountName)'. Implement an automated account lifecycle process to disable accounts inactive for more than 90 days."
            })
        }
    }

    # ------------------------------------------------------------------
    # 4. KerberoastableAccount — enabled user accounts with an SPN set
    # ------------------------------------------------------------------
    $kerberoastUsers = @(Get-ADUser -Filter { ServicePrincipalName -ne '*' -and Enabled -eq $true } -Properties ServicePrincipalName)
    foreach ($user in $kerberoastUsers) {
        if ($user.ServicePrincipalName -and @($user.ServicePrincipalName).Count -gt 0) {
            $spnList = @($user.ServicePrincipalName) -join '; '
            $findings.Add([PSCustomObject]@{
                FindingType    = 'KerberoastableAccount'
                UserName       = $user.SamAccountName
                ComputerName   = $null
                GroupName      = $null
                Detail         = "User '$($user.SamAccountName)' has SPNs registered: $spnList"
                Score          = 8
                Severity       = (Get-SeverityLabel 8)
                Recommendation = "Move service SPNs for '$($user.SamAccountName)' to Group Managed Service Accounts (gMSA) which use auto-rotating 120-character passwords, eliminating Kerberoasting risk."
            })
        }
    }

    # ------------------------------------------------------------------
    # 5. ASREPRoastableAccount — enabled users with pre-auth not required
    # ------------------------------------------------------------------
    $asrepUsers = @(Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth)
    foreach ($user in $asrepUsers) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'ASREPRoastableAccount'
            UserName       = $user.SamAccountName
            ComputerName   = $null
            GroupName      = $null
            Detail         = "User '$($user.SamAccountName)' does not require Kerberos pre-authentication (AS-REP roastable)."
            Score          = 8
            Severity       = (Get-SeverityLabel 8)
            Recommendation = "Enable Kerberos pre-authentication for '$($user.SamAccountName)' by unchecking 'Do not require Kerberos preauthentication' in the account properties. This prevents offline hash cracking."
        })
    }

    # ------------------------------------------------------------------
    # 6. WeakDomainPasswordPolicy — min length < 12 or max age > 90 days
    # ------------------------------------------------------------------
    $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
    $policyWeak     = $false
    $policyReasons  = [System.Collections.Generic.List[string]]::new()

    if ($passwordPolicy.MinPasswordLength -lt 12) {
        $policyWeak = $true
        $policyReasons.Add("MinPasswordLength is $($passwordPolicy.MinPasswordLength) (required: >=12)")
    }
    if ($passwordPolicy.MaxPasswordAge.TotalDays -gt 90) {
        $policyWeak = $true
        $policyReasons.Add("MaxPasswordAge is $([int]$passwordPolicy.MaxPasswordAge.TotalDays) days (required: <=90)")
    }

    if ($policyWeak) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'WeakDomainPasswordPolicy'
            UserName       = $null
            ComputerName   = $null
            GroupName      = 'Default Domain Password Policy'
            Detail         = $policyReasons -join '; '
            Score          = 7
            Severity       = (Get-SeverityLabel 7)
            Recommendation = "Strengthen the Default Domain Password Policy: set MinPasswordLength >= 12 and MaxPasswordAge <= 90 days. Consider using Fine-Grained Password Policies for privileged accounts."
        })
    }

    # ------------------------------------------------------------------
    # 7. ExcessiveDomainAdmins — Domain Admins group has more than 5 members
    # ------------------------------------------------------------------
    $domainAdmins     = @(Get-ADGroupMember -Identity 'Domain Admins' -Recursive)
    $domainAdminCount = $domainAdmins.Count

    if ($domainAdminCount -gt 5) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'ExcessiveDomainAdmins'
            UserName       = $null
            ComputerName   = $null
            GroupName      = 'Domain Admins'
            Detail         = "Domain Admins group has $domainAdminCount members (threshold: >5). Members: $(($domainAdmins | ForEach-Object { $_.SamAccountName }) -join ', ')."
            Score          = 6
            Severity       = (Get-SeverityLabel 6)
            Recommendation = "Reduce Domain Admins membership to the absolute minimum required. Use tiered administration, JIT access, and Privileged Access Workstations (PAWs) for domain admin tasks."
        })
    }

    # ------------------------------------------------------------------
    # 8. DomainAdminStale — Domain Admin members not logged in for > 30 days
    # ------------------------------------------------------------------
    $staleDaaCutoff = $now.AddDays(-30)
    foreach ($member in $domainAdmins) {
        try {
            $daUser = Get-ADUser -Identity $member.SamAccountName -Properties LastLogonDate -ErrorAction SilentlyContinue
            if ($null -ne $daUser -and $null -ne $daUser.LastLogonDate -and $daUser.LastLogonDate -lt $staleDaaCutoff) {
                $daysSince = [int]($now - $daUser.LastLogonDate).TotalDays
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'DomainAdminStale'
                    UserName       = $daUser.SamAccountName
                    ComputerName   = $null
                    GroupName      = 'Domain Admins'
                    Detail         = "Domain Admin '$($daUser.SamAccountName)' has not logged in for $daysSince days (last logon: $($daUser.LastLogonDate))."
                    Score          = 7
                    Severity       = (Get-SeverityLabel 7)
                    Recommendation = "Remove '$($daUser.SamAccountName)' from Domain Admins if no longer needed. If the account is required, investigate why it has not been used and consider JIT access instead."
                })
            }
        } catch {
            Write-Warning "Could not retrieve details for Domain Admin member '$($member.SamAccountName)': $_"
        }
    }

    # ------------------------------------------------------------------
    # 9. ProtectedUsersEmpty — Protected Users group has no members
    # ------------------------------------------------------------------
    $protectedUsers = @(Get-ADGroupMember -Identity 'Protected Users')
    if ($protectedUsers.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'ProtectedUsersEmpty'
            UserName       = $null
            ComputerName   = $null
            GroupName      = 'Protected Users'
            Detail         = "The Protected Users security group has no members. Privileged accounts are not protected against credential theft techniques."
            Score          = 5
            Severity       = (Get-SeverityLabel 5)
            Recommendation = "Add all privileged accounts (Domain Admins, Enterprise Admins, etc.) to the Protected Users group. This prevents NTLM, DES, RC4, and unconstrained delegation for those accounts."
        })
    }

    # ------------------------------------------------------------------
    # 10. RecycleBinDisabled — AD Recycle Bin feature not enabled
    # ------------------------------------------------------------------
    $recycleBinFeature = @(Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' })
    $recycleBinEnabled = $false
    if ($recycleBinFeature.Count -gt 0) {
        $feature = $recycleBinFeature[0]
        if ($feature.PSObject.Properties['IsEnabled'] -and $feature.IsEnabled -eq $true) {
            $recycleBinEnabled = $true
        }
    }

    if (-not $recycleBinEnabled) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'RecycleBinDisabled'
            UserName       = $null
            ComputerName   = $null
            GroupName      = $null
            Detail         = "The Active Directory Recycle Bin optional feature is not enabled. Deleted objects cannot be easily recovered."
            Score          = 3
            Severity       = (Get-SeverityLabel 3)
            Recommendation = "Enable the AD Recycle Bin feature using: Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest). This requires Windows Server 2008 R2 forest functional level or higher."
        })
    }

    # ------------------------------------------------------------------
    # 11. TrustUnconstrained — computers with unconstrained Kerberos delegation
    #     (excluding computers in the Domain Controllers OU)
    # ------------------------------------------------------------------
    $unconstrainedComputers = @(Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation)
    foreach ($computer in $unconstrainedComputers) {
        $isDC = $computer.DistinguishedName -like '*OU=Domain Controllers*' -or
                $computer.DistinguishedName -like '*CN=Domain Controllers*'
        if (-not $isDC) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'TrustUnconstrained'
                UserName       = $null
                ComputerName   = $computer.Name
                GroupName      = $null
                Detail         = "Computer '$($computer.Name)' is trusted for unconstrained Kerberos delegation (DN: $($computer.DistinguishedName))."
                Score          = 9
                Severity       = (Get-SeverityLabel 9)
                Recommendation = "Remove unconstrained delegation from '$($computer.Name)'. Migrate to constrained delegation (KCD) or resource-based constrained delegation (RBCD). Unconstrained delegation allows any user's TGT to be captured and reused."
            })
        }
    }

    # ------------------------------------------------------------------
    # 12. AdminCountFlagOrphan — users with adminCount=1 not in privileged groups
    # ------------------------------------------------------------------
    $privilegedGroupPatterns = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
    $adminCountUsers = @(Get-ADUser -Filter { adminCount -eq 1 -and Enabled -eq $true } -Properties adminCount, MemberOf)
    foreach ($user in $adminCountUsers) {
        $memberOfDNs    = @($user.MemberOf)
        $isPrivileged   = $false
        foreach ($pattern in $privilegedGroupPatterns) {
            if ($memberOfDNs | Where-Object { $_ -like "*$pattern*" }) {
                $isPrivileged = $true
                break
            }
        }
        if (-not $isPrivileged) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'AdminCountFlagOrphan'
                UserName       = $user.SamAccountName
                ComputerName   = $null
                GroupName      = $null
                Detail         = "User '$($user.SamAccountName)' has adminCount=1 but is not a member of Domain Admins, Enterprise Admins, or Schema Admins. The SDProp process may not be resetting ACLs on this account."
                Score          = 6
                Severity       = (Get-SeverityLabel 6)
                Recommendation = "Investigate why '$($user.SamAccountName)' has adminCount=1. If they were previously in a protected group and are no longer, reset adminCount to 0 and restore default permissions on the account object."
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Main — skipped when dot-sourced (InvocationName is '.' when dot-sourced)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Get-Module -ListAvailable -Name 'ActiveDirectory')) {
        Write-Error "ActiveDirectory module (RSAT) required. Install via: Add-WindowsFeature RSAT-AD-PowerShell"
        exit 1
    }

    $domain = Get-ADDomain

    Write-Host "Auditing domain: $($domain.DistinguishedName)" -ForegroundColor Gray

    $allFindings = @(Get-ADFindings)
    $totalUsers  = @(Get-ADUser -Filter { Enabled -eq $true } -Properties *).Count

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $reportData = @{
        generated_at = $timestamp
        domain_name  = $domain.DistinguishedName
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
            ConvertTo-HtmlReport -Findings $allFindings -DomainName $domain.DistinguishedName -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "HTML report: $Output.html"
        }
        'all'    {
            $reportData | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
            Set-RestrictedPermissions "$Output.json"
            ConvertTo-CsvReport $allFindings | Out-File "$Output.csv" -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            ConvertTo-HtmlReport -Findings $allFindings -DomainName $domain.DistinguishedName -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $allFindings -UsersScanned $totalUsers -DomainName $domain.DistinguishedName
}
