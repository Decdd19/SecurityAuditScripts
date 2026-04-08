<#
.SYNOPSIS
    Audits Microsoft 365 / Exchange Online security posture.
.DESCRIPTION
    Read-only audit of M365 tenant security controls:
    - Conditional Access: MFA enforcement and legacy auth blocking
    - Exchange Online: mailbox auto-forwarding and inbox forwarding rules
    - OAuth app consent: tenant-level user consent policy
.PARAMETER Output
    Output file prefix (default: m365_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER TenantDomain
    Primary tenant domain (e.g. contoso.com) — used for external-forward detection.
    Defaults to the domain in the current Az context account UPN.
.EXAMPLE
    .\m365_auditor.ps1 -TenantDomain contoso.com
    .\m365_auditor.ps1 -TenantDomain contoso.com -Format json
#>
param(
    [string]$Output       = 'm365_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format       = 'all',
    [string]$TenantDomain = ''
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Graph / Exchange / Az stubs — overridden by real modules; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-MgIdentityConditionalAccessPolicy' -ErrorAction SilentlyContinue)) {
    function Connect-MgGraph        { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext          { $null }
    function Get-MgIdentityConditionalAccessPolicy { @() }
    function Get-MgPolicyAuthorizationPolicy       { $null }
    function Get-MgOrganization     { @() }
    function Get-MgUser             { param($Filter, $Property, [switch]$All) @() }
    function Get-MgUserAuthenticationMethod { param($UserId) @() }
    function Get-MgDirectoryRole    { @() }
    function Get-MgDirectoryRoleMember { param($DirectoryRoleId) @() }
}
if (-not (Get-Command -Name 'Get-Mailbox' -ErrorAction SilentlyContinue)) {
    function Connect-ExchangeOnline    { param($AppId, $Organization, $ShowBanner) }
    function Get-Mailbox               { param($ResultSize) @() }
    function Get-InboxRule             { param($Mailbox) @() }
    function Get-CASMailbox            { param($Identity) $null }
    function Disconnect-ExchangeOnline { param([switch]$Confirm) }
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
# Check 1: Conditional Access — MFA enforcement
# ---------------------------------------------------------------------------
function Get-M365ConditionalAccessFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $policies  = @(Get-MgIdentityConditionalAccessPolicy)

    $enabledMfaPolicies = @($policies | Where-Object {
        $_.State -eq 'enabled' -and
        $null -ne $_.GrantControls -and
        $_.GrantControls.BuiltInControls -contains 'mfa'
    })

    $reportOnlyMfaPolicies = @($policies | Where-Object {
        $_.State -eq 'enabledForReportingButNotEnforced' -and
        $null -ne $_.GrantControls -and
        $_.GrantControls.BuiltInControls -contains 'mfa'
    })

    if ($enabledMfaPolicies.Count -eq 0 -and $reportOnlyMfaPolicies.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'NoMfaCaPolicy'
            Resource       = 'tenant'
            Score          = 9
            Severity       = 'CRITICAL'
            CisControl     = 'CIS 6'
            Recommendation = "Create a Conditional Access policy requiring MFA for all users: " +
                             "Entra admin centre → Protection → Conditional Access → New policy → " +
                             "Assign to All users, All apps → Grant → Require multifactor authentication → Enable."
        })
    } elseif ($enabledMfaPolicies.Count -eq 0 -and $reportOnlyMfaPolicies.Count -gt 0) {
        $reportOnlyMfaPolicies | ForEach-Object {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'CaPolicyReportOnly'
                Resource       = $_.DisplayName
                Score          = 7
                Severity       = 'HIGH'
                CisControl     = 'CIS 6'
                Recommendation = "Switch Conditional Access policy '$($_.DisplayName)' from report-only to enabled: " +
                                 "Entra admin centre → Protection → Conditional Access → $($_.DisplayName) → " +
                                 "Enable policy → On → Save."
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Check 2: Conditional Access — legacy authentication block
# ---------------------------------------------------------------------------
function Get-M365LegacyAuthFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $policies  = @(Get-MgIdentityConditionalAccessPolicy)

    $legacyBlockPolicies = @($policies | Where-Object {
        $_.State -eq 'enabled' -and
        $null -ne $_.GrantControls -and
        $_.GrantControls.BuiltInControls -contains 'block' -and
        $null -ne $_.Conditions -and
        $null -ne $_.Conditions.ClientAppTypes -and
        ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
         $_.Conditions.ClientAppTypes -contains 'other')
    })

    if ($legacyBlockPolicies.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'LegacyAuthNotBlocked'
            Resource       = 'tenant'
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 4'
            Recommendation = "Block legacy authentication protocols via Conditional Access: " +
                             "Entra admin centre → Protection → Conditional Access → New policy → " +
                             "Assign to All users → Cloud apps: All → Conditions → Client apps: " +
                             "Exchange ActiveSync clients + Other clients → Grant: Block access → Enable."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Check 3: Exchange Online — mailbox auto-forwarding to external addresses
# ---------------------------------------------------------------------------
function Get-M365MailboxForwardingFindings {
    param([string]$TenantDomain = '')

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mailboxes = @(Get-Mailbox -ResultSize Unlimited)

    foreach ($mbx in $mailboxes) {
        $upn = $mbx.UserPrincipalName

        # Check ForwardingSmtpAddress (explicit SMTP forwarding)
        if ($mbx.ForwardingSmtpAddress) {
            $fwdAddr = $mbx.ForwardingSmtpAddress -replace '^smtp:', ''
            $isExternal = $TenantDomain -eq '' -or
                          (-not $fwdAddr.EndsWith("@$TenantDomain", [System.StringComparison]::OrdinalIgnoreCase))
            if ($isExternal) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'ExternalMailboxForwarding'
                    Resource       = $upn
                    ForwardingTo   = $fwdAddr
                    Score          = 7
                    Severity       = 'HIGH'
                    CisControl     = 'CIS 9'
                    Recommendation = "Remove external forwarding from mailbox '$upn': " +
                                     "Exchange admin centre → Recipients → Mailboxes → $upn → " +
                                     "Mail flow → Manage mail flow settings → Remove forwarding address. " +
                                     "If forwarding is business-required, document and review periodically."
                })
            }
        }

        # Check inbox rules that forward or redirect externally
        $rules = @(Get-InboxRule -Mailbox $upn)
        foreach ($rule in $rules) {
            if (-not $rule.Enabled) { continue }
            $fwdTargets = @()
            if ($rule.ForwardTo)             { $fwdTargets += @($rule.ForwardTo) }
            if ($rule.ForwardAsAttachmentTo) { $fwdTargets += @($rule.ForwardAsAttachmentTo) }
            if ($rule.RedirectTo)            { $fwdTargets += @($rule.RedirectTo) }

            foreach ($target in $fwdTargets) {
                $targetStr = "$target"
                $isExternal = $TenantDomain -eq '' -or
                              (-not $targetStr.Contains("@$TenantDomain"))
                if ($isExternal) {
                    $findings.Add([PSCustomObject]@{
                        FindingType    = 'ExternalInboxForwardRule'
                        Resource       = $upn
                        RuleName       = $rule.Name
                        ForwardingTo   = $targetStr
                        Score          = 7
                        Severity       = 'HIGH'
                        CisControl     = 'CIS 9'
                        Recommendation = "Remove external inbox forwarding rule '$($rule.Name)' from mailbox '$upn': " +
                                         "Exchange admin centre → Recipients → Mailboxes → $upn → " +
                                         "Manage automatic replies → or use PowerShell: " +
                                         "Remove-InboxRule -Mailbox '$upn' -Identity '$($rule.Name)'"
                    })
                    break  # one finding per rule is enough
                }
            }
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Check 4: OAuth app consent — unrestricted user consent
# ---------------------------------------------------------------------------
function Get-M365OAuthConsentFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $authPolicy = Get-MgPolicyAuthorizationPolicy
    if ($null -eq $authPolicy) { return $findings }

    $perms = $authPolicy.DefaultUserRolePermissions
    if ($null -eq $perms) { return $findings }

    # Legacy permissive consent: microsoft-user-default-legacy allows broad consent
    $legacyConsent = $perms.PermissionGrantPoliciesAssigned |
        Where-Object { $_ -match 'user-default-legacy' }

    # AllowedToCreateApps does not directly govern OAuth consent, but combined with
    # unrestricted grant policies it indicates a permissive posture.
    $hasPermissiveGrant = @($legacyConsent).Count -gt 0

    if ($hasPermissiveGrant) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'UnrestrictedOAuthConsent'
            Resource       = 'tenant'
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 16'
            Recommendation = "Restrict OAuth app consent to verified publishers only: " +
                             "Entra admin centre → Applications → Enterprise applications → " +
                             "Consent and permissions → User consent settings → " +
                             "'Allow user consent for apps from verified publishers, for selected permissions' → Save. " +
                             "Also configure admin consent workflow to review app consent requests."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Check 5: MFA per-user registration coverage
# ---------------------------------------------------------------------------
function Get-M365MfaCoverageFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $users = @(Get-MgUser -Filter "accountEnabled eq true and userType eq 'Member'" `
                          -Property Id,DisplayName,UserPrincipalName -All)

    if ($users.Count -eq 0) { return $findings }

    $noMfaUsers = [System.Collections.Generic.List[string]]::new()
    foreach ($user in $users) {
        $methods = @(Get-MgUserAuthenticationMethod -UserId $user.Id)
        # Password method is always present; any other method counts as MFA
        $mfaMethods = @($methods | Where-Object {
            $t = if ($null -ne $_.PSObject.Properties['AdditionalProperties']) { $_.AdditionalProperties['@odata.type'] } else { $_.'@odata.type' }
            $t -ne '#microsoft.graph.passwordAuthenticationMethod'
        })
        if ($mfaMethods.Count -eq 0) {
            $noMfaUsers.Add($user.UserPrincipalName)
        }
    }

    if ($noMfaUsers.Count -gt 0) {
        $pct   = [math]::Round(100 * $noMfaUsers.Count / $users.Count)
        $sev   = if ($pct -ge 50) { 'HIGH' } elseif ($pct -ge 20) { 'MEDIUM' } else { 'LOW' }
        $score = if ($pct -ge 50) { 7 }      elseif ($pct -ge 20) { 4 }       else { 2 }
        $sample = ($noMfaUsers | Select-Object -First 5) -join '; '
        $findings.Add([PSCustomObject]@{
            FindingType    = 'UsersMissingMfaRegistration'
            Resource       = $sample
            Score          = $score
            Severity       = $sev
            CisControl     = 'CIS 6'
            Recommendation = "$($noMfaUsers.Count) of $($users.Count) enabled member account(s) ($pct%) " +
                             "have no MFA methods registered. " +
                             "Entra admin centre → Users → Per-user MFA, or enforce registration via " +
                             "Conditional Access → Registration policy."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Check 6: Privileged admin role enumeration
# ---------------------------------------------------------------------------
function Get-M365AdminRoleFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $privilegedRoles = @(
        'Global Administrator', 'Privileged Role Administrator',
        'Security Administrator', 'Exchange Administrator',
        'SharePoint Administrator', 'Teams Administrator',
        'User Administrator', 'Billing Administrator',
        'Application Administrator', 'Cloud Application Administrator'
    )

    $roles = @(Get-MgDirectoryRole | Where-Object { $_.DisplayName -in $privilegedRoles })

    foreach ($role in $roles) {
        $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id)
        foreach ($member in $members) {
            # Skip service principals — they're expected to hold app-level roles
            $memberType = if ($null -ne $member.PSObject.Properties['AdditionalProperties']) { $member.AdditionalProperties['@odata.type'] } else { $member.'@odata.type' }
            if ($memberType -eq '#microsoft.graph.servicePrincipal') { continue }

            $upn = if ($member.AdditionalProperties -and $member.AdditionalProperties['userPrincipalName']) {
                $member.AdditionalProperties['userPrincipalName']
            } else { $member.Id }

            $findings.Add([PSCustomObject]@{
                FindingType    = 'PrivilegedRoleMember'
                Resource       = "$($role.DisplayName): $upn"
                Score          = 3
                Severity       = 'MEDIUM'
                CisControl     = 'CIS 5'
                Recommendation = "Review whether '$upn' requires '$($role.DisplayName)' permanently. " +
                                 "Use Entra PIM (Privileged Identity Management) for just-in-time access: " +
                                 "Entra admin centre → Identity Governance → Privileged Identity Management."
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Check 7: Guest / external user access review
# ---------------------------------------------------------------------------
function Get-M365GuestAccessFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $guests = @(Get-MgUser -Filter "userType eq 'Guest'" `
                           -Property Id,DisplayName,UserPrincipalName,CreatedDateTime -All)

    if ($guests.Count -eq 0) { return $findings }

    $staleThreshold = (Get-Date).AddDays(-90)
    $staleGuests = @($guests | Where-Object {
        $_.CreatedDateTime -and ([datetime]$_.CreatedDateTime) -lt $staleThreshold
    })

    $sev   = if ($staleGuests.Count -gt 5) { 'MEDIUM' } else { 'LOW' }
    $score = if ($staleGuests.Count -gt 5) { 4 }        else { 2 }

    $findings.Add([PSCustomObject]@{
        FindingType    = 'GuestUsersPresent'
        Resource       = "Total guests: $($guests.Count); Stale (>90 days): $($staleGuests.Count)"
        Score          = $score
        Severity       = $sev
        CisControl     = 'CIS 5'
        Recommendation = "$($guests.Count) guest account(s) found, $($staleGuests.Count) inactive >90 days. " +
                         "Review and remove stale guests: Entra admin centre → Users → " +
                         "Filter by Guest → Remove inactive accounts. " +
                         "Consider enabling Guest expiration policy via Identity Governance."
    })

    return $findings
}

# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------
function ConvertTo-M365JsonReport {
    param([array]$Findings, [string]$TenantId = '')

    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) {
        if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ }
    }

    return @{
        generated_at  = (Get-Date).ToUniversalTime().ToString('o')
        tenant_id     = $TenantId
        summary       = @{
            total_findings = $Findings.Count
            critical       = $counts.CRITICAL
            high           = $counts.HIGH
            medium         = $counts.MEDIUM
            low            = $counts.LOW
        }
        findings      = @($Findings | ForEach-Object {
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

function ConvertTo-M365CsvReport {
    param([array]$Findings, [string]$Path)
    if ($Findings.Count -eq 0) { return }
    $rows = $Findings | ForEach-Object {
        [PSCustomObject]@{
            finding_type   = $_.FindingType
            resource       = if ($null -ne $_.Resource) { $_.Resource } else { '' }
            risk_level     = $_.Severity
            severity_score = $_.Score
            cis_control    = $_.CisControl
            recommendation = $_.Recommendation
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function ConvertTo-M365HtmlReport {
    param([array]$Findings, [string]$TenantId)

    $rows = ''
    foreach ($f in ($Findings | Sort-Object Score -Descending)) {
        $colour = Get-SeverityColour $f.Severity
        $resource = if ($null -ne $f.Resource) { [System.Web.HttpUtility]::HtmlEncode($f.Resource) } else { '&mdash;' }
        $rec = [System.Web.HttpUtility]::HtmlEncode($f.Recommendation)
        $rows += "<tr>
          <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
          <td><code>$resource</code></td>
          <td><span style='background:$colour;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em'>$($f.Severity)</span></td>
          <td style='font-size:0.85em'>$([System.Web.HttpUtility]::HtmlEncode($f.CisControl))</td>
          <td style='font-size:0.82em;color:#555;font-style:italic'>$rec</td>
        </tr>`n"
    }

    $noFindings = if ($Findings.Count -eq 0) {
        "<tr><td colspan='5' style='text-align:center;color:#888'>No findings — tenant appears compliant.</td></tr>"
    } else { '' }

    $tenantDisplay = if ($TenantId) { [System.Web.HttpUtility]::HtmlEncode($TenantId) } else { 'N/A' }
    $ts = (Get-Date).ToUniversalTime().ToString('o')

    return @"
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>M365 Security Audit</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}
  .header h1{margin:0;font-size:1.8em}
  .header p{margin:5px 0 0;opacity:0.8}
  .section{padding:20px 32px}
  .section h2{font-size:1.1em;color:#333;border-bottom:2px solid #e0e0e0;padding-bottom:8px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
  td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
  .footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style>
</head>
<body>
<div class="header">
  <h1>M365 / Exchange Online Security Audit</h1>
  <p>Tenant: $tenantDisplay &nbsp;|&nbsp; Generated: $ts</p>
</div>
<div class="section">
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Type</th><th>Resource</th><th>Risk</th><th>CIS</th><th>Recommendation</th></tr></thead>
    <tbody>$rows$noFindings</tbody>
  </table>
</div>
<div class="footer">M365 Security Audit &nbsp;|&nbsp; For internal use only</div>
</body>
</html>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ctx         = Get-AzContext
$tenantId    = if ($ctx -and $ctx.Tenant) { $ctx.Tenant.Id } else { '' }
$accountUpn  = if ($ctx -and $ctx.Account) { $ctx.Account.Id } else { '' }

# Derive tenant domain from account UPN if not supplied
if (-not $TenantDomain -and $accountUpn -match '@(.+)$') {
    $TenantDomain = $Matches[1]
}

Write-Host "M365 / Exchange Online Security Auditor"
Write-Host "Tenant ID  : $tenantId"
Write-Host "Tenant Domain: $TenantDomain"

# Collect findings from all checks
$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "[1/7] Checking Conditional Access — MFA policies…"
Get-M365ConditionalAccessFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[2/7] Checking Conditional Access — legacy authentication…"
Get-M365LegacyAuthFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[3/7] Checking Exchange Online — mailbox forwarding…"
Get-M365MailboxForwardingFindings -TenantDomain $TenantDomain | ForEach-Object { $allFindings.Add($_) }

Write-Host "[4/7] Checking OAuth app consent policy…"
Get-M365OAuthConsentFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[5/7] Checking MFA per-user registration coverage…"
Get-M365MfaCoverageFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[6/7] Checking privileged admin role members…"
Get-M365AdminRoleFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[7/7] Checking guest / external user access…"
Get-M365GuestAccessFindings | ForEach-Object { $allFindings.Add($_) }

$findings = @($allFindings)
Write-Host "Findings: $($findings.Count)"

# Output
switch ($Format) {
    'stdout' {
        $findings | Format-Table FindingType, Resource, Severity, CisControl, Recommendation -Wrap
    }
    'json' {
        $jsonReport = ConvertTo-M365JsonReport -Findings $findings -TenantId $tenantId
        $jsonReport | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        Write-Host "JSON report: $Output.json"
    }
    'csv' {
        ConvertTo-M365CsvReport -Findings $findings -Path "$Output.csv"
        Write-Host "CSV report: $Output.csv"
    }
    'html' {
        $html = ConvertTo-M365HtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "HTML report: $Output.html"
    }
    'all' {
        $jsonReport = ConvertTo-M365JsonReport -Findings $findings -TenantId $tenantId
        $jsonReport | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"

        ConvertTo-M365CsvReport -Findings $findings -Path "$Output.csv"

        $html = ConvertTo-M365HtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"

        Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
    }
}
