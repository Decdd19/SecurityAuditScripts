<#
.SYNOPSIS
    Audits Microsoft Teams guest access, external federation, and meeting policies.
.DESCRIPTION
    Read-only audit of Teams security posture:
    - TM-01: External access open to all domains
    - TM-02: Guest access enabled with no restrictions
    - TM-03: Guests can create/delete channels
    - TM-04: Meeting lobby bypass for anonymous users
    - TM-05: Meeting recordings auto-saved with no expiry
    - TM-06: Third-party app installs allowed
.PARAMETER Output
    Output file prefix (default: teams_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER TenantDomain
    Primary tenant domain (e.g. contoso.com)
.EXAMPLE
    .\teams_auditor.ps1 -TenantDomain contoso.com
#>
param(
    [string]$Output       = 'teams_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format       = 'all',
    [string]$TenantDomain = ''
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# MicrosoftTeams / Az stubs
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-CsTenantFederationConfiguration' -ErrorAction SilentlyContinue)) {
    function Connect-MicrosoftTeams   { param($TenantId) }
    function Disconnect-MicrosoftTeams { }
    function Get-CsTenantFederationConfiguration {
        [PSCustomObject]@{ AllowFederatedUsers = $false; AllowedDomains = @() }
    }
    function Get-CsTeamsMeetingPolicy {
        param($Identity)
        [PSCustomObject]@{
            AllowAnonymousUsersToJoinMeeting  = $false
            AutoAdmittedUsers                 = 'EveryoneInCompany'
            AllowCloudRecording               = $false
            NewMeetingRecordingExpirationDays = 60
        }
    }
    function Get-CsTeamsClientConfiguration {
        [PSCustomObject]@{ AllowGuestUser = $false }
    }
    function Get-CsTeamsChannelPolicy {
        param($Identity)
        [PSCustomObject]@{ AllowGuestCreateUpdateChannels = $false; AllowGuestDeleteChannels = $false }
    }
    function Get-CsTeamsAppPermissionPolicy {
        param($Identity)
        [PSCustomObject]@{ DefaultCatalogAppsType = 'BlockedAppList'; GlobalCatalogAppsType = 'BlockedAppList' }
    }
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
# TM-01: External federation open to all domains
# ---------------------------------------------------------------------------
function Get-TeamsFederationFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $fed = Get-CsTenantFederationConfiguration

    $allowedDomains = @($fed.AllowedDomains)
    if ($fed.AllowFederatedUsers -eq $true -and $allowedDomains.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'ExternalAccessAllDomains'
            Resource       = 'tenant'
            Score          = 6
            Severity       = 'HIGH'
            CisControl     = 'CIS 5'
            Recommendation = "Restrict Teams external access to specific trusted domains: " +
                             "Teams admin centre → Users → External access → " +
                             "Add allowed domains and remove 'Allow all external domains'."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# TM-02, TM-03: Guest access and channel permissions
# ---------------------------------------------------------------------------
function Get-TeamsGuestFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $client   = Get-CsTeamsClientConfiguration
    if ($client.AllowGuestUser -ne $true) { return $findings }

    # TM-02: Guest access enabled
    $findings.Add([PSCustomObject]@{
        FindingType    = 'GuestAccessUnrestricted'
        Resource       = 'tenant'
        Score          = 5
        Severity       = 'MEDIUM'
        CisControl     = 'CIS 5'
        Recommendation = "Review guest access settings and apply restrictions: " +
                         "Teams admin centre → Users → Guest access → " +
                         "Disable capabilities guests do not need (calling, meetings, messaging)."
    })

    # TM-03: Guests can create/delete channels
    $channelPolicy = Get-CsTeamsChannelPolicy -Identity Global
    if ($channelPolicy.AllowGuestCreateUpdateChannels -eq $true -or
        $channelPolicy.AllowGuestDeleteChannels -eq $true) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'GuestsCanCreateChannels'
            Resource       = 'Global'
            Score          = 4
            Severity       = 'MEDIUM'
            CisControl     = 'CIS 5'
            Recommendation = "Prevent guests from creating or deleting channels: " +
                             "Teams admin centre → Teams → Teams policies → Global → " +
                             "Disable 'Allow guests to create and update channels' and " +
                             "'Allow guests to delete channels'."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# TM-04, TM-05: Meeting policies
# ---------------------------------------------------------------------------
function Get-TeamsMeetingFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $policy   = Get-CsTeamsMeetingPolicy -Identity Global

    # TM-04: Anonymous lobby bypass
    if ($policy.AutoAdmittedUsers -eq 'Everyone' -or
        $policy.AllowAnonymousUsersToJoinMeeting -eq $true) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'MeetingLobbyBypassAnonymous'
            Resource       = 'Global'
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 5'
            Recommendation = "Require anonymous users to wait in the lobby: " +
                             "Teams admin centre → Meetings → Meeting policies → Global → " +
                             "Who can bypass the lobby: change to 'People in my org and guests'."
        })
    }

    # TM-05: Recording expiry not set
    if ($policy.AllowCloudRecording -eq $true -and
        $policy.NewMeetingRecordingExpirationDays -le 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'RecordingsNoExpiry'
            Resource       = 'Global'
            Score          = 4
            Severity       = 'MEDIUM'
            CisControl     = 'CIS 3'
            Recommendation = "Set an expiry on meeting recordings (60 days recommended): " +
                             "Teams admin centre → Meetings → Meeting policies → Global → " +
                             "Meetings recordings expiry: set number of days."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# TM-06: Unmanaged app installs
# ---------------------------------------------------------------------------
function Get-TeamsAppFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $policy   = Get-CsTeamsAppPermissionPolicy -Identity Global

    if ($policy.DefaultCatalogAppsType -eq 'AllowedAppList' -or
        $policy.GlobalCatalogAppsType  -eq 'AllowedAppList') {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'UnmanagedAppInstallsAllowed'
            Resource       = 'Global'
            Score          = 5
            Severity       = 'MEDIUM'
            CisControl     = 'CIS 2'
            Recommendation = "Restrict third-party app installs to approved apps only: " +
                             "Teams admin centre → Teams apps → Permission policies → Global → " +
                             "Third-party apps: change to 'Block specific apps' or 'Block all apps'."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------
function ConvertTo-TeamsJsonReport {
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

function ConvertTo-TeamsCsvReport {
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

function ConvertTo-TeamsHtmlReport {
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
<head><meta charset="UTF-8"><title>Teams Security Audit</title>
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
<div class="header"><h1>Microsoft Teams Security Audit</h1><p>Tenant: $tenantDisplay &nbsp;|&nbsp; Generated: $ts</p></div>
<div class="section"><table>
  <thead><tr><th>Type</th><th>Resource</th><th>Risk</th><th>CIS</th><th>Recommendation</th></tr></thead>
  <tbody>$rows$noFindings</tbody>
</table></div>
<div class="footer">Teams Security Audit &nbsp;|&nbsp; For internal use only</div>
</body></html>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ctx      = Get-AzContext
$tenantId = if ($ctx -and $ctx.Tenant) { $ctx.Tenant.Id } else { '' }

Write-Host "Microsoft Teams Security Auditor"
Write-Host "Tenant ID: $tenantId"

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "[1/4] Checking external federation configuration..."
Get-TeamsFederationFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[2/4] Checking guest access settings..."
Get-TeamsGuestFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[3/4] Checking meeting policies..."
Get-TeamsMeetingFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[4/4] Checking app permission policies..."
Get-TeamsAppFindings | ForEach-Object { $allFindings.Add($_) }

$findings = @($allFindings)
Write-Host "Findings: $($findings.Count)"

switch ($Format) {
    'stdout' { $findings | Format-Table FindingType, Resource, Severity, CisControl, Recommendation -Wrap }
    'json' {
        $r = ConvertTo-TeamsJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        Write-Host "JSON report: $Output.json"
    }
    'csv' {
        ConvertTo-TeamsCsvReport -Findings $findings -Path "$Output.csv"
        Write-Host "CSV report: $Output.csv"
    }
    'html' {
        $html = ConvertTo-TeamsHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "HTML report: $Output.html"
    }
    'all' {
        $r = ConvertTo-TeamsJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        ConvertTo-TeamsCsvReport -Findings $findings -Path "$Output.csv"
        $html = ConvertTo-TeamsHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
    }
}
