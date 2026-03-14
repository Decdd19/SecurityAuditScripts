<#
.SYNOPSIS
    Audits Azure Subscription and Tenant posture for security compliance.
.DESCRIPTION
    Read-only audit of subscription-level security controls and tenant-level
    identity hygiene across one or all accessible subscriptions. Flags missing
    Defender for Cloud plans, permanent privileged role assignments without PIM,
    too many Global Administrators, Global Admins without MFA, missing resource
    locks, and absent budget alerts.
.PARAMETER Output
    Output file prefix (default: subscription_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.EXAMPLE
    .\subscription_auditor.ps1
    .\subscription_auditor.ps1 -AllSubscriptions -Format html
#>
param(
    [string]$Output          = 'subscription_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Az / Graph stubs — overridden by real modules at runtime; Pester Mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-AzSecurityPricing' -ErrorAction SilentlyContinue)) {
    function Get-AzSecurityPricing { @() }
    function Get-AzRoleAssignment { param($Scope) @() }
    function Get-AzResourceLock { @() }
    function Get-AzConsumptionBudget { @() }
    function Get-MgRoleManagementDirectoryRoleAssignment { param($Filter, [switch]$All) @() }
    function Get-MgUserAuthenticationMethod { param($UserId) @() }
    function Get-MgRoleManagementDirectoryRoleEligibilitySchedule { param([switch]$All) @() }
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
# Audit function
# ---------------------------------------------------------------------------
function Get-SubscriptionFindings {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Subscription
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $base = @{ Subscription = $Subscription.Name; SubscriptionId = $Subscription.Id }

    # ------------------------------------------------------------------
    # 1. Defender for Cloud — flag any plan still at Free tier
    # ------------------------------------------------------------------
    $pricings = Get-AzSecurityPricing
    foreach ($pricing in $pricings) {
        if ($pricing.PricingTier -eq 'Free') {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'DefenderNotEnabled'
                Detail         = "Defender plan '$($pricing.Name)' is at Free tier"
                Score          = 7; Severity = (Get-SeverityLabel 7)
                Recommendation = "Enable Microsoft Defender for Cloud Standard tier for '$($pricing.Name)'."
            } + $base))
        }
    }

    # ------------------------------------------------------------------
    # 2. Permanent Owner/Contributor assignments without PIM
    # ------------------------------------------------------------------
    $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.Id)" |
        Where-Object { $_.Scope -eq "/subscriptions/$($Subscription.Id)" }
    $eligibleAssignments = @(Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction SilentlyContinue)
    $eligibleIds = $eligibleAssignments | ForEach-Object { $_.PrincipalId }

    foreach ($assignment in $roleAssignments) {
        if ($assignment.RoleDefinitionName -in @('Owner', 'Contributor') -and
            $assignment.ObjectType -eq 'User' -and
            $assignment.ObjectId -notin $eligibleIds) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'PermanentOwnerAssignment'
                Detail         = "$($assignment.RoleDefinitionName) permanently assigned to '$($assignment.SignInName)' — no PIM eligible assignment found"
                Score          = 8; Severity = (Get-SeverityLabel 8)
                Recommendation = "Use Privileged Identity Management (PIM) for just-in-time Owner/Contributor access instead of permanent assignments."
            } + $base))
        }
    }

    # ------------------------------------------------------------------
    # 3. Global Administrator hygiene (count + MFA)
    # ------------------------------------------------------------------
    $globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
    $globalAdmins = @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$globalAdminRoleId'" -All -ErrorAction SilentlyContinue)

    if ($globalAdmins.Count -gt 5) {
        $findings.Add([PSCustomObject](@{
            FindingType    = 'TooManyGlobalAdmins'
            Detail         = "$($globalAdmins.Count) Global Administrators (recommended: <= 5)"
            Score          = 4; Severity = (Get-SeverityLabel 4)
            Recommendation = "Reduce Global Administrator count. Use more specific roles (e.g., Security Administrator) where full tenant access is not required."
        } + $base))
    }

    foreach ($admin in $globalAdmins) {
        $principalId = $admin.PrincipalId
        $displayName = if ($admin.Principal) { $admin.Principal.DisplayName } else { $principalId }
        $upn = if ($admin.Principal) { $admin.Principal.UserPrincipalName } else { '' }
        try {
            $methods = @(Get-MgUserAuthenticationMethod -UserId $principalId -ErrorAction SilentlyContinue)
            $hasMfa = $methods | Where-Object {
                $null -ne $_.AdditionalProperties -and
                $_.AdditionalProperties['@odata.type'] -notin @(
                    '#microsoft.graph.passwordAuthenticationMethod',
                    $null
                )
            }
            if (-not $hasMfa) {
                $findings.Add([PSCustomObject](@{
                    FindingType    = 'GlobalAdminNoMfa'
                    Detail         = "Global Admin '$displayName' ($upn) has no MFA method registered"
                    Score          = 9; Severity = (Get-SeverityLabel 9)
                    Recommendation = "Require MFA for all Global Administrators immediately."
                } + $base))
            }
        } catch {
            Write-Warning "Could not check MFA for Global Admin '$displayName': $_"
        }
    }

    # ------------------------------------------------------------------
    # 4. Resource locks — subscription should have at least one
    # ------------------------------------------------------------------
    $locks = @(Get-AzResourceLock)
    if ($locks.Count -eq 0) {
        $findings.Add([PSCustomObject](@{
            FindingType    = 'NoResourceLocks'
            Detail         = "Subscription '$($Subscription.Name)' has no resource locks configured"
            Score          = 4; Severity = (Get-SeverityLabel 4)
            Recommendation = "Apply CanNotDelete or ReadOnly locks to critical resources or resource groups to prevent accidental deletion."
        } + $base))
    }

    # ------------------------------------------------------------------
    # 5. Budget alerts — subscription should have at least one budget
    # ------------------------------------------------------------------
    $budgets = @(Get-AzConsumptionBudget)
    if ($budgets.Count -eq 0) {
        $findings.Add([PSCustomObject](@{
            FindingType    = 'NoBudgetAlerts'
            Detail         = "Subscription '$($Subscription.Name)' has no budget alerts configured"
            Score          = 2; Severity = (Get-SeverityLabel 2)
            Recommendation = "Configure at least one budget with alert thresholds to monitor and control cloud spending."
        } + $base))
    }

    return [PSCustomObject]@{ Findings = $findings; SubscriptionCount = 1 }
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [string]$TenantId = '',
        [string]$ScannedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $Findings) {
        $colour = Get-SeverityColour $f.Severity
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Subscription))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.SubscriptionId))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Detail))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Subscription & Tenant Posture Audit Report</title>
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
<h1>Subscription &amp; Tenant Posture Audit Report</h1>
<p class='meta'>Tenant: $TenantId &nbsp;|&nbsp; Generated: $ScannedAt</p>
<div class='summary'>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
</div>
<table><thead><tr>
  <th>Subscription</th><th>Subscription ID</th><th>Finding</th>
  <th>Detail</th><th>Severity</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
}

function ConvertTo-CsvReport {
    param([Parameter(Mandatory)][array]$Findings)
    $Findings | Select-Object Subscription, SubscriptionId,
        FindingType, Detail, Score, Severity, Recommendation
}

function Write-TerminalSummary {
    param([array]$Findings, [int]$SubscriptionsScanned)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $top3 = $Findings | Sort-Object Score -Descending | Select-Object -First 3

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║     SUBSCRIPTION & TENANT POSTURE AUDIT COMPLETE ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Subscriptions : $($SubscriptionsScanned.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  Total findings: $($Findings.Count.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    if ($top3) {
        Write-Host '║  Top findings:                                   ║' -ForegroundColor Cyan
        foreach ($f in $top3) {
            $line = "  [$($f.Severity)] $($f.Subscription): $($f.FindingType)"
            Write-Host "║  $($line.PadRight(47))║" -ForegroundColor Cyan
        }
    }
    Write-Host '╚══════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
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
# Main — skipped when dot-sourced (InvocationName is '.' when dot-sourced)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $RequiredModules = @(
        'Az.Accounts', 'Az.Resources', 'Az.Security',
        'Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.Governance',
        'Microsoft.Graph.Users'
    )
    foreach ($mod in $RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Error "Required module '$mod' is not installed. Run: Install-Module $mod -Scope CurrentUser"
            exit 1
        }
    }

    $azContext = Get-AzContext
    if (-not $azContext) {
        Write-Error 'No active Azure context. Run Connect-AzAccount first.'
        exit 1
    }
    $tenantId = $azContext.Tenant.Id

    # Connect to Microsoft Graph if not already connected
    $mgContext = $null
    try { $mgContext = Get-MgContext } catch { }
    if (-not $mgContext) {
        Connect-MgGraph -Scopes 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory'
    }

    if ($AllSubscriptions) {
        $subscriptions = Get-AzSubscription
    } else {
        $subscriptions = @(Get-AzSubscription -SubscriptionId $azContext.Subscription.Id)
    }

    $allFindings        = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalSubscriptions = 0
    foreach ($sub in $subscriptions) {
        Write-Host "Scanning subscription: $($sub.Name) ($($sub.Id))" -ForegroundColor Gray
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        $result = Get-SubscriptionFindings -Subscription $sub
        $allFindings.AddRange([PSCustomObject[]]$result.Findings)
        $totalSubscriptions += $result.SubscriptionCount
    }

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $reportData = @{
        generated_at = $timestamp
        tenant_id    = $tenantId
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
            ConvertTo-CsvReport $allFindings | Export-Csv "$Output.csv" -NoTypeInformation -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            Write-Host "CSV report: $Output.csv"
        }
        'html'   {
            ConvertTo-HtmlReport -Findings $allFindings -TenantId $tenantId -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "HTML report: $Output.html"
        }
        'all'    {
            $reportData | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
            Set-RestrictedPermissions "$Output.json"
            ConvertTo-CsvReport $allFindings | Export-Csv "$Output.csv" -NoTypeInformation -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            ConvertTo-HtmlReport -Findings $allFindings -TenantId $tenantId -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $allFindings -SubscriptionsScanned $totalSubscriptions
}
