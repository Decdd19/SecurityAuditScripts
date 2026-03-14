<#
.SYNOPSIS
    Audits Azure Entra ID (Azure AD) and RBAC posture for security compliance.
.DESCRIPTION
    Read-only audit of Entra ID identity hygiene and RBAC configuration across
    one or all accessible subscriptions. Flags users without MFA, privileged guest
    accounts, service principals with broad scope, stale app credentials, overly
    permissive custom roles, and privilege escalation paths.
.PARAMETER Output
    Output file prefix (default: entra_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.EXAMPLE
    .\entra_auditor.ps1
    .\entra_auditor.ps1 -AllSubscriptions -Format html
#>
param(
    [string]$Output          = 'entra_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Az / Graph stubs — overridden by real modules at runtime; Pester Mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-AzADUser' -ErrorAction SilentlyContinue)) {
    function Get-AzADUser { @() }
    function Get-AzRoleAssignment { param($Scope) @() }
    function Get-AzADServicePrincipal { @() }
    function Get-AzADApplication { @() }
    function Get-AzADAppCredential { param($ObjectId) @() }
    function Get-AzRoleDefinition { @() }
    function Get-MgUserAuthenticationMethod { param($UserId) @() }
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext { $null }
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
# Audit functions
# ---------------------------------------------------------------------------
function Get-EntraFindings {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Subscription
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ------------------------------------------------------------------
    # 1. UserNoMfa — flag users with no MFA method registered
    # ------------------------------------------------------------------
    $users = @(Get-AzADUser)
    foreach ($user in $users) {
        try {
            $methods = @(Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue)
            $hasMfa = $methods | Where-Object {
                $null -ne $_.AdditionalProperties -and
                $_.AdditionalProperties['@odata.type'] -notin @('#microsoft.graph.passwordAuthenticationMethod', $null)
            }
            if (-not $hasMfa) {
                $findings.Add([PSCustomObject]@{
                    FindingType      = 'UserNoMfa'
                    SubscriptionId   = $Subscription.Id
                    SubscriptionName = $Subscription.Name
                    PrincipalId      = $user.Id
                    PrincipalName    = $user.UserPrincipalName
                    Score            = 7
                    Severity         = (Get-SeverityLabel 7)
                    Recommendation   = "Enable MFA for user '$($user.UserPrincipalName)'. Use Conditional Access policies to enforce MFA for all users."
                })
            }
        } catch {
            Write-Warning "Could not check MFA for user '$($user.UserPrincipalName)': $_"
        }
    }

    # ------------------------------------------------------------------
    # 2. PrivilegedGuest — guest users with privileged role assignments
    # ------------------------------------------------------------------
    $guestUsers = $users | Where-Object { $_.UserType -eq 'Guest' }
    if ($guestUsers) {
        $allAssignments = @(Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.Id)")
        $privilegedRoles = @('Owner', 'Contributor', 'User Access Administrator')
        foreach ($guest in $guestUsers) {
            $guestAssignments = @($allAssignments | Where-Object {
                $_.ObjectId -eq $guest.Id -and
                $_.RoleDefinitionName -in $privilegedRoles
            })
            foreach ($assignment in $guestAssignments) {
                $findings.Add([PSCustomObject]@{
                    FindingType      = 'PrivilegedGuest'
                    SubscriptionId   = $Subscription.Id
                    SubscriptionName = $Subscription.Name
                    PrincipalId      = $guest.Id
                    PrincipalName    = $guest.UserPrincipalName
                    RoleName         = $assignment.RoleDefinitionName
                    Score            = 7
                    Severity         = (Get-SeverityLabel 7)
                    Recommendation   = "Remove privileged role '$($assignment.RoleDefinitionName)' from guest user '$($guest.UserPrincipalName)'. Guest accounts should have minimal permissions."
                })
            }
        }
    }

    # ------------------------------------------------------------------
    # 3. ServicePrincipalBroadScope — SPs with Owner/Contributor at sub scope
    # ------------------------------------------------------------------
    $servicePrincipals = @(Get-AzADServicePrincipal)
    $subScope = "/subscriptions/$($Subscription.Id)"
    $spAssignments = @(@(Get-AzRoleAssignment -Scope $subScope) | Where-Object {
        $_.ObjectType -eq 'ServicePrincipal' -and
        $_.RoleDefinitionName -in @('Owner', 'Contributor') -and
        $_.Scope -eq $subScope
    })
    foreach ($spAssignment in $spAssignments) {
        $sp = $servicePrincipals | Where-Object { $_.Id -eq $spAssignment.ObjectId }
        $spName = if ($sp) { $sp.DisplayName } else { $spAssignment.ObjectId }
        $findings.Add([PSCustomObject]@{
            FindingType      = 'ServicePrincipalBroadScope'
            SubscriptionId   = $Subscription.Id
            SubscriptionName = $Subscription.Name
            PrincipalId      = $spAssignment.ObjectId
            PrincipalName    = $spName
            RoleName         = $spAssignment.RoleDefinitionName
            Score            = 5
            Severity         = (Get-SeverityLabel 5)
            Recommendation   = "Replace broad '$($spAssignment.RoleDefinitionName)' role with a least-privilege custom role scoped to specific resource groups or resources."
        })
    }

    # ------------------------------------------------------------------
    # 4. StaleAppCredential — expired or long-running app secrets/certs
    # ------------------------------------------------------------------
    $apps = @(Get-AzADApplication)
    foreach ($app in $apps) {
        try {
            $credentials = @(Get-AzADAppCredential -ObjectId $app.Id -ErrorAction SilentlyContinue)
            foreach ($cred in $credentials) {
                $isExpired   = $cred.EndDateTime -lt (Get-Date)
                $isLongLived = $cred.StartDateTime -lt (Get-Date).AddDays(-90)
                if ($isExpired -or $isLongLived) {
                    $findings.Add([PSCustomObject]@{
                        FindingType      = 'StaleAppCredential'
                        SubscriptionId   = $Subscription.Id
                        SubscriptionName = $Subscription.Name
                        PrincipalId      = $app.Id
                        PrincipalName    = $app.DisplayName
                        CredentialId     = $cred.KeyId
                        EndDate          = $cred.EndDateTime
                        Score            = 5
                        Severity         = (Get-SeverityLabel 5)
                        Recommendation   = "Rotate or remove the stale credential (KeyId: $($cred.KeyId)) for app '$($app.DisplayName)'. Use managed identities where possible to avoid credential management."
                    })
                }
            }
        } catch {
            Write-Warning "Could not check credentials for app '$($app.DisplayName)': $_"
        }
    }

    # ------------------------------------------------------------------
    # 5. OverpermissiveCustomRole — custom roles with wildcard write/delete
    # ------------------------------------------------------------------
    $customRoles = @(Get-AzRoleDefinition | Where-Object { $_.IsCustom })
    foreach ($role in $customRoles) {
        $dangerousActions = @($role.Actions | Where-Object {
            $_ -like '*/write' -or $_ -like '*/delete' -or $_ -eq '*'
        })
        if ($dangerousActions.Count -gt 0) {
            $findings.Add([PSCustomObject]@{
                FindingType      = 'OverpermissiveCustomRole'
                SubscriptionId   = $Subscription.Id
                SubscriptionName = $Subscription.Name
                RoleName         = $role.Name
                DangerousActions = ($dangerousActions -join ', ')
                Score            = 6
                Severity         = (Get-SeverityLabel 6)
                Recommendation   = "Review and restrict custom role '$($role.Name)'. Replace wildcard write/delete actions with specific resource actions following least-privilege principles."
            })
        }
    }

    return $findings
}

function Get-PrivescFindings {
    param(
        [Parameter(Mandatory)][array]$Assignments,
        [Parameter(Mandatory)][string]$SubscriptionName,
        [Parameter(Mandatory)][string]$SubscriptionId
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Group assignments by ObjectId
    $byPrincipal = $Assignments | Group-Object -Property ObjectId

    foreach ($group in $byPrincipal) {
        $roles = $group.Group.RoleDefinitionName

        # Combo 1: User Access Administrator + Contributor
        if ('User Access Administrator' -in $roles -and 'Contributor' -in $roles) {
            $findings.Add([PSCustomObject]@{
                FindingType      = 'PrivilegeEscalationPath'
                SubscriptionId   = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ObjectId         = $group.Name
                Combo            = 'User Access Administrator + Contributor'
                Score            = 9
                Severity         = 'CRITICAL'
                Recommendation   = 'Remove one of the conflicting roles or restrict scope'
            })
        }

        # Combo 2: Managed Identity Contributor + Contributor
        if ('Managed Identity Contributor' -in $roles -and 'Contributor' -in $roles) {
            $findings.Add([PSCustomObject]@{
                FindingType      = 'PrivilegeEscalationPath'
                SubscriptionId   = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ObjectId         = $group.Name
                Combo            = 'Managed Identity Contributor + Contributor'
                Score            = 9
                Severity         = 'CRITICAL'
                Recommendation   = 'Remove one of the conflicting roles or restrict scope'
            })
        }

        # Combo 3: Role Based Access Control Administrator (alone is dangerous)
        if ('Role Based Access Control Administrator' -in $roles) {
            $findings.Add([PSCustomObject]@{
                FindingType      = 'PrivilegeEscalationPath'
                SubscriptionId   = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ObjectId         = $group.Name
                Combo            = 'Role Based Access Control Administrator'
                Score            = 9
                Severity         = 'CRITICAL'
                Recommendation   = 'Remove one of the conflicting roles or restrict scope'
            })
        }

        # Combo 4: Owner assigned to unmonitored service principal
        $objectTypes = @($group.Group | ForEach-Object {
            if ($_.PSObject.Properties['ObjectType']) { $_.ObjectType } else { $null }
        } | Select-Object -Unique)
        if ('ServicePrincipal' -in $objectTypes -and 'Owner' -in $roles) {
            $findings.Add([PSCustomObject]@{
                FindingType      = 'PrivilegeEscalationPath'
                SubscriptionId   = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ObjectId         = $group.Name
                Combo            = 'Owner assigned to unmonitored service principal'
                Score            = 9
                Severity         = 'CRITICAL'
                Recommendation   = 'Audit this service principal and apply ownership tagging or remove Owner role'
            })
        }

        # Combo 5: Role with Microsoft.Authorization/*/write + Contributor
        if ('Contributor' -in $roles) {
            $otherRoles = $roles | Where-Object { $_ -ne 'Contributor' }
            foreach ($roleName in $otherRoles) {
                $roleDef = Get-AzRoleDefinition -Name $roleName -ErrorAction SilentlyContinue
                if ($roleDef -and ($roleDef.Actions | Where-Object { $_ -like 'Microsoft.Authorization/*/write' })) {
                    $findings.Add([PSCustomObject]@{
                        FindingType      = 'PrivilegeEscalationPath'
                        SubscriptionId   = $SubscriptionId
                        SubscriptionName = $SubscriptionName
                        ObjectId         = $group.Name
                        Combo            = 'Role with Microsoft.Authorization/*/write + Contributor'
                        Score            = 9
                        Severity         = 'CRITICAL'
                        Recommendation   = 'Remove the role with write authorization permissions or the Contributor role'
                    })
                    break
                }
            }
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [string]$TenantId  = '',
        [string]$ScannedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $Findings) {
        $colour   = Get-SeverityColour $f.Severity
        $resource = if ($f.PrincipalName) { $f.PrincipalName } elseif ($f.ObjectId) { $f.ObjectId } elseif ($f.RoleName) { $f.RoleName } else { 'N/A' }
        $detail   = if ($f.Combo) { $f.Combo } elseif ($f.RoleName -and $f.PrincipalName) { $f.RoleName } elseif ($f.CredentialId) { "Key: $($f.CredentialId)" } else { $f.FindingType }
        $finding  = $f.FindingType
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.SubscriptionName))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.SubscriptionId))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($finding))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($resource)) — $([System.Web.HttpUtility]::HtmlEncode($detail))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Entra ID &amp; RBAC Audit Report</title>
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
<h1>Entra ID &amp; RBAC Audit Report</h1>
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
    $Findings | Select-Object `
        @{N='SubscriptionName'; E={$_.SubscriptionName}},
        @{N='FindingType';      E={$_.FindingType}},
        @{N='Resource';         E={ if ($_.PrincipalName) { $_.PrincipalName } elseif ($_.ObjectId) { $_.ObjectId } elseif ($_.RoleName) { $_.RoleName } else { '' } }},
        @{N='Detail';           E={ if ($_.Combo) { $_.Combo } elseif ($_.RoleName) { $_.RoleName } elseif ($_.CredentialId) { "CredentialId: $($_.CredentialId)" } else { '' } }},
        Severity, Score, Recommendation |
        ConvertTo-Csv -NoTypeInformation
}

function Write-TerminalSummary {
    param([array]$Findings, [int]$UsersScanned, [int]$SubscriptionsScanned)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $top3 = $Findings | Sort-Object Score -Descending | Select-Object -First 3

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║        ENTRA ID & RBAC AUDIT COMPLETE            ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Subscriptions : $($SubscriptionsScanned.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  Users scanned : $($UsersScanned.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  Total findings: $($Findings.Count.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    if ($top3) {
        Write-Host '║  Top findings:                                   ║' -ForegroundColor Cyan
        foreach ($f in $top3) {
            $name = if ($f.PSObject.Properties['PrincipalName'] -and $f.PrincipalName) { $f.PrincipalName } else { $f.FindingType }
            $line = "  [$($f.Severity)] $($f.SubscriptionName): $name"
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
    $requiredModules = @('Az.Accounts', 'Az.Resources', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
    foreach ($mod in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Error "Required module '$mod' is not installed. Run: Install-Module $mod"
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
    try {
        $null = Get-MgContext -ErrorAction Stop
    } catch {
        Connect-MgGraph -Scopes 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory' -NoWelcome
    }

    if ($AllSubscriptions) {
        $subscriptions = Get-AzSubscription
    } else {
        $subscriptions = @(Get-AzSubscription -SubscriptionId $azContext.Subscription.Id)
    }

    $allFindings        = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalSubscriptions = 0
    $totalUsers         = 0

    foreach ($sub in $subscriptions) {
        Write-Host "Scanning subscription: $($sub.Name) ($($sub.Id))" -ForegroundColor Gray
        Set-AzContext -SubscriptionId $sub.Id | Out-Null

        $entraResult = Get-EntraFindings -Subscription $sub
        $allFindings.AddRange([PSCustomObject[]]@($entraResult))

        $roleAssignments = @(Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)")
        $privescResult   = Get-PrivescFindings -Assignments $roleAssignments -SubscriptionName $sub.Name -SubscriptionId $sub.Id
        $allFindings.AddRange([PSCustomObject[]]@($privescResult))

        $totalUsers         += (Get-AzADUser).Count
        $totalSubscriptions += 1
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
            ConvertTo-CsvReport $allFindings | Out-File "$Output.csv" -Encoding UTF8
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
            ConvertTo-CsvReport $allFindings | Out-File "$Output.csv" -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            ConvertTo-HtmlReport -Findings $allFindings -TenantId $tenantId -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $allFindings -UsersScanned $totalUsers -SubscriptionsScanned $totalSubscriptions
}
