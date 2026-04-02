<#
.SYNOPSIS
    Audits Azure Policy assignments and compliance posture.
.DESCRIPTION
    Read-only audit of Azure Policy across one or all accessible subscriptions.
    Flags missing policy assignments, non-compliant resources per assignment,
    and absence of CIS/security benchmark initiatives.
.PARAMETER Output
    Output file prefix (default: policy_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.EXAMPLE
    .\azpolicy_auditor.ps1
    .\azpolicy_auditor.ps1 -AllSubscriptions -Format html
    .\azpolicy_auditor.ps1 -Format json
#>
param(
    [string]$Output          = 'policy_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Az stubs -- overridden by real Az module at runtime; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-AzPolicyAssignment' -ErrorAction SilentlyContinue)) {
    function Get-AzPolicyAssignment { @() }
}
if (-not (Get-Command -Name 'Get-AzPolicyState' -ErrorAction SilentlyContinue)) {
    function Get-AzPolicyState { param($PolicyAssignmentName) @() }
}
if (-not (Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue)) {
    function Get-AzContext { @{ Subscription = @{ Id = ''; Name = '' }; Tenant = @{ Id = '' } } }
}
if (-not (Get-Command -Name 'Get-AzSubscription' -ErrorAction SilentlyContinue)) {
    function Get-AzSubscription { @() }
}
if (-not (Get-Command -Name 'Set-AzContext' -ErrorAction SilentlyContinue)) {
    function Set-AzContext { param($SubscriptionId) }
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
function Get-PolicyFindings {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Subscription
    )
    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $assignments = @(Get-AzPolicyAssignment)

    # 1. No policy assignments at all
    if ($assignments.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType      = 'NoPolicyAssignments'
            Resource         = $Subscription.Name
            Severity         = (Get-SeverityLabel 7)
            Score            = [int]7
            Description      = 'No Azure Policy assignments found -- compliance posture unknown'
            Recommendation   = "Assign Azure Policy initiatives: Azure Portal -> Policy -> Assignments -> Assign Initiative. Start with the Azure Security Benchmark or CIS initiative for baseline compliance."
            SubscriptionId   = $Subscription.Id
            SubscriptionName = $Subscription.Name
        })
        return [PSCustomObject]@{ Findings = $findings; AssignmentCount = 0 }
    }

    # 2. Check each assignment for non-compliant resources
    foreach ($assignment in $assignments) {
        $assignmentName = $assignment.Name
        $displayName    = $assignment.Properties.DisplayName

        $policyStates = @(Get-AzPolicyState -PolicyAssignmentName $assignmentName)
        $nonCompliant = @($policyStates | Where-Object { $_.ComplianceState -eq 'NonCompliant' })

        if ($nonCompliant.Count -gt 0) {
            $findings.Add([PSCustomObject]@{
                FindingType      = 'NonCompliantResources'
                Resource         = $displayName
                Severity         = (Get-SeverityLabel 5)
                Score            = [int]5
                Description      = "Policy assignment '$displayName' has $($nonCompliant.Count) non-compliant resources"
                Recommendation   = "Review non-compliant resources: Azure Portal -> Policy -> Compliance -> $displayName. Remediate or create exemptions for each non-compliant resource."
                SubscriptionId   = $Subscription.Id
                SubscriptionName = $Subscription.Name
            })
        }
    }

    # 3. No CIS/security benchmark initiative
    $securityPattern = 'CIS|Security|Benchmark|NIST'
    $hasSecurityInitiative = $false
    foreach ($assignment in $assignments) {
        $dn = $assignment.Properties.DisplayName
        if ($dn -match $securityPattern) {
            $hasSecurityInitiative = $true
            break
        }
    }

    if (-not $hasSecurityInitiative) {
        $findings.Add([PSCustomObject]@{
            FindingType      = 'NoSecurityBenchmark'
            Resource         = $Subscription.Name
            Severity         = (Get-SeverityLabel 4)
            Score            = [int]4
            Description      = 'No CIS or security benchmark initiative assigned'
            Recommendation   = "Assign a security benchmark: Azure Portal -> Policy -> Assignments -> Assign Initiative -> search for 'CIS' or 'Azure Security Benchmark'. This provides baseline compliance monitoring."
            SubscriptionId   = $Subscription.Id
            SubscriptionName = $Subscription.Name
        })
    }

    return [PSCustomObject]@{ Findings = $findings; AssignmentCount = $assignments.Count }
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
        $colour = Get-SeverityColour $f.Severity
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$($f.Score)/10</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Description))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.SubscriptionName))</td>
            <td><div class='rem-text'>&#8627; $([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</div></td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Azure Policy Audit Report</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
.header{background:#1a1a2e;color:#fff;padding:30px 40px}
.header h1{margin:0;font-size:1.8em}.header p{margin:5px 0 0;opacity:0.8}
.content{padding:24px 40px}
.summary{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:24px}
.card{background:#fff;border-radius:8px;padding:20px 30px;box-shadow:0 2px 8px rgba(0,0,0,0.08);min-width:140px;text-align:center}
.card .num{font-size:2.5em;font-weight:bold}.card .lbl{color:#666;font-size:.85em;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);margin-bottom:24px}
th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
.rem-text{display:block;font-size:.78em;color:#555;padding-left:12px;font-style:italic;margin-top:4px}
.footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style></head><body>
<div class='header'>
<h1>&#128274; Azure Policy Audit Report</h1>
<p>Scanned: $ScannedAt$(if ($TenantId) { " &bull; Tenant: $([System.Web.HttpUtility]::HtmlEncode($TenantId))" })</p>
</div>
<div class='content'>
<div class='summary'>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
</div>
$(if ($Findings.Count -eq 0) { "<p>&#10003; No Azure Policy findings.</p>" } else {
"<table>
  <thead><tr>
    <th>Resource</th><th>Finding</th><th>Severity</th><th>Score</th><th>Description</th><th>Subscription</th><th>Recommendation</th>
  </tr></thead>
  <tbody>$($rows -join '')</tbody>
</table>"
})
</div>
<div class='footer'>Generated by Azure Policy Auditor</div>
</body></html>
"@
}

function ConvertTo-JsonReport {
    param([array]$Findings, [string]$TenantId = '', [int]$AssignmentCount = 0)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    return @{
        generated_at       = (Get-Date).ToUniversalTime().ToString('o')
        tenant_id          = $TenantId
        assignments_scanned = $AssignmentCount
        summary            = @{
            total_findings = $Findings.Count
            critical       = $counts.CRITICAL
            high           = $counts.HIGH
            medium         = $counts.MEDIUM
            low            = $counts.LOW
        }
        findings           = @($Findings | ForEach-Object {
            @{
                finding_type      = $_.FindingType
                resource          = $_.Resource
                severity          = $_.Severity
                score             = $_.Score
                description       = $_.Description
                recommendation    = $_.Recommendation
                subscription_id   = $_.SubscriptionId
                subscription_name = $_.SubscriptionName
            }
        })
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Invoke-Audit {
    param([switch]$AllSubscriptions)

    $ctx             = Get-AzContext
    $tenantId        = $ctx.Tenant.Id
    $allFindings     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalAssignments = 0

    if ($AllSubscriptions) {
        $subs = @(Get-AzSubscription)
        foreach ($sub in $subs) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            $result = Get-PolicyFindings -Subscription $sub
            foreach ($f in $result.Findings) { $allFindings.Add($f) }
            $totalAssignments += $result.AssignmentCount
        }
    } else {
        $sub    = [PSCustomObject]@{ Id = $ctx.Subscription.Id; Name = $ctx.Subscription.Name }
        $result = Get-PolicyFindings -Subscription $sub
        foreach ($f in $result.Findings) { $allFindings.Add($f) }
        $totalAssignments = $result.AssignmentCount
    }

    return @{
        TenantId        = $tenantId
        Findings        = $allFindings.ToArray()
        AssignmentCount = $totalAssignments
    }
}

# ---------------------------------------------------------------------------
# Entry point (skipped when dot-sourced by Pester)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $result          = Invoke-Audit -AllSubscriptions:$AllSubscriptions
    $findings        = $result.Findings
    $tenantId        = $result.TenantId
    $assignmentCount = $result.AssignmentCount

    if ($Format -eq 'stdout') {
        ConvertTo-JsonReport -Findings $findings -TenantId $tenantId -AssignmentCount $assignmentCount | ConvertTo-Json -Depth 10
        exit 0
    }

    if ($Format -in @('html','all')) {
        $html = ConvertTo-HtmlReport -Findings $findings -TenantId $tenantId
        $htmlPath = "$Output.html"
        $html | Out-File -FilePath $htmlPath -Encoding utf8
        Write-Host "HTML report: $htmlPath"
    }

    if ($Format -in @('json','all')) {
        $jsonReport = ConvertTo-JsonReport -Findings $findings -TenantId $tenantId -AssignmentCount $assignmentCount
        $jsonPath = "$Output.json"
        $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
        Write-Host "JSON report: $jsonPath"
    }

    if ($Format -in @('csv','all')) {
        $csvPath = "$Output.csv"
        $findings | Select-Object Resource, FindingType, Severity, Score, Description, Recommendation, SubscriptionId, SubscriptionName |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
        Write-Host "CSV report: $csvPath"
    }
}
