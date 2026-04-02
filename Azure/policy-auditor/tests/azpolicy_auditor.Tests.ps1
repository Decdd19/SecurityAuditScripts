BeforeAll {
    function Get-AzContext { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = 'sub-001'; Name = 'TestSub' } }
    function Set-AzContext { param($SubscriptionId) }
    function Get-AzPolicyAssignment { @() }
    function Get-AzPolicyState { param($PolicyAssignmentName) @() }

    . "$PSScriptRoot/../azpolicy_auditor.ps1"

    # -- Helpers --------------------------------------------------------------

    function script:New-PolicyAssignment {
        param(
            [string]$Name        = 'assignment-1',
            [string]$DisplayName = 'Test Policy',
            [string]$Scope       = '/subscriptions/sub-001'
        )
        [PSCustomObject]@{
            Name       = $Name
            Properties = [PSCustomObject]@{
                DisplayName = $DisplayName
                Scope       = $Scope
            }
        }
    }

    function script:New-PolicyState {
        param(
            [string]$ComplianceState    = 'Compliant',
            [string]$ResourceId         = '/subscriptions/sub-001/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1',
            [string]$PolicyAssignmentName = 'assignment-1'
        )
        [PSCustomObject]@{
            ComplianceState      = $ComplianceState
            ResourceId           = $ResourceId
            PolicyAssignmentName = $PolicyAssignmentName
        }
    }

    $script:Sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
}

# -- 1. No policy assignments -> HIGH finding --------------------------------

Describe 'Get-PolicyFindings -- no assignments' {
    It 'generates HIGH finding when no policy assignments exist' {
        Mock Get-AzPolicyAssignment { @() }
        $result = Get-PolicyFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'NoPolicyAssignments'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
        $f.Score | Should -Be 7
        $f.Description | Should -Match 'No Azure Policy assignments found'
    }
}

# -- 2. Assignments present -> no "no assignments" finding --------------------

Describe 'Get-PolicyFindings -- assignments present' {
    It 'does not generate NoPolicyAssignments finding when assignments exist' {
        $assignment = New-PolicyAssignment -DisplayName 'Allowed Locations'
        Mock Get-AzPolicyAssignment { @($assignment) }
        Mock Get-AzPolicyState { @() }
        $result = Get-PolicyFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'NoPolicyAssignments' | Should -BeNullOrEmpty
    }
}

# -- 3. Non-compliant resources -> MEDIUM finding with count ------------------

Describe 'Get-PolicyFindings -- non-compliant resources' {
    It 'generates MEDIUM finding with count for non-compliant resources' {
        $assignment = New-PolicyAssignment -Name 'assign-1' -DisplayName 'Require Tags'
        Mock Get-AzPolicyAssignment { @($assignment) }
        Mock Get-AzPolicyState {
            @(
                (New-PolicyState -ComplianceState 'NonCompliant' -PolicyAssignmentName 'assign-1'),
                (New-PolicyState -ComplianceState 'NonCompliant' -ResourceId '/sub/rg/vm2' -PolicyAssignmentName 'assign-1')
            )
        }
        $result = Get-PolicyFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'NonCompliantResources'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
        $f.Description | Should -Match '2 non-compliant'
    }
}

# -- 4. All compliant -> no non-compliant finding ----------------------------

Describe 'Get-PolicyFindings -- all compliant' {
    It 'does not generate NonCompliantResources finding when all resources are compliant' {
        $assignment = New-PolicyAssignment -DisplayName 'CIS Benchmark'
        Mock Get-AzPolicyAssignment { @($assignment) }
        Mock Get-AzPolicyState {
            @(
                (New-PolicyState -ComplianceState 'Compliant'),
                (New-PolicyState -ComplianceState 'Compliant' -ResourceId '/sub/rg/vm2')
            )
        }
        $result = Get-PolicyFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'NonCompliantResources' | Should -BeNullOrEmpty
    }
}

# -- 5. No CIS initiative -> MEDIUM finding ----------------------------------

Describe 'Get-PolicyFindings -- no CIS initiative' {
    It 'generates MEDIUM finding when no security benchmark initiative is assigned' {
        $assignment = New-PolicyAssignment -DisplayName 'Allowed Locations'
        Mock Get-AzPolicyAssignment { @($assignment) }
        Mock Get-AzPolicyState { @() }
        $result = Get-PolicyFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'NoSecurityBenchmark'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
        $f.Score | Should -Be 4
    }
}

# -- 6. CIS initiative present -> no CIS finding -----------------------------

Describe 'Get-PolicyFindings -- CIS initiative present' {
    It 'does not generate NoSecurityBenchmark finding when CIS initiative exists' {
        $assignment = New-PolicyAssignment -DisplayName 'CIS Microsoft Azure Foundations Benchmark'
        Mock Get-AzPolicyAssignment { @($assignment) }
        Mock Get-AzPolicyState { @() }
        $result = Get-PolicyFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'NoSecurityBenchmark' | Should -BeNullOrEmpty
    }

    It 'does not generate NoSecurityBenchmark finding when NIST initiative exists' {
        $assignment = New-PolicyAssignment -DisplayName 'NIST SP 800-53 Rev 5'
        Mock Get-AzPolicyAssignment { @($assignment) }
        Mock Get-AzPolicyState { @() }
        $result = Get-PolicyFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'NoSecurityBenchmark' | Should -BeNullOrEmpty
    }
}

# -- 7. Multiple assignments with mixed compliance -> multiple findings -------

Describe 'Get-PolicyFindings -- mixed compliance across assignments' {
    It 'generates multiple NonCompliantResources findings for different assignments' {
        $a1 = New-PolicyAssignment -Name 'a1' -DisplayName 'Policy A'
        $a2 = New-PolicyAssignment -Name 'a2' -DisplayName 'Policy B'
        Mock Get-AzPolicyAssignment { @($a1, $a2) }
        Mock Get-AzPolicyState {
            param($PolicyAssignmentName)
            @((New-PolicyState -ComplianceState 'NonCompliant' -PolicyAssignmentName $PolicyAssignmentName))
        }
        $result = Get-PolicyFindings -Subscription $script:Sub
        $ncFindings = @($result.Findings | Where-Object FindingType -eq 'NonCompliantResources')
        $ncFindings.Count | Should -Be 2
    }
}

# -- 8. Finding has correct FindingType field ---------------------------------

Describe 'Get-PolicyFindings -- FindingType field' {
    It 'returns findings with valid FindingType values' {
        Mock Get-AzPolicyAssignment { @() }
        $result = Get-PolicyFindings -Subscription $script:Sub
        foreach ($f in $result.Findings) {
            $f.FindingType | Should -BeIn @('NoPolicyAssignments', 'NonCompliantResources', 'NoSecurityBenchmark')
        }
    }
}

# -- 9. Finding has SubscriptionId and SubscriptionName fields ----------------

Describe 'Get-PolicyFindings -- subscription fields' {
    It 'includes SubscriptionId and SubscriptionName on every finding' {
        Mock Get-AzPolicyAssignment { @() }
        $result = Get-PolicyFindings -Subscription $script:Sub
        foreach ($f in $result.Findings) {
            $f.SubscriptionId | Should -Be 'sub-001'
            $f.SubscriptionName | Should -Be 'TestSub'
        }
    }
}

# -- 10. Score field is an integer --------------------------------------------

Describe 'Get-PolicyFindings -- Score type' {
    It 'returns Score as an integer on all findings' {
        Mock Get-AzPolicyAssignment { @() }
        $result = Get-PolicyFindings -Subscription $script:Sub
        foreach ($f in $result.Findings) {
            $f.Score | Should -BeOfType [int]
        }
    }
}

# -- 11. ConvertTo-JsonReport summary counts ----------------------------------

Describe 'ConvertTo-JsonReport' {
    It 'returns correct summary counts' {
        $findings = @(
            [PSCustomObject]@{ FindingType='NoPolicyAssignments'; Resource='TestSub'; Severity='HIGH'; Score=7; Description='...'; Recommendation='...'; SubscriptionId='sub-001'; SubscriptionName='TestSub' },
            [PSCustomObject]@{ FindingType='NoSecurityBenchmark'; Resource='TestSub'; Severity='MEDIUM'; Score=4; Description='...'; Recommendation='...'; SubscriptionId='sub-001'; SubscriptionName='TestSub' }
        )
        $report = ConvertTo-JsonReport -Findings $findings -TenantId 'tenant-001' -AssignmentCount 0
        $report.summary.high | Should -Be 1
        $report.summary.medium | Should -Be 1
        $report.summary.total_findings | Should -Be 2
        $report.assignments_scanned | Should -Be 0
    }
}

# -- 12. Severity helpers ----------------------------------------------------

Describe 'Get-SeverityLabel' {
    It 'returns HIGH for score 7' {
        Get-SeverityLabel -Score 7 | Should -Be 'HIGH'
    }

    It 'returns MEDIUM for score 4' {
        Get-SeverityLabel -Score 4 | Should -Be 'MEDIUM'
    }

    It 'returns CRITICAL for score 8' {
        Get-SeverityLabel -Score 8 | Should -Be 'CRITICAL'
    }
}
