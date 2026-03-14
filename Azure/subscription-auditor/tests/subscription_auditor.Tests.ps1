BeforeAll {
    function Get-AzContext { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = 'sub-001'; Name = 'TestSub' } }
    function Set-AzContext { }
    function Get-AzSecurityPricing { @() }
    function Get-AzRoleAssignment { @() }
    function Get-AzResourceLock { @() }
    function Get-AzConsumptionBudget { @() }
    function Get-MgRoleManagementDirectoryRoleAssignment { @() }
    function Get-MgUserAuthenticationMethod { @() }
    function Get-MgRoleManagementDirectoryRoleEligibilitySchedule { @() }

    . "$PSScriptRoot/../subscription_auditor.ps1"
}

Describe 'Get-SubscriptionFindings' {
    It 'flags Defender for Cloud at Free tier as HIGH' {
        Mock Get-AzSecurityPricing {
            @([PSCustomObject]@{ Name = 'VirtualMachines'; PricingTier = 'Free' })
        }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzResourceLock { @([PSCustomObject]@{ LockId = 'lock1' }) }
        Mock Get-AzConsumptionBudget { @([PSCustomObject]@{ Name = 'budget1' }) }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { @() }
        Mock Get-MgUserAuthenticationMethod { @() }
        Mock Get-MgRoleManagementDirectoryRoleEligibilitySchedule { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-SubscriptionFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'DefenderNotEnabled' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'flags permanent human Owner assignment with no PIM as CRITICAL' {
        Mock Get-AzSecurityPricing {
            @([PSCustomObject]@{ Name = 'VirtualMachines'; PricingTier = 'Standard' })
        }
        Mock Get-AzRoleAssignment {
            @([PSCustomObject]@{
                RoleDefinitionName = 'Owner'
                ObjectType         = 'User'
                ObjectId           = 'user-001'
                SignInName         = 'admin@contoso.com'
                Scope              = '/subscriptions/sub-001'
            })
        }
        Mock Get-AzResourceLock { @([PSCustomObject]@{ LockId = 'lock1' }) }
        Mock Get-AzConsumptionBudget { @([PSCustomObject]@{ Name = 'budget1' }) }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { @() }
        Mock Get-MgUserAuthenticationMethod { @() }
        Mock Get-MgRoleManagementDirectoryRoleEligibilitySchedule { @() }  # No eligible assignments

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-SubscriptionFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'PermanentOwnerAssignment' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'does not flag Owner assignment when PIM eligible assignment exists' {
        Mock Get-AzSecurityPricing {
            @([PSCustomObject]@{ Name = 'VirtualMachines'; PricingTier = 'Standard' })
        }
        Mock Get-AzRoleAssignment {
            @([PSCustomObject]@{
                RoleDefinitionName = 'Owner'
                ObjectType         = 'User'
                ObjectId           = 'user-001'
                SignInName         = 'admin@contoso.com'
                Scope              = '/subscriptions/sub-001'
            })
        }
        Mock Get-AzResourceLock { @([PSCustomObject]@{ LockId = 'lock1' }) }
        Mock Get-AzConsumptionBudget { @([PSCustomObject]@{ Name = 'budget1' }) }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { @() }
        Mock Get-MgUserAuthenticationMethod { @() }
        # Eligible assignment exists for same user
        Mock Get-MgRoleManagementDirectoryRoleEligibilitySchedule {
            @([PSCustomObject]@{ PrincipalId = 'user-001' })
        }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-SubscriptionFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'PermanentOwnerAssignment' }
        $finding | Should -BeNullOrEmpty
    }

    It 'flags subscription with no resource locks as MEDIUM' {
        Mock Get-AzSecurityPricing {
            @([PSCustomObject]@{ Name = 'VirtualMachines'; PricingTier = 'Standard' })
        }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzResourceLock { @() }
        Mock Get-AzConsumptionBudget { @([PSCustomObject]@{ Name = 'budget1' }) }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { @() }
        Mock Get-MgUserAuthenticationMethod { @() }
        Mock Get-MgRoleManagementDirectoryRoleEligibilitySchedule { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-SubscriptionFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'NoResourceLocks' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
    }

    It 'flags subscription with no budget alerts as LOW' {
        Mock Get-AzSecurityPricing {
            @([PSCustomObject]@{ Name = 'VirtualMachines'; PricingTier = 'Standard' })
        }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzResourceLock { @([PSCustomObject]@{ LockId = 'lock1' }) }
        Mock Get-AzConsumptionBudget { @() }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { @() }
        Mock Get-MgUserAuthenticationMethod { @() }
        Mock Get-MgRoleManagementDirectoryRoleEligibilitySchedule { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-SubscriptionFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'NoBudgetAlerts' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'LOW'
    }

    It 'flags Global Admin without MFA as CRITICAL' {
        Mock Get-AzSecurityPricing {
            @([PSCustomObject]@{ Name = 'VirtualMachines'; PricingTier = 'Standard' })
        }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzResourceLock { @([PSCustomObject]@{ LockId = 'lock1' }) }
        Mock Get-AzConsumptionBudget { @([PSCustomObject]@{ Name = 'budget1' }) }
        # One Global Admin assignment
        Mock Get-MgRoleManagementDirectoryRoleAssignment {
            @([PSCustomObject]@{
                PrincipalId = 'ga-001'
                Principal   = [PSCustomObject]@{ DisplayName = 'GlobalAdmin'; UserPrincipalName = 'ga@contoso.com' }
            })
        }
        # No MFA methods (only password method)
        Mock Get-MgUserAuthenticationMethod {
            @([PSCustomObject]@{ AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' } })
        }
        Mock Get-MgRoleManagementDirectoryRoleEligibilitySchedule { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-SubscriptionFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'GlobalAdminNoMfa' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }
}

Describe 'Get-SeverityLabel' {
    It 'returns correct labels' {
        Get-SeverityLabel 9 | Should -Be 'CRITICAL'
        Get-SeverityLabel 7 | Should -Be 'HIGH'
        Get-SeverityLabel 4 | Should -Be 'MEDIUM'
        Get-SeverityLabel 2 | Should -Be 'LOW'
    }
}
