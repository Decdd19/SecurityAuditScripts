# Azure/entra-auditor/tests/entra_auditor.Tests.ps1
BeforeAll {
    function Get-AzContext { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = 'sub-001'; Name = 'TestSub' } }
    function Set-AzContext { }
    function Get-MgUserAuthenticationMethod { @() }
    function Get-AzADUser { @() }
    function Get-AzRoleAssignment { @() }
    function Get-AzADServicePrincipal { @() }
    function Get-AzADApplication { @() }
    function Get-AzADAppCredential { @() }
    function Get-AzRoleDefinition { @() }

    . "$PSScriptRoot/../entra_auditor.ps1"
}

Describe 'Get-EntraFindings' {
    It 'flags user without MFA' {
        $user = [PSCustomObject]@{
            Id          = 'user-001'
            DisplayName = 'Test User'
            UserPrincipalName = 'test@contoso.com'
            UserType    = 'Member'
        }
        Mock Get-AzADUser { @($user) }
        Mock Get-MgUserAuthenticationMethod {
            param($UserId)
            # Return only password method — no MFA
            @([PSCustomObject]@{ AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' } })
        }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzADServicePrincipal { @() }
        Mock Get-AzADApplication { @() }
        Mock Get-AzRoleDefinition { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-EntraFindings -Subscription $sub
        $finding = $findings | Where-Object { $_.FindingType -eq 'UserNoMfa' -and $_.PrincipalName -eq 'test@contoso.com' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'flags guest user with Owner role assignment' {
        $guestUser = [PSCustomObject]@{
            Id = 'guest-001'; DisplayName = 'External User'
            UserPrincipalName = 'ext@partner.com'; UserType = 'Guest'
        }
        Mock Get-AzADUser { @($guestUser) }
        Mock Get-MgUserAuthenticationMethod { @() }
        Mock Get-AzRoleAssignment {
            @([PSCustomObject]@{
                ObjectId           = 'guest-001'
                ObjectType         = 'User'
                RoleDefinitionName = 'Owner'
                Scope              = '/subscriptions/sub-001'
            })
        }
        Mock Get-AzADServicePrincipal { @() }
        Mock Get-AzADApplication { @() }
        Mock Get-AzRoleDefinition { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-EntraFindings -Subscription $sub
        $finding = $findings | Where-Object { $_.FindingType -eq 'PrivilegedGuest' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -BeIn @('HIGH', 'CRITICAL')
    }

    It 'flags app registration with stale secret (>90 days old)' {
        $app = [PSCustomObject]@{ AppId = 'app-001'; DisplayName = 'OldApp'; Id = 'app-001' }
        $staleSecret = [PSCustomObject]@{
            KeyId    = 'key-001'
            EndDateTime = (Get-Date).AddDays(-100)  # expired
            StartDateTime = (Get-Date).AddDays(-200)
            Type     = 'Password'
        }
        Mock Get-AzADUser { @() }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzADServicePrincipal { @() }
        Mock Get-AzADApplication { @($app) }
        Mock Get-AzADAppCredential { param($ObjectId) @($staleSecret) }
        Mock Get-AzRoleDefinition { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-EntraFindings -Subscription $sub
        $finding = $findings | Where-Object { $_.FindingType -eq 'StaleAppCredential' -and $_.PrincipalName -eq 'OldApp' }
        $finding | Should -Not -BeNullOrEmpty
    }

    It 'does not flag user with MFA registered' {
        $user = [PSCustomObject]@{
            Id = 'user-mfa'; DisplayName = 'MFA User'
            UserPrincipalName = 'mfa@contoso.com'; UserType = 'Member'
        }
        Mock Get-AzADUser { @($user) }
        Mock Get-MgUserAuthenticationMethod {
            param($UserId)
            @(
                [PSCustomObject]@{ AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' } },
                [PSCustomObject]@{ AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' } }
            )
        }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzADServicePrincipal { @() }
        Mock Get-AzADApplication { @() }
        Mock Get-AzRoleDefinition { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-EntraFindings -Subscription $sub
        $noMfaFindings = $findings | Where-Object { $_.FindingType -eq 'UserNoMfa' }
        $noMfaFindings | Should -BeNullOrEmpty
    }

    It 'flags custom role with wildcard write permissions' {
        Mock Get-AzADUser { @() }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzADServicePrincipal { @() }
        Mock Get-AzADApplication { @() }
        Mock Get-AzRoleDefinition {
            @([PSCustomObject]@{
                Name       = 'DangerousCustomRole'
                IsCustom   = $true
                Actions    = @('Microsoft.Compute/*/write', 'Microsoft.Storage/*/read')
                NotActions = @()
            })
        }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-EntraFindings -Subscription $sub
        $finding = $findings | Where-Object { $_.FindingType -eq 'OverpermissiveCustomRole' }
        $finding | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-PrivescFindings' {
    It 'flags principal with User Access Administrator + Contributor' {
        $assignments = @(
            [PSCustomObject]@{ ObjectId = 'user-001'; RoleDefinitionName = 'User Access Administrator'; Scope = '/subscriptions/sub-001' }
            [PSCustomObject]@{ ObjectId = 'user-001'; RoleDefinitionName = 'Contributor'; Scope = '/subscriptions/sub-001' }
        )
        $findings = Get-PrivescFindings -Assignments $assignments -SubscriptionName 'TestSub' -SubscriptionId 'sub-001'
        $finding = $findings | Where-Object { $_.FindingType -eq 'PrivilegeEscalationPath' -and $_.ObjectId -eq 'user-001' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags service principal with Owner role as unmonitored privileged SP' {
        $assignments = @(
            [PSCustomObject]@{ ObjectId = 'sp-001'; ObjectType = 'ServicePrincipal'; RoleDefinitionName = 'Owner'; Scope = '/subscriptions/sub-001' }
        )
        $findings = Get-PrivescFindings -Assignments $assignments -SubscriptionName 'TestSub' -SubscriptionId 'sub-001'
        $finding = $findings | Where-Object { $_.FindingType -eq 'PrivilegeEscalationPath' -and $_.ObjectId -eq 'sp-001' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }
}
