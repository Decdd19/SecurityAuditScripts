# M365/m365-auditor/tests/m365_auditor.Tests.ps1
BeforeAll {
    # Stub all Graph, Exchange, and Az cmdlets before dot-sourcing
    function Connect-MgGraph        { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext          { $null }
    function Get-MgIdentityConditionalAccessPolicy { @() }
    function Get-MgPolicyAuthorizationPolicy       { $null }
    function Get-MgOrganization     { @() }

    function Connect-ExchangeOnline { param($AppId, $Organization, $ShowBanner) }
    function Get-Mailbox            { param($ResultSize) @() }
    function Get-InboxRule          { param($Mailbox) @() }
    function Get-CASMailbox         { param($Identity) $null }
    function Disconnect-ExchangeOnline { param([switch]$Confirm) }

    function Get-AzContext { @{ Tenant = @{ Id = 'tenant-001' }; Account = @{ Id = 'admin@contoso.com' } } }

    . "$PSScriptRoot/../m365_auditor.ps1"
}

# ---------------------------------------------------------------------------
# Get-M365ConditionalAccessFindings
# ---------------------------------------------------------------------------

Describe 'Get-M365ConditionalAccessFindings' {
    It 'flags when no MFA-enforcing CA policy exists' {
        Mock Get-MgIdentityConditionalAccessPolicy { @() }

        $findings = Get-M365ConditionalAccessFindings
        $finding = $findings | Where-Object { $_.FindingType -eq 'NoMfaCaPolicy' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
        $finding.CisControl | Should -Match '^CIS'
        $finding.Recommendation | Should -Match 'Conditional Access'
    }

    It 'does not flag when a report-only-excluded MFA CA policy is enabled' {
        Mock Get-MgIdentityConditionalAccessPolicy {
            @([PSCustomObject]@{
                State             = 'enabled'
                GrantControls     = [PSCustomObject]@{
                    BuiltInControls = @('mfa')
                }
                Conditions        = [PSCustomObject]@{
                    Users = [PSCustomObject]@{ IncludeUsers = @('All') }
                    Applications = [PSCustomObject]@{ IncludeApplications = @('All') }
                }
                DisplayName       = 'Require MFA for All'
            })
        }

        $findings = Get-M365ConditionalAccessFindings
        $finding = $findings | Where-Object { $_.FindingType -eq 'NoMfaCaPolicy' }
        $finding | Should -BeNullOrEmpty
    }

    It 'flags report-only CA policy as HIGH not CRITICAL' {
        Mock Get-MgIdentityConditionalAccessPolicy {
            @([PSCustomObject]@{
                State             = 'enabledForReportingButNotEnforced'
                GrantControls     = [PSCustomObject]@{ BuiltInControls = @('mfa') }
                Conditions        = [PSCustomObject]@{
                    Users = [PSCustomObject]@{ IncludeUsers = @('All') }
                    Applications = [PSCustomObject]@{ IncludeApplications = @('All') }
                }
                DisplayName       = 'Require MFA (report only)'
            })
        }

        $findings = Get-M365ConditionalAccessFindings
        $finding = $findings | Where-Object { $_.FindingType -eq 'CaPolicyReportOnly' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }
}

# ---------------------------------------------------------------------------
# Get-M365LegacyAuthFindings
# ---------------------------------------------------------------------------

Describe 'Get-M365LegacyAuthFindings' {
    It 'flags when no CA policy blocks legacy authentication' {
        Mock Get-MgIdentityConditionalAccessPolicy { @() }

        $findings = Get-M365LegacyAuthFindings
        $finding = $findings | Where-Object { $_.FindingType -eq 'LegacyAuthNotBlocked' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.CisControl | Should -Match '^CIS'
    }

    It 'does not flag when an enabled CA policy blocks legacy auth clients' {
        Mock Get-MgIdentityConditionalAccessPolicy {
            @([PSCustomObject]@{
                State         = 'enabled'
                GrantControls = [PSCustomObject]@{ BuiltInControls = @('block') }
                Conditions    = [PSCustomObject]@{
                    Users = [PSCustomObject]@{ IncludeUsers = @('All') }
                    ClientAppTypes = @('exchangeActiveSync', 'other')
                    Applications = [PSCustomObject]@{ IncludeApplications = @('All') }
                }
                DisplayName   = 'Block Legacy Auth'
            })
        }

        $findings = Get-M365LegacyAuthFindings
        $finding = $findings | Where-Object { $_.FindingType -eq 'LegacyAuthNotBlocked' }
        $finding | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-M365MailboxForwardingFindings
# ---------------------------------------------------------------------------

Describe 'Get-M365MailboxForwardingFindings' {
    It 'flags mailbox with external ForwardingSmtpAddress set' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName    = 'alice@contoso.com'
                PrimarySmtpAddress   = 'alice@contoso.com'
                ForwardingSmtpAddress = 'smtp:alice@external.com'
                ForwardingAddress    = $null
                DeliverToMailboxAndForward = $false
            })
        }
        Mock Get-InboxRule { @() }

        $findings = Get-M365MailboxForwardingFindings -TenantDomain 'contoso.com'
        $finding = $findings | Where-Object { $_.FindingType -eq 'ExternalMailboxForwarding' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Resource | Should -Be 'alice@contoso.com'
        $finding.Severity | Should -Be 'HIGH'
        $finding.CisControl | Should -Match '^CIS'
    }

    It 'does not flag mailbox with no forwarding configured' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName    = 'bob@contoso.com'
                PrimarySmtpAddress   = 'bob@contoso.com'
                ForwardingSmtpAddress = $null
                ForwardingAddress    = $null
                DeliverToMailboxAndForward = $false
            })
        }
        Mock Get-InboxRule { @() }

        $findings = Get-M365MailboxForwardingFindings -TenantDomain 'contoso.com'
        $findings | Should -BeNullOrEmpty
    }

    It 'flags inbox rule that forwards to external address' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName    = 'carol@contoso.com'
                PrimarySmtpAddress   = 'carol@contoso.com'
                ForwardingSmtpAddress = $null
                ForwardingAddress    = $null
                DeliverToMailboxAndForward = $false
            })
        }
        Mock Get-InboxRule {
            @([PSCustomObject]@{
                Name            = 'Forward to personal'
                ForwardTo       = @('external@gmail.com')
                ForwardAsAttachmentTo = $null
                RedirectTo      = $null
                Enabled         = $true
            })
        }

        $findings = Get-M365MailboxForwardingFindings -TenantDomain 'contoso.com'
        $finding = $findings | Where-Object { $_.FindingType -eq 'ExternalInboxForwardRule' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }
}

# ---------------------------------------------------------------------------
# Get-M365OAuthConsentFindings
# ---------------------------------------------------------------------------

Describe 'Get-M365OAuthConsentFindings' {
    It 'flags when user consent to OAuth apps is unrestricted' {
        Mock Get-MgPolicyAuthorizationPolicy {
            [PSCustomObject]@{
                DefaultUserRolePermissions = [PSCustomObject]@{
                    AllowedToCreateApps = $true
                    PermissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
                }
            }
        }

        $findings = Get-M365OAuthConsentFindings
        $finding = $findings | Where-Object { $_.FindingType -eq 'UnrestrictedOAuthConsent' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -BeIn @('HIGH', 'CRITICAL')
        $finding.CisControl | Should -Match '^CIS'
        $finding.Recommendation | Should -Match 'consent'
    }

    It 'does not flag when OAuth consent is restricted or disabled' {
        Mock Get-MgPolicyAuthorizationPolicy {
            [PSCustomObject]@{
                DefaultUserRolePermissions = [PSCustomObject]@{
                    AllowedToCreateApps = $false
                    PermissionGrantPoliciesAssigned = @()
                }
            }
        }

        $findings = Get-M365OAuthConsentFindings
        $finding = $findings | Where-Object { $_.FindingType -eq 'UnrestrictedOAuthConsent' }
        $finding | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# ConvertTo-M365JsonReport
# ---------------------------------------------------------------------------

Describe 'ConvertTo-M365JsonReport' {
    It 'emits standard schema with generated_at, summary, findings' {
        $finding = [PSCustomObject]@{
            FindingType    = 'NoMfaCaPolicy'
            Resource       = 'tenant'
            Score          = 9
            Severity       = 'CRITICAL'
            CisControl     = 'CIS 6'
            Recommendation = 'Enable MFA policy'
        }
        $report = ConvertTo-M365JsonReport -Findings @($finding) -TenantId 'tenant-001'

        $report.generated_at | Should -Not -BeNullOrEmpty
        $report.summary | Should -Not -BeNullOrEmpty
        $report.summary.critical | Should -Be 1
        $report.findings | Should -HaveCount 1
        $report.findings[0].cis_control | Should -Be 'CIS 6'
        $report.findings[0].risk_level | Should -Be 'CRITICAL'
        $report.findings[0].severity_score | Should -Be 9
    }
}
