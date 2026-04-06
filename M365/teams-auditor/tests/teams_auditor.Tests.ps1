# M365/teams-auditor/tests/teams_auditor.Tests.ps1
BeforeAll {
    function Connect-MicrosoftTeams  { param($TenantId) }
    function Disconnect-MicrosoftTeams { }
    function Get-CsTenantFederationConfiguration {
        [PSCustomObject]@{ AllowFederatedUsers = $false; AllowedDomains = @() }
    }
    function Get-CsTeamsMeetingPolicy {
        param($Identity)
        [PSCustomObject]@{
            AllowAnonymousUsersToJoinMeeting = $false
            AutoAdmittedUsers                = 'EveryoneInCompany'
            AllowCloudRecording              = $false
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
    function Get-AzContext { @{ Tenant = @{ Id = 'tid-001' }; Account = @{ Id = 'admin@contoso.com' } } }

    . "$PSScriptRoot/../teams_auditor.ps1"
}

# ---------------------------------------------------------------------------
# Get-TeamsFederationFindings
# ---------------------------------------------------------------------------

Describe 'Get-TeamsFederationFindings' {
    It 'flags TM-01 when AllowFederatedUsers is true with no domain restriction' {
        Mock Get-CsTenantFederationConfiguration {
            [PSCustomObject]@{ AllowFederatedUsers = $true; AllowedDomains = @() }
        }
        $findings = Get-TeamsFederationFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'ExternalAccessAllDomains' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
        $f.CisControl | Should -Match '^CIS'
    }

    It 'does not flag TM-01 when AllowFederatedUsers is false' {
        Mock Get-CsTenantFederationConfiguration {
            [PSCustomObject]@{ AllowFederatedUsers = $false; AllowedDomains = @() }
        }
        $findings = Get-TeamsFederationFindings
        ($findings | Where-Object { $_.FindingType -eq 'ExternalAccessAllDomains' }) | Should -BeNullOrEmpty
    }

    It 'does not flag TM-01 when federation restricted to allowed domains' {
        Mock Get-CsTenantFederationConfiguration {
            [PSCustomObject]@{ AllowFederatedUsers = $true; AllowedDomains = @('partner.com') }
        }
        $findings = Get-TeamsFederationFindings
        ($findings | Where-Object { $_.FindingType -eq 'ExternalAccessAllDomains' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-TeamsGuestFindings
# ---------------------------------------------------------------------------

Describe 'Get-TeamsGuestFindings' {
    It 'flags TM-02 when AllowGuestUser is true' {
        Mock Get-CsTeamsClientConfiguration {
            [PSCustomObject]@{ AllowGuestUser = $true }
        }
        Mock Get-CsTeamsChannelPolicy {
            [PSCustomObject]@{ AllowGuestCreateUpdateChannels = $false; AllowGuestDeleteChannels = $false }
        }
        $findings = Get-TeamsGuestFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'GuestAccessUnrestricted' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'flags TM-03 when guests can create channels' {
        Mock Get-CsTeamsClientConfiguration {
            [PSCustomObject]@{ AllowGuestUser = $true }
        }
        Mock Get-CsTeamsChannelPolicy {
            [PSCustomObject]@{ AllowGuestCreateUpdateChannels = $true; AllowGuestDeleteChannels = $false }
        }
        $findings = Get-TeamsGuestFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'GuestsCanCreateChannels' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'does not flag TM-02/TM-03 when guest access is disabled' {
        Mock Get-CsTeamsClientConfiguration {
            [PSCustomObject]@{ AllowGuestUser = $false }
        }
        Mock Get-CsTeamsChannelPolicy {
            [PSCustomObject]@{ AllowGuestCreateUpdateChannels = $true; AllowGuestDeleteChannels = $true }
        }
        $findings = Get-TeamsGuestFindings
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-TeamsMeetingFindings
# ---------------------------------------------------------------------------

Describe 'Get-TeamsMeetingFindings' {
    It 'flags TM-04 when AutoAdmittedUsers is Everyone (lobby bypass)' {
        Mock Get-CsTeamsMeetingPolicy {
            [PSCustomObject]@{
                AllowAnonymousUsersToJoinMeeting  = $true
                AutoAdmittedUsers                 = 'Everyone'
                AllowCloudRecording               = $false
                NewMeetingRecordingExpirationDays = 60
            }
        }
        $findings = Get-TeamsMeetingFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'MeetingLobbyBypassAnonymous' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'flags TM-05 when recordings have no expiry (value is -1)' {
        Mock Get-CsTeamsMeetingPolicy {
            [PSCustomObject]@{
                AllowAnonymousUsersToJoinMeeting  = $false
                AutoAdmittedUsers                 = 'EveryoneInCompany'
                AllowCloudRecording               = $true
                NewMeetingRecordingExpirationDays = -1
            }
        }
        $findings = Get-TeamsMeetingFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'RecordingsNoExpiry' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'does not flag TM-04 when AutoAdmittedUsers restricts anonymous' {
        Mock Get-CsTeamsMeetingPolicy {
            [PSCustomObject]@{
                AllowAnonymousUsersToJoinMeeting  = $false
                AutoAdmittedUsers                 = 'EveryoneInCompany'
                AllowCloudRecording               = $true
                NewMeetingRecordingExpirationDays = 60
            }
        }
        $findings = Get-TeamsMeetingFindings
        ($findings | Where-Object { $_.FindingType -eq 'MeetingLobbyBypassAnonymous' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-TeamsAppFindings
# ---------------------------------------------------------------------------

Describe 'Get-TeamsAppFindings' {
    It 'flags TM-06 when DefaultCatalogAppsType is AllowedAppList (all apps permitted)' {
        Mock Get-CsTeamsAppPermissionPolicy {
            [PSCustomObject]@{ DefaultCatalogAppsType = 'AllowedAppList'; GlobalCatalogAppsType = 'AllowedAppList' }
        }
        $findings = Get-TeamsAppFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'UnmanagedAppInstallsAllowed' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'does not flag TM-06 when apps are restricted' {
        Mock Get-CsTeamsAppPermissionPolicy {
            [PSCustomObject]@{ DefaultCatalogAppsType = 'BlockedAppList'; GlobalCatalogAppsType = 'BlockedAppList' }
        }
        $findings = Get-TeamsAppFindings
        ($findings | Where-Object { $_.FindingType -eq 'UnmanagedAppInstallsAllowed' }) | Should -BeNullOrEmpty
    }
}
