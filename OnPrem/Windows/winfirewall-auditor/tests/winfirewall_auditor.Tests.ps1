# OnPrem/Windows/winfirewall-auditor/tests/winfirewall_auditor.Tests.ps1
BeforeAll {
    # NetSecurity module stubs — replaced by Pester Mocks inside each It block
    function Get-NetFirewallRule { param([string]$Direction, $Enabled, $Action) @() }
    function Get-NetFirewallPortFilter { param($AssociatedNetFirewallRule) [PSCustomObject]@{ LocalPort = 'Any'; Protocol = 'Any' } }
    function Get-NetFirewallAddressFilter { param($AssociatedNetFirewallRule) [PSCustomObject]@{ RemoteAddress = 'Any' } }
    function Get-NetFirewallProfile { @() }

    . "$PSScriptRoot/../winfirewall_auditor.ps1"
}

Describe 'Get-FirewallFindings' {

    It 'flags disabled firewall profile' {
        Mock Get-NetFirewallProfile {
            @([PSCustomObject]@{
                Name                 = 'Public'
                Enabled              = $false
                DefaultInboundAction = 'Block'
                DefaultOutboundAction = 'Allow'
                LogBlocked           = $true
            })
        }
        Mock Get-NetFirewallRule { @() }

        $findings = Get-FirewallFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'FirewallProfileDisabled' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Profile | Should -Be 'Public'
    }

    It 'flags inbound default allow' {
        Mock Get-NetFirewallProfile {
            @([PSCustomObject]@{
                Name                  = 'Public'
                Enabled               = $true
                DefaultInboundAction  = 'Allow'
                DefaultOutboundAction = 'Block'
                LogBlocked            = $true
            })
        }
        Mock Get-NetFirewallRule { @() }

        $findings = Get-FirewallFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'InboundDefaultAllow' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags RDP open to all' {
        Mock Get-NetFirewallProfile {
            @([PSCustomObject]@{
                Name                  = 'Public'
                Enabled               = $true
                DefaultInboundAction  = 'Block'
                DefaultOutboundAction = 'Block'
                LogBlocked            = $true
            })
        }
        Mock Get-NetFirewallRule {
            @([PSCustomObject]@{
                Name        = 'RDP-In'
                DisplayName = 'RDP'
                Direction   = 'Inbound'
                Enabled     = 'True'
                Action      = 'Allow'
                Profile     = 'Any'
            })
        }
        Mock Get-NetFirewallPortFilter {
            [PSCustomObject]@{ LocalPort = '3389'; Protocol = 'TCP' }
        }
        Mock Get-NetFirewallAddressFilter {
            [PSCustomObject]@{ RemoteAddress = 'Any' }
        }

        $findings = Get-FirewallFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'RDPOpenToAll' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Score | Should -Be 10
    }

    It 'flags WinRM open to all' {
        Mock Get-NetFirewallProfile {
            @([PSCustomObject]@{
                Name                  = 'Private'
                Enabled               = $true
                DefaultInboundAction  = 'Block'
                DefaultOutboundAction = 'Block'
                LogBlocked            = $true
            })
        }
        Mock Get-NetFirewallRule {
            @([PSCustomObject]@{
                Name        = 'WinRM-HTTP-In'
                DisplayName = 'Windows Remote Management (HTTP-In)'
                Direction   = 'Inbound'
                Enabled     = 'True'
                Action      = 'Allow'
                Profile     = 'Any'
            })
        }
        Mock Get-NetFirewallPortFilter {
            [PSCustomObject]@{ LocalPort = '5985'; Protocol = 'TCP' }
        }
        Mock Get-NetFirewallAddressFilter {
            [PSCustomObject]@{ RemoteAddress = 'Any' }
        }

        $findings = Get-FirewallFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'WinRMOpenToAll' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Port | Should -Be '5985'
    }

    It 'does not flag RDP rule restricted to specific IP' {
        Mock Get-NetFirewallProfile {
            @([PSCustomObject]@{
                Name                  = 'Public'
                Enabled               = $true
                DefaultInboundAction  = 'Block'
                DefaultOutboundAction = 'Block'
                LogBlocked            = $true
            })
        }
        Mock Get-NetFirewallRule {
            @([PSCustomObject]@{
                Name        = 'RDP-In-Restricted'
                DisplayName = 'RDP Restricted'
                Direction   = 'Inbound'
                Enabled     = 'True'
                Action      = 'Allow'
                Profile     = 'Any'
            })
        }
        Mock Get-NetFirewallPortFilter {
            [PSCustomObject]@{ LocalPort = '3389'; Protocol = 'TCP' }
        }
        Mock Get-NetFirewallAddressFilter {
            [PSCustomObject]@{ RemoteAddress = '192.168.1.0/24' }
        }

        $findings = Get-FirewallFindings
        $rdpFindings = $findings | Where-Object { $_.FindingType -eq 'RDPOpenToAll' }
        $rdpFindings | Should -BeNullOrEmpty
    }

    It 'flags no log dropped packets' {
        Mock Get-NetFirewallProfile {
            @([PSCustomObject]@{
                Name                  = 'Domain'
                Enabled               = $true
                DefaultInboundAction  = 'Block'
                DefaultOutboundAction = 'Allow'
                LogBlocked            = $false
            })
        }
        Mock Get-NetFirewallRule { @() }

        $findings = Get-FirewallFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'NoLogDroppedPackets' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Profile | Should -Be 'Domain'
    }
}
