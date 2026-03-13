BeforeAll {
    # Define stub functions BEFORE dot-sourcing so they shadow real Az cmdlets
    function Get-AzContext { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = 'sub-001'; Name = 'TestSub' } }
    function Set-AzContext { }

    . "$PSScriptRoot/../nsg_auditor.ps1"
}

Describe 'Get-NsgFindings' {
    BeforeEach {
        $dangerousRule = [PSCustomObject]@{
            Name                  = 'allow-rdp'
            Direction             = 'Inbound'
            Access                = 'Allow'
            SourceAddressPrefix   = '*'
            DestinationPortRange  = '3389'
            DestinationPortRanges = @()
            Priority              = 100
        }
        $safeRule = [PSCustomObject]@{
            Name                  = 'allow-https'
            Direction             = 'Inbound'
            Access                = 'Allow'
            SourceAddressPrefix   = '10.0.0.1'
            DestinationPortRange  = '443'
            DestinationPortRanges = @()
            Priority              = 200
        }
        $denyRule = [PSCustomObject]@{
            Name                  = 'deny-all'
            Direction             = 'Inbound'
            Access                = 'Deny'
            SourceAddressPrefix   = '*'
            DestinationPortRange  = '*'
            DestinationPortRanges = @()
            Priority              = 4096
        }
        $nsg = [PSCustomObject]@{
            Name              = 'test-nsg'
            ResourceGroupName = 'test-rg'
            Id                = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg'
            NetworkInterfaces = @()
            Subnets           = @([PSCustomObject]@{ Id = '/subs/sub-001/subnets/sub1' })
            SecurityRules     = @($dangerousRule, $safeRule, $denyRule)
        }
        Mock Get-AzNetworkSecurityGroup { @($nsg) }
    }

    It 'flags RDP open to internet as CRITICAL or HIGH' {
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-NsgFindings -Subscription $sub
        $rdpFinding = $findings | Where-Object { $_.Port -eq 3389 -and $_.NsgName -eq 'test-nsg' }
        $rdpFinding | Should -Not -BeNullOrEmpty
        $rdpFinding.Severity | Should -BeIn @('CRITICAL', 'HIGH')
    }

    It 'does not flag HTTPS restricted to specific IP' {
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-NsgFindings -Subscription $sub
        $httpsFinding = $findings | Where-Object { $_.Port -eq 443 -and $_.NsgName -eq 'test-nsg' }
        $httpsFinding | Should -BeNullOrEmpty
    }

    It 'flags NSG with no explicit deny rules as MEDIUM' {
        $nsgNoDeny = [PSCustomObject]@{
            Name              = 'nodeny-nsg'
            ResourceGroupName = 'test-rg'
            Id                = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/nodeny-nsg'
            NetworkInterfaces = @()
            Subnets           = @([PSCustomObject]@{ Id = '/subs/sub-001/subnets/sub1' })
            SecurityRules     = @(
                [PSCustomObject]@{
                    Name = 'allow-web'; Direction = 'Inbound'; Access = 'Allow'
                    SourceAddressPrefix = '10.0.0.0/8'
                    DestinationPortRange = '443'; DestinationPortRanges = @(); Priority = 100
                }
            )
        }
        Mock Get-AzNetworkSecurityGroup { @($nsgNoDeny) }
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-NsgFindings -Subscription $sub
        $finding = $findings | Where-Object { $_.NsgName -eq 'nodeny-nsg' -and $_.FindingType -eq 'NoDenyRules' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
    }

    It 'flags orphaned NSG with no subnet or NIC association' {
        $orphanNsg = [PSCustomObject]@{
            Name              = 'orphan-nsg'
            ResourceGroupName = 'test-rg'
            Id                = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/orphan-nsg'
            NetworkInterfaces = @()
            Subnets           = @()
            SecurityRules     = @()
        }
        Mock Get-AzNetworkSecurityGroup { @($orphanNsg) }
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $findings = Get-NsgFindings -Subscription $sub
        $orphanFinding = $findings | Where-Object { $_.NsgName -eq 'orphan-nsg' -and $_.FindingType -eq 'Orphaned' }
        $orphanFinding | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-SeverityLabel' {
    It 'returns CRITICAL for score 8-10' {
        Get-SeverityLabel 8  | Should -Be 'CRITICAL'
        Get-SeverityLabel 10 | Should -Be 'CRITICAL'
    }
    It 'returns HIGH for score 6-7' {
        Get-SeverityLabel 6 | Should -Be 'HIGH'
        Get-SeverityLabel 7 | Should -Be 'HIGH'
    }
    It 'returns MEDIUM for score 3-5' {
        Get-SeverityLabel 3 | Should -Be 'MEDIUM'
        Get-SeverityLabel 5 | Should -Be 'MEDIUM'
    }
    It 'returns LOW for score 1-2' {
        Get-SeverityLabel 1 | Should -Be 'LOW'
        Get-SeverityLabel 2 | Should -Be 'LOW'
    }
}

Describe 'ConvertTo-HtmlReport' {
    It 'produces valid HTML containing finding data' {
        $findings = @([PSCustomObject]@{
            NsgName        = 'test-nsg'
            ResourceGroup  = 'test-rg'
            Subscription   = 'TestSub'
            SubscriptionId = 'sub-001'
            FindingType    = 'DangerousPort'
            Port           = 3389
            SourceRange    = '*'
            RuleName       = 'allow-rdp'
            Score          = 9
            Severity       = 'CRITICAL'
            Recommendation = 'Restrict RDP access to known IPs or remove rule.'
        })
        $html = ConvertTo-HtmlReport -Findings $findings -TenantId 'tenant-001'
        $html | Should -Match '<html'
        $html | Should -Match 'test-nsg'
        $html | Should -Match 'CRITICAL'
        $html | Should -Match '3389'
    }
}
