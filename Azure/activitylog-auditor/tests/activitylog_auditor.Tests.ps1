BeforeAll {
    function Get-AzContext { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = 'sub-001'; Name = 'TestSub' } }
    function Set-AzContext { }
    function Get-AzDiagnosticSetting { @() }
    function Get-AzActivityLogAlert { @() }

    . "$PSScriptRoot/../activitylog_auditor.ps1"
}

Describe 'Get-ActivityLogFindings' {
    It 'flags subscription with no diagnostic setting as CRITICAL' {
        Mock Get-AzDiagnosticSetting { @() }
        Mock Get-AzActivityLogAlert { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-ActivityLogFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'NoDiagnosticSetting' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags diagnostic setting with no destination configured as CRITICAL' {
        $diagSetting = [PSCustomObject]@{
            Name             = 'test-diag'
            WorkspaceId      = $null
            StorageAccountId = $null
            EventHubName     = $null
            Logs             = @()
        }
        Mock Get-AzDiagnosticSetting { @($diagSetting) }
        Mock Get-AzActivityLogAlert { @([PSCustomObject]@{ Name = 'alert1' }) }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-ActivityLogFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'NoLogDestination' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags diagnostic setting missing Administrative category as HIGH' {
        $diagSetting = [PSCustomObject]@{
            Name             = 'test-diag'
            WorkspaceId      = '/subscriptions/sub-001/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
            StorageAccountId = $null
            EventHubName     = $null
            Logs             = @(
                [PSCustomObject]@{ Category = 'Security';  Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Policy';    Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Alert';     Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                # Administrative is missing
            )
        }
        Mock Get-AzDiagnosticSetting { @($diagSetting) }
        Mock Get-AzActivityLogAlert { @([PSCustomObject]@{ Name = 'alert1' }) }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-ActivityLogFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'MissingLogCategory' -and $_.Detail -like '*Administrative*' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'flags subscription with no Activity Log alerts as HIGH' {
        $diagSetting = [PSCustomObject]@{
            Name             = 'test-diag'
            WorkspaceId      = '/subscriptions/sub-001/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
            StorageAccountId = $null
            EventHubName     = $null
            Logs             = @(
                [PSCustomObject]@{ Category = 'Administrative'; Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Security';       Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Policy';         Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Alert';          Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
            )
        }
        Mock Get-AzDiagnosticSetting { @($diagSetting) }
        Mock Get-AzActivityLogAlert { @() }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-ActivityLogFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'NoActivityLogAlerts' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'flags short retention on storage account destination as MEDIUM' {
        $diagSetting = [PSCustomObject]@{
            Name             = 'test-diag'
            WorkspaceId      = $null
            StorageAccountId = '/subscriptions/sub-001/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa'
            EventHubName     = $null
            Logs             = @(
                [PSCustomObject]@{ Category = 'Administrative'; Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 30; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Security';       Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 30; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Policy';         Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 30; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Alert';          Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 30; Enabled = $true } }
            )
        }
        Mock Get-AzDiagnosticSetting { @($diagSetting) }
        Mock Get-AzActivityLogAlert { @([PSCustomObject]@{ Name = 'alert1' }) }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-ActivityLogFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'ShortRetention' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
    }

    It 'returns empty findings for fully compliant subscription' {
        $diagSetting = [PSCustomObject]@{
            Name             = 'compliant-diag'
            WorkspaceId      = '/subscriptions/sub-001/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
            StorageAccountId = $null
            EventHubName     = $null
            Logs             = @(
                [PSCustomObject]@{ Category = 'Administrative'; Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Security';       Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Policy';         Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
                [PSCustomObject]@{ Category = 'Alert';          Enabled = $true; RetentionPolicy = [PSCustomObject]@{ Days = 90; Enabled = $true } }
            )
        }
        Mock Get-AzDiagnosticSetting { @($diagSetting) }
        Mock Get-AzActivityLogAlert { @([PSCustomObject]@{ Name = 'alert1' }) }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-ActivityLogFindings -Subscription $sub
        $result.Findings | Should -BeNullOrEmpty
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
