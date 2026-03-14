BeforeAll {
    function Get-AzContext { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = 'sub-001'; Name = 'TestSub' } }
    function Set-AzContext { }
    function Get-AzStorageAccount { @() }
    function New-AzStorageContext { [PSCustomObject]@{} }
    function Get-AzStorageBlobServiceProperty { [PSCustomObject]@{ DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 } } }
    function Get-AzDiagnosticSetting { param($ResourceId) @([PSCustomObject]@{ Name = 'default' }) }

    . "$PSScriptRoot/../storage_auditor.ps1"
}

Describe 'Get-StorageFindings' {
    It 'flags storage account with public blob access enabled' {
        $account = [PSCustomObject]@{
            StorageAccountName    = 'publicstore'
            ResourceGroupName     = 'test-rg'
            AllowBlobPublicAccess  = $true
            AllowSharedKeyAccess   = $false
            EnableHttpsTrafficOnly = $true
            Id                     = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/publicstore'
            Encryption             = [PSCustomObject]@{
                KeySource = 'Microsoft.Storage'
                RequireInfrastructureEncryption = $false
            }
            SasPolicy              = [PSCustomObject]@{ ExpirationAction = 'Log'; SasExpirationPeriod = '30.00:00:00' }
        }
        Mock Get-AzStorageAccount { @($account) }
        Mock New-AzStorageContext { [PSCustomObject]@{ StorageAccountName = 'publicstore' } }
        Mock Get-AzStorageBlobServiceProperty {
            [PSCustomObject]@{ DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 } }
        }
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.AccountName -eq 'publicstore' -and $_.FindingType -eq 'PublicBlobAccess' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags storage account with shared key access enabled' {
        $account = [PSCustomObject]@{
            StorageAccountName    = 'sharedkeystore'
            ResourceGroupName     = 'test-rg'
            AllowBlobPublicAccess  = $false
            AllowSharedKeyAccess   = $true
            EnableHttpsTrafficOnly = $true
            Id                     = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/sharedkeystore'
            Encryption             = [PSCustomObject]@{
                KeySource = 'Microsoft.Storage'
                RequireInfrastructureEncryption = $false
            }
            SasPolicy              = [PSCustomObject]@{ ExpirationAction = 'Log'; SasExpirationPeriod = '30.00:00:00' }
        }
        Mock Get-AzStorageAccount { @($account) }
        Mock New-AzStorageContext { [PSCustomObject]@{ StorageAccountName = 'sharedkeystore' } }
        Mock Get-AzStorageBlobServiceProperty {
            [PSCustomObject]@{ DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 } }
        }
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.AccountName -eq 'sharedkeystore' -and $_.FindingType -eq 'SharedKeyAccess' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'flags storage account without customer-managed keys' {
        $account = [PSCustomObject]@{
            StorageAccountName    = 'nokmstore'
            ResourceGroupName     = 'test-rg'
            AllowBlobPublicAccess  = $false
            AllowSharedKeyAccess   = $false
            EnableHttpsTrafficOnly = $true
            Id                     = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/nokmstore'
            Encryption             = [PSCustomObject]@{
                KeySource = 'Microsoft.Storage'
                RequireInfrastructureEncryption = $false
            }
            SasPolicy              = [PSCustomObject]@{ ExpirationAction = 'Log'; SasExpirationPeriod = '30.00:00:00' }
        }
        Mock Get-AzStorageAccount { @($account) }
        Mock New-AzStorageContext { [PSCustomObject]@{ StorageAccountName = 'nokmstore' } }
        Mock Get-AzStorageBlobServiceProperty {
            [PSCustomObject]@{ DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 } }
        }
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.AccountName -eq 'nokmstore' -and $_.FindingType -eq 'NoCustomerManagedKey' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
    }

    It 'flags storage account with soft delete disabled' {
        $account = [PSCustomObject]@{
            StorageAccountName    = 'nosoftdelete'
            ResourceGroupName     = 'test-rg'
            AllowBlobPublicAccess  = $false
            AllowSharedKeyAccess   = $false
            EnableHttpsTrafficOnly = $true
            Id                     = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/nosoftdelete'
            Encryption             = [PSCustomObject]@{
                KeySource = 'Microsoft.Keyvault'
                RequireInfrastructureEncryption = $true
            }
            SasPolicy              = [PSCustomObject]@{ ExpirationAction = 'Log'; SasExpirationPeriod = '30.00:00:00' }
        }
        Mock Get-AzStorageAccount { @($account) }
        Mock New-AzStorageContext { [PSCustomObject]@{ StorageAccountName = 'nosoftdelete' } }
        Mock Get-AzStorageBlobServiceProperty {
            [PSCustomObject]@{ DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $false } }
        }
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.AccountName -eq 'nosoftdelete' -and $_.FindingType -eq 'SoftDeleteDisabled' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
    }

    It 'does not flag a well-configured storage account' {
        $account = [PSCustomObject]@{
            StorageAccountName    = 'securestore'
            ResourceGroupName     = 'test-rg'
            AllowBlobPublicAccess  = $false
            AllowSharedKeyAccess   = $false
            EnableHttpsTrafficOnly = $true
            Id                     = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/securestore'
            Encryption             = [PSCustomObject]@{
                KeySource = 'Microsoft.Keyvault'
                RequireInfrastructureEncryption = $true
            }
            SasPolicy              = [PSCustomObject]@{
                ExpirationAction = 'Log'
                SasExpirationPeriod = '1.00:00:00'
            }
        }
        Mock Get-AzStorageAccount { @($account) }
        Mock New-AzStorageContext { [PSCustomObject]@{ StorageAccountName = 'securestore' } }
        Mock Get-AzStorageBlobServiceProperty {
            [PSCustomObject]@{ DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }; IsVersioningEnabled = $true }
        }
        Mock Get-AzDiagnosticSetting { @([PSCustomObject]@{ Name = 'default' }) }
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $result.Findings | Should -BeNullOrEmpty
    }

    It 'flags storage account with no diagnostic logging configured' {
        $account = [PSCustomObject]@{
            StorageAccountName    = 'nodiagstore'
            ResourceGroupName     = 'test-rg'
            AllowBlobPublicAccess  = $false
            AllowSharedKeyAccess   = $false
            EnableHttpsTrafficOnly = $true
            Id                     = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/nodiagstore'
            SasPolicy              = [PSCustomObject]@{ ExpirationAction = 'Log'; SasExpirationPeriod = '1.00:00:00' }
            Encryption             = [PSCustomObject]@{
                KeySource = 'Microsoft.Keyvault'
                RequireInfrastructureEncryption = $true
            }
        }
        Mock Get-AzStorageAccount { @($account) }
        Mock New-AzStorageContext { [PSCustomObject]@{ StorageAccountName = 'nodiagstore' } }
        Mock Get-AzStorageBlobServiceProperty {
            [PSCustomObject]@{
                DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                IsVersioningEnabled   = $true
            }
        }
        Mock Get-AzDiagnosticSetting { @() }  # No diagnostic settings

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.AccountName -eq 'nodiagstore' -and $_.FindingType -eq 'NoDiagnosticLogging' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
    }

    It 'flags storage account with versioning disabled' {
        $account = [PSCustomObject]@{
            StorageAccountName    = 'noversionstore'
            ResourceGroupName     = 'test-rg'
            AllowBlobPublicAccess  = $false
            AllowSharedKeyAccess   = $false
            EnableHttpsTrafficOnly = $true
            Id                     = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/noversionstore'
            SasPolicy              = [PSCustomObject]@{ ExpirationAction = 'Log'; SasExpirationPeriod = '1.00:00:00' }
            Encryption             = [PSCustomObject]@{
                KeySource = 'Microsoft.Keyvault'
                RequireInfrastructureEncryption = $true
            }
        }
        Mock Get-AzStorageAccount { @($account) }
        Mock New-AzStorageContext { [PSCustomObject]@{ StorageAccountName = 'noversionstore' } }
        Mock Get-AzStorageBlobServiceProperty {
            [PSCustomObject]@{
                DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                IsVersioningEnabled   = $false
            }
        }
        Mock Get-AzDiagnosticSetting { @([PSCustomObject]@{ Name = 'default' }) }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.AccountName -eq 'noversionstore' -and $_.FindingType -eq 'VersioningDisabled' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
    }

    It 'flags storage account with no SAS expiry policy' {
        $account = [PSCustomObject]@{
            StorageAccountName    = 'nosaspolicystore'
            ResourceGroupName     = 'test-rg'
            AllowBlobPublicAccess  = $false
            AllowSharedKeyAccess   = $false
            EnableHttpsTrafficOnly = $true
            Id                     = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/nosaspolicystore'
            SasPolicy              = $null
            Encryption             = [PSCustomObject]@{
                KeySource = 'Microsoft.Keyvault'
                RequireInfrastructureEncryption = $true
            }
        }
        Mock Get-AzStorageAccount { @($account) }
        Mock New-AzStorageContext { [PSCustomObject]@{ StorageAccountName = 'nosaspolicystore' } }
        Mock Get-AzStorageBlobServiceProperty {
            [PSCustomObject]@{
                DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 }
                IsVersioningEnabled   = $true
            }
        }
        Mock Get-AzDiagnosticSetting { @([PSCustomObject]@{ Name = 'default' }) }

        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.AccountName -eq 'nosaspolicystore' -and $_.FindingType -eq 'NoSasExpiryPolicy' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'LOW'
    }

    It 'returns empty findings and AccountCount 0 for subscription with no storage accounts' {
        Mock Get-AzStorageAccount { @() }
        $sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-StorageFindings -Subscription $sub
        $result.Findings | Should -BeNullOrEmpty
        $result.AccountCount | Should -Be 0
    }
}

Describe 'Get-SeverityLabel' {
    It 'returns correct labels for all bands' {
        Get-SeverityLabel 9  | Should -Be 'CRITICAL'
        Get-SeverityLabel 7  | Should -Be 'HIGH'
        Get-SeverityLabel 4  | Should -Be 'MEDIUM'
        Get-SeverityLabel 2  | Should -Be 'LOW'
    }
}

Describe 'ConvertTo-HtmlReport' {
    It 'produces valid HTML with finding data' {
        $findings = @([PSCustomObject]@{
            AccountName    = 'test-account'
            ResourceGroup  = 'test-rg'
            Subscription   = 'TestSub'
            SubscriptionId = 'sub-001'
            FindingType    = 'PublicBlobAccess'
            Score          = 9
            Severity       = 'CRITICAL'
            Recommendation = 'Disable public blob access.'
        })
        $html = ConvertTo-HtmlReport -Findings $findings -TenantId 'tenant-001'
        $html | Should -Match '<html'
        $html | Should -Match 'test-account'
        $html | Should -Match 'CRITICAL'
    }
}
