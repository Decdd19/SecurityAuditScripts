BeforeAll {
    # Override Az cmdlet stubs before dot-sourcing so Pester controls all data
    function Get-AzContext    { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = $SubscriptionId; Name = 'TestSub' } }
    function Set-AzContext    { param($SubscriptionId) }

    # Default stubs — tests override per-context via Mock
    function Get-AzRecoveryServicesVault          { @() }
    function Set-AzRecoveryServicesVaultContext   { param($Vault) }
    function Get-AzRecoveryServicesBackupProperty { param($Vault) [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled'; BackupStorageRedundancy = 'GeoRedundant' } }
    function Get-AzRecoveryServicesVaultProperty  { param($Vault) [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
    function Get-AzRecoveryServicesBackupJob      { param($VaultId) @() }

    . (Join-Path $PSScriptRoot '..' 'azbackup_auditor.ps1')
}

Describe 'Get-BackupFindings' {

    It 'flags when no vaults exist' {
        Mock Get-AzRecoveryServicesVault { @() }
        $sub     = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result  = Get-BackupFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'NoVaults' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'does not flag when vaults are present' {
        $vault = [PSCustomObject]@{ Name = 'vault-01'; ID = 'vault-id-01'; ResourceGroupName = 'rg-01'; Location = 'westeurope' }
        Mock Get-AzRecoveryServicesVault { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
        Mock Get-AzRecoveryServicesBackupJob      { @() }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $result.Findings | Where-Object { $_.FindingType -eq 'NoVaults' } | Should -BeNullOrEmpty
    }

    It 'flags when soft delete is disabled' {
        $vault = [PSCustomObject]@{ Name = 'vault-01'; ID = 'vault-id-01'; ResourceGroupName = 'rg-01'; Location = 'westeurope' }
        Mock Get-AzRecoveryServicesVault          { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Disabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
        Mock Get-AzRecoveryServicesBackupJob      { @() }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'SoftDeleteDisabled' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'does not flag when soft delete is enabled' {
        $vault = [PSCustomObject]@{ Name = 'vault-01'; ID = 'vault-id-01'; ResourceGroupName = 'rg-01'; Location = 'westeurope' }
        Mock Get-AzRecoveryServicesVault          { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
        Mock Get-AzRecoveryServicesBackupJob      { @() }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $result.Findings | Where-Object { $_.FindingType -eq 'SoftDeleteDisabled' } | Should -BeNullOrEmpty
    }

    It 'flags when immutability is disabled' {
        $vault = [PSCustomObject]@{ Name = 'vault-01'; ID = 'vault-id-01'; ResourceGroupName = 'rg-01'; Location = 'westeurope' }
        Mock Get-AzRecoveryServicesVault          { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Disabled' } }
        Mock Get-AzRecoveryServicesBackupJob      { @() }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'ImmutabilityDisabled' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
    }

    It 'does not flag when immutability is locked' {
        $vault = [PSCustomObject]@{ Name = 'vault-01'; ID = 'vault-id-01'; ResourceGroupName = 'rg-01'; Location = 'westeurope' }
        Mock Get-AzRecoveryServicesVault          { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
        Mock Get-AzRecoveryServicesBackupJob      { @() }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $result.Findings | Where-Object { $_.FindingType -eq 'ImmutabilityDisabled' } | Should -BeNullOrEmpty
    }

    It 'flags when recent backup failures exist' {
        $vault   = [PSCustomObject]@{ Name = 'vault-01'; ID = 'vault-id-01'; ResourceGroupName = 'rg-01'; Location = 'westeurope' }
        $failJob = [PSCustomObject]@{ Status = 'Failed'; StartTime = (Get-Date).AddHours(-2) }
        Mock Get-AzRecoveryServicesVault          { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
        Mock Get-AzRecoveryServicesBackupJob      { @($failJob) }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $finding = $result.Findings | Where-Object { $_.FindingType -eq 'RecentBackupFailure' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'does not flag when no recent backup failures' {
        $vault = [PSCustomObject]@{ Name = 'vault-01'; ID = 'vault-id-01'; ResourceGroupName = 'rg-01'; Location = 'westeurope' }
        Mock Get-AzRecoveryServicesVault          { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
        Mock Get-AzRecoveryServicesBackupJob      { @() }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $result.Findings | Where-Object { $_.FindingType -eq 'RecentBackupFailure' } | Should -BeNullOrEmpty
    }

    It 'does not flag old failures outside 24h window' {
        $vault   = [PSCustomObject]@{ Name = 'vault-01'; ID = 'vault-id-01'; ResourceGroupName = 'rg-01'; Location = 'westeurope' }
        $oldJob  = [PSCustomObject]@{ Status = 'Failed'; StartTime = (Get-Date).AddHours(-48) }
        Mock Get-AzRecoveryServicesVault          { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
        Mock Get-AzRecoveryServicesBackupJob      { @($oldJob) }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $result.Findings | Where-Object { $_.FindingType -eq 'RecentBackupFailure' } | Should -BeNullOrEmpty
    }

    It 'finding has required fields' {
        Mock Get-AzRecoveryServicesVault { @() }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $finding = $result.Findings[0]
        $finding.FindingType    | Should -Not -BeNullOrEmpty
        $finding.Severity       | Should -Not -BeNullOrEmpty
        $finding.Score          | Should -BeOfType [int]
        $finding.SubscriptionId | Should -Be 'sub-001'
    }

    It 'VaultCount reflects number of vaults scanned' {
        $vault = [PSCustomObject]@{ Name = 'v1'; ID = 'id1'; ResourceGroupName = 'rg'; Location = 'westeurope' }
        Mock Get-AzRecoveryServicesVault          { @($vault) }
        Mock Get-AzRecoveryServicesBackupProperty { [PSCustomObject]@{ SoftDeleteFeatureState = 'Enabled' } }
        Mock Get-AzRecoveryServicesVaultProperty  { [PSCustomObject]@{ ImmutabilityState = 'Locked' } }
        Mock Get-AzRecoveryServicesBackupJob      { @() }
        $sub    = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
        $result = Get-BackupFindings -Subscription $sub
        $result.VaultCount | Should -Be 1
    }
}
