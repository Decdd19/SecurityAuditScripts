BeforeAll {
    function Get-BitLockerVolume { @() }
    function Get-Volume           { @() }

    . (Join-Path $PSScriptRoot '..' 'bitlocker_auditor.ps1')
}

# Helper: build a mock volume object
function New-MockVolume {
    param(
        [string]$MountPoint       = 'C:',
        [string]$VolumeStatus     = 'FullyEncrypted',
        [string]$ProtectionStatus = 'On',
        [string]$EncryptionMethod = 'XtsAes256',
        [array]$KeyProtectors     = @(
            [PSCustomObject]@{ KeyProtectorType = 'Tpm' },
            [PSCustomObject]@{ KeyProtectorType = 'RecoveryPassword' }
        )
    )
    [PSCustomObject]@{
        MountPoint       = $MountPoint
        VolumeStatus     = $VolumeStatus
        ProtectionStatus = $ProtectionStatus
        EncryptionMethod = $EncryptionMethod
        KeyProtector     = $KeyProtectors
    }
}

Describe 'Get-DriveFindings' {
    It 'Strong encryption and TPM gives LOW risk' {
        $vol = New-MockVolume
        $f = Get-DriveFindings -Volume $vol
        $f.risk_level | Should -Be 'LOW'
        $f.severity_score | Should -Be 0
    }

    It 'Protection off gives CRITICAL score 8' {
        $vol = New-MockVolume -ProtectionStatus 'Off' -VolumeStatus 'FullyDecrypted'
        $f = Get-DriveFindings -Volume $vol
        $f.severity_score | Should -Be 8
        $f.risk_level | Should -Be 'CRITICAL'
    }

    It 'Weak encryption method AES128 gives HIGH' {
        $vol = New-MockVolume -EncryptionMethod 'Aes128'
        $f = Get-DriveFindings -Volume $vol
        $f.severity_score | Should -BeGreaterOrEqual 4
        ($f.flags | Where-Object { $_ -match 'weak' }).Count | Should -BeGreaterThan 0
    }

    It 'No TPM protector adds to score' {
        $vol = New-MockVolume -KeyProtectors @(
            [PSCustomObject]@{ KeyProtectorType = 'RecoveryPassword' }
        )
        $f = Get-DriveFindings -Volume $vol
        $f.severity_score | Should -BeGreaterThan 0
        ($f.flags | Where-Object { $_ -match 'TPM' }).Count | Should -BeGreaterThan 0
    }

    It 'No recovery password adds info flag' {
        $vol = New-MockVolume -KeyProtectors @(
            [PSCustomObject]@{ KeyProtectorType = 'Tpm' }
        )
        $f = Get-DriveFindings -Volume $vol
        ($f.flags | Where-Object { $_ -match 'recovery' }).Count | Should -BeGreaterThan 0
    }

    It 'Flags and remediations have equal length' {
        $vol = New-MockVolume -ProtectionStatus 'Off' -VolumeStatus 'FullyDecrypted'
        $f = Get-DriveFindings -Volume $vol
        $f.flags.Count | Should -Be $f.remediations.Count
    }

    It 'Clean drive has positive flag' {
        $vol = New-MockVolume
        $f = Get-DriveFindings -Volume $vol
        ($f.flags | Where-Object { $_ -match '✅' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-BitLockerAudit' {
    It 'No volumes returns warning finding' {
        Mock Get-BitLockerVolume { @() }
        $report = Invoke-BitLockerAudit
        $report.findings[0].risk_level | Should -Not -BeNullOrEmpty
        ($report.findings[0].flags | Where-Object { $_ -match 'No BitLocker' }).Count | Should -BeGreaterThan 0
    }

    It 'Returns report with generated_at' {
        Mock Get-BitLockerVolume { @() }
        $report = Invoke-BitLockerAudit
        $report.generated_at | Should -Not -BeNullOrEmpty
    }

    It 'One encrypted drive produces LOW overall risk' {
        Mock Get-BitLockerVolume { @(New-MockVolume) }
        $report = Invoke-BitLockerAudit
        $report.summary.overall_risk | Should -Be 'LOW'
        $report.summary.encrypted | Should -Be 1
    }

    It 'Unencrypted drive produces CRITICAL overall risk' {
        Mock Get-BitLockerVolume { @(
            New-MockVolume -ProtectionStatus 'Off' -VolumeStatus 'FullyDecrypted'
        )}
        $report = Invoke-BitLockerAudit
        $report.summary.overall_risk | Should -Be 'CRITICAL'
        $report.summary.not_encrypted | Should -Be 1
    }
}
