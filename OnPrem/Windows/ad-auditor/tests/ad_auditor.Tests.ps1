# OnPrem/Windows/ad-auditor/tests/ad_auditor.Tests.ps1
BeforeAll {
    # ---------------------------------------------------------------------------
    # AD module stubs — all return empty by default; individual tests Mock as needed
    # ---------------------------------------------------------------------------
    function Get-ADUser { param($Filter, $Properties, $SearchBase, $Identity) @() }
    function Get-ADComputer { param($Filter, $Properties) @() }
    function Get-ADGroupMember { param($Identity, [switch]$Recursive) @() }
    function Get-ADDomain { @{ DistinguishedName = 'DC=contoso,DC=com'; DomainMode = 'Windows2016Domain' } }
    function Get-ADDefaultDomainPasswordPolicy {
        [PSCustomObject]@{
            MinPasswordLength          = 14
            MaxPasswordAge             = [TimeSpan]::FromDays(60)
            ComplexityEnabled          = $true
            ReversibleEncryptionEnabled = $false
        }
    }
    function Get-ADFineGrainedPasswordPolicy { param($Filter) @() }
    function Get-ADObject { param($Filter, $Properties, $SearchBase) @() }
    function Get-ADForest { [PSCustomObject]@{ Name = 'contoso.com' } }
    function Get-ADOptionalFeature { param($Filter) @() }
    function Get-ADTrust { param($Filter) @() }

    . "$PSScriptRoot/../ad_auditor.ps1"
}

Describe 'Get-ADFindings' {

    It 'flags user with password never expires' {
        $neverExpireUser = [PSCustomObject]@{
            SamAccountName      = 'svc_app'
            Enabled             = $true
            PasswordNeverExpires = $true
            PasswordNotRequired  = $false
            LastLogonDate        = (Get-Date)
            ServicePrincipalName = @()
            DoesNotRequirePreAuth = $false
            adminCount           = 0
            MemberOf             = @()
        }

        Mock Get-ADUser {
            param($Filter, $Properties, $SearchBase, $Identity)
            $filterStr = "$Filter"
            if ($filterStr -like '*PasswordNeverExpires*') {
                return @($neverExpireUser)
            }
            return @()
        }
        Mock Get-ADGroupMember { @() }
        Mock Get-ADDefaultDomainPasswordPolicy {
            [PSCustomObject]@{
                MinPasswordLength          = 14
                MaxPasswordAge             = [TimeSpan]::FromDays(60)
                ComplexityEnabled          = $true
                ReversibleEncryptionEnabled = $false
            }
        }
        Mock Get-ADOptionalFeature { @() }
        Mock Get-ADComputer { @() }

        $findings = Get-ADFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'UserPasswordNeverExpires' -and $_.UserName -eq 'svc_app' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'flags user with no password required' {
        $noPasswordUser = [PSCustomObject]@{
            SamAccountName      = 'svc_nopass'
            Enabled             = $true
            PasswordNeverExpires = $false
            PasswordNotRequired  = $true
            LastLogonDate        = (Get-Date)
            ServicePrincipalName = @()
            DoesNotRequirePreAuth = $false
            adminCount           = 0
            MemberOf             = @()
        }

        Mock Get-ADUser {
            param($Filter, $Properties, $SearchBase, $Identity)
            $filterStr = "$Filter"
            if ($filterStr -like '*PasswordNotRequired*') {
                return @($noPasswordUser)
            }
            return @()
        }
        Mock Get-ADGroupMember { @() }
        Mock Get-ADDefaultDomainPasswordPolicy {
            [PSCustomObject]@{
                MinPasswordLength          = 14
                MaxPasswordAge             = [TimeSpan]::FromDays(60)
                ComplexityEnabled          = $true
                ReversibleEncryptionEnabled = $false
            }
        }
        Mock Get-ADOptionalFeature { @() }
        Mock Get-ADComputer { @() }

        $findings = Get-ADFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'UserPasswordNotRequired' -and $_.UserName -eq 'svc_nopass' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags Kerberoastable account (SPN on user)' {
        $kerberoastUser = [PSCustomObject]@{
            SamAccountName       = 'svc_sql'
            Enabled              = $true
            PasswordNeverExpires  = $false
            PasswordNotRequired   = $false
            LastLogonDate         = (Get-Date)
            ServicePrincipalName  = @('MSSQLSvc/sqlserver.contoso.com:1433')
            DoesNotRequirePreAuth = $false
            adminCount            = 0
            MemberOf              = @()
        }

        Mock Get-ADUser {
            param($Filter, $Properties, $SearchBase, $Identity)
            $filterStr = "$Filter"
            if ($filterStr -like '*ServicePrincipalName*') {
                return @($kerberoastUser)
            }
            return @()
        }
        Mock Get-ADGroupMember { @() }
        Mock Get-ADDefaultDomainPasswordPolicy {
            [PSCustomObject]@{
                MinPasswordLength          = 14
                MaxPasswordAge             = [TimeSpan]::FromDays(60)
                ComplexityEnabled          = $true
                ReversibleEncryptionEnabled = $false
            }
        }
        Mock Get-ADOptionalFeature { @() }
        Mock Get-ADComputer { @() }

        $findings = Get-ADFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'KerberoastableAccount' -and $_.UserName -eq 'svc_sql' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Score | Should -Be 8
    }

    It 'flags AS-REP roastable account' {
        $asrepUser = [PSCustomObject]@{
            SamAccountName       = 'svc_asrep'
            Enabled              = $true
            PasswordNeverExpires  = $false
            PasswordNotRequired   = $false
            LastLogonDate         = (Get-Date)
            ServicePrincipalName  = @()
            DoesNotRequirePreAuth = $true
            adminCount            = 0
            MemberOf              = @()
        }

        Mock Get-ADUser {
            param($Filter, $Properties, $SearchBase, $Identity)
            $filterStr = "$Filter"
            if ($filterStr -like '*DoesNotRequirePreAuth*') {
                return @($asrepUser)
            }
            return @()
        }
        Mock Get-ADGroupMember { @() }
        Mock Get-ADDefaultDomainPasswordPolicy {
            [PSCustomObject]@{
                MinPasswordLength          = 14
                MaxPasswordAge             = [TimeSpan]::FromDays(60)
                ComplexityEnabled          = $true
                ReversibleEncryptionEnabled = $false
            }
        }
        Mock Get-ADOptionalFeature { @() }
        Mock Get-ADComputer { @() }

        $findings = Get-ADFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'ASREPRoastableAccount' -and $_.UserName -eq 'svc_asrep' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags weak domain password policy' {
        Mock Get-ADUser { @() }
        Mock Get-ADGroupMember { @() }
        Mock Get-ADDefaultDomainPasswordPolicy {
            [PSCustomObject]@{
                MinPasswordLength          = 8
                MaxPasswordAge             = [TimeSpan]::FromDays(60)
                ComplexityEnabled          = $true
                ReversibleEncryptionEnabled = $false
            }
        }
        Mock Get-ADOptionalFeature { @() }
        Mock Get-ADComputer { @() }

        $findings = Get-ADFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'WeakDomainPasswordPolicy' }
        $finding  | Should -Not -BeNullOrEmpty
    }

    It 'flags excessive domain admins' {
        # Build 7 member objects for Domain Admins
        $adminMembers = 1..7 | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName    = "da_user$_"
                DistinguishedName = "CN=da_user$_,CN=Users,DC=contoso,DC=com"
                ObjectClass       = 'user'
            }
        }

        Mock Get-ADGroupMember {
            param($Identity, [switch]$Recursive)
            if ($Identity -eq 'Domain Admins') {
                return $adminMembers
            }
            return @()
        }

        # Get-ADUser -Identity calls (for DomainAdminStale check) return users with recent logon
        Mock Get-ADUser {
            param($Filter, $Properties, $SearchBase, $Identity)
            if ($null -ne $Identity -and $Identity -ne '') {
                return [PSCustomObject]@{
                    SamAccountName = $Identity
                    Enabled        = $true
                    LastLogonDate  = (Get-Date).AddDays(-1)
                }
            }
            return @()
        }

        Mock Get-ADDefaultDomainPasswordPolicy {
            [PSCustomObject]@{
                MinPasswordLength          = 14
                MaxPasswordAge             = [TimeSpan]::FromDays(60)
                ComplexityEnabled          = $true
                ReversibleEncryptionEnabled = $false
            }
        }
        Mock Get-ADOptionalFeature { @() }
        Mock Get-ADComputer { @() }

        $findings = Get-ADFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'ExcessiveDomainAdmins' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Score | Should -Be 6
    }

    It 'flags unconstrained delegation on computer' {
        $unconstrainedComputer = [PSCustomObject]@{
            Name                = 'WORKSTATION01'
            TrustedForDelegation = $true
            DistinguishedName   = 'CN=WORKSTATION01,CN=Computers,DC=contoso,DC=com'
        }

        Mock Get-ADComputer {
            param($Filter, $Properties)
            $filterStr = "$Filter"
            if ($filterStr -like '*TrustedForDelegation*') {
                return @($unconstrainedComputer)
            }
            return @()
        }
        Mock Get-ADUser { @() }
        Mock Get-ADGroupMember { @() }
        Mock Get-ADDefaultDomainPasswordPolicy {
            [PSCustomObject]@{
                MinPasswordLength          = 14
                MaxPasswordAge             = [TimeSpan]::FromDays(60)
                ComplexityEnabled          = $true
                ReversibleEncryptionEnabled = $false
            }
        }
        Mock Get-ADOptionalFeature { @() }

        $findings = Get-ADFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'TrustUnconstrained' -and $_.ComputerName -eq 'WORKSTATION01' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags empty Protected Users group' {
        Mock Get-ADGroupMember {
            param($Identity, [switch]$Recursive)
            # Return empty for Protected Users; return a list for Domain Admins
            # so that the ExcessiveDomainAdmins check does not fire
            if ($Identity -eq 'Domain Admins') {
                return 1..3 | ForEach-Object {
                    [PSCustomObject]@{
                        SamAccountName    = "da$_"
                        DistinguishedName = "CN=da$_,CN=Users,DC=contoso,DC=com"
                        ObjectClass       = 'user'
                    }
                }
            }
            # Protected Users and any other group — return empty
            return @()
        }

        Mock Get-ADUser {
            param($Filter, $Properties, $SearchBase, $Identity)
            if ($null -ne $Identity -and $Identity -ne '') {
                return [PSCustomObject]@{
                    SamAccountName = $Identity
                    Enabled        = $true
                    LastLogonDate  = (Get-Date).AddDays(-1)
                }
            }
            return @()
        }

        Mock Get-ADDefaultDomainPasswordPolicy {
            [PSCustomObject]@{
                MinPasswordLength          = 14
                MaxPasswordAge             = [TimeSpan]::FromDays(60)
                ComplexityEnabled          = $true
                ReversibleEncryptionEnabled = $false
            }
        }
        Mock Get-ADOptionalFeature { @() }
        Mock Get-ADComputer { @() }

        $findings = Get-ADFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'ProtectedUsersEmpty' }
        $finding  | Should -Not -BeNullOrEmpty
    }
}
