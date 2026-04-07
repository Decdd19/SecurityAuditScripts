# Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1
BeforeAll {
    # Stub all Graph cmdlets so the script loads without real modules installed.
    # Individual It blocks override with Mock as needed.
    function Get-MgDomain { @() }
    function Get-MgBetaDirectorySetting { @() }
    function Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy { $null }
    function Invoke-MgGraphRequest { param($Uri, $Method) @{} }
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext { $null }

    . "$PSScriptRoot/../entrapwd_auditor.ps1"
}
