Connect-AzAccount
Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','Policy.Read.All','DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All','Organization.Read.All','OnPremDirectorySynchronization.Read.All','RoleManagement.Read.Directory','UserAuthenticationMethod.Read.All','AuditLog.Read.All' -NoWelcome

# Export tenant ID so child auditor processes can reconnect silently via MSAL cache
$env:AUDIT_TENANT_ID = (Get-MgContext).TenantId

& "$PSScriptRoot/Run-Audit.ps1" -Client 'Declan-Tenant' -Azure -M365
