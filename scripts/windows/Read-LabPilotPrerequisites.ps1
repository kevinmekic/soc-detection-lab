# Historical read-only collection, user-executed on 2026-10-04.
# It stopped on the observed no-per-user-policy exit 2; its counter getter failed.
# Do not rerun: next use Read-LabAddressDrift.ps1. Original logic retained as history.
& {
    $ErrorActionPreference = 'Stop'
    if ($env:COMPUTERNAME -ne 'DESKTOP-7HFI2UV') { throw 'Wrong lab computer.' }
    if (-not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -ne 5 -or
        $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Use 64-bit Windows PowerShell 5.1.' }
    $principal = [System.Security.Principal.WindowsPrincipal]::new(
        [System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open Windows PowerShell as Administrator.'
    }
    $labUser = Get-LocalUser -Name 'lab-auth01' -ErrorAction Stop

    $observed = [DateTimeOffset]::Now
    [pscustomobject]@{
        Section = 'Guest time'
        LocalTime = $observed.ToString('o')
        UtcTime = $observed.ToUniversalTime().ToString('o')
    } | Format-List
    Get-TimeZone -ErrorAction Stop | Select-Object Id, DisplayName, BaseUtcOffset | Format-List

    $lsa = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        'SYSTEM\CurrentControlSet\Control\Lsa', $false)
    if ($null -eq $lsa) { throw 'Cannot read the LSA registry key.' }
    try {
        $valueNames = @($lsa.GetValueNames())
        foreach ($name in @('ForceGuest', 'SCENoApplyLegacyAuditPolicy')) {
            $present = $name -in $valueNames
            $kind = $null
            $value = $null
            if ($present) {
                $kind = [string]$lsa.GetValueKind($name)
                $value = $lsa.GetValue($name, $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
            [pscustomobject]@{
                Section = 'Existing LSA registry values'
                ValueName = $name
                Present = $present
                RegistryKind = $kind
                ValueIsNull = ($null -eq $value)
                ValueJson = if ($null -eq $value) { 'null' } else {
                    ConvertTo-Json -InputObject $value -Compress -Depth 3
                }
            } | Format-List
        }
    } finally {
        $lsa.Close()
    }

    $entry = [System.DirectoryServices.DirectoryEntry]::new(
        "WinNT://$env:COMPUTERNAME/$($labUser.Name),user")
    try {
        foreach ($propertyName in @('BadLoginCount', 'IsAccountLocked')) {
            try {
                $value = $entry.psbase.InvokeGet($propertyName)
                $type = '<null>'
                if ($null -ne $value) { $type = $value.GetType().FullName }
                [pscustomobject]@{
                    Section = 'Local WinNT native user getter'
                    Account = $labUser.Name
                    PropertyName = $propertyName
                    ReadStatus = 'Returned'
                    ValueType = $type
                    ValueIsNull = ($null -eq $value)
                    ValueJson = if ($null -eq $value) { 'null' } else {
                        ConvertTo-Json -InputObject $value -Compress -Depth 3
                    }
                } | Format-List
            } catch {
                [pscustomobject]@{
                    Section = 'Local WinNT native user getter'
                    Account = $labUser.Name
                    PropertyName = $propertyName
                    ReadStatus = 'Unavailable'
                    Message = $_.Exception.Message
                } | Format-List
            }
        }
    } finally {
        $entry.psbase.Dispose()
    }

    $licenseQuery = 'SELECT Name, Description, LicenseFamily, LicenseStatus, GracePeriodRemaining ' +
        'FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL'
    $licenses = @(Get-CimInstance -Namespace 'root/cimv2' -Query $licenseQuery -ErrorAction Stop)
    [pscustomobject]@{ Section = 'Installed-key product status'; ProductCount = $licenses.Count } | Format-List
    $licenses | Select-Object Name, Description, LicenseFamily, LicenseStatus, GracePeriodRemaining | Format-List

    $routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
    [pscustomobject]@{ Section = 'All active routes'; RouteCount = $routes.Count } | Format-List
    $routes | Sort-Object AddressFamily, InterfaceIndex, DestinationPrefix |
        Select-Object AddressFamily, InterfaceIndex, InterfaceAlias, DestinationPrefix, NextHop | Format-List

    [pscustomobject]@{ Section = 'Per-user Audit Logon'; Account = $labUser.Name } | Format-List
    $userArgument = '/user:{' + $labUser.SID.Value + '}'
    & "$env:SystemRoot\System32\auditpol.exe" /get $userArgument '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}' /r
    $auditExitCode = $LASTEXITCODE
    [pscustomobject]@{ AuditPolExitCode = $auditExitCode } | Format-List
    if ($auditExitCode -ne 0) { throw 'Per-user audit query failed; preserve its complete output.' }

    [pscustomobject]@{
        PilotStateCollection = 'Complete'
        NetworkLogonRights = 'Read the two lists in secpol.msc separately'
        PilotReadiness = 'Not decided by this collection'
    } | Format-List
}
