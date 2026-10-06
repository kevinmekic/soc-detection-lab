# Read-only follow-up to the observed Ethernet0 .129/32 route.
# No firewall/network changes, connection probes or test-account logons.
# Completed user output received on 2026-10-05; do not repeat for this correction.
& {
    $ErrorActionPreference = 'Stop'
    if ($env:COMPUTERNAME -ne 'DESKTOP-7HFI2UV') { throw 'Wrong lab computer.' }

    Get-NetAdapter -Name 'Ethernet0' -ErrorAction Stop |
        Select-Object Name, ifIndex, Status | Format-List
    Get-NetIPInterface -InterfaceAlias 'Ethernet0' -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object InterfaceAlias, InterfaceIndex, ConnectionState, Dhcp | Format-List
    Get-NetIPAddress -InterfaceAlias 'Ethernet0' -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object InterfaceAlias, InterfaceIndex, IPAddress, PrefixLength, AddressState,
            PrefixOrigin, SuffixOrigin | Format-List

    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $rules = @(Get-NetFirewallRule -PolicyStore $store -Name 'SOC-Lab-SMB-Allow-Mac' -ErrorAction Stop)
        [pscustomobject]@{ Store = $store; RuleCount = $rules.Count } | Format-List
        if ($rules.Count -ne 1) { throw "Expected one Mac Allow rule in $store." }

        $rule = $rules[0]
        $addresses = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        [pscustomobject]@{ Store = $store; AddressFilterCount = $addresses.Count } | Format-List
        if ($addresses.Count -ne 1) { throw "Expected one address filter in $store." }

        [pscustomobject]@{
            Store = $store
            Name = $rule.Name
            Enabled = [string]$rule.Enabled
            Direction = [string]$rule.Direction
            Action = [string]$rule.Action
            Profile = [string]$rule.Profile
            PrimaryStatus = [string]$rule.PrimaryStatus
            EnforcementStatus = [string]$rule.EnforcementStatus
            LocalAddress = @($addresses[0].LocalAddress) -join ','
            RemoteAddress = @($addresses[0].RemoteAddress) -join ','
        } | Format-List
    }

    [pscustomobject]@{
        AddressDriftCollection = 'Complete'
        NetworkOrFirewallChanged = $false
        PilotReadiness = 'Not decided by this collection'
    } | Format-List
}
