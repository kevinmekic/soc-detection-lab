# Manual correction of the confirmed stale local address on the owned Mac Allow.
# User execution received on 2026-10-05 passed selected readback; do not repeat now.
& {
    $ErrorActionPreference = 'Stop'
    $ruleName = 'SOC-Lab-SMB-Allow-Mac'
    $stores = @('PersistentStore', 'ActiveStore')

    if ($env:COMPUTERNAME -ne 'DESKTOP-7HFI2UV') { throw 'Wrong lab computer.' }
    $principal = [System.Security.Principal.WindowsPrincipal]::new(
        [System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open Windows PowerShell as Administrator.'
    }
    $adapter = @(Get-NetAdapter -Name 'Ethernet0' -ErrorAction Stop)
    if ($adapter.Count -ne 1 -or [string]$adapter[0].Status -ne 'Up') {
        throw 'Expected one running Ethernet0 adapter.'
    }
    $addresses = @(Get-NetIPAddress -InterfaceAlias 'Ethernet0' -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { [string]$_.AddressState -eq 'Preferred' })
    if ($addresses.Count -ne 1 -or $addresses[0].PrefixLength -ne 24 -or
        $addresses[0].IPAddress -notlike '192.168.243.*' -or
        $addresses[0].IPAddress -in @('192.168.243.0', '192.168.243.1', '192.168.243.255') -or
        [string]$addresses[0].PrefixOrigin -ne 'Dhcp' -or [string]$addresses[0].SuffixOrigin -ne 'Dhcp') {
        $addresses | Format-List | Out-Host
        throw 'Expected one preferred DHCP IPv4 address in the known private lab subnet.'
    }
    $addresses | Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressState,
        PrefixOrigin, SuffixOrigin | Format-List
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -ne 3 -or
        @($profiles | Where-Object { [string]$_.Enabled -ne 'True' }).Count -gt 0) {
        throw 'All three firewall profiles must remain enabled.'
    }

    function Read-MacAllow {
        param([string]$Store)
        $rules = @(Get-NetFirewallRule -Name $ruleName -PolicyStore $Store -ErrorAction Stop)
        if ($rules.Count -ne 1) { throw "Expected exactly one own Mac Allow rule in $Store." }
        $rule = $rules[0]
        $scopes = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $interfaces = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $security = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        if ($scopes.Count -ne 1 -or $ports.Count -ne 1 -or $interfaces.Count -ne 1 -or $security.Count -ne 1) {
            throw "Expected one of each required filter in $Store."
        }
        $row = [pscustomobject]@{
            Store = $Store
            Name = $rule.Name
            Enabled = [string]$rule.Enabled
            Direction = [string]$rule.Direction
            Action = [string]$rule.Action
            Profile = [string]$rule.Profile
            PrimaryStatus = [string]$rule.PrimaryStatus
            EnforcementStatus = $rule.EnforcementStatus -join ','
            LocalAddress = $scopes[0].LocalAddress -join ','
            RemoteAddress = $scopes[0].RemoteAddress -join ','
            Protocol = [string]$ports[0].Protocol
            LocalPort = $ports[0].LocalPort -join ','
            RemotePort = $ports[0].RemotePort -join ','
            InterfaceAlias = $interfaces[0].InterfaceAlias -join ','
            EdgeTraversalPolicy = [string]$rule.EdgeTraversalPolicy
            Authentication = [string]$security[0].Authentication
            Encryption = [string]$security[0].Encryption
            OverrideBlockRules = [string]$security[0].OverrideBlockRules
        }
        $row | Format-List | Out-Host
        if ($row.Enabled -ne 'True' -or $row.Direction -ne 'Inbound' -or
            $row.Action -ne 'Allow' -or $row.Profile -ne 'Any' -or $row.PrimaryStatus -ne 'OK' -or
            $row.RemoteAddress -ne '192.168.243.1' -or $row.Protocol -ne 'TCP' -or
            $row.LocalPort -ne '445' -or $row.RemotePort -ne 'Any' -or
            $row.InterfaceAlias -ne 'Ethernet0' -or $row.EdgeTraversalPolicy -ne 'Block' -or
            $row.Authentication -ne 'NotRequired' -or $row.Encryption -ne 'NotRequired' -or
            $row.OverrideBlockRules -ne 'False') {
            throw "Unexpected Mac Allow conditions in $Store; no further change is permitted."
        }
        if ($Store -eq 'ActiveStore') {
            $states = @($row.EnforcementStatus -split '[,\s]+' | Where-Object { $_ -ne '' })
            if ('Enforced' -notin $states -or
                @($states | Where-Object { $_ -notin @('Enforced', 'ProfileInactive') }).Count -gt 0) {
                throw 'Active Mac Allow enforcement needs review.'
            }
        }
        return $row
    }

    $phase = 'Preflight'
    $changed = $false
    try {
        $before = @{}
        foreach ($store in $stores) {
            $before[$store] = Read-MacAllow $store
            if ($before[$store].LocalAddress -notin @('192.168.243.128', 'Any')) {
                throw "Unexpected local-address state in $store."
            }
        }
        if ($before['PersistentStore'].LocalAddress -ne $before['ActiveStore'].LocalAddress) {
            throw 'The two stores disagree; inspect the output before any change.'
        }

        $phase = 'SetOwnLocalAddress'
        if ($before['PersistentStore'].LocalAddress -ne 'Any') {
            Set-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore -LocalAddress Any -ErrorAction Stop
            $changed = $true
        }

        $phase = 'Readback'
        foreach ($store in $stores) {
            $after = Read-MacAllow $store
            if ($after.LocalAddress -ne 'Any') { throw "LocalAddress Any not observed in $store." }
        }
        [pscustomobject]@{
            MacAllowAddressReadback = 'Passed'
            RuleName = $ruleName
            LocalAddress = 'Any'
            RemoteAddress = '192.168.243.1'
            RuleChanged = $changed
            PilotReadiness = 'Not decided by this correction'
        } | Format-List
    } catch {
        [pscustomobject]@{
            MacAllowAddressStopped = $phase
            SetterReturnedSuccessfully = $changed
            Message = $_.Exception.Message
        } | Format-List | Out-Host
        throw
    }
}
