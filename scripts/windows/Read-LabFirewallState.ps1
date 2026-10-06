& {
    $ErrorActionPreference = 'Stop'
    $names = @(
        'SOC-Lab-SMB-Block-OtherIPv4'
        'SOC-Lab-SMB-Block-IPv6'
        'SOC-Lab-SMB-Allow-Mac'
    )

    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $rules = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop |
            Where-Object { $_.Name -in $names })
        $foundNames = @($rules | Select-Object -ExpandProperty Name)
        [pscustomobject]@{
            Store = $store
            LabRuleCount = $rules.Count
            MissingNames = ($names | Where-Object { $_ -notin $foundNames }) -join ','
        } | Format-List

        foreach ($rule in ($rules | Sort-Object Name)) {
            $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $scopes = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $interfaces = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $security = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            if ($ports.Count -ne 1 -or $scopes.Count -ne 1 -or $interfaces.Count -ne 1 -or $security.Count -ne 1) {
                throw 'Incomplete firewall filter result.'
            }
            [pscustomobject]@{
                Store = $store
                Name = $rule.Name
                Enabled = $rule.Enabled
                Direction = $rule.Direction
                Action = $rule.Action
                Profile = $rule.Profile
                PrimaryStatus = $rule.PrimaryStatus
                EnforcementStatus = $rule.EnforcementStatus -join ','
                Protocol = $ports[0].Protocol
                LocalPort = $ports[0].LocalPort -join ','
                RemotePort = $ports[0].RemotePort -join ','
                LocalAddress = $scopes[0].LocalAddress -join ','
                RemoteAddress = $scopes[0].RemoteAddress -join ','
                InterfaceAlias = $interfaces[0].InterfaceAlias -join ','
                EdgeTraversalPolicy = $rule.EdgeTraversalPolicy
                Authentication = $security[0].Authentication
                Encryption = $security[0].Encryption
                OverrideBlockRules = $security[0].OverrideBlockRules
            } | Format-List
        }
    }
}
