& {
    $ErrorActionPreference = 'Stop'
    $v4Name = 'SOC-Lab-SMB-Block-OtherIPv4'
    $v6Name = 'SOC-Lab-SMB-Block-IPv6'
    $allowName = 'SOC-Lab-SMB-Allow-Mac'
    $names = @($v4Name, $v6Name, $allowName)
    $v4Ranges = @('0.0.0.0-192.168.243.0', '192.168.243.2-255.255.255.255')
    $v6Range = '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'

    function Read-RequiredNullString {
        param($Instance, [string]$PropertyName, [string]$Context)
        $properties = @($Instance.CimInstanceProperties |
            Where-Object { $_.Name -eq $PropertyName })
        if ($properties.Count -ne 1) {
            throw "Expected one actual CIM property $PropertyName on $Context; found $($properties.Count)."
        }
        $property = $properties[0]
        if ([string]$property.CimType -ne 'String' -or $null -ne $property.Value) {
            [pscustomobject]@{
                Context = $Context
                PropertyName = $property.Name
                CimType = [string]$property.CimType
                ValueIsNull = ($null -eq $property.Value)
                ValueJson = if ($null -eq $property.Value) { 'null' } else {
                    ConvertTo-Json -InputObject $property.Value -Compress -Depth 3
                }
            } | Format-List | Out-Host
            throw "Expected the observed String/null CIM property $PropertyName on $Context."
        }
        return $property
    }

    function Read-LabState {
        param([string]$Store)
        $rules = @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop |
            Where-Object { $_.Name -in $names })
        if (@($rules | Group-Object Name | Where-Object { $_.Count -ne 1 }).Count -gt 0) {
            throw "Duplicate lab name in $Store."
        }
        foreach ($rule in ($rules | Sort-Object Name)) {
            $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $scopes = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $interfaces = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $security = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $applications = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $services = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $interfaceTypes = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            if ($ports.Count -ne 1 -or $scopes.Count -ne 1 -or $interfaces.Count -ne 1 -or
                $security.Count -ne 1 -or $applications.Count -ne 1 -or $services.Count -ne 1 -or
                $interfaceTypes.Count -ne 1) {
                throw "Incomplete filters: $($rule.Name) in $Store."
            }
            if ($applications[0].CimSystemProperties.ClassName -ne 'MSFT_NetApplicationFilter') {
                throw "Unexpected application filter class: $($rule.Name) in $Store."
            }
            $context = "$($rule.Name) in $Store"
            $appPath = Read-RequiredNullString $applications[0] 'AppPath' $context
            $package = Read-RequiredNullString $applications[0] 'Package' $context
            $packageFamily = Read-RequiredNullString $rule 'PackageFamilyName' $context
            $policyApp = Read-RequiredNullString $rule 'PolicyAppId' $context
            [pscustomobject]@{
                Store = $Store
                Name = $rule.Name
                Enabled = [string]$rule.Enabled
                Direction = [string]$rule.Direction
                Action = [string]$rule.Action
                Profile = [string]$rule.Profile
                PrimaryStatus = [string]$rule.PrimaryStatus
                EnforcementStatus = $rule.EnforcementStatus -join ','
                Protocol = [string]$ports[0].Protocol
                LocalPort = $ports[0].LocalPort -join ','
                RemotePort = $ports[0].RemotePort -join ','
                LocalAddress = $scopes[0].LocalAddress -join ','
                RemoteAddress = @($scopes[0].RemoteAddress | Sort-Object) -join ','
                InterfaceAlias = $interfaces[0].InterfaceAlias -join ','
                InterfaceType = [string]$interfaceTypes[0].InterfaceType
                Program = [string]$applications[0].Program
                AppPathCimType = [string]$appPath.CimType
                AppPathIsNull = ($null -eq $appPath.Value)
                PackageCimType = [string]$package.CimType
                PackageIsNull = ($null -eq $package.Value)
                PackageFamilyNameCimType = [string]$packageFamily.CimType
                PackageFamilyNameIsNull = ($null -eq $packageFamily.Value)
                PolicyAppIdCimType = [string]$policyApp.CimType
                PolicyAppIdIsNull = ($null -eq $policyApp.Value)
                Service = [string]$services[0].Service
                EdgeTraversalPolicy = [string]$rule.EdgeTraversalPolicy
                Authentication = [string]$security[0].Authentication
                Encryption = [string]$security[0].Encryption
                OverrideBlockRules = [string]$security[0].OverrideBlockRules
            }
        }
    }

    function Assert-LabConditions {
        param($Row, [switch]$BeforeRepair)
        $expectedAction = 'Block'
        if ($Row.Name -eq $allowName) { $expectedAction = 'Allow' }
        if ($Row.Enabled -ne 'True' -or $Row.Direction -ne 'Inbound' -or
            $Row.Action -ne $expectedAction -or $Row.Profile -ne 'Any' -or
            $Row.PrimaryStatus -ne 'OK' -or $Row.Protocol -ne 'TCP' -or
            $Row.LocalPort -ne '445' -or $Row.RemotePort -ne 'Any' -or
            $Row.InterfaceAlias -ne 'Ethernet0' -or $Row.InterfaceType -ne 'Any' -or
            $Row.Program -ne 'Any' -or $Row.Service -ne 'Any' -or
            $Row.EdgeTraversalPolicy -ne 'Block' -or
            $Row.Authentication -ne 'NotRequired' -or $Row.Encryption -ne 'NotRequired' -or
            $Row.OverrideBlockRules -ne 'False') {
            $Row | Format-List | Out-Host
            throw "Unexpected rule conditions: $($Row.Name) in $($Row.Store)."
        }
        $local = @('Any')
        $remote = $v6Range
        if ($Row.Name -eq $allowName) {
            $local = @('192.168.243.128')
            $remote = '192.168.243.1'
        } elseif ($Row.Name -eq $v4Name) {
            $remote = @($v4Ranges | Sort-Object) -join ','
            if ($BeforeRepair) { $local = @('0.0.0.0', 'Any') }
        }
        if ($Row.LocalAddress -notin $local -or $Row.RemoteAddress -ne $remote) {
            $Row | Format-List | Out-Host
            throw "Unexpected address conditions: $($Row.Name) in $($Row.Store)."
        }
    }

    if ($env:COMPUTERNAME -ne 'DESKTOP-7HFI2UV') { throw 'Wrong lab computer.' }
    $adapter = Get-NetAdapter -Name 'Ethernet0' -ErrorAction Stop
    if ($adapter.Status -ne 'Up') { throw 'Ethernet0 is not up.' }
    $address = @(Get-NetIPAddress -InterfaceAlias 'Ethernet0' -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -eq '192.168.243.128' -and $_.PrefixLength -eq 24 -and $_.AddressState -eq 'Preferred' })
    if ($address.Count -ne 1) { throw 'The expected lab IPv4 address is missing.' }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -ne 3 -or @($profiles | Where-Object { [string]$_.Enabled -ne 'True' }).Count -gt 0) {
        throw 'All firewall profiles must remain enabled.'
    }
    $persistentV4 = $null
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $before = @(Read-LabState $store)
        if ($before.Count -ne 2 -or @($before | Where-Object { $_.Name -eq $v6Name }).Count -ne 0 -or
            @($before | Where-Object { $_.Name -eq $v4Name }).Count -ne 1 -or
            @($before | Where-Object { $_.Name -eq $allowName }).Count -ne 1) {
            throw "Expected only the two observed IPv4 rules in $store; inspect the current state."
        }
        foreach ($row in $before) { Assert-LabConditions $row -BeforeRepair }
        if ($store -eq 'PersistentStore') {
            $persistentV4 = $before | Where-Object { $_.Name -eq $v4Name }
        }
    }

    if ($persistentV4.LocalAddress -ne 'Any') {
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $v4Name -LocalAddress Any -ErrorAction Stop
    }
    $updated = @(Read-LabState 'PersistentStore')
    if ($updated.Count -ne 2) { throw 'Unexpected state after local-address correction.' }
    foreach ($row in $updated) { Assert-LabConditions $row }

    $newRule = @{
        PolicyStore = 'PersistentStore'
        Name = $v6Name
        DisplayName = 'SOC Lab SMB block IPv6'
        Direction = 'Inbound'
        Action = 'Block'
        Enabled = 'True'
        Profile = 'Any'
        Protocol = 'TCP'
        LocalPort = '445'
        RemotePort = 'Any'
        LocalAddress = 'Any'
        RemoteAddress = $v6Range
        InterfaceAlias = 'Ethernet0'
        EdgeTraversalPolicy = 'Block'
        Authentication = 'NotRequired'
        Encryption = 'NotRequired'
        OverrideBlockRules = $false
        ErrorAction = 'Stop'
    }
    New-NetFirewallRule @newRule | Out-Null

    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $after = @(Read-LabState $store)
        [pscustomobject]@{ Store = $store; LabRuleCount = $after.Count } | Format-List
        $after | Format-List
        if ($after.Count -ne 3) { throw "Expected three lab rules in $store." }
        foreach ($row in $after) {
            Assert-LabConditions $row
            if ($store -eq 'ActiveStore') {
                $states = @($row.EnforcementStatus -split ',' | ForEach-Object { $_.Trim() })
                if ('Enforced' -notin $states -or
                    @($states | Where-Object { $_ -notin @('Enforced', 'ProfileInactive') }).Count -gt 0) {
                    throw "Active enforcement needs review: $($row.Name)."
                }
            }
        }
    }
    [pscustomobject]@{ ConfigurationReadback = 'Passed' } | Format-List
}
