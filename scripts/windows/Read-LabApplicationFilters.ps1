& {
    $ErrorActionPreference = 'Stop'
    $names = @('SOC-Lab-SMB-Allow-Mac', 'SOC-Lab-SMB-Block-OtherIPv4')

    function Describe-Property {
        param($Property)
        $value = $Property.Value
        $kind = 'NonEmpty'
        $type = '<null>'
        if ($null -eq $value) {
            $kind = 'Null'
        } else {
            $type = $value.GetType().FullName
            if ($value -is [string] -and $value.Length -eq 0) { $kind = 'EmptyString' }
        }
        [pscustomobject]@{
            PropertyName = $Property.Name
            CimType = [string]$Property.CimType
            ValueIsNull = ($null -eq $value)
            ValueKind = $kind
            ValueType = $type
            ValueJson = if ($null -eq $value) { 'null' } else {
                ConvertTo-Json -InputObject $value -Compress -Depth 3
            }
        }
    }

    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $rules = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop |
            Where-Object { $_.Name -in $names })
        if ($rules.Count -ne 2 -or
            @($rules | Where-Object { $_.Name -eq $names[0] }).Count -ne 1 -or
            @($rules | Where-Object { $_.Name -eq $names[1] }).Count -ne 1) {
            throw "Expected the two observed lab rules in $store."
        }
        foreach ($rule in ($rules | Sort-Object Name)) {
            $filters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            if ($filters.Count -ne 1) { throw 'Expected exactly one application filter.' }
            $filter = $filters[0]
            $properties = @($filter.CimInstanceProperties)
            $package = @($properties | Where-Object { $_.Name -eq 'Package' })
            if ($package.Count -gt 1) { throw 'Duplicate Package property.' }
            [pscustomobject]@{
                Store = $store
                Rule = $rule.Name
                ApplicationFilterClass = $filter.CimSystemProperties.ClassName
                CimPropertyNames = @($properties | ForEach-Object { $_.Name }) -join ','
                PackagePropertyPresent = ($package.Count -eq 1)
            } | Format-List
            if ($package.Count -eq 1) {
                Describe-Property $package[0] | Format-List
            }
            foreach ($property in ($properties | Where-Object {
                $_.Name -ne 'Package' -and $_.Name -match 'Package|App|Program|Fqbn|PolicyApp'
            })) {
                Describe-Property $property | Format-List
            }
            [pscustomobject]@{ RuleApplicationProperties = 'Existing CIM fields only' } | Format-List
            foreach ($property in ($rule.CimInstanceProperties | Where-Object {
                $_.Name -match 'Package|App|Program|Fqbn|PolicyApp'
            })) {
                Describe-Property $property | Format-List
            }
        }
    }
}
