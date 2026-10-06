# Prepared for manual use in the owned Windows test VM; not executed here.
# Paste this complete block into elevated 64-bit Windows PowerShell 5.1.
& {
    $ErrorActionPreference = 'Stop'
    $stage = 'Preflight'
    $parentPath = 'C:\SOC-Lab'
    $probePath = 'C:\SOC-Lab\Probe'
    $shareName = 'SOC-LAB'

    function Assert-OrdinaryDirectory {
        param([string]$Path)
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Expected an ordinary directory, not a file or reparse point: $Path"
        }
    }

    function Read-VerifiedProbeAcl {
        param(
            [string]$Path,
            [System.Security.Principal.SecurityIdentifier]$OwnerSid,
            [System.Security.AccessControl.FileSystemAccessRule[]]$ExpectedRules
        )
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $rules = @($acl.GetAccessRules($true, $true,
            [System.Security.Principal.SecurityIdentifier]))
        if (-not $acl.AreAccessRulesProtected -or
            $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $OwnerSid.Value -or
            $rules.Count -ne 3) {
            throw 'Probe ACL must be protected, owned by BUILTIN Administrators, with exactly three entries.'
        }
        foreach ($expected in $ExpectedRules) {
            $matching = @($rules | Where-Object {
                $_.IdentityReference.Value -eq $expected.IdentityReference.Value
            })
            if ($matching.Count -ne 1) {
                throw "Missing or duplicate NTFS entry: $($expected.IdentityReference.Value)"
            }
            $actual = $matching[0]
            if ($actual.AccessControlType -ne $expected.AccessControlType -or
                $actual.FileSystemRights -ne $expected.FileSystemRights -or
                $actual.InheritanceFlags -ne $expected.InheritanceFlags -or
                $actual.PropagationFlags -ne $expected.PropagationFlags -or
                $actual.IsInherited) {
                throw "Unexpected NTFS rights: $($expected.IdentityReference.Value)"
            }
        }
        $acl
    }

    try {
        if ($env:COMPUTERNAME -ne 'DESKTOP-7HFI2UV') {
            throw 'This step is limited to the known DESKTOP-7HFI2UV test VM.'
        }
        if (-not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -ne 5 -or
            $PSVersionTable.PSVersion.Minor -ne 1) {
            throw 'Use 64-bit Windows PowerShell 5.1.'
        }
        $principal = [System.Security.Principal.WindowsPrincipal]::new(
            [System.Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Open Windows PowerShell as Administrator.'
        }

        $labUser = Get-LocalUser -Name 'lab-auth01' -ErrorAction Stop
        $users = @(Get-LocalGroupMember -SID 'S-1-5-32-545' -ErrorAction Stop)
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        $inUsers = @($users | Where-Object { $_.SID.Value -eq $labUser.SID.Value }).Count -eq 1
        $inAdmins = @($admins | Where-Object { $_.SID.Value -eq $labUser.SID.Value }).Count -ne 0
        if (-not $labUser.Enabled -or $labUser.PrincipalSource -ne 'Local' -or
            -not $inUsers -or $inAdmins) {
            throw 'lab-auth01 must be enabled, local, in Users, and outside Administrators.'
        }
        $labAccount = "$env:COMPUTERNAME\$($labUser.Name)"
        $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $adminsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')

        $server = Get-Service -Name 'LanmanServer' -ErrorAction Stop
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        if ($server.Status -ne 'Running' -or $smb.EnableSMB1Protocol -ne $false -or
            $smb.EnableSMB2Protocol -ne $true -or $smb.RequireSecuritySignature -ne $true) {
            throw 'Expected the running SMB server, SMB1 disabled, SMB2 enabled, and signing required.'
        }

        Assert-OrdinaryDirectory 'C:\'
        $parentExists = Test-Path -LiteralPath $parentPath -ErrorAction Stop
        if ($parentExists) { Assert-OrdinaryDirectory $parentPath }
        if (Test-Path -LiteralPath $probePath -ErrorAction Stop) {
            throw 'Probe already exists; stop and inspect it instead of changing it.'
        }
        $existingShares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -eq $shareName })
        if ($existingShares.Count -ne 0) {
            throw 'SOC-LAB already exists; stop and inspect it instead of changing it.'
        }

        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $expectedRules = @(
            [System.Security.AccessControl.FileSystemAccessRule]::new($systemSid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance, $propagation, $allow)
            [System.Security.AccessControl.FileSystemAccessRule]::new($adminsSid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance, $propagation, $allow)
            [System.Security.AccessControl.FileSystemAccessRule]::new($labUser.SID,
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                $inheritance, $propagation, $allow)
        )
        $newAcl = [System.Security.AccessControl.DirectorySecurity]::new()
        $newAcl.SetAccessRuleProtection($true, $false)
        $newAcl.SetOwner($adminsSid)
        foreach ($rule in $expectedRules) { $newAcl.AddAccessRule($rule) }

        if (-not $parentExists) {
            $stage = 'CreateParent'
            New-Item -Path $parentPath -ItemType Directory -ErrorAction Stop | Out-Null
        }
        Assert-OrdinaryDirectory $parentPath
        $stage = 'CreateProbe'
        New-Item -Path $probePath -ItemType Directory -ErrorAction Stop | Out-Null
        Assert-OrdinaryDirectory $probePath
        $stage = 'SetProbeAcl'
        Set-Acl -LiteralPath $probePath -AclObject $newAcl -ErrorAction Stop
        $verifiedAcl = Read-VerifiedProbeAcl -Path $probePath -OwnerSid $adminsSid -ExpectedRules $expectedRules
        if (@(Get-ChildItem -LiteralPath $probePath -Force -ErrorAction Stop).Count -ne 0) {
            throw 'Probe must be empty before sharing it.'
        }

        $stage = 'CreateShare'
        New-SmbShare -Name $shareName -Path $probePath -ReadAccess $labAccount -CachingMode None `
            -Description 'SOC lab authentication probe (empty, read-only)' -ErrorAction Stop | Out-Null

        $stage = 'Readback'
        Assert-OrdinaryDirectory $parentPath
        Assert-OrdinaryDirectory $probePath
        $verifiedAcl = Read-VerifiedProbeAcl -Path $probePath -OwnerSid $adminsSid -ExpectedRules $expectedRules
        $shares = @(Get-SmbShare -Name $shareName -ErrorAction Stop)
        if ($shares.Count -ne 1 -or $shares[0].Path -ne $probePath -or $shares[0].CachingMode -ne 'None') {
            throw 'Unexpected share path, count, or caching mode.'
        }
        $shareAccess = @(Get-SmbShareAccess -Name $shareName -ErrorAction Stop)
        if ($shareAccess.Count -ne 1 -or $shareAccess[0].AccessControlType -ne 'Allow' -or
            $shareAccess[0].AccessRight -ne 'Read') {
            throw 'The SMB share must have exactly one Allow/Read entry.'
        }
        $shareSid = [System.Security.Principal.NTAccount]::new($shareAccess[0].AccountName).Translate(
            [System.Security.Principal.SecurityIdentifier])
        if ($shareSid.Value -ne $labUser.SID.Value) {
            throw 'The SMB Read entry does not belong to lab-auth01.'
        }
        if (@(Get-ChildItem -LiteralPath $probePath -Force -ErrorAction Stop).Count -ne 0) {
            throw 'Probe is no longer empty.'
        }

        $verifiedAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
            Select-Object @{Name='SID'; Expression={$_.IdentityReference.Value}}, FileSystemRights,
                AccessControlType, InheritanceFlags, PropagationFlags, IsInherited | Format-Table -AutoSize
        $shareAccess | Select-Object Name, AccountName, AccessControlType, AccessRight | Format-List
        [pscustomobject]@{
            ShareName = $shares[0].Name
            ProbePath = $shares[0].Path
            DirectoryEmpty = $true
            OwnerSID = $verifiedAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            NtfsInheritanceProtected = $verifiedAcl.AreAccessRulesProtected
            NtfsEntryCount = 3
            ShareEntryCount = $shareAccess.Count
            ShareAccountSID = $shareSid.Value
            ShareSetupReadback = 'Passed'
        } | Format-List
    } catch {
        [pscustomobject]@{
            ShareSetupStopped = $stage
            Message = $_.Exception.Message
        } | Format-List | Out-Host
        throw
    }
}
