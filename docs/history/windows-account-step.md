# Local standard test account: created and checked

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

Status: **2026-10-03**. The user created the account successfully in the owned Windows 11 Pro test VM **DESKTOP-7HFI2UV**. The output confirms **Name lab-auth01, Enabled True, PrincipalSource Local, UsersMember True, AdministratorsMember False**. The first attempt stopped at the password length check before `New-LocalUser`; the second succeeded. No password is documented. The coding tool created no account and set no password. The existing 40 GiB installation is kept.

**Completed: do not repeat the creation block.** The SMB pre-check and firewall candidates have since been observed as well; next is the [limited firewall configuration](windows-firewall-configure.md). Windows stays powered on. The commands below document the account step that was carried out.

## Network state reached

The user supplied: **Ethernet0**, ifIndex **8**, status **Up**; IPv4 **192.168.243.128/24**, state **Preferred**. The active default route query for IPv4/IPv6 stayed empty twice. On the Mac, **bridge100 active, 192.168.243.1/24** and the local route to the Windows target via **bridge100** were read on 2026-10-03. After a sandbox block, the route had to be queried read-only with approval; this created no connection and changed nothing.

The selected current VMX fields confirm **ethernet0.connectionType = hostonly**, adapter present and **isolation.tools.hgfs.disable = TRUE**. A saved shared-folder entry remains declared as present/active; this does not cancel the global deactivation value. No runtime share use was tested and no personal host path is documented. The user confirms: **Internet Sharing off, no other VMs running; only the current test VM runs**. The IPv4/IPv6 forwarding state 0/0 read on 2026-10-02 was not measured again today. All remaining guest routes, guest time / time zone / UTC and a suitable license / successful activation remain to be clarified before the pilot.

## Documented creation block

In **Windows PowerShell as Administrator**, in the existing console session, paste the entire following block including `& {` and the closing brace. No switch to the test account and no SMB call yet. The block runs in its own variable scope and stops on errors; the normal shell setting is not changed permanently.

Choose a **new password used only for this lab, with at least 14 characters**. This length is a decision for the new test account, not a change of the local password or lockout policy. Input is hidden; do not put the password into chat, a command or a file. The Users group is selected by its language-independent SID; no administrator rights are granted. An existing account with the same name is not replaced or reset.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    if (Get-LocalUser -Name 'lab-auth01' -ErrorAction SilentlyContinue) {
        throw 'lab-auth01 exists already; inspect it before changing anything.'
    }
    $labPassword = Read-Host 'New lab password (at least 14 characters)' -AsSecureString
    if ($labPassword.Length -lt 14) { throw 'Use at least 14 characters.' }
    $labUser = New-LocalUser -Name 'lab-auth01' -Password $labPassword -Description 'SOC lab authentication test'
    $inUsers = [bool](Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.SID -eq $labUser.SID })
    if (-not $inUsers) {
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $labUser
    }
    $labUser = Get-LocalUser -Name 'lab-auth01'
    $inUsers = [bool](Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.SID -eq $labUser.SID })
    $inAdmins = [bool](Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID -eq $labUser.SID })
    [pscustomobject]@{
        Name = $labUser.Name
        Enabled = $labUser.Enabled
        PrincipalSource = $labUser.PrincipalSource
        UsersMember = $inUsers
        AdministratorsMember = $inAdmins
    } | Format-List
}
```

## Success criteria

The output must contain:

```text
Name                  : lab-auth01
Enabled               : True
PrincipalSource       : Local
UsersMember           : True
AdministratorsMember  : False
```

The actual output supplied by the user on **2026-10-03** matches these five values; the account step passed. The stored table is a reference, not a Security event export. Missing output or an error is not a passed step. If something fails, supply the exact message and the account state reached; do not repeat the creation block blindly. After an error following account creation, the account may already exist. Nothing is deleted, reset or removed from groups automatically. The check covers the standard Users group and the Administrators group, not a general determination of every possible privileged permission.

The name for later SMB logons in the local context is **DESKTOP-7HFI2UV\\lab-auth01**; `WORKGROUP` is not used as the authentication domain. Password expiry follows the existing policy; no `PasswordNeverExpires`, `NoPassword` or lockout bypass. No automatic expiry date is derived from the guest clock that is still to be checked. After the lab ends, the account state is documented explicitly and the account is removed in a separate cleanup step if needed.

**Keep Windows running.** The account output has been supplied; next, [read the SMB service, existing test path / share name and firewall profiles](windows-smb-step.md). Share/NTFS rights, a tightly limited firewall rule, account-specific audit settings and network logon rights follow in the next step. The current system audit "Logon: Success and Failure" and the lockout values 10/10/10 are not changed. The new account can produce its own account management events; that is not a captured 4624/4625 SMB pilot and no evidence of type 3.

## Sources and check limits

Officially checked on 2026-10-03: [Microsoft New-LocalUser, PowerShell 5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1), [Add-LocalGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember?view=powershell-5.1), [well-known SIDs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers). `S-1-5-32-545` denotes Users, `S-1-5-32-544` Administrators. The LocalAccounts module is not available in 32-bit PowerShell on a 64-bit system; use the normal 64-bit Windows PowerShell, no installation required.

The commands were checked against the API documentation and not run by the coding tool in PowerShell. Their actual execution by the user is now established by the supplied account output; share and firewall changes remain unobserved. Detector, adapter decision, export script and tests were not changed or repeated; Splunk remains pending. No AI author fields, commit trailers or Git identity changes are created.
