# SMB pre-check: run and passed

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

Status: **2026-10-03**. The user created `lab-auth01` and checked it successfully: **Enabled True, PrincipalSource Local, UsersMember True, AdministratorsMember False**. The first attempt stopped at the password length check before the account was created. No password is documented; do not repeat the creation block.

## Observed result, 2026-10-03

The user ran the complete block and supplied the following actual values:

| Check | Result |
| --- | --- |
| LanmanServer | Running, Automatic |
| SMB1 / SMB2 | False / True |
| RequireSecuritySignature / EncryptData | True / False |
| ProbePathExists / SOC_LABShareCount | False / 0 |
| Connection profile | Ethernet0, index 8, Public; IPv4Connectivity NoTraffic; IPv6Connectivity NoTraffic |
| Domain / Private / Public firewall | Each Enabled True; DefaultInboundAction Block; AllowInboundRules True; AllowLocalFirewallRules True |

The pre-check passed. Signing requirement, SMB1 state, profile and firewall stay unchanged. NoTraffic is not an executed connection test. Account and SMB pre-check are not repeated; the [firewall candidates](windows-firewall-step.md) have now been supplied as well; the next step is the [limited rule configuration](windows-firewall-configure.md). No share/ACL/firewall changes yet, no controlled SMB attempt and no XML export.

## Documented block, already run

Keep Windows and the host-only adapter running. Paste the entire block into **Windows PowerShell as Administrator**. It only reads local state; no folder or share creation, service starts, policy changes or network logons.

```powershell
& {
    $ErrorActionPreference = 'Stop'

    Get-Service -Name 'LanmanServer' |
        Select-Object Name, Status, StartType | Format-List

    Get-SmbServerConfiguration |
        Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData |
        Format-List

    $existingShare = @(Get-SmbShare | Where-Object { $_.Name -eq 'SOC-LAB' })
    [pscustomobject]@{
        ProbePathExists = (Test-Path -LiteralPath 'C:\SOC-Lab\Probe')
        SOC_LABShareCount = $existingShare.Count
    } | Format-List
    $existingShare | Select-Object Name, Path | Format-List

    Get-NetConnectionProfile -InterfaceIndex 8 |
        Select-Object InterfaceAlias, InterfaceIndex, NetworkCategory, IPv4Connectivity, IPv6Connectivity |
        Format-List

    Get-NetFirewallProfile -PolicyStore ActiveStore |
        Select-Object Name, Enabled, DefaultInboundAction, AllowInboundRules, AllowLocalFirewallRules |
        Format-List
}
```

`Get-SmbShare` is read with abort on error and only filtered afterwards. **SOC_LABShareCount 0** means a successfully queried absence; an error or an aborted block does not mean that. If the path or name exists, do not replace, delete or reset rights.

## Success criteria

Service status, SMB configuration, path/share inventory, connection profile and active firewall profiles must be present without errors. For the planned fresh folder we expect **ProbePathExists False** and **SOC_LABShareCount 0**. For the later SMB attempt, **LanmanServer Running** and **EnableSMB2Protocol True** are intended; any other state is investigated first. SMB1 is not enabled, and signing/encryption requirements are not switched off. **Public** as network profile is not an error and is not changed to Private just for SMB. Missing profile output has to be explained. Firewall profiles should stay active; `NotConfigured` is not interpreted as an explicit allow or block without further checks. The supplied output meets these criteria; the actual values are above. The profile check alone does not prove a matching TCP 445 allow.

The profile overview does **not yet show the complete effective TCP 445 rule set**. Before creating the share, the active inbound rules for TCP 445, `Any` and relevant port ranges follow, with profile, source/destination address, interface and program/service binding. A new narrow allow does not restrict existing broad allows. Then only a new empty folder **C:\SOC-Lab\Probe** with NTFS read rights for the test account and administrative management, plus the SMB share **SOC-LAB**, is prepared; existing parent folders are checked for folders/reparse points. No creation block and no share/ACL/firewall proof yet.

**Keep Windows running; the [firewall candidates](windows-firewall-step.md) have been supplied and the [limited configuration](windows-firewall-configure.md) follows now.** The SMB pre-check values have been supplied. Account-specific audit, network logon rights / account model, remaining guest routes, guest time / UTC and a suitable license / successful activation remain open before the pilot. System audit for logon success/failure and the lockout values 10/10/10 are already observed and not repeated routinely. Genuine events, the exact adapter and the Splunk execution remain pending.

## Sources and check limits

Official APIs checked on **2026-10-03**: [Get-SmbShare](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbshare?view=windowsserver2025-ps), [Get-SmbServerConfiguration](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbserverconfiguration?view=windowsserver2025-ps), [Get-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile?view=windowsserver2025-ps), [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps). `ActiveStore` reads the merged active firewall configuration. The Windows Server documentation view is an API reference; the guest is Windows 11 Pro. Actual availability and the selected values are now established by the user's query in the guest.

The commands were checked against the documentation and independently in the source text. The coding tool did not run them on Windows; the account and SMB pre-check blocks are now established by the user's actual execution and supplied output. The new firewall rule check has not yet been run on Windows. Code, schema, export script and tests remain unchanged; no test repetition. No AI author fields, commit trailers or Git identity changes.
