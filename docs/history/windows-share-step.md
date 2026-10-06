# Empty probe folder and SOC-LAB share: acceptance passed

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

**Latest finding, 2026-10-05:** the Allow correction stays passed: **MacAllowAddressReadback Passed / RuleChanged True**, both stores LocalAddress Any, source .1 / Ethernet0 / TCP 445 and the selected conditions preserved; DHCP guest address during the run .129/24 Preferred. The earlier administrative MMC view failed with "Unknown error", cause unknown. The user ran the rights export: **ExportExitCode 0**, file/size/UTF-16LE BOM checks passed. Then the parser stopped with **Expected exactly one Privilege Rights section**, before both target lines and **NetworkRightsExport Collected**. The actual section count was not printed; cause and both rights values remain unknown. Next step: run only [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). This new diagnostic block has **not yet been run**. It only reads the existing INF and its log: section headers, selected possible rights lines and the end of the log. No new export, no file write, policy repair or logon. Do not repeat successful setups, diagnoses and setters. The Allow acceptance is no packet/WFP/authentication proof.

Historical state of the share acceptance: **2026-10-04**. The user ran [New-LabProbeShare.ps1](../../scripts/windows/New-LabProbeShare.ps1) completely and without errors in the owned Windows guest: **ShareSetupReadback : Passed**. The [firewall repair](windows-firewall-repair.md) has also passed its selected configuration acceptance. **Do not repeat** either setup or the completed diagnoses. SMB/logon attempt and Security event export remain pending.

The test VM **DESKTOP-7HFI2UV** now has the new empty folder **C:\SOC-Lab\Probe** and the Windows SMB share **SOC-LAB**. The address diagnosis and the Allow correction are complete as well. Next, only [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md). Keep the VM running. Host-only stays configured, Mac Internet Sharing off, no other VMs on the lab network.

## Configuration created and checked

| Area | Checked state |
| --- | --- |
| New probe folder | Empty; no marker, no payload data, no exports |
| NTFS owner | BUILTIN\Administrators, language-independent via SID S-1-5-32-544 |
| NTFS inheritance | Protected; no additional inherited access entries |
| NTFS access | Exactly three explicit Allow entries: SYSTEM (S-1-5-18) and Administrators each FullControl; the actually read SID of lab-auth01 with ReadAndExecute |
| SMB share access | Exactly one Allow/Read entry for DESKTOP-7HFI2UV\lab-auth01; no Everyone/Guest entry |
| Caching | CachingMode None |

The newly set access entries give the test account no write, delete or permission-change rights; the SMB share grants it Read only. **Synchronize** can appear in the NTFS display in addition to ReadAndExecute: .NET adds this right to Allow rules. The acceptance therefore compares against the rule rights actually constructed. The NTFS entries apply to the folder and could be inherited by children created later; the folder stays empty in this step. FullControl for SYSTEM/Administrators concerns NTFS only. The check covers the probe/share entries that were set, not a complete proof of all effective local rights through unchanged parent folders or other access paths.

Whether **C:\SOC-Lab** existed before this run was not printed explicitly and remains unknown. An existing ordinary parent folder stays unchanged in the script, with its content and ACLs. If it is missing, the script creates it as a new folder with the normal inherited rights; only the new probe folder gets the ACL described. Files or reparse points at the checked paths abort the run. An already existing probe path or SOC-LAB share is neither adopted nor changed. A failed partial setup is not deleted automatically.

## Successful manual run

The user ran the complete block in elevated 64-bit Windows PowerShell 5.1 and supplied the complete output. **Do not run it again:** the guards require fresh paths and shares and would stop in the state that now exists.

Before making changes, the script checked the known computer name, the elevated 64-bit Windows PowerShell, the enabled local standard account **lab-auth01** (Users member, not an administrator), the running SMB service and the SMB security settings already observed. It changed no accounts, firewall rules, audit or lockout policies, network profiles or SMB protocol/signing settings. No test password was needed here. The completed pre-checks were therefore not requested again as separate blocks; the short guards belonged to the folder/share change at that time.

**No connection or logon attempt** follows. In particular, do not yet connect to the share in Finder and do not try wrong passwords.

## Success criteria from the actual readback

The error-free actual run concluding with **ShareSetupReadback : Passed** has passed this step. The output confirms:

- ProbePath **C:\SOC-Lab\Probe**, ShareName **SOC-LAB** and **DirectoryEmpty True**.
- **OwnerSID S-1-5-32-544**, **NtfsInheritanceProtected True**, **NtfsEntryCount 3**; all three printed entries are Allow, not inherited, and match the SIDs and rights given above.
- **ShareEntryCount 1**, Allow/Read for the qualified local test account. **ShareAccountSID** matches its actually read local SID; the script translates the account name read back into a SID and checks the identity.

These values come from the supplied output. The NTFS table shows SYSTEM and Administrators FullControl and lab-auth01 ReadAndExecute,Synchronize; some right-hand table columns are truncated by the window width. The helper that actually ran checked owner, protection, SIDs, rights, inheritance/propagation flags and IsInherited completely before Passed. The truncation therefore does not justify a repetition. The SMB entry is Allow/Read for DESKTOP-7HFI2UV\lab-auth01. The dynamic account SID matches but is not copied here. The NTFS ACL was read and checked before the share was created and again afterwards; the SMB rights were read after creation. Passed confirms this folder/share configuration, not a successful logon or the presence of event fields.

For any other run: on an error the block ends with **ShareSetupStopped** and the section concerned, for example CreateParent, CreateProbe, SetProbeAcl, CreateShare or Readback. Do not run it again unchanged and do not delete anything wholesale. If the abort happened after a change, the parent folder, the probe folder or even the share may already exist. Then exactly this partial state is checked based on the complete output. The current user run contains no such error.

## Still open afterwards

The Allow correction has passed its readback. Next, only [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md). Do not repeat the diagnosis, the setter or completed setups. The partial findings from the previous collection and the prerequisites remaining afterwards are documented in the [pilot guide](windows-pilot-prerequisites.md). The user confirmed the own Windows 11 Pro license; technically Notification / status 5 is observed. After evaluating both rights lists and clarifying the remaining prerequisites, an individually controlled pilot with one wrong and one correct logon from the Mac follows. Logon type 3 as well as source IP, account and target host must be confirmed from genuine events. Native events, XML export, the exact adapter and the Splunk comparison remain pending.

## Official sources and check limit

Checked on **2026-10-04**: [New-SmbShare](https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare?view=windowsserver2025-ps) for Path, ReadAccess, CachingMode and the note that its WhatIf does not work; [Get-SmbShareAccess](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbshareaccess?view=windowsserver2025-ps) for AccountName, AccessControlType and AccessRight; [Get-LocalGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember?view=powershell-5.1) for group-related SID queries in 64-bit Windows PowerShell.

NTFS/identity APIs: [FileSystemAccessRule constructor](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemaccessrule.-ctor?view=netframework-4.8.1), [FileSystemRights](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=netframework-4.8.1), [SetAccessRuleProtection](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection?view=netframework-4.8.1), [SetOwner](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setowner?view=netframework-4.8.1), [NTAccount.Translate](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.ntaccount.translate?view=netframework-4.8.1) and [well-known Windows SIDs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers). [Set-Acl](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-7.5) describes LiteralPath and AclObject; the 5.1 page was not available when the documentation was retrieved. This is no executed PowerShell 5.1 validation.

The source/API review prepared the block. Now the user's actual successful Windows run exists as well; the coding tool checked the complete output but ran no Windows commands itself. No packet/SMB/logon proof. No application code, schema or fixture change and no automatic repetition of the Python tests. No AI authorship information, Co-authored-by trailers or changes to the Git identity.
