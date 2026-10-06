# Firewall partial failure: rule state read

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

**Latest finding, 2026-10-05:** the Allow correction stays passed: **MacAllowAddressReadback Passed / RuleChanged True**, both stores LocalAddress Any, source .1 / Ethernet0 / TCP 445 and the selected conditions preserved; DHCP guest address during the run .129/24 Preferred. The earlier administrative MMC view failed with "Unknown error", cause unknown. The user ran the rights export: **ExportExitCode 0**, file/size/UTF-16LE BOM checks passed. Then the parser stopped with **Expected exactly one Privilege Rights section**, before both target lines and **NetworkRightsExport Collected**. The actual section count was not printed; cause and both rights values remain unknown. Next step: run only [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). This new diagnostic block has **not yet been run**. It only reads the existing INF and its log: section headers, selected possible rights lines and the end of the log. No new export, no file write, policy repair or logon. Do not repeat successful setups, diagnoses and setters. The Allow acceptance is no packet/WFP/authentication proof.

Historical state of the troubleshooting: **2026-10-04**. The earlier two-rule partial state has since been fixed by the corrected repair run by the user. Both stores show **three unique lab rules**, the complete six lines match the intended conditions, and the conclusion reads **ConfigurationReadback : Passed**. The configuration is accepted; this is no complete WFP/packet, SMB or logon proof. **Do not repeat the repair or the completed diagnoses.** The subsequent empty [probe folder / SOC-LAB share](windows-share-step.md) has also been created and read back with **ShareSetupReadback : Passed**; do not repeat this setup. The separate address diagnosis and Allow correction are also complete, the latter with MacAllowAddressReadback Passed / RuleChanged True. Current next step: only [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md). The pilot collection block has since been run with partial findings and aborted; do not repeat it. The following sections keep the historical sequence of errors and diagnoses.

## Historical creation error

- `New-NetFirewallRule` reports **"At least one address prefix is invalid"**, HRESULT **0x80070057**.
- Afterwards `Get-NetFirewallRule` reports the rule **SOC-Lab-SMB-Block-IPv6** as not found. The block ends with **Expected exactly three active lab rules**; the intended filter/status values were not printed.
- Despite `$ErrorActionPreference = 'Stop'` being set, the block kept running after the first error. The exact cause of this module/error behavior is not established. New NetSecurity calls therefore get `-ErrorAction Stop` explicitly.
- At the time of the error, the IPv4 partial state was unchecked. The follow-up query at the time showed both IPv4 rules in both stores; the Mac allow and the remote ranges were correct. The block rule's LocalAddress was **0.0.0.0** at the time and was not accepted as all-IPv4 coverage.
- The Markdown line of three backticks copied along at the end caused a separate unknown command. It neither created nor removed any rule.

The earlier IPv6 prefix `::/0` was unsuitable: Microsoft specifies prefix lengths **1 to 128** for `FW_IPV6_SUBNET`. This supports attributing the parameter error to that specification; the error message does not distinguish between its LocalAddress and RemoteAddress arguments. The old [creation block](windows-firewall-configure.md) is withdrawn. [Official IPv6 subnet definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/ccb501eb-6620-4b49-befd-2b59828a28c8)

## Completed read-only query

The user ran [Read-LabFirewallState.ps1](../../scripts/windows/Read-LabFirewallState.ps1) without errors. PersistentStore and ActiveStore each report **LabRuleCount 2 / MissingNames SOC-Lab-SMB-Block-IPv6** and completely captured port/address/interface/security filters. PrimaryStatus is OK in each; PersistentStore reports NotApplicable, ActiveStore **ProfileInactive,Enforced**. The diagnostic success criterion has passed; no rule was changed. The raw file contains no Markdown fences.

The query is not run again now. The [repair guide](windows-firewall-repair.md) documents the two changes since run by the user and the successful configuration readback. In case of a further partial failure, the purely read-only block can serve again to clarify the state.

This actual Windows execution comes from the user. The coding tool only created and checked files in the project; no Windows runtime or empirical syntax validation was performed. Status metadata does not replace an actual connection test.

## Application filter diagnosis also completed

After the two historical repair stops before changes, the user ran [Read-LabApplicationFilters.ps1](../../scripts/windows/Read-LabApplicationFilters.ps1) successfully. All four combinations of PersistentStore/ActiveStore and the two IPv4 rules return **MSFT_NetApplicationFilter**. The actual CIM properties **AppPath** and **Package** on the filter as well as **PackageFamilyName** and **PolicyAppId** on the rule are present in each case, have **CimType String** and a genuine **null** value. The output distinguishes this from missing properties, empty strings and the text Any. No rules were changed and no raw evidence was copied into the project.

The earlier request to run this diagnosis as the next step is therefore done. The repair run afterwards required exactly one present string CIM property with a genuine null for each of the four fields, without a Package=Any assumption or cast fallback. When the IPv6 rule was created, the optional Program/Service/InterfaceType parameters were not set; their actual defaults Any were read back successfully afterwards.

## Repair on 2026-10-04 read back successfully

The new user output confirms **three unique rules in PersistentStore and ActiveStore** as well as **ConfigurationReadback : Passed**. All six lines show the matching actions, TCP 445 / Ethernet0 / Any profile, Program/Service/InterfaceType Any, PrimaryStatus OK and the intended security fields. The four CIM properties each have type String and IsNull True. PersistentStore reports NotApplicable, ActiveStore ProfileInactive,Enforced.

The IPv4 block rule now has LocalAddress **Any** and unchanged remote complement ranges. The IPv6 rule is present with LocalAddress **Any** and remote range **::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff**. The Mac allow stays local **192.168.243.128**, remote **192.168.243.1**. The configuration readback is accepted; the historical failures remain documented. No raw evidence was copied into the project.

## Share setup and Allow correction completed; the next check is read-only

The new user output confirms the empty **C:\SOC-Lab\Probe / SOC-LAB**, a protected NTFS ACL with three entries and exactly one SMB Allow/Read entry for the same local test account **lab-auth01**, concluded with **ShareSetupReadback : Passed**. The dynamic account SID is not included in the project. The shortened NTFS table display does not require a repetition: the helper that ran checked the complete rights and inheritance conditions before the successful conclusion. Whether the parent folder existed before or was created then remains unknown from this output.

1. Do not repeat successful setups, diagnoses/setters, MMC, export and the pilot collection block. The Mac Allow readback stays passed; secedit succeeded with exit code 0, but the parser stopped before the rights lines / Collected, without a section count.
2. Run the complete current [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). The new diagnosis has not yet been run and only reads existing INF and log files, without an export or write operation.
3. Supply the complete diagnostic console output, not the complete INF. Parser cause and rights values stay open until there is concrete output. No policy repair or logon; the remaining [pilot prerequisites](windows-pilot-prerequisites.md) follow separately.

The passed configuration readback proves no complete WFP/packet effect and no SMB/logon success.

No firewall reset, no disabling of IPv6, the firewall, SMB signing or account lockout. No native logon proof or Security event export exists. Splunk remains pending. The Python detection logic was not changed; its tests are not repeated because of this separate Windows partial failure. No AI author fields, commit trailers or changes to the Git identity.

API basis: [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps) for PolicyStore and associated filters, and [ErrorAction](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7.5#erroraction) for the explicitly set abort. The general parameter description is not presented as a Windows runtime test or as a request to upgrade PowerShell.
