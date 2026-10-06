# Application filters of the own lab rules: diagnosis completed

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

**Latest finding, 2026-10-05:** the Allow correction stays passed: **MacAllowAddressReadback Passed / RuleChanged True**, both stores LocalAddress Any, source .1 / Ethernet0 / TCP 445 and the selected conditions preserved; DHCP guest address during the run .129/24 Preferred. The earlier administrative MMC view failed with "Unknown error", cause unknown. The user ran the rights export: **ExportExitCode 0**, file/size/UTF-16LE BOM checks passed. Then the parser stopped with **Expected exactly one Privilege Rights section**, before both target lines and **NetworkRightsExport Collected**. The actual section count was not printed; cause and both rights values remain unknown. Next step: run only [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). This new diagnostic block has **not yet been run**. It only reads the existing INF and its log: section headers, selected possible rights lines and the end of the log. No new export, no file write, policy repair or logon. Do not repeat successful setups, diagnoses and setters. The Allow acceptance is no packet/WFP/authentication proof.

Historical state of the application filter diagnosis: **2026-10-04**. The user ran [Read-LabApplicationFilters.ps1](../../scripts/windows/Read-LabApplicationFilters.ps1) completely and without errors. The diagnosis changed no rules. **Not needed again:** the [firewall correction](windows-firewall-repair.md) and the [test share](windows-share-step.md) have since passed the configuration acceptance as well. The later Allow address correction has also passed its readback. The next step is only to [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md).

## Cause of the earlier abort

The earlier repair stopped at PersistentStore / SOC-Lab-SMB-Allow-Mac before Set-NetFirewallRule and New-NetFirewallRule. Program Any, Service Any and InterfaceType Any were observed; the display of the projected Package was empty. The mistaken guard Package=Any led to Unexpected rule conditions. The string cast did not distinguish a missing property, a genuine null and an empty string. This attempt changed no firewall rule.

Microsoft documents Package as a string containing an application SID and AppPath as a string containing the application path. An application path or package SID that is actually not set (`null`) means no corresponding process condition in the protocol. No general target value Package Any follows from this. [Filter class](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netapplicationfilter), [FW_RULE / wszLocalApplication and wszPackageId](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/8c008258-166d-46d4-9090-f2ffaa01be4b)

## Actual result

The following values were printed identically for **both rules** (SOC-Lab-SMB-Allow-Mac and SOC-Lab-SMB-Block-OtherIPv4) in **both stores** (PersistentStore and ActiveStore):

| Object | Actual CIM property | CIM type | Actual value |
| --- | --- | --- | --- |
| MSFT_NetApplicationFilter | AppPath | String | null |
| MSFT_NetApplicationFilter | Package | String | null |
| Firewall rule | PackageFamilyName | String | null |
| Firewall rule | PolicyAppId | String | null |

PackagePropertyPresent is True in each case. For all four properties listed, the output gives ValueIsNull True, ValueKind Null, ValueType `<null>` and ValueJson `null`. The properties are present; none contains an empty string. The actual CIM property names and the filter class name are printed as well. The additionally captured LocalOnlyMapping and LooseSourceMapping are Boolean false in each case; this metadata is not a logon event.

The diagnostic success criterion is met: four complete store/rule combinations, actual types and values, and no errors. The raw text stays in the user's attachment and is not copied as a project fixture or Security event export. The Windows execution comes from the user; the coding tool ran no Windows commands.

## Repair run successfully afterwards

[Repair-LabFirewall.ps1](../../scripts/windows/Repair-LabFirewall.ps1) was corrected to exactly these observed properties. Before any change, the helper Read-RequiredNullString requires exactly one actual CIM property of type String with a genuine null in each case. Missing properties, other types and empty or non-empty strings abort the run. There is neither a string cast of the values nor an invented substitute value Any.

The four checks apply to all existing rules in both stores and later also to the newly created IPv6 rule. The earlier immediate withdrawal abort was removed after this correction; the outdated versions remain historically withdrawn. **The user has since run the current repair in the guest without errors:** three rules per store, all selected conditions and ConfigurationReadback : Passed. The newly created IPv6 rule also shows these four properties as String/null. The configuration acceptance has passed; packet and logon proofs remain open.

The VM stays on. Do not repeat the diagnosis, repair and share setup. The IPv4 block is now local Any and the IPv6 block has been added; the [repair report](windows-firewall-repair.md) contains the actual values. The [empty test share](windows-share-step.md) was also created successfully, concluding with ShareSetupReadback : Passed. The separate address diagnosis and Allow correction are complete as well; do not repeat the setter. Next, only [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md). After that the missing [pilot prerequisites](windows-pilot-prerequisites.md) remain to be clarified; no logon yet. Python detection logic, schema and export script remain unchanged; their tests are not repeated. Splunk remains pending. No AI author fields, commit trailers or Git identity changes.

API basis: [Get-NetFirewallApplicationFilter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallapplicationfilter?view=windowsserver2025-ps) for the filter association and [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps) for both rule stores. The actual additional CIM properties are established by the diagnosis; older published class definitions do not replace this observation.
