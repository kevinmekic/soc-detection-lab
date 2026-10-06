# Firewall candidates: read and assessed

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

**Latest finding, 2026-10-05:** the Allow correction stays passed: **MacAllowAddressReadback Passed / RuleChanged True**, both stores LocalAddress Any, source .1 / Ethernet0 / TCP 445 and the selected conditions preserved; DHCP guest address during the run .129/24 Preferred. The earlier administrative MMC view failed with "Unknown error", cause unknown. The user ran the rights export: **ExportExitCode 0**, file/size/UTF-16LE BOM checks passed. Then the parser stopped with **Expected exactly one Privilege Rights section**, before both target lines and **NetworkRightsExport Collected**. The actual section count was not printed; cause and both rights values remain unknown. Next step: run only [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). This new diagnostic block has **not yet been run**. It only reads the existing INF and its log: section headers, selected possible rights lines and the end of the log. No new export, no file write, policy repair or logon. Do not repeat successful setups, diagnoses and setters. The Allow acceptance is no packet/WFP/authentication proof.

Historical state of the candidate check: **2026-10-03**. The [SMB pre-check](windows-smb-step.md) was run by the user and passed. The documentation below records the **read-only** step at that time in the owned Windows test VM; it changed no accounts, shares, ACLs or firewall rules and triggered no logon.

**Continuation, 2026-10-04:** after the failed creation attempt, the two-rule partial state and the actual application filters were read successfully. Two earlier repair attempts stopped before making changes. The user has now run the subsequently corrected [repair](windows-firewall-repair.md) without errors: **three unique rules per store**, all six complete lines with matching conditions and **ConfigurationReadback : Passed**. IPv4 block local Any, IPv6 range and the unchanged Mac allow are confirmed. **Do not repeat the repair or the completed diagnoses.** The subsequent empty [probe folder / SOC-LAB share](windows-share-step.md) has since been created and read back with **ShareSetupReadback : Passed**. Do not repeat the share setup either. The later [pilot collection block](windows-pilot-prerequisites.md) supplied partial findings and aborted; do not repeat it. The current continuation of 2026-10-05 is above. No SMB/logon or complete WFP proof is claimed.

## Historically observed state before the share setup

| Check | Actual user output |
| --- | --- |
| Service LanmanServer | Running, Automatic |
| SMB protocols | SMB1 False; SMB2 True |
| Security | RequireSecuritySignature True; EncryptData False |
| New folder / share | ProbePathExists False; SOC_LABShareCount 0 |
| Adapter profile | Ethernet0, index 8, Public; IPv4/IPv6Connectivity NoTraffic |
| Firewall profiles | Domain, Private, Public: Enabled True, DefaultInboundAction Block, AllowInboundRules True, AllowLocalFirewallRules True |

The signing requirement stays, SMB1 is not enabled, and the profile is not changed to Private for SMB. **NoTraffic is not an observed SMB connection error**: no controlled Mac/VM connection had been tested yet. Profile values and a running server do not prove a successful network logon path.

## Actual output and assessment — 2026-10-03

The user supplied the complete block with its output: **EnabledInboundRuleCount 127, CandidateCount 38**; all 38 printed candidates are **Allow**, all have **OverrideBlockRules False**. The printed candidates were counted and match the final count. No Block rule was printed in this limited candidate search. This is no complete WFP access proof and no executed connection.

| Relevant observed candidate | Printed conditions / assessment |
| --- | --- |
| {40930648-8C4A-486D-B1BB-B9DA2B68F5D8} | Public, TCP 445, System, RemoteAddress LocalSubnet, local address and interface Any: existing broader SMB allow condition |
| NETDIS-UPnPHost-In-TCP-Teredo | Public, TCP/Any, System, source Any: broad candidate; additional dynamic conditions not claimed |
| WiFiDirect-KM-Driver-In-TCP | Any profile, TCP/Any, System, source Any: broad candidate; no global access conclusion |
| Other application/service candidates | Some concern Public; program, package, user and dynamic conditions may contain additional bindings |

**PackageRestricted False** only means that the expression at that time found no non-empty .Package value; it does not prove an unrestricted application. The current MS-FASP rule schema also knows package family / trust conditions that are not contained in the shortened result. No package fields were made up and no app rules were disabled wholesale. The block hid direct program paths and package values; some printed app rule names nevertheless contained local user SIDs. The raw text is therefore not copied into the project; this documentation contains only the values needed for the lab setup and system rule names.

**Do not repeat this search.** The later first [rule setup](windows-firewall-configure.md) failed; the diagnoses at the time showed two IPv4 rules and the actual null values of the application filters. The corrected repair that followed has now been run successfully and accepted in both stores. Do not repeat it either. The subsequent [probe folder / share](windows-share-step.md) is now complete with ShareSetupReadback Passed. The subsequent address diagnosis and Allow correction are also complete; do not repeat the setter. Next, only [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md); no SMB connection or logon.

## Documented read block, already run

The following block documents the candidate search that was already run and is **not run again** now. It was used in Windows PowerShell as Administrator and reads active, enabled inbound rules of all profiles with their associated filters. It keeps Allow and Block rules and considers TCP/Any, port 445, matching port ranges and unclear port expressions. It hides direct program paths and package values; rule names can still contain local SIDs and are therefore not treated as complete anonymization. The entire rule state stays unchanged.

```powershell
& {
    $ErrorActionPreference = 'Stop'

    function Read-LabFilter {
        param($Rule, [string]$Command)
        $items = @(& $Command -AssociatedNetFirewallRule $Rule)
        if ($items.Count -ne 1) { throw "Incomplete filter: $Command" }
        $items[0]
    }

    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound)
    $rows = @(foreach ($rule in $rules) {
        $port = Read-LabFilter $rule 'Get-NetFirewallPortFilter'
        $protocol = ([string]$port.Protocol).Trim()
        if (-not $protocol) { throw 'Missing protocol in firewall filter.' }
        if ($protocol -notin @('TCP', '6', 'Any', '256')) { continue }

        $candidate = $protocol -in @('Any', '256')
        $unknownPort = -not $port.LocalPort
        if ($unknownPort) { $candidate = $true }
        foreach ($entry in $port.LocalPort) {
            foreach ($value in ([string]$entry -split ',')) {
                $value = $value.Trim()
                if ($value -eq 'Any' -or
                    ($value -match '^\d{1,5}$' -and [int]$value -eq 445)) {
                    $candidate = $true
                } elseif ($value -match '^(\d{1,5})\s*-\s*(\d{1,5})$') {
                    $low = [int]$Matches[1]
                    $high = [int]$Matches[2]
                    if ($low -gt $high -or $high -gt 65535) {
                        $candidate = $true
                        $unknownPort = $true
                    } elseif ($low -le 445 -and $high -ge 445) {
                        $candidate = $true
                    }
                } elseif ($value -notmatch '^\d{1,5}$' -or [int]$value -gt 65535) {
                    $candidate = $true
                    $unknownPort = $true
                }
            }
        }
        if (-not $candidate) { continue }

        $address = Read-LabFilter $rule 'Get-NetFirewallAddressFilter'
        $interface = Read-LabFilter $rule 'Get-NetFirewallInterfaceFilter'
        $interfaceType = Read-LabFilter $rule 'Get-NetFirewallInterfaceTypeFilter'
        $application = Read-LabFilter $rule 'Get-NetFirewallApplicationFilter'
        $service = Read-LabFilter $rule 'Get-NetFirewallServiceFilter'
        $security = Read-LabFilter $rule 'Get-NetFirewallSecurityFilter'
        [pscustomobject]@{
            Name = $rule.Name
            Action = $rule.Action
            Profile = $rule.Profile
            Protocol = $protocol
            LocalPort = $port.LocalPort -join ','
            RemotePort = $port.RemotePort -join ','
            PortNeedsReview = $unknownPort
            LocalAddress = $address.LocalAddress -join ','
            RemoteAddress = $address.RemoteAddress -join ','
            InterfaceAlias = $interface.InterfaceAlias -join ','
            InterfaceType = $interfaceType.InterfaceType
            ProgramScope = if ($application.Program -in @('Any', 'System')) {
                $application.Program
            } else { 'SpecificProgram (path omitted)' }
            PackageRestricted = [bool]($application.Package -and $application.Package -ne 'Any')
            Service = $service.Service
            Authentication = $security.Authentication
            Encryption = $security.Encryption
            OverrideBlockRules = $security.OverrideBlockRules
        }
    })
    [pscustomobject]@{
        EnabledInboundRuleCount = $rules.Count
        CandidateCount = $rows.Count
    } | Format-List
    $rows | Sort-Object Action, Name | Format-List
}
```

## Historical success criteria and assessment

The block must return the final values **EnabledInboundRuleCount** and **CandidateCount** without errors. Return all candidates printed afterwards completely, not just the first lines. There is no predefined expected count. **CandidateCount 0** only means a successful empty candidate search; an error or aborted block is not a passed result. **PortNeedsReview True** requires further evaluation of the port expression and does not prove a match on 445. Any-protocol rules are shown as a precaution as well.

For program/package bindings, personal paths or package SIDs are hidden. If such a binding becomes relevant for the decision, a targeted local check follows; no SMB applicability is claimed from the shortened value. Address, profile, interface, service and security conditions were checked at the time against **Ethernet0 / Public**, Windows **192.168.243.128** and Mac **192.168.243.1**; the currently confirmed DHCP address .129 and the Allow correction, since read back successfully, are above. A new narrow allow does not restrict existing broader allows; a matching block rule is not neutralized by an additional normal allow.

These are **rule candidates from ActiveStore**, not a complete simulation of all effective WFP/IPsec/third-party filters and not yet a connection proof. The first [firewall creation attempt](windows-firewall-configure.md) of 2026-10-04 failed; after state queries, the targeted correction has since been run and the configuration readback accepted. The subsequent lab share / NTFS setup is also complete with ShareSetupReadback Passed. The later pilot collection block has since supplied partial findings on audit, account model, time/UTC, routes and technical activation. The network logon rights remain unknown after the GUI error and the parser stop; the export itself succeeded with exit code 0 and is not repeated. Its existing files are now read in a targeted way; the remaining experiment prerequisites follow separately; do not repeat queries already supplied. The user confirmed an own suitable Pro license; no keys are requested. No logon attempts in this step.

**Do not repeat completed setups, diagnoses/setters, MMC, export and the pilot collection block.** The Allow correction has been read back successfully. The user ran the rights export: **ExportExitCode 0**, file/size/UTF-16LE BOM checks passed. Then the parser stopped with **Expected exactly one Privilege Rights section**, before both target lines and **NetworkRightsExport Collected**. The actual section count was not printed; cause and both rights values remain unknown. Next step: run only [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). This new diagnostic block has **not yet been run**. It only reads the existing INF and its log: section headers, selected possible rights lines and the end of the log. No new export, no file write, policy repair or logon. Supply the complete diagnostic console output, not the complete INF. The own Pro license stays confirmed; Notification / status 5 is open separately. Native events, event export, adapter and Splunk remain pending.

## Sources and check limits

Official APIs read on **2026-10-03**: [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps) (ActiveStore, enabled inbound rules, one-to-one filter association), [port filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter?view=windowsserver2025-ps), [address filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter?view=windowsserver2025-ps), [interface filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallinterfacefilter?view=windowsserver2025-ps), [interface type filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallinterfacetypefilter?view=windowsserver2025-ps), [application filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallapplicationfilter?view=windowsserver2025-ps), [service filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallservicefilter?view=windowsserver2025-ps) and [security filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallsecurityfilter?view=windowsserver2025-ps). Protocol/port representation additionally: [MSFT_NetProtocolPortFilter](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netprotocolportfilter), [firewall protocol values](https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_ip_protocol).

Documentation and source review; the coding tool did not run the block on Windows. Its actual execution by the user is now established by 127/38 and the complete output. The later configuration was first checked against the documentation and independently in the source text; the user's creation attempt of 2026-10-04 revealed the overlooked IPv6 prefix restriction and a partial failure. That original attempt was not accepted; the corrected repair that followed is now accepted based on the user output with three rules per store and ConfigurationReadback Passed. This is a configuration readback, not a complete WFP/packet or logon proof. No application code/schema/fixture/export change or automatic test repetition. No AI author fields, commit trailers, Git identity changes or publication.
