# Private network: Allow address correction passed

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

Status: **2026-10-05**. The user continues with the existing **40 GiB test VM**. The separate address diagnosis and the subsequent [limited Allow address correction](windows-address-repair-step.md) ran successfully. **MacAllowAddressReadback Passed / RuleChanged True** confirms LocalAddress **Any** in both stores instead of the previous **192.168.243.128**; source **192.168.243.1**, **Ethernet0**, **TCP 445** and the other selected conditions are preserved. The measured guest address remains **192.168.243.129/24 / Preferred** with DHCP origins; the setter does not change DHCP. Do not repeat the diagnosis, the setter, or the host-only/account/firewall/share setup. The administrative secpol.msc view then failed with "Unknown error" and an empty MMC tree; both rights are missing, cause unknown. The subsequent secedit export succeeded with **exit code 0**, but the parser stopped at **Expected exactly one Privilege Rights section** before the target lines / Collected; the section count was not printed, and the rights remain unknown. **Next step: only [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md).** No new export, no write operation or logon. The history below is preserved; the acceptance covers the selected configuration and does not prove packet behavior or complete WFP coverage.

## Diagnosis and passed correction, 2026-10-05

The user ran [Read-LabAddressDrift.ps1](../../scripts/windows/Read-LabAddressDrift.ps1) successfully: **AddressDriftCollection Complete / NetworkOrFirewallChanged False**. **Ethernet0** is **Up**, index **8**, IPv4 **Connected**, **DHCP enabled**. Get-NetIPAddress shows **192.168.243.129/24**, **AddressState Preferred**, **PrefixOrigin Dhcp / SuffixOrigin Dhcp**. The current address is therefore directly established; the earlier .128 remains a historical measurement. DHCP is observed; the specific trigger or time of the change is not established.

Before the correction, **PersistentStore** and **ActiveStore** each contained exactly one own Mac Allow rule with exactly one address filter: **LocalAddress 192.168.243.128 / RemoteAddress 192.168.243.1**. Both rules show **Enabled True / Inbound / Allow / Profile Any / PrimaryStatus OK**; PersistentStore **NotApplicable**, ActiveStore **ProfileInactive,Enforced**. The local address condition at that time therefore did not match the assigned .129. This does not prove that SMB as a whole is blocked: other existing rules and the actual packet processing are not tested by this targeted query. Nor does it turn the earlier complete firewall acceptance into a current Passed for the new address.

The completed diagnosis changed nothing and is not repeated. The subsequently run [Update-LabMacAllowAddress.ps1](../../scripts/windows/Update-LabMacAllowAddress.ps1) set the own Allow LocalAddress to **Any**: both before lines local .128, both after lines local Any; **MacAllowAddressReadback Passed / RuleChanged True**. RemoteAddress .1, Ethernet0, TCP 445, RemotePort Any, Enabled True/Inbound/Allow/Profile Any/PrimaryStatus OK as well as EdgeTraversalPolicy Block, Authentication/Encryption NotRequired and OverrideBlockRules False are identical before and after the setter. PersistentStore reports NotApplicable, ActiveStore ProfileInactive,Enforced. The run again reads Preferred .129/24 with both DHCP origins; only the own LocalAddress was set. This selected acceptance does not replace a packet/SMB/authentication proof; do not repeat the successful setter either.

## Earlier note, 2026-10-04

From the read-only pilot check block the user supplied **15 active routes**: loopback, the host-only network **192.168.243.0/24** with broadcast and multicast routes, and IPv6 loopback, link-local and multicast. There is no IPv4/IPv6 default route and no foreign gateway route in this list. This is a route view, not a complete isolation test or packet proof.

On **Ethernet0 / InterfaceIndex 8** there is a host route **192.168.243.129/32**, NextHop **0.0.0.0**. The previously reported .128 remains a historical measurement. At first the route was only a hint at a different local address; Get-NetIPAddress and DHCP were not yet confirmed at that time. The previously successful firewall acceptance applied to the state at that time with the Mac Allow on local .128. The separate diagnosis of 2026-10-05 then confirmed the deviation without correcting anything; its results are above.

Further results of the same block: ForceGuest present / DWORD 0, SCENoApplyLegacyAuditPolicy not present (not 0), BadLoginCount Unavailable, IsAccountLocked actually Boolean false. Local **2026-10-04 20:33:13.4066612 +02:00** and UTC **18:33:13.4066612 +00:00** belong to the same instant; W. Europe Standard Time has a base offset of +01:00, and the current +02:00 offset is consistent with daylight saving time. A simultaneous comparison with the Mac clock is missing. Professional/RETAIL reports **LicenseStatus 5 / Notification, GracePeriodRemaining 0**; the own suitable Pro license remains a separate user confirmation.

Auditpol reported that no audit policy is defined for the user account, with **exit 2**. The guard aborted; **PilotStateCollection Complete was not printed**. This per-user policy message does not negate the system audit for success/failure read earlier. The failure counter remains unknown and no logon follows.

## Next step: only read the existing export files

The user ran the rights export: **ExportExitCode 0**, file/size/UTF-16LE BOM checks passed. Then the parser stopped with **Expected exactly one Privilege Rights section**, before both target lines and **NetworkRightsExport Collected**. The actual section count was not printed; cause and both rights values remain unknown. Next step: run only [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). This new diagnostic block has **not yet been run**. It only reads the existing INF and its log: section headers, selected possible rights lines and the end of the log. No new export, no file write, policy repair or logon.

Supply the complete diagnostic console output with completion or error; do not copy the complete INF. Neither missing nor duplicate sections or rights values are invented from the guard error. Do not repeat the GUI attempt, export, setup, completed diagnoses/setters or the pilot collection block. Afterwards the failure counter / attempt budget and the remaining prerequisites are clarified; the technical Notification status stays open separately. The Mac route to the established guest address and a simultaneous time comparison still need to be assessed.

## Result, 2026-10-03

- Supplied by the user: **Ethernet0**, ifIndex **8**, status **Up**; IPv4 **192.168.243.128/24**, **Preferred**. Loopback 127.0.0.1 is not a target. The IPv4/IPv6 default route query returned no output twice.
- Confirmed read-only on the Mac: **bridge100 active, 192.168.243.1/24**; route to **192.168.243.128** via **bridge100**. The sandbox initially blocked the route query; the same read-only query succeeded after approval, without sending packets or changing anything.
- Current selected VMX values: one existing adapter **ethernet0.connectionType = hostonly**, **isolation.tools.hgfs.disable = TRUE**. A saved shared-folder definition remains; global deactivation is set, actual access was not tested. No personal host paths are stored.
- User confirms **Internet Sharing on the Mac is off** and **no other VMs are running**. The current test VM stays powered on for the next guest steps.
- Still open at the time: remaining guest routes, guest time / time zone / UTC, clipboard and drag-and-drop, license/activation as well as account/share/firewall and genuine type-3 events. Account/firewall/share setup and the partial pilot measurement have since taken place; the current state and remaining points are above. The IPv4/IPv6 forwarding values 0/0 come from the check on 2026-10-02; no repeated query or change on 2026-10-03.

## Already observed read-only from the Mac

| Check | Result | Limit |
| --- | --- | --- |
| Mac IPv4/IPv6 forwarding | `net.inet.ip.forwarding: 0`, `net.inet6.ip6.forwarding: 0` | Momentary kernel state, not a general check of all host services or proxies. The sandbox blocked it at first; the same read-only query succeeded after approval. Nothing set. |
| Fusion network configuration VNET 1 | DHCP enabled, subnet **192.168.243.0**, mask **255.255.255.0**, virtual adapter enabled | Configuration read; no Windows address invented from it. |
| Actual Mac interface | **bridge100**, active, IPv4 **192.168.243.1/24** | Matching currently present private host address. To be confirmed later by the route to the real Windows target and its native `IpAddress`. |
| Other Mac bridge | bridge101, active, 192.168.57.1/24; Fusion VNET 8 has NAT enabled | The existing NAT network is not the chosen lab network. Its presence alone does not connect the VM, which is later configured as host-only only. |
| Interface naming | `ifconfig vmnet1`: not present; `ifconfig -a`: the bridges above are present | Do not adopt old vendor names blindly as current macOS interface names. |

These values were read from the Mac, **not a guest network or logon proof**. IP forwarding was not changed; no ports were opened, no networks set up, no programs installed and no foreign systems contacted. The Mac may keep its own Internet connection; the VM gets no NAT/bridged adapter and no forwarded Internet path for the experiment.

## Historical manual setup in Fusion — do not repeat now

1. If Windows is still running: shut it down normally via Start → Power → Shut down; Fusion must show the VM as powered off. Suspension is not enough.
2. Keep other VMs on this private network powered off. On the Mac, under System Settings → General → Sharing, only check **Internet Sharing**: no sharing or forwarding into this VM network may run during setup. If it is active or unknown additional forwarding or VPN routes exist, clarify that actual state first; do not change any host policy automatically.
3. Settings of the existing test VM → Network Adapter: set exactly **one** adapter to **Host-only / "Private to my Mac"**. This is the private connection between Mac and VM. "Share with my Mac" is NAT, "Bridged" connects to the physical network. Additional adapters are not part of this setup. Connect the selected host-only adapter now and allow it to connect at startup.
4. In the VM settings under Sharing / Shared Folders, **turn off Shared Folders and any enabled mirroring of Mac folders**. This concerns VMware HGFS; the later own SMB test share is set up separately. Clipboard and drag-and-drop are limited before the pilot; this step does not yet produce logon attempts. The exact labels of the installed Fusion 26 interface were not seen here.
5. Start Windows and log on at the console. If Windows asks about network discoverability, choose **No**; do not turn on automatic broad network sharing. The Windows Firewall stays active.
6. Open Windows PowerShell, run the following three local read-only queries and return their output. The earlier Windows/audit/disk commands are already recorded and do not need to be repeated.

```powershell
Get-NetAdapter | Format-Table Name,ifIndex,Status
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState
Get-NetRoute -PolicyStore ActiveStore | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | Format-Table AddressFamily,InterfaceAlias,DestinationPrefix,NextHop
```

The route query covers IPv4 and IPv6. Empty output is the expected case here when there is no active default route; it is not an error. These commands read the local state and make no Internet or SMB test connection. DHCP may take a moment; a `169.254.*` address, status `Tentative` or an unexpected network is clarified first, not reported as a successful configuration. Do not enter a fixed example address.

## Historical success criteria of the network setup

- Fusion shows exactly one connected host-only adapter and disabled HGFS/mirroring shares; no other VM runs on the same private network, and no forwarding into it is set up.
- Windows shows an active adapter with an actually assigned, usable IPv4 address in the observed private network **192.168.243.0/24**. Its last octet is not guessed or prescribed; loopback is not the target.
- Windows shows no active default route (`0.0.0.0/0` or `::/0`). This is a required configuration check, not sole proof of absolute isolation; specific routes, host services and other VMs still have to be considered.
- Mac and Windows target addresses are known. We then read the Mac route to the actual Windows target; before the pilot we also check the remaining active guest routes and guest time / time zone / UTC. Only then do the account, a tightly limited SMB share/firewall and controlled events follow.

After the queries Windows can keep running for the next configuration. If the Fusion selection, addresses or routes differ in a later repetition, supply the exact display or output; no failed SMB attempt "to try things out". **The switch, Windows IP and missing default routes reported above were observed on 2026-10-03.** Account, share and firewall setup has since been completed and remains historical configuration evidence. The address diagnosis and the subsequent limited Allow LocalAddress correction to Any were completed on 2026-10-05; both stores were read back successfully. The GUI query failed afterwards; the subsequent export succeeded with exit code 0, but the rights evaluation stopped. Next, only the existing INF and log files are diagnosed; the own license is confirmed, and the technical Notification status and further pilot questions remain open separately. The pilot export, the exact adapter and Splunk are still pending. The private host-only access does not by itself provide Internet access for activation.

Official basis: [Broadcom: network types](https://knowledge.broadcom.com/external/article/303393) describes host-only and its shared VM/host view; the examples concern older Fusion versions. The read-only guest commands are documented by Microsoft: [Get-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter), [Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress), [Get-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute). Local observations and a prepared guide do not replace an executed guest network check. No code change or repeated tests for this documentation continuation.
