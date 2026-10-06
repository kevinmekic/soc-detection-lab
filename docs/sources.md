# Sources and review scope

Sources checked on **2026-10-01**, with AuditPol and Secure Boot clarification on **2026-10-02** below. These sources establish event meanings and
language behavior. The rule, threshold, correlation key and synthetic scenarios
are this project's design decisions, not vendor detection recommendations.
No third-party rule or dataset was copied. No ATT&CK technique is asserted from
this pattern alone.

## Windows Security events

| Official source | Relevant section | Application here |
| --- | --- | --- |
| [Microsoft: event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) | Event Description; Event XML; Logon types and descriptions; New Logon; Network Information | Successful destination logon session; `TargetUserName`, `TargetDomainName`, `IpAddress`, `LogonType`; type 3 is Network, type 10 RemoteInteractive. Source address availability depends on authentication context. |
| [Microsoft: event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) | Event Description; Event XML; Account For Which Logon Failed; Failure Information | Failed logon on the computer where the attempt is recorded; target account fields, `Status` and `SubStatus`. System fields supply provider, channel, computer, timestamp and record identity. |
| [Microsoft: Audit Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon) | Description; events list; success/failure table | Audit settings and collection must be checked on the accessed test system. Resource access produces the network logon perspective on the resource host. Actual lab policy and generated records are still unverified. |

Account domain may identify a domain or the computer owning a local account.
The lab preserves this context separately from the user. The XML examples above
use `Microsoft-Windows-Security-Auditing` and `Security`; these are Windows
Security records, not Sysmon events or Entra sign-in logs. Their presence in the
lab schema does not turn synthetic JSONL into a Windows export.

## Splunk Enterprise 10.0: SPL, not SPL2

| Official source | Relevant section | Review decision |
| --- | --- | --- |
| [eventstats](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/search-commands/eventstats) | Syntax; BY; memory limits; supported functions | Aggregate failure tokens per complete key; detect missing/truncated aggregates and inspect job warnings. |
| [Multivalue statistical functions](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/statistical-and-charting-functions/multivalue-stats-and-chart-functions) | `values`; `list`; limits | Use distinct time/UID tokens with `values`; `list` truncates after 100 values. Configured `maxvalues` can constrain `values`. |
| [Multivalue eval functions](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/evaluation-functions/multivalue-eval-functions) | `mvmap`; `mvfilter`; `mvcount`; `mvindex` | `mvmap` can combine each token with a scalar success time. Remove nulls separately with `mvfilter`, whose predicate references one field. Count and retain full evidence. |
| [Conversion functions](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/evaluation-functions/conversion-functions) | `printf`; `tonumber` | Fixed-width timestamp tokens, numeric comparisons and the supported integer range. |
| [Text functions](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/evaluation-functions/text-functions) | `substr` | One-based substring indexes decode the fixed-width timestamp and UID. |
| [sort](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/search-commands/sort) | Syntax; count; numeric/string ordering | `sort 0` retains every result and orders explicitly ascending by time and UID. |
| [spath](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/search-commands/spath) | Explicit path; automatic extraction cutoff | Explicit JSON paths avoid reliance on automatic first-5,000-character extraction. |
| [streamstats](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/search-commands/streamstats) | `time_window`; `max_stream_window` | Not used: the event-count window can override a time window, so naive use risks incomplete evidence. |

Documentation checks alone do not establish SPL execution or import
correctness. The query was later executed on Splunk Enterprise 10.2.6 and is
`lab-validated` for two datasets ([validation record](splunk-validation.md#validation-record-2026-10-06)).
No Splunk Enterprise Security integration is tested.

## Milestone 2 preparation: reviewed 2026-10-01

| Official source | Relevant section / scope | Use here |
| --- | --- | --- |
| [VMware: 26H1 announcement](https://blogs.vmware.com/cloud-foundation/2026/05/14/announcing-vmware-workstation-and-fusion-26h1/) | Pricing and release/download links | Fusion 26H1 free for personal, educational and commercial use; no purchase |
| [Desktop Hypervisor FAQ](https://www.vmware.com/docs/desktop-hypervisor-faqs) | PDF pages 3–5: licenses, platforms, access | No key/subscription for the free hypervisor; Windows rights separate; support limits |
| [Broadcom KB 368734](https://knowledge.broadcom.com/external/article/368734/download-desktop-hypervisor-workstation.html) | Account and export compliance | Future download prerequisites; no account or download created |
| [Broadcom host matrix, KB 315635](https://knowledge.broadcom.com/external/article/315635/supported-host-operating-systems-for-vmw.html) | Accessible Fusion 13.6 / Intel macOS 15 matrix | Legacy evidence only; **not** Fusion-26 certification. Linked current release requirements returned HTTP 403 |
| Installed Fusion `Contents/Info.plist` | Version 26.0.0, build 25388279, minimum OS 13.00.0 | Local vendor-bundle evidence, separate from formal support certification |
| [Broadcom KB 303393](https://knowledge.broadcom.com/external/article/303393) | Host-only, NAT, bridged definitions | Mac/VM private network; legacy UI examples do not certify current UI layout |
| [Broadcom KB 341387](https://knowledge.broadcom.com/external/article/341387), [KB 344574](https://knowledge.broadcom.com/external/article/344574/copying-a-virtual-machine-in-vmware-fusi.html) | HGFS host paths / VM copy | Host shared folders differ from SMB; disable during exercise; don't blindly duplicate |
| [Broadcom KB 344854](https://knowledge.broadcom.com/external/article/344854) | Backup before expansion, guest partition stays separate | Plan current 40 GiB storage correction; no expansion performed |
| [Microsoft: Windows 11 requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements) | Virtual machine support, updated 2026-07-14 | Two vCPUs, 4 GB RAM, 64 GB disk, Secure-Boot capability and vTPM; use equivalent Fusion settings |
| [Microsoft Intel CPU list](https://learn.microsoft.com/en-us/windows-hardware/design/minimum/supported/windows-11-supported-intel-processors), [Intel i5-8257U](https://www.intel.com/content/www/us/en/products/sku/191067/intel-core-i58257u-processor-6m-cache-up-to-3-90-ghz/downloads.html) | 8th-generation i5 family / exact processor generation | Observed CPU belongs to the listed family; other prerequisites still need checks |
| [Microsoft Store Germany: Windows 11 Pro](https://www.microsoft.com/de-de/d/windows-11-pro/dg7gmgf0d8h4) | Product price | 259,00 € at review; existing license first; no purchase or price guarantee |
| [Microsoft: Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise) | 90 days, registration/activation, expiration and audience | Conditional evaluation alternative, no permanent free license |
| [Microsoft: desktop VM licensing](https://download.microsoft.com/download/9/8/D/98D6A56C-4D79-40F4-8462-DA3ECBA2DC2C/Licensing_Windows_Desktop_OS_for_Virtual_Machines.pdf) | Local virtual-use rights and acquisition distinctions | Actual rights depend on the license/channel; activation alone isn't assumed to settle them |
| [Microsoft: auditpol get](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get) | `/get`, wildcard subcategories, `/r`, read permissions | Read effective policy; observe localized subcategories |
| [Microsoft: Net commands](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems) | Net Accounts display | Read local threshold/duration/window; examples aren't this VM's values |
| [Microsoft: lockout threshold](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold) | Threshold, duration/reset relation, protocol/application retries | Pilot and actual event budget first; no policy weakening or assumed command/event ratio |
| [Microsoft: New-SmbShare](https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare?view=windowsserver2025-ps) | Share and ReadAccess semantics | Planned small read-only share; no Windows command executed |
| [Microsoft: Get-WinEvent, PowerShell 5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1) | FilterHashtable, MaxEvents, Security-log access | Bounded export selection; Windows runtime untested |
| [Microsoft: ToXml](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogrecord.toxml), [Event schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema) | Native representation, System and named EventData | Preserve native XML; project wrapper explicitly described |

The existing 4624/4625 sources also supply representative XML examples. Their original times contain nonzero 100 ns fractions and their examples use type 2 / localhost. They establish structure and the precision issue, not our planned network capture. The new minimal structural fixture is independently constructed, explicitly synthetic, and documented in its own README; no full vendor example or third-party dataset was copied.

Mac client options were verified with the installed Apple tool's read-only `/usr/bin/smbutil help view`: `-A` authorizes only, `-f` avoids session sharing. This verifies the local interface, not endpoint acceptance or event generation. Hardware/resource facts come from the local commands in [host-inventory.md](host-inventory.md). Exact current Fusion-26 formal host requirements remain an access gap; older numerical requirements are not substituted.

## Guest preflight interpretation: reviewed 2026-10-02

| Official source | Relevant section | Use here |
| --- | --- | --- |
| [Microsoft: auditpol get](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get) | Syntax, GUID/name selection, `/category:*`, `/r`, help | Original wildcard-subcategory syntax is documented; no unverified cause of the guest error is asserted. Targeted read query and local-help fallback remain unexecuted here. |
| [Microsoft: Auditing Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants) | `Audit_Logon_Logon` | Official subcategory GUID `0CCE9215-69AE-11D9-BED3-505054503030`, independent of localized names. |
| [Microsoft: System Error Codes 0–499](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-) | `ERROR_INVALID_PARAMETER`, 87 / `0x57` | Parameter error, not proof of an access-denied error or disabled audit policy. |
| [Microsoft: Confirm-SecureBootUEFI](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi?view=windowsserver2025-ps) | Return values and unsupported-platform distinction | `False` means Secure Boot supported but disabled; does not establish a failure to support UEFI. |
| [Broadcom KB 344854](https://knowledge.broadcom.com/external/article/344854) | Backup recommendation, powered-off VM, no snapshots, separate guest partition | Expansion plan after user waived backup for disposable VM; no resize performed. Linked Fusion-25H2 resize instructions returned HTTP 403. |
| [Broadcom KB 311483](https://knowledge.broadcom.com/external/article/311483/making-a-fusion-virtual-disk-preallocate.html) | Sparse versus preallocated storage, legacy Fusion UI | Preserve observed `twoGbMaxExtentSparse`; capacity increase differs from reserving the full physical size. Legacy UI examples do not certify the current 26.0.0 layout. |
| [Broadcom KB 303393](https://knowledge.broadcom.com/external/article/303393) | Host-only shared private network; NAT/bridged distinctions | Rechecked for chosen 40-GiB pilot; legacy `vmnet1` naming differs from observed current Mac bridge100. |
| [Microsoft: Get-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter), [Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress), [Get-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute) | Local visible adapters, address/prefix/state, active routing store | Prepared read-only guest network check; no guest runtime results supplied yet. |

Guest version/resources, lockout, successful system Audit Logon query and disconnected NIC come from the user's supplied outputs/statements, not these documentation examples. The [preflight record](history/windows-preflight-2026-10-02.md) keeps that provenance explicit; it contains no native authentication capture or personal screenshot. The user's latest instruction supersedes the earlier backup gate; no extra permission is inferred from the vendor recommendation.

## Standard test account: reviewed 2026-10-03

| Official source | Relevant section | Use here |
| --- | --- | --- |
| [Microsoft New-LocalUser, PowerShell 5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1) | SecureString password, LocalUser object, Local PrincipalSource, 64-bit module requirement | Prepared fresh local test account; hidden password, no password-expiry disabling or date-based account expiration. Not executed here. |
| [Microsoft Add-LocalGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember?view=powershell-5.1) | SID and LocalPrincipal parameters | Add only the new account to builtin Users when necessary; no administrator membership added. |
| [Microsoft Security Identifiers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) | Well-known SID stability and builtin groups | Users/Benutzer `S-1-5-32-545`; Administrators/Administratoren `S-1-5-32-544`, avoiding translated names. |

The new [account guide](history/windows-account-step.md) distinguishes prepared commands and expected results from actual user-executed results. Current IPs, private connection and route come from user-provided guest output and local read-only observations; no documentation sample is presented as a real authentication record.

## Read-only SMB readiness — 2026-10-03

Official APIs reviewed for the next manual Windows step:

| Source | Relevant section / use | Checked |
| --- | --- | --- |
| [Get-SmbShare](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbshare?view=windowsserver2025-ps) | Description/syntax; local existing-share inventory, followed by exact SOC-LAB filtering and explicit count | 2026-10-03 |
| [Get-SmbServerConfiguration](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbserverconfiguration?view=windowsserver2025-ps) | Example 1 properties: SMB1/SMB2, RequireSecuritySignature, EncryptData | 2026-10-03 |
| [Get-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile?view=windowsserver2025-ps) | InterfaceIndex parameter; read existing profile, no Set call | 2026-10-03 |
| [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps) | PolicyStore ActiveStore; combined active policy, profile overview does not replace individual rule review | 2026-10-03 |
| [New-SmbShare](https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare?view=windowsserver2025-ps) | ReadAccess and description; future creation only. WhatIf does not work per documented note | 2026-10-03 |

These are API references, not an assertion of a Windows Server guest or empirical Windows execution. The installed Windows 11 Pro module/service availability and values remain to be read. No third-party script or data copied.

## Active inbound firewall candidates — 2026-10-03

Official Microsoft references reviewed for the next manual read-only step:

- [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps): ActiveStore, Enabled/Direction and one-to-one associated filters.
- [Get-NetFirewallPortFilter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter?view=windowsserver2025-ps), [MSFT_NetProtocolPortFilter](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netprotocolportfilter) and [NET_FW_IP_PROTOCOL](https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_ip_protocol): port arrays/ranges/keywords, TCP 6 and Any 256.
- [Address filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter?view=windowsserver2025-ps), [interface filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallinterfacefilter?view=windowsserver2025-ps) and [interface-type filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallinterfacetypefilter?view=windowsserver2025-ps): associated scope conditions.
- [Application filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallapplicationfilter?view=windowsserver2025-ps), [service filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallservicefilter?view=windowsserver2025-ps) and [security filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallsecurityfilter?view=windowsserver2025-ps): program/package, service and Authentication/Encryption/OverrideBlockRules conditions. Application paths/package SIDs are omitted from user output.

Checked **2026-10-03**. These API references do not prove Windows execution or full resultant packet access. The manual block remains source-reviewed, not executed on Windows here. No source script copied or third-party data imported.

## Scoped TCP445 rule configuration — 2026-10-03

Checked official references:

- [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps): PersistentStore creation, IPv4 range/IPv6 prefix syntax, InterfaceAlias, Protocol/LocalPort/RemotePort, Profile and authentication conditions.
- [Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules) and [MS-FASP rule arbitration](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/702e3c23-c9d8-43db-8380-b4c670dd7f7d): explicit Block versus ordinary Allow; authenticated Bypass is distinct.
- [FW_IPV4_ADDRESS_RANGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/f11b8499-00a0-43d8-bf3a-6b596ec0d55c): inclusive DWORD begin/end and begin <= end. Guest range acceptance still requires execution/readback.
- [MSFT_NetFirewallRule](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule): ActiveStore EnforcementStatus including Full 1/inactive/unresolved states.
- [Dual-stack sockets](https://learn.microsoft.com/en-us/windows/win32/winsock/dual-stack-sockets): IPv4-mapped address representation versus underlying IPv4 traffic; no invented IPv6 allowance.
- [Remove-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/remove-netfirewallrule?view=windowsserver2025-ps): future exact-name removal of the three new PersistentStore lab objects.
- [Current MS-FASP FW_RULE schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/8c008258-166d-46d4-9090-f2ffaa01be4b): package ID/family/trust conditions; the earlier Boolean .Package projection cannot establish unrestricted application traffic.

Checked **2026-10-03**. Documentation-based design and independent source review, no Windows mutation/execution or effective-access certification. No third-party scripts or genuine event fields were invented or copied.

## Failed IPv6 prefix and read-only recovery — 2026-10-04

- [FW_IPV6_SUBNET](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/ccb501eb-6620-4b49-befd-2b59828a28c8): semantic constraint **1–128** prefix bits (despite the displayed IDL range annotation 0–128); earlier generic prefix review did not catch this. Supports ::/0 as the cause of the actual invalid-prefix failure, not a successful replacement rule.
- [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps): read PersistentStore/ActiveStore, filter exact known names after successful inventory, read associated filters.
- [Common parameters / ErrorAction](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7.5#erroraction): explicit per-call Stop escalates nonterminating errors. The 5.1 documentation URL was unavailable during retrieval; the general current description is not a Windows PowerShell version change or runtime proof. The exact cause of the earlier scoped preference continuing is not established.

Actual failure and missing IPv6 rule come from the user's 2026-10-04 transcript. Partial IPv4 state, an accepted replacement IPv6 condition, effective connection and native authentication events remain unverified. No third-party script was copied and no genuine lab export invented.

## Targeted firewall repair after real readback — 2026-10-04

- [FW_IPV4_SUBNET](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/ed0a65ec-d3b6-461c-a4ca-ecf08ed18025): zero subnet mask invalid; a returned single 0.0.0.0 is not established all-local-address coverage. [Set-NetFirewallRule / LocalAddress](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule?view=windowsserver2025-ps#-localaddress) documents Any and targeted named-rule property changes.
- [FW_IPV6_ADDRESS_RANGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/fbf349cc-8455-490d-b97d-951c63084861) and [New-NetFirewallRule / RemoteAddress](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps#-remoteaddress): IPv6 ranges, ordered endpoints, unspecified/loopback endpoints forbidden; selected ::2–max range still requires guest acceptance.
- [RFC4291 §§2.5.2–2.5.3](https://www.rfc-editor.org/rfc/rfc4291.html#section-2.5.2): unspecified/loopback semantics; range coverage is not described as every mathematical IPv6 address.
- [FW_ENFORCEMENT_STATE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/4767a26e-0687-4c4f-ad94-8de700e5cf83): 1 enforced, 5 at least one intended profile inactive. Actual text ProfileInactive,Enforced is compatible with Any-profile rules; numeric values will be read, not invented. Metadata is not packet reachability.
- [Application](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallapplicationfilter?view=windowsserver2025-ps), [service](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallservicefilter?view=windowsserver2025-ps), [interface-type](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallinterfacetypefilter?view=windowsserver2025-ps) filter APIs: associated one-to-one reads and extra intended Any guards, no modification of those existing conditions.

Actual two-rule readback is user-supplied evidence. Replacement creation and full configuration acceptance remain pending. No third-party script copied, no native lab export invented, no Windows syntax/runtime validation by the agent.

### Correction after actual PowerShell status-cast failure — 2026-10-04

The subsequent real transcript reports NotApplicable as nonconvertible text. The numeric [FW_ENFORCEMENT_STATE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/4767a26e-0687-4c4f-ad94-8de700e5cf83) definition is not proof of a directly castable cmdlet property. The earlier static inference was wrong. The repair now checks preserved, actually observed status names (Enforced with optional ProfileInactive); no numeric values or replacement lab evidence are fabricated. The failure preceded both writes. Corrected Windows execution remains pending.

### Correction of the unsubstantiated Package Any guard — 2026-10-04

[MSFT_NetApplicationFilter](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netapplicationfilter) documents Package as an application-SID string and AppPath as the executable path; it does not require a return value Any. [FW_RULE / wszPackageId](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/8c008258-166d-46d4-9090-f2ffaa01be4b) documents real null as absence of that condition; its newer package-family/FQBN fields are not invented as properties of the older CIM class. Real blank projected output cannot distinguish absent/null/empty because the script cast it to string. Current readback enumerates actual properties and preserves their distinctions. The latest user run stopped before both writes, and the repair is withdrawn pending typed evidence.

### Typed evidence received and repair revised — 2026-10-04

The subsequent actual user diagnosis resolves that distinction: AppPath and Package on MSFT_NetApplicationFilter, plus PackageFamilyName and PolicyAppId on the actual rule, are present String CIM properties with genuine null in all four store/rule combinations. These property observations come from the user's typed readback, not an assumed modern extension of the older filter class. No rule change or native logon evidence follows from this diagnostic.

Rechecked official [filter class](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netapplicationfilter) and [FW_RULE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/8c008258-166d-46d4-9090-f2ffaa01be4b) on **2026-10-04**: actual AppPath/Package names and String types; null application/package conditions. The revised helper reads raw CIM presence/type/value instead of the collapsed string projection. PolicyAppId and PackageFamilyName remain separately guarded actual rule properties; no guessed synonym is used.

Rechecked [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps): optional application/service/interface-type parameters, LocalAddress Any and documented IPv6 RemoteAddress range syntax. [Set-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule?view=windowsserver2025-ps): exact Name/PolicyStore selection and modification of specified remaining properties. The revised creation omits those optional parameters and verifies actual stored defaults afterward. The revised repair is prepared rather than withdrawn; its Windows execution, range acceptance and configuration success remain pending. No source script copied or fabricated execution result.


### Subsequent actual firewall success — 2026-10-04

The next user transcript establishes successful corrected guest execution: three rules per store, accepted IPv6 range, IPv4 local Any, preserved Mac Allow, checked default/binding conditions and ConfigurationReadback Passed. This replaces the preceding pending-execution state. Its scope is selected configuration readback; no packet/authentication/event coverage is inferred. The raw transcript is not copied into project fixtures.

## New empty NTFS/SMB probe preparation — 2026-10-04

Official sources checked on **2026-10-04** for the next manually executed guest step:

- [New-SmbShare](https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare?view=windowsserver2025-ps): expose a folder under an explicit share name; ReadAccess accepts account-name lists. Creation is a real change; WhatIf is documented as not functional and is not used as a purported dry run.
- [Get-SmbShareAccess](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbshareaccess?view=windowsserver2025-ps): read actual share permission entries, separately from NTFS.
- [.NET Framework FileSystemAccessRule constructors](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemaccessrule.-ctor?view=netframework-4.8.1): IdentityReference/SecurityIdentifier, rights and inheritance/propagation flags. Actual constructed expected ACE rights account for Allow/Synchronize behavior; no guessed short rights display is required.
- [ObjectSecurity.SetAccessRuleProtection](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection?view=netframework-4.8.1): protect the new folder DACL from inherited access; no parent/existing folder ACL is changed.
- [Set-Acl](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-7.5): apply a supplied security descriptor to an explicit LiteralPath. Retrieval of the PowerShell 5.1 view returned an internal error; the current description is a general API reference, not an installation/version change or guest runtime proof.

This is source/API preparation for a new empty folder with read-only lab-auth01 NTFS and SMB access. Existing folders/shares are not taken over, no sample files or passwords are written, and the new script has not been run on Windows. No third-party script copied; no genuine logon export or test result invented.

### Subsequent actual probe/share success and license reply — 2026-10-04

The next full user transcript establishes successful guest execution and ShareSetupReadback Passed: correct empty path/share, protected three-entry NTFS DACL, Administrators owner and one matching local-account SMB Allow/Read entry. This replaces the preceding pending-execution state. Truncated display columns do not replace or invalidate the helper's original-value checks. No parent preexistence, packet result or native logon event is inferred; the raw attachment/dynamic SID stay outside project evidence. The user separately confirms an owned suitable Windows-11-Pro license, with technical activation still unread.

## Read-only remaining pilot prerequisites — 2026-10-04

Official documentation checked on **2026-10-04**, supporting the prepared read block and guide:

- [IADsUser property methods](https://learn.microsoft.com/en-us/windows/win32/adsi/iadsuser-property-methods) and [provider support](https://learn.microsoft.com/en-us/windows/win32/adsi/provider-support-of-adsi-interfaces): BadLoginCount and IsAccountLocked are documented native getters supported by WinNT. [DirectoryEntry.InvokeGet](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry.invokeget?view=windowsdesktop-10.0) invokes a native property getter. The Framework 4.8.1 view retrieval failed; the general managed API page and provider contract are source support, not proof of PowerShell 5.1 execution. No same-named ADSI cache/Win32 attribute is fabricated.
- [USER_INFO_3 / usri3_bad_pw_count](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_3) documents the unknown DWORD sentinel -1. Raw negative/max values are conservatively not treated as 0 or free budget; no particular WinNT returned value or cross-provider mapping is asserted before capture.
- [auditpol /get](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get): per-user account/SID argument, SID braces, subcategory GUID and report mode. Returned inclusion/exclusion and actual exit status are retained; no policy setter is used.
- [SoftwareLicensingProduct](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct): Name/Description/LicenseFamily/LicenseStatus/GracePeriodRemaining; LicenseStatus 1 Licensed, grace in minutes. PartialProductKey is used solely as a non-null query filter, never selected/output. Technical status does not substantiate license provenance or require a network/policy change.
- [Local account security model](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-sharing-and-security-model-for-local-accounts), explicitly applicable to Windows 11: Classic preserves local-account identity, Guest only maps it to Guest. [Azure baseline registry correspondence](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows) lists ForceGuest and SCENoApplyLegacyAuditPolicy under SYSTEM\CurrentControlSet\Control\Lsa; that server baseline is a correspondence reference, not this Windows 11 guest's observed policy/default. Unknown raw values require the actual policy view.
- [MS-GPSB Event Audit Policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/506f97dd-00f9-49dc-b3ba-bb041328cafb) documents DWORD SCENoApplyLegacyAuditPolicy 1 suppressing legacy category processing. [Windows 11 audit setting](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/audit-force-audit-policy-subcategory-settings-to-override) supplies the policy context. Registry presence/absence is preserved, not a reason for an automatic setter.
- [Allow network logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network) and [deny network logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-access-to-this-computer-from-the-network): assignment through direct/group membership, SMB relevance and Deny precedence. Both actual account/group lists must be read; documented defaults are not substituted. secpol.msc is used only to inspect/cancel, avoiding a secedit export and its file writes.

This is source preparation, not a real guest read, Windows syntax/runtime test or native lab record. Two independent saved-source reviews found no necessary correction. No third-party script copied; no genuine evidence or AI authorship invented.

## Actual pilot partial read and corrected interpretations — 2026-10-04

The next real user transcript provides partial prerequisite observations and the audit-exit2 stop, not Complete. The old BadLoginCount source-level assumption was insufficient: the actual InvokeGet path reports a cache exception, whereas IsAccountLocked genuinely returns Boolean false. Counter stays unknown and that unsuccessful getter is not repeated. ForceGuestDWord 0 and absent SCENoApplyLegacyAuditPolicy are distinct actual registry results, not substituted defaults. The Windows Professional/RETAIL row now reports LicenseStatus 5/Grace 0, interpreted technically as Notification by [SoftwareLicensingProduct](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct); user-owned licensing remains separate.

Official documents rechecked on **2026-10-04**:

- [AuditQueryPerUserPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditqueryperuserpolicy) explicitly describes ERROR_FILE_NOT_FOUND 2 as absence of per-user policy. Together with the observed German auditpol message, it supports the concrete result; it is not an indiscriminate acceptance of every nonzero CLI code or proof of system audit disabled. The previous exit 0-only guard was too strict for this case. Original collector is retained as history, not rerun.
- [Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=windowsserver2025-ps), [Get-NetIPInterface](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipinterface?view=windowsserver2025-ps), [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps), [Get-NetFirewallAddressFilter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter?view=windowsserver2025-ps): selected actual adapter/address/DHCP and named-rule/associated-filter reads. The new .129/32 route is evidence motivating these reads, not assumed Preferred-state IP or an invented DHCP cause. Earlier .128 rule acceptance is historical.
- [Reset account lockout counter after](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/reset-account-lockout-counter-after): quiet interval after failure determines counter reset. More than the actually observed 10 minutes with no account attempts, explicitly confirmed, plus fresh unlocked state can support a small trial without pretending to have measured counter 0. [Account lockout threshold](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold) explains automatic protocol retries; later actual event counts, not command counts, govern the test.

Prepared only a small read-only address follow-up, independently source-reviewed twice; it has not run on Windows here. No unproven replacement counter field, interop implementation, guest/policy/activation change, third-party script copy or genuine logon evidence invented.

## Actual DHCP address mismatch and selected correction — 2026-10-05

The next full user-message readback replaces the pending diagnosis: Ethernet0/index 8 Up/Connected, DhcpEnabled and actual IPv4 **.129/24 Preferred with both origins Dhcp**. Both store/own-rule counts and associated address-filter counts are 1; own Allow remains LocalAddress.128/RemoteMac.1. Complete and NetworkOrFirewallChangedFalse are observed. No specific DHCP renewal cause, packet failure, authentication or logon fields are inferred.

Official [Set-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule?view=windowsserver2025-ps) rechecked on **2026-10-05**: ByName/PolicyStore select the existing own rule, LocalAddress accepts Any, and specified remaining parameters modify those selected properties. The prepared sole setter uses only LocalAddressAny; no wildcard/group or remote/interface/port/program/service/package reassignment. Permanent [PersistentStore](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule?view=windowsserver2025-ps#-policystore) modification is followed by both-store readback, since higher-priority policy can affect ActiveStore. Any local destination is still constrained by unchanged RemoteMacIPv4, Ethernet0 and TCP445; no arbitrary IPv6 source is granted.

Selected [address](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter?view=windowsserver2025-ps), [port](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter?view=windowsserver2025-ps), [interface](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallinterfacefilter?view=windowsserver2025-ps) and [security](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallsecurityfilter?view=windowsserver2025-ps) readers support the exact condition guards and narrow acceptance. Existing other conditions are not set or claimed newly fully audited. Rendered enforcement tokens use the actual Enforced/ProfileInactive names and accept observed comma/space separation; no numeric-cast inference.

The saved correction and guide received root and two independent source reviews. This remains prepared manual code, not an actual Windows execution, parser result or successful address correction. No third-party script copied, native evidence fabricated, system-wide firewall/network change made or AI authorship added.


## Accepted selected correction and network-logon rights sources — 2026-10-05

The full subsequent user attachment confirms the actual own-rule correction: both stores change local .128 to **Any**, while Mac source 192.168.243.1, Ethernet0, TCP445 and the other selected conditions remain unchanged. **MacAllowAddressReadback Passed / RuleChanged True** are observed, with no error. This supersedes the preceding prepared-only execution status; it is selected configuration evidence, not a packet, authentication or genuine Security-event result.

Official sources rechecked on **2026-10-05**, both applicable to Windows 11:

- [Access this computer from the network](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/access-this-computer-from-the-network): SeNetworkLogonRight is needed for network access including SMB and can be supplied through applicable group membership. The documented location is Local Policies / User Rights Assignment.
- [Deny access to this computer from the network](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-access-to-this-computer-from-the-network): SeDenyNetworkLogonRight takes precedence when both rights apply. Read both actual lists; defaults in this document do not establish this guest's assignments or the test account's membership in every listed group.

The [GUI guide](history/windows-network-logon-rights-step.md) only asks for the two complete current lists and Cancel. No list result, policy change, auth attempt or native evidence is claimed. Previously successful setup/diagnosis/correction is not repeated.


## Observed MMC failure and scoped policy-export contract — 2026-10-05

The actual user screenshots establish an inability to open the local group-policy object, generic Unbekannter Fehler and no rights lists; the user explicitly reports administrator launch also fails. They do not establish a particular root cause. No speculative policy/database repair, reset, installation, activation operation or authentication is requested.

Official sources checked on **2026-10-05**:

- [secedit /export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export): Windows 11 support, existing security-database export, /mergedpolicy local/domain combination and USER_RIGHTS area. The prepared call omits /db and uses unique TEMP /cfg and /log files; it never imports or configures a policy. Treat the result as a stored/merged assignment snapshot, not direct independent LSA or SMB evidence.
- [MS-GPSB Message Syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/fa15485d-ae9f-456e-a08f-81f2e5725a7e): UTF-16LE+BOM security-INF representation and section/key structure. The saved reader bounds the new file and validates this actual representation before Unicode reading; unexpected format stops instead of guessing.
- [LsaEnumerateAccountsWithUserRight](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright) was considered as a possible later direct reader. It returns direct assignments and distinguishes no accounts from other failures. Native interop is not implemented for this first fallback; existing export is simpler and preserves unknown values.

No actual exported assignments are claimed. Raw returned SIDs/names are kept for later applicable-group assessment; absent keys are not treated as empty or replaced by documented defaults. The manual script received independent source review, not Windows execution or parser validation.

## Intel macOS Splunk package, Trial and import preparation — 2026-10-05

Official sources checked on **2026-10-05** for the user-selected home-directory
`.tgz` installation. No archive or license was downloaded, no Splunk instance
was installed or started, and no SPL execution is claimed.

Update 2026-10-06: the user installed 10.2.6 (build bcdcf0552e0c) from the previous-releases page. The `enttrial.lic` host returned DNS NXDOMAIN; the first start created a Trial license itself. See the [validation record](splunk-validation.md#validation-record-2026-10-06).

- [Enterprise download](https://www.splunk.com/en_us/download/splunk-enterprise.html): the visible macOS package is ARM64; inconsistent 10.4/10.6 headings are not used to assert a single global latest version. The advertised Trial is 60 days and 500 MB/day, without a credit card.
- [Previous releases](https://www.splunk.com/en_us/download/previous-releases.html): highest visible Intel macOS 10.x archive **10.2.7 / c0bff5b0fac3**, `splunk-10.2.7-c0bff5b0fac3-darwin-intel.tgz`, advertised 1002.93 MB. Its non-Linux Trial note requires the updated `enttrial.lic` at `$SPLUNK_HOME/etc/licenses/download-trial/enttrial.lic`; the [official license link](https://coverall1.splunk.com/web_assets/product/enttrial.lic) was obtained from that page, but the license contents were not retrieved.
- [10.2 system requirements / Darwin table](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises): macOS 15/x86 64-bit has **D** in Developer and an empty Trial column. The chosen Trial on this host is documented as **not officially listed** and will still be tested locally as requested. Successful lab execution would not change vendor support status.
- [Install on macOS](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/install-splunk-enterprise-on-linux-or-macos/install-on-macos): manual tar installation, archive-root `Splunk`, no automatically created macOS service account. The runbook's single-component extraction selects a stable user-owned path instead.
- [First start](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/start-using-splunk-enterprise/start-splunk-enterprise-for-the-first-time): manual start, license acceptance, interactive initial administrator credentials, Web port 8000 and management port 8089.
- [Bind Splunk to an IP](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/bind-splunk-to-an-ip): `SPLUNK_BINDIP` in `splunk-launch.conf`, Web `server.socket_host` and management `mgmtHostPort`. The local run uses 127.0.0.1 and requires actual listener verification.
- [File input CLI](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.2/get-data-from-files-and-directories/monitor-splunk-enterprise-files-and-directories-with-the-cli): `add oneshot` with an exact path, `-index`, `-sourcetype` and `-rename-source`; it is a one-time import rather than a continuing monitor.
- [Timestamp recognition](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.2/configure-timestamps/configure-timestamp-recognition) and [props.conf 10.2.7](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.7-configuration-file-reference/props.conf): `%6N` parses microseconds; `TIME_PREFIX`, `TIME_FORMAT`, `TZ`, `MAX_TIMESTAMP_LOOKAHEAD` configure timestamp selection; `ADD_EXTRA_TIME_FIELDS=subseconds` preserves subsecond index-time precision. Original indexed `_time` is inspected before the detection query's correction; both imported batches require a complete per-UID comparison.
- [Administrative CLI commands](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/administer-splunk-enterprise-with-the-command-line-interface-cli/administrative-cli-commands): `logout` is a documented command. Any lab-created external client/browser artifacts still need inspection during real cleanup.
- [Uninstall Splunk Enterprise](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/uninstall-splunk-enterprise/uninstall-splunk-enterprise): stop, remove the installation and any externally configured datastores. No boot-start registration, launchd service, root installation or external datastore is part of this chosen procedure.

Prepared steps are in [the macOS runbook](splunk-macos-runbook.md). Local Python
and synthetic comparator tests validate the preparation only; the genuine
Splunk import, license status, indexed timestamp precision and detection
comparison remain outstanding.
