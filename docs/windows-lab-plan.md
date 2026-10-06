# Windows lab: concrete setup for this machine

Status: **2026-10-06**. The user carried out the pilot, the main run and a genuine Security XML export on the owned Fusion/Windows test VM. The capture is kept privately under **data/lab-captured/pilot-01/**; the adapter and Python analysis ran locally and were checked against the expectation fixed beforehand. The coding tool installed no programs on the VM and changed no VM settings or system policies.

**Verified result:** the adapter reads **12 events**, emits **8** and reports **4 SYSTEM/type-5 events as outside scope**. The analysis counts **8 processed / 0 duplicates / 0 excluded / 0 errors**. Exactly one alert contains success **53330** and failures **53325–53329**, key **DESKTOP-7HFI2UV / lab-auth01 / 192.168.243.1 / DESKTOP-7HFI2UV / 3** (text values casefolded in the normalized result). Success **53314** has only one matching failure and produces no alert. The private **expectation-check.json** reports **matched: true**. The complete suite at that time passed with **155 passed in 5.40s**; the current count is in the [project status](project-status.md). Results are under **reports/lab-captured/pilot-01/**; both private directories are ignored by Git.

**No further Windows steps or rights diagnostics are needed.** The successful logon proves the required path for this account/source/target context; the full list of user-rights assignments and the cause of the earlier MMC/export read error were not determined. The [XML contract](windows-export-format.md) documents the explicitly accepted string truncation to six fractional digits, `timestamp_raw`, `record_id` and the UID limits.

The decision to keep **40 GiB** stands; earlier resource, platform and license limits are kept below as a historical inventory. The setup phases and the checklist further down document the earlier plan, **not a request to repeat anything**. On 2026-10-06 the SPL query, including the RecordID exception and native evidence, was executed on Splunk Enterprise 10.2.6 and matched Python for this capture and a separate synthetic boundary dataset ([validation record](splunk-validation.md#validation-record-2026-10-06)).

## Chosen setup

We use **VMware Fusion 26.0.0 and the existing Windows 11 x64 VM**, with macOS as the SMB client. The first network-logon case therefore needs only one Windows VM. A domain controller, a second Windows VM and RDP are not required for this experiment.

```mermaid
flowchart LR
    A[macOS Intel: SMB client] -->|individually triggered logon, TCP 445| B[Host-only network: Private to my Mac]
    B --> C[Windows x64 test VM: local test account]
    C --> D[Security log: genuine 4624 and 4625]
    D --> E[UTF-8 Event XML: unmodified ToXml events]
    E --> F[Read-only XML inspection on macOS]
    F --> G[XML adapter and Python analysis: verified locally]
```

Host-only deliberately connects the Mac and the VM. It isolates from the physical LAN and the Internet, but not from the host or other VMs on the same virtual network. No bridged adapter, no additional NAT adapter and no sharing through a VPN or Internet Sharing during the experiment. "Share with my Mac" is NAT; "Private to my Mac" is the required network type. VMware HGFS folders do not produce the intended SMB logon case.

| Resource | Observed | Target / open point |
| --- | --- | --- |
| Host | Intel i5-8257U, macOS 15.8.1, 8 GiB RAM | x64 guest; close other memory-heavy apps before starting |
| Windows VM | 2 vCPU, 4096 MiB RAM | Keep; no second Windows VM in parallel |
| Virtual disk | **40 GiB**, NVMe `Virtual Disk.vmdk`, `twoGbMaxExtentSparse` | Kept for the small pilot; official 64 GB baseline documented as an open deviation |
| Host storage / backup | On 2026-10-02: about **18.31 GiB free**; VM bundle last about 26.6 GiB; no backup or external storage according to the user | User treats the test VM as disposable; continue without a backup or second copy. Keep watching growth |
| Guest disk / C: | On 2026-10-02: GPT, disk 0 with 40 GiB; C: 39.79 GiB, of which 19.48 GiB free | Confirms the undersized virtual capacity; guest space does not replace free host space |
| Firmware | EFI configuration; TPM present and ready in the guest, Secure Boot `False` | Secure Boot capable, currently disabled; document the later firmware state, do not infer it from the AuditPol error |
| Network | 2026-10-03: VMX host-only, Windows .128/24, Mac **192.168.243.1/24** and a route to the target at the time. 2026-10-04: 15 guest routes without a default or foreign gateway route. 2026-10-05: **Ethernet0 / index 8 / Up / IPv4 Connected / DHCP enabled / 192.168.243.129/24 Preferred**, PrefixOrigin and SuffixOrigin DHCP | Address diagnosis complete without changes; then the targeted change of the own Allow rule's LocalAddress from .128 to **Any** in both stores passed: **MacAllowAddressReadback Passed / RuleChanged True**. Source .1, Ethernet0/TCP 445 and the other selected conditions preserved; DHCP unchanged. No packet or authentication check at that point. Forwarding 0/0 dates from 2026-10-02 |
| Host integration | Current VMX **isolation.tools.hgfs.disable = TRUE**; the saved share definition is still present | HGFS configured as globally disabled; actual share access not tested. Limit clipboard and drag-and-drop before the pilot |
| Windows | Windows 11 Pro 25H2, build 26200.8037, x64; DESKTOP-7HFI2UV, not domain-joined; activation page "Unable to connect" | Guest start, edition and build observed; own suitable Pro license confirmed by the user. Technical status: Professional/RETAIL, LicenseStatus **5 / Notification**, GracePeriodRemaining **0**, not Licensed |
| SMB / firewall profiles | LanmanServer Running/Automatic; SMB1 False, SMB2 True, signing required True, EncryptData False; 2026-10-03 probe path missing / SOC-LAB 0, 2026-10-04 probe path and SOC-LAB created and empty; Ethernet0 Public/NoTraffic; all three firewall profiles enabled, inbound Block, inbound/local rules allowed | Historical repair: 3 unique rules per store, IPv4 block local Any, IPv6 range and the Mac Allow (local .128 at the time) read back, ConfigurationReadback Passed. ShareSetupReadback Passed with protected NTFS ACL / 3 entries and 1 SMB Allow/Read for lab-auth01. The address drift confirmed on 2026-10-05 was then corrected: own Allow LocalAddress Any in both stores, MacAllowAddressReadback Passed |
| Lockout / audit | 10 failures, 10-minute duration, 10-minute reset window; Security log active; **System / Logon / Success and Failure**, exit 0 | System audit for logon read historically; a later per-user query reported no policy / exit 2 and the block stopped without Complete. IsAccountLocked false, failure counter unknown at the time. The genuine events later confirmed both 4625 and 4624 auditing |

The [host inventory](host-inventory.md) contains commands, measurements and evidence limits. Microsoft requires at least 4 GB RAM, two virtual processors, 64 GB storage, Secure Boot capability and vTPM for Windows 11 VMs. The 40 GiB disk does not meet the storage requirement. Extending the VMDK does not automatically enlarge the Windows partition. A snapshot does not replace an independent backup. No recovery partition is changed or deleted to force an extension.

**Clarification of the user's question from 2026-10-02:** the 64 GB figure belongs to the [official Windows 11 VM minimum configuration](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements#virtual-machine-support). It is **not a technical requirement of the detection rule or of a few SMB logon events**. The existing guest runs and reports 19.48 GiB free on C:, so an extension is not mandatory for the bounded pilot. A pilot with the unchanged 40 GiB is documented as a deviation from the official storage requirement. The earlier wording as an indispensable prerequisite was too strict. The extension remains a recommended setup step that was not carried out; isolation, account/audit checks and the actual event fields remained required.

The user confirmed that there is no backup or external storage and stated explicitly that the test VM is disposable. **At the user's request we continued without a backup.** Broadcom recommends a backup before an extension; this is documented as a recommendation and was not turned into a renewed approval requirement after that decision. The earlier planning target of 40 GiB free host space referred to an additional copy or snapshot; it is not a vendor minimum and is not used as a hard block. The existing sparse disk stays sparse: a virtual capacity of 64 GiB does not mean an immediate full physical reservation. With about 18.31 GiB of host space, further large installations or copies were not part of this bounded experiment. No purchase was made.

The supplied guest partition list shows System, Reserved and C: partitions, but no recovery partition; that is no proof of the WinRE state. Offsets and actual extensibility were not checked, so no partition is deleted and no automatic extension is claimed. Before a virtual extension, Fusion must be powered off and work without snapshots; the bounded read-only bundle check found no `.vmsn`, which alone does not confirm the absence of snapshots.

## Platform support, cost and licenses

Official sources were checked on 2026-10-01; links and sections are in [sources.md](sources.md). According to the vendor, Fusion 26H1 is free for personal, educational and commercial use. It includes no Windows license. A new download requires a Broadcom account and its export screening; no download or update was needed or performed.

The installed vendor app declares macOS 13.00.0 as its minimum version and is present on this Intel Mac. The complete current Fusion 26 host matrix and numerical installation requirements were not accessible through the linked release documents (HTTP 403). The older matrix for Fusion 13.6 is no evidence for Fusion 26. Before a later reinstallation or update, this exact combination must be checked in the vendor portal. The guest start observed by the user on 2026-10-02 is practical operating evidence, not a complete formal platform certification.

| Component | Cost decision |
| --- | --- |
| Existing Fusion | €0 license cost according to the current vendor statement; free direct vendor support is not assumed |
| Existing Windows | Own suitable Pro license confirmed by the user on 2026-10-04; no new purchase planned. Technically Professional/RETAIL, **LicenseStatus 5 / Notification, GracePeriodRemaining 0** observed; to be clarified separately, no key requested |
| New Windows 11 Pro license | Historical price note from the check date: €259.00 in the German Microsoft Store. No purchase planned after the existing license was confirmed |
| Windows 11 Enterprise evaluation | Free 90-day evaluation with registration/activation and its own terms; no permanent license. After expiry, restrictions up to hourly shutdowns apply. Not to be used unchecked as a substitute for a required license |
| Storage / second VM / cloud | Use existing resources; no new purchase, no second VM and no cloud cost planned |
| Splunk | Splunk Enterprise 10.2.6 with Trial (until 2026-12-05) run as a user-directory installation on 2026-10-06 and removed afterwards; no Enterprise Security scope or free permanent operation claimed |

The own suitable Pro license remains an explicit **user confirmation**. The technical output reports **LicenseStatus 5 (Notification)** instead of Licensed, and **GracePeriodRemaining 0**. This is documented separately from the usage rights and left for separate clarification; no license file, product key or standalone Internet connection was requested. See the [official SoftwareLicensingProduct status definition](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct).

## Identities and systems

- **Source:** this own Mac, only through its actually observed host-only IP. No documentation IP is used as a supposedly real address.
- **Target:** the existing test VM, actual Windows computer name **`DESKTOP-7HFI2UV`**. `LAB-SERVER-01` was only the planned logical name; renaming was not needed. The local account context in the event has to be observed, not guessed from `WORKGROUP`.
- **Test account:** `lab-auth01`, created by the user on 2026-10-03: Enabled True, PrincipalSource Local, UsersMember True, AdministratorsMember False. Its lab-specific password was entered interactively only and is not documented. The administration account stays separate.
- **Administration:** a separate existing local administrator account for console management and reading the Security log; it does not take part in the failed logons.
- **Share:** created and read back by the user on 2026-10-04: empty `C:\SOC-Lab\Probe`, share `SOC-LAB`, protected NTFS ACL with three entries (SYSTEM/Administrators FullControl, lab-auth01 ReadAndExecute including the .NET representation Synchronize), one SMB Allow/Read for the same test account. No payload data and no broad guest rights. Whether `C:\SOC-Lab` existed before or was created then cannot be derived from the output; the earlier uncertainty is not replaced by an assumption.

## Phases and outcomes

1. **Console preflight observed.** Edition/build, guest start, resources, TPM/Secure Boot state, account lockout, Security log and system audit for logon success/failure were recorded. The network adapter was disconnected at that preflight. The activation display was read; an own suitable Pro license is confirmed, and the technical query returns Notification (5), to be clarified separately.
2. **Storage decision:** the existing 40 GiB VM stays for the small pilot, with the deviation documented. No disk extension or second VM. 64 GB would be the official Windows 11 baseline; a later extension is a separate step.
3. **Private network and limited Allow address correction:** host-only, global HGFS deactivation and the .128/.1 addresses with the Mac route remain historical evidence. On 2026-10-05 the diagnosis confirmed Preferred DHCP .129/24 against the own Allow LocalAddress .128. The correction run changed only this LocalAddress to Any; both stores were read back successfully, MacAllowAddressReadback Passed / RuleChanged True. Source .1, Ethernet0/TCP 445 and the selected status/security conditions were preserved, Persistent NotApplicable and Active ProfileInactive,Enforced. DHCP unchanged.
4. **Account/SMB setup and remaining checks:** ForceGuest DWORD 0 and IsAccountLocked Boolean false were read; SCENoApplyLegacyAuditPolicy was missing and BadLoginCount Unavailable. The per-user audit query reported no defined policy and exit 2, after which the block stopped without Complete; this does not negate the system audit observed earlier. The administrative GUI query failed with "Unknown error". The subsequent rights export succeeded with exit code 0, but the parser stopped before both rights values. These diagnostics were abandoned once a successful network logon proved the required right for this path.
5. **Pilot (done 2026-10-05):** one controlled wrong and one correct logon, each triggered manually, with a log check after each call. Result: 4625 RecordID 53293 and 4624 RecordID 53314, type 3, complete identity, source and target.
6. **Main run (done 2026-10-05):** after separation from the pilot window, five individual controlled failures and one success, within the verified lockout threshold of 10. Result: 4625 RecordIDs 53325–53329 and 4624 RecordID 53330. Details and stop criteria are in [windows-first-capture.md](history/windows-first-capture.md).
7. **Original export (done):** unmodified `ToXml()` events in a UTF-8 `Events` container, with hash and capture notes, transferred to the Mac after the experiment window closed; raw data kept in `data/lab-captured/`.
8. **Inspection and adapter (done):** original fields and time precision checked. Native times carry 100-ns digits that schema 1.0 cannot represent exactly; the accepted decision is string truncation to microseconds, never rounding, with the original SystemTime and RecordID retained. Mapping in the [XML contract](windows-export-format.md).
9. **Python/SPL comparison (done 2026-10-05 and 2026-10-06):** Python matched the fixed expectation; Splunk 10.2.6 matched Python for the capture and the synthetic boundary dataset.

## Current state

The Windows/Python comparison of this capture is complete and meets the fixed expectation. **No new logon, rights diagnosis or system change** is required. Originals, manifest and private results are preserved; actual check results are in [validation](validation.md) and [project status](project-status.md). The local evaluation can be re-checked after a concrete change with the [adapter/analysis commands](windows-export-format.md#commands-and-artifacts).

The [Splunk run on the Intel Mac](splunk-macos-runbook.md) took place on 2026-10-06: Splunk Enterprise 10.2.6 in the user directory, Trial, no root/service/autostart, Windows VM shut down. The import of both datasets was complete, and the SPL results match Python; details in the [validation record](splunk-validation.md#validation-record-2026-10-06). Splunk has been removed. The technical Windows Notification status and formal Fusion support remain separate historical open points; they do not affect the passed local comparison.

## Historical setup checklist

This list preserves the earlier plan with its final state. It is **not a current task list**.

- [x] Observe guest start, Windows edition/build, resources, TPM/Secure Boot state, lockout values and Security log through the user preflight.
- [x] Observe system audit for logon success/failure, exit code 0 and the then still disconnected adapter; activation display recorded.
- [x] Document the user's decision to proceed without a backup for the disposable test VM; read sparse type and current host space.
- [x] Document the own suitable Windows 11 Pro license as a user confirmation from 2026-10-04; record no keys.
- [x] Read the technical status: Professional/RETAIL, LicenseStatus 5 / Notification, GracePeriodRemaining 0.
- [ ] Clarify the Notification status separately; the user's confirmation of the own license stands. *(Open, not needed for the experiment.)*
- [ ] Optionally extend to at least 64 GiB for the recommended Windows 11 baseline and check the guest partition. *(Not pursued; the 40 GiB deviation is documented.)*
- [x] Read guest date/time zone and matching local/UTC values; W. Europe Standard Time, +02:00 at the time.
- [ ] Compare against Mac time at the same moment. *(Not done; no clock drift is asserted.)*
- [ ] Confirm exact Fusion 26 host support in an accessible vendor portal. *(Open; a successful guest start does not replace this.)*
- [x] Observe/confirm host-only, both private IPv4 addresses, no guest default route, Mac route, global HGFS deactivation, Internet Sharing off and no other VMs.
- [x] Create the local standard test account lab-auth01 and check it against the five reported values.
- [x] Observe SMB service/configuration, fresh test path and share name, connection profile and active firewall profiles.
- [x] Read active firewall candidates: 127 enabled inbound rules / 38 Allow candidates; existing broader SMB allow conditions recognized.
- [x] Read rule state and actual application filters: two rules per store; four relevant string CIM properties per store/rule present with a genuine null value; no change.
- [x] Repair the two-rule partial state and check the configuration readback: three unique rules per store, all conditions matching, ConfigurationReadback Passed.
- [x] Create and read back the new empty probe folder and SOC-LAB share: ShareSetupReadback Passed, protected NTFS ACL / 3 entries, 1 SMB Allow/Read for lab-auth01.
- [x] Read 15 active routes, ForceGuest DWORD 0, the missing audit precedence value and IsAccountLocked false; document BadLoginCount Unavailable and the per-user audit message / exit 2.
- [x] On 2026-10-05 read current IP/DHCP and the Mac Allow address filter in both stores: Preferred .129/24 with DHCP, Allow still local .128; AddressDriftCollection Complete / NetworkOrFirewallChanged False.
- [x] On 2026-10-05 change the own Allow LocalAddress from .128 to Any and read back both stores: MacAllowAddressReadback Passed / RuleChanged True.
- [x] Document the administrative secpol.msc attempt: local group policy object not opened ("Unknown error"), red X / empty MMC tree; cause unknown.
- [x] Rights export: secedit exit code 0, file/size/UTF-16LE BOM checks passed; parser stopped before the target lines.
- [x] ~~Diagnose the existing export INF and log read-only.~~ Superseded: the successful network logon proved the required right; the diagnosis was dropped.
- [x] Lockout/attempt budget: threshold 10 known; the main run used five failures and stayed below it.
- [x] Run the pilot with actual logon type and complete required fields.
- [x] Define a safe lockout/attempt frame; run and export the genuine bounded sequence.
- [x] Check original precision and implement the adapter for the actual export version.
- [x] Compare genuine events with the Python rule; keep synthetic and real evidence separate.
- [x] Validate the Splunk environment, import and executed SPL.
