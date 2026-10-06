# First genuine logon attempt: SMB and logon type 3

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

Status: 2026-10-05. This is still a **prepared logon procedure**, not an executed SMB attempt. Account, firewall and share setup, the separate address diagnosis and the following [Allow address correction](windows-address-repair-step.md) are complete and are not repeated. **MacAllowAddressReadback Passed / RuleChanged True** proves the change of the own Allow LocalAddress from **192.168.243.128** to **Any** in both stores, with the source **192.168.243.1 / Ethernet0 / TCP 445** and the selected status/security conditions preserved. The run still reads **192.168.243.129/24 / Preferred / PrefixOrigin Dhcp / SuffixOrigin Dhcp**; DHCP is not changed. The following administrative secpol.msc attempt failed with "Unknown error" and an empty MMC tree; cause unknown, both rights missing. The following secedit export succeeded with **exit code 0**, but the parser stopped at **Expected exactly one Privilege Rights section** before both rights lines / Collected; section count not printed. Next, only [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md); both rights remain unknown. No new export or logon attempt. The earlier [pilot pre-check](windows-pilot-prerequisites.md) stopped at AuditPolExitCode **2** without Complete. The own suitable Pro license remains a user confirmation; technically **Notification (5), GracePeriodRemaining 0** is observed. Failure counter / attempt budget and further prerequisites remain open. The experiment stays at 40 GiB; the export script and the actual logon attempt have not been run. The configuration readback is no packet or complete WFP proof.

## Preflight in the guest

The following preflight commands document the original setup with the adapter disconnected. They are not run again now; the current host-only state and the account step have already been observed. Log on at the VM console with the own administrator account, open PowerShell as Administrator and only read:

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
Get-CimInstance Win32_ComputerSystem | Select-Object Name, PartOfDomain, Domain, TotalPhysicalMemory
Get-Disk | Select-Object Number, PartitionStyle, @{Name='SizeGiB';Expression={[math]::Round($_.Size/1GB,2)}}
Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, Size
Get-Volume -DriveLetter C | Select-Object DriveLetter, Size, SizeRemaining
Get-Tpm | Select-Object TpmPresent, TpmReady
Confirm-SecureBootUEFI
auditpol /get '/category:*'
net accounts
Get-WinEvent -ListLog Security | Select-Object IsEnabled, RecordCount, MaximumSizeInBytes, LogMode
```

Additionally check edition/build with `winver`, and activation/evaluation via Settings → System → Activation. Do not share product keys or complete license files. `net accounts` without options shows the local password/lockout configuration; nothing about it is changed. If the machine is domain-joined, do not continue: the setup needs an own workgroup VM with local accounts.

The earlier call `auditpol /get /subcategory:* /r` failed on the actual VM with `0x00000057`. The cause is still unknown; the later targeted GUID query, however, succeeded with exit code 0 and **System / Logon / Success and Failure**. The local help was read as well. System audit for logon does not need to be queried or enabled again for this continuation; account-specific settings and genuine event fields remain to be checked later. The adapter is now connected to the [observed private network](windows-network-step.md). The historical activation page showed "Unable to connect", without proof of successful activation. The user has since confirmed an own suitable Windows 11 Pro license. The new technical query returned Professional/RETAIL, LicenseStatus 5 / Notification and GracePeriodRemaining 0; these separate statements are kept. **The chosen small pilot keeps 40 GiB; the [test account](windows-account-step.md) is observed, the [SMB pre-check](windows-smb-step.md) has passed, the [active firewall candidates](windows-firewall-step.md) have been supplied; the corrected firewall repair and then the [probe folder / SOC-LAB share](windows-share-step.md) are complete, ConfigurationReadback Passed and ShareSetupReadback Passed; the later pilot check aborted after auditpol exit 2 without Complete; the separate address diagnosis is Complete and the following Allow address correction has been read back successfully with MacAllowAddressReadback Passed / RuleChanged True; as the next step, only [read the existing rights export files in a targeted way](windows-network-logon-rights-step.md)**. No disk extension or repeated preflight query is planned. The user explicitly treats the VM as disposable and wants to continue without a backup. The [dated preflight](windows-preflight-2026-10-02.md) contains the original resource values.

For **Audit Logon**, success and failure must effectively be logged. Read the matching subcategory and GUID from the localized `auditpol` output; do not assume an English subcategory name on a German Windows. On Pro/Enterprise additionally check Local Security Policy → Advanced Audit Policy → Logon/Logoff → Logon. Legacy categories, the setting for subcategory precedence and possible account-specific exclusions can affect the expected logging. First read the effective state; justify and document any necessary later guest changes separately. **Audit Account Logon / Credential Validation does not replace Audit Logon.**

Record all three lockout values: failed-attempt threshold, lockout duration and reset/observation window. Observed on 2026-10-02: **10 failures / 10 minutes / 10 minutes**. That is not yet a guaranteed frame for five SMB calls; first check the actual repetitions in the pilot. Do not disable the lockout or raise the threshold to force an alert. A success can affect Windows lockout counters; our detector explicitly does not reset its failure list on earlier successes.

## Setup overview after the passed preflight

The following overview records the setup. Network, account, firewall and share steps already observed are not repeated. The address diagnosis and the limited Allow address correction are also complete; the subsequent GUI view failed. The following export succeeded with exit code 0, but the parser stopped before both rights lines. Currently only the read-only diagnosis of the existing INF/log files follows; no new export. Other missing prerequisites are clarified separately afterwards.

1. Check sufficient guest and host space. For the official Windows 11 baseline, an increase to at least 64 GiB is recommended; a bounded pilot with the existing 40 GiB is technically possible and documents this deviation. When extending: powered-off VM without snapshots, keep sparse, then check the guest partition. At the user's explicit request, the disposable VM is used without a backup. Check EFI / Secure Boot / vTPM.
2. While powered off, select exactly one host-only adapter ("Private to my Mac"), disable HGFS shared folders, power off other VMs on this network. The guest firewall stays active. Internet Sharing or forwarding from the Mac must not give this network a LAN or Internet path.
3. In the guest, read the actual computer name with `hostname` and the actual IPv4 configuration with `Get-NetIPConfiguration`. On the Mac, determine the matching virtual host-only address with `ifconfig`. Do not adopt an example address blindly. A missing Internet path has to be checked; a failed DNS query alone does not prove isolation.
4. The local standard test account `lab-auth01` and the empty `C:\SOC-Lab\Probe` with the share `SOC-LAB` were set up and read back by the user; ShareSetupReadback Passed. Three protected NTFS entries and exactly one SMB Allow/Read for the test account are confirmed; keep the administration account separate. Do not repeat the setup. ForceGuest has since been read as an existing DWORD 0; both network logon rights are still unknown after the GUI error and the later parser stop. Now the existing export files are to be read and evaluated according to the [rights guide](windows-network-logon-rights-step.md). Do not enable a guest/anonymous share.
5. The limited TCP 445 firewall configuration has now been run by the user and read back in both stores: three unique lab rules, the Mac allow preserved, IPv4 block local Any and a new IPv6 rule. This follows the documented creation error and replaces the two-rule partial state at that time. Do not repeat the repair and do not turn off the firewall. The account change, the firewall readback at the time and the [share/NTFS creation](windows-share-step.md) are observed. The later diagnosis of 2026-10-05 confirmed Preferred DHCP .129/24 against the local .128 Allow condition at the time. Afterwards the user changed only this LocalAddress to Any; both stores return the intended values, MacAllowAddressReadback Passed / RuleChanged True. Source .1, Ethernet0 / TCP 445 and the selected status/security conditions are preserved, Persistent NotApplicable and Active ProfileInactive,Enforced. DHCP stays unchanged. Do not repeat the diagnosis or the setter; next, after the successful export with the subsequent parser stop, only read the existing INF/log files in a targeted way. A complete WFP/packet proof or an SMB logon has not been provided by this.

## Pilot: only after the open prerequisites are clarified

**Do not start yet.** The own Allow address correction has been read back successfully; no further setter or setup block is needed. The user ran the rights export: **ExportExitCode 0**, file/size/UTF-16LE BOM checks passed. Then the parser stopped with **Expected exactly one Privilege Rights section**, before both target lines and **NetworkRightsExport Collected**. The actual section count was not printed; cause and both rights values remain unknown. Next step: run only [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). This new diagnostic block has **not yet been run**. It only reads the existing INF and its log: section headers, selected possible rights lines and the end of the log. No new export, no file write, policy repair or logon. The earlier MMC query failed as well and is not repeated. BadLoginCount was Unavailable and is no counter of 0; IsAccountLocked false alone does not establish a free failed-attempt budget. SCENoApplyLegacyAuditPolicy was not present, not DWORD 0. The specific auditpol message with exit 2 is no evidence of missing system auditing. Remaining audit/attempt prerequisites and the technical Notification status stay open separately. Until then, the following pilot commands remain a plan.

SMB is a network logon path, so **type 3** is expected. What actually counts, however, is the native `LogonType` in the target event. We use no local Windows console logon (typically type 2), no RDP (a different case) and no VMware shared folders.

The Mac already includes `smbutil`. Its help, actually read, confirms `view -A` for authorization only and `-f` for a non-shared session. Replace with the **observed** values:

```sh
smbutil view -A -f '//ACTUAL-WINDOWS-HOST;lab-auth01@ACTUAL-HOST-ONLY-IP'
```

Enter the password only at the interactive prompt. No password in the command, a script or the shell history, no password list and no loop. The whole URL stays in single quotes because of the semicolon. If the command shows no password prompt or uses an existing/stored identity, clarify that session/credential context first; do not keep trying.

1. Before the pilot, compare guest and Mac time simultaneously. The new guest measurement showed 2026-10-04 20:33:13.4066612 +02:00 and the same instant 18:33:13.4066612 UTC; W. Europe Standard Time has a base offset of +01:00, and the current +02:00 offset is consistent with daylight saving time. A simultaneous Mac measurement does not exist yet. Then record the UTC start time on the target: `[DateTimeOffset]::UtcNow.ToString('o')`.
2. Enter a deliberately wrong test value **once**. Do not derive the real number of native failures from the number of terminal calls: a client can produce several protocol attempts.
3. Immediately check in the target Security log whether the attempt produced a matching 4625; record the actual count, Status/SubStatus and lockout state.
4. Only if enough budget safely remains, log on **once** with the correct test password and check the corresponding 4624.
5. Record the UTC end time and export the pilot. If the type, account or IP is missing or different, investigate the pilot first; do not run the main attempt.

The target VM records the logons in **Windows Logs → Security**. Event Viewer → Details → XML is suitable for looking at the native field names directly. The console administrator logon can also produce 4624; it is distinguished from the SMB case by account, source and type, not silently deleted.

| To check | XML field | Success criterion |
| --- | --- | --- |
| Event type | `System/EventID` | Failure 4625, success 4624 |
| Source/provider | `System/Provider/@Name`, `System/Channel` | Windows Security Auditing, Security |
| Target host | `System/Computer` | Actually observed Windows target computer |
| Account and context | `TargetUserName`, `TargetDomainName` | Test account and correct local account context in both events |
| Source | `IpAddress` | Present, valid host-only IP of the Mac; no `-`, empty or guessed value |
| Type | `LogonType` | Actually 3 for failure and success |
| Time/identity | `TimeCreated/@SystemTime`, `EventRecordID` | Original time with zone, record ID present, export context recorded |

A different observed account, domain, source IP, target host or type is not mixed with the intended attempt. Missing values are a telemetry problem, not yet an attack finding.

## Main attempt: checking the existing rule safely

After the pilot, wait at least the longer of **300 seconds plus a small safety margin** and the observed lockout reset window. Choose a new export window and confirm that the account is not locked and that no background logons are running with this account. This prevents pilot failures from contributing to the main alert or the lockout budget.

The preferred main attempt keeps the rule unchanged: **five actual matching failures, then a success within 300 seconds of the earliest counted failure**. At most five individual wrong password entries, no automated repetition. After each call, the administrator checks the events actually added and the account state. As soon as five matching failures exist, trigger no further wrong attempts but log on correctly. If five failures are reached with fewer calls, document that deviation.

Beforehand, the local lockout threshold must be sufficiently higher than the planned actual number of failures and still leave a margin for the protocol repetitions observed in the pilot. With threshold 5 or an unknown/tight budget, this sequence is **not** run. Then only capture a safe small pilot (for example one failure + success) and later check the same logic explicitly with a documented smaller CLI threshold. A threshold of 1 is a transfer/smoke test and no proof of the standard case with five failures. The policy stays; no guarantee of "one call = one event".

**Stop on:** unexpectedly many failures, signs of lockout, unclear account context, missing logs, wrong source or type, connection problems or approaching the lockout threshold. No unlock loop and no further failed attempt. Instead secure the export so far and investigate the cause.

The genuine dataset has to be described independently of a detector result: which success, which actual failure record IDs, which complete key, which original times and which expected result. An SMB logon alone does not prove a compromised identity.

## Lossless export

The chosen format is [UTF-8 Event XML](../windows-export-format.md): an `Events` root with unmodified, namespaced `EventLogRecord.ToXml()` events. No CSV, `Export-Clixml`, rendered message text or renamed EVTX. The prepared [export script](../../scripts/windows/Export-LogonEvents.ps1) reads only Security 4624/4625 in the given window and writes XML plus hash/manifest; it changes no policy and produces no logons. It has **not yet been run on Windows**.

Use it after an own review in the guest; replace the UTC times with the real pilot values:

```powershell
.\Export-LogonEvents.ps1 -StartUtc 'ACTUAL-UTC-START' -EndUtc 'ACTUAL-UTC-END' -OutputDirectory 'C:\SOC-Lab\Exports\pilot-01'
```

The script requires the UTC format `yyyy-MM-ddTHH:mm:ssZ`, a window of up to 15 minutes and at most 1000 records. With too many records it aborts without presenting a truncated export as complete. It keeps all accounts and types of the two IDs in the window; downstream filters stay traceable. Original timestamps are neither reformatted from `TimeCreated` nor truncated. Choose the start at least one second before and the end one second after the action, so the second boundaries are not cut off by accident.

Close the export window, record the hash and only then transfer the files to the Mac in a controlled way, for example via a specifically shared SMB export folder. This later transfer can produce additional logons, which must lie outside the closed window. Do not turn broad shared folders back on permanently. Store under `data/lab-captured/pilot-01/`, compare the file hash, check for personal content and do not publish the raw data.

Then on the Mac:

```sh
python -m soc_detection_lab inspect-windows-xml --input data/lab-captured/pilot-01/events.xml
```

Inspection verifies structure, required fields and time compatibility, **not authenticity**. For timestamps that are not microsecond-exact, the original is preserved and the exact adapter is designed based on this sample. Do not present rounding as a "successful import". The Splunk execution remains pending.
