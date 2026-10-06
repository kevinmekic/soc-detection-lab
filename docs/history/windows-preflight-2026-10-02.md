# Windows preflight, 2026-10-02

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

Source: PowerShell output supplied by the user, a visible `winver` screenshot and a subsequent activation screenshot of the owned test VM. The guest values were not collected again through remote access. The screenshots and the personal e-mail address they contain are not included in the project. These are genuine statements about the guest state, **not exported Security events and no proof of the logon use case**.

## Observed guest state

| Check | Observed value | Meaning / open limit |
| --- | --- | --- |
| Windows | Windows 11 Pro, 25H2, build **26200.8037** according to `winver`; CIM reports `10.0.26200` / build `26200`, 64-bit | The different level of detail in the build values is not a contradiction. The VM actually starts. |
| Computer | **DESKTOP-7HFI2UV**, `PartOfDomain = False`, `Domain = WORKGROUP` | Workgroup target for local test accounts. `WORKGROUP` is not automatically the later `TargetDomainName`; that native event field has to be observed. |
| Guest RAM | 4293677056 bytes, about **4.00 GiB** | Matches the configured 4096 MiB VM; RAM on the 8 GiB Mac remains limited. |
| Disk | Disk 0, GPT, **40 GiB** | Confirms the earlier VMDK check. The planned Windows 11 storage requirement remains open. |
| Partitions | 1: System, 209715200 bytes (200 MiB); 2: Reserved, 16777216 bytes (16 MiB); 3: C:, Basic, 42720034816 bytes | No recovery partition is listed in this output. That proves neither the absence nor the state of Windows Recovery; do not change or delete any partition. Offsets and extensibility were not queried. |
| C: volume | Size 42720030720 bytes (**39.79 GiB**), free 20911587328 bytes (**19.48 GiB**) | Free guest space is not free host space and does not replace increasing the virtual disk capacity. |
| TPM | `TpmPresent = True`, `TpmReady = True` | TPM is present and ready in the running guest. |
| Secure Boot | `Confirm-SecureBootUEFI = False` | According to [Microsoft](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi?view=windowsserver2025-ps) the system supports Secure Boot, but it is disabled. This is not a report of missing UEFI support. It was not enabled; no explanation of the AuditPol error is derived from this value. |
| Account lockout | Threshold **10**, duration **10 minutes**, reset/observation window **10 minutes** | Watch the pilot budget before the main run. One SMB call can produce several native failed attempts. Between pilot and main run, wait at least the longer of 300 seconds plus a margin and these 10 minutes. |
| Other password values | Minimum age 0 days, maximum age 42 days, minimum length 0, no password history; forced logoff: never | Observed local policy; not changed. A later new test account gets its own strong lab password regardless. |
| Security log | Enabled, **33545** records, maximum **20971520 bytes = 20 MiB**, `Circular` | The log is available and overwrites old records at capacity. This does not yet prove that success/failure auditing for **Audit Logon** is enabled or that the required fields are present. |
| First audit query | `auditpol /get /subcategory:* /r` → `0x00000057`, "The parameter is incorrect" | Historical diagnostic error; specific cause not determined. The later targeted query works. |
| Targeted system audit query | Computer DESKTOP-7HFI2UV, policy target System, subcategory Logon, GUID `0CCE9215-69AE-11D9-BED3-505054503030`, inclusion setting **Success and Failure**, exclusion setting empty; exit code **0** | System audit for logon was read successfully and is enabled for success and failure. This does not yet prove genuine 4624/4625 events or per-user audit settings; the empty column in a system query does not rule out individual exclusions in general. |
| Network adapter | User confirms: **still disconnected** | Current disconnection confirmed; the later host-only network, addresses and absence of an Internet path were not yet set up or verified. |
| Activation display | Windows 11 Pro, **"Unable to connect"**; prompt to connect to the Internet and note about a later automatic activation attempt | Successful activation not confirmed. No proof of a missing license and no guarantee of later activation. No connection or activation performed. |
| Visible guest clock | Activation screenshot: **2026-10-01, 21:58** | Differs from the conversation date 2026-10-02; capture time and time zone are not established. Check guest time, time zone and UTC alignment before the pilot; do not claim clock drift from the image alone. |

Successful activation and a suitable license origin and rights remain open; the "licensed to" display in `winver` does not confirm them. According to the user, the network adapter is still disconnected. Shutting down afterwards is recommended but not yet confirmed as done. A renewed read-only host space check on 2026-10-02 showed **19200364 KiB = about 18.31 GiB free**, capacity display 92 %, on the volume holding the VM bundle. The other host values from 2026-10-01 were not measured again.

## AuditPol diagnosis — completed successfully

`0x57` corresponds to [Microsoft's `ERROR_INVALID_PARAMETER`](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-). The earlier call basically matches the [documented syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get). The specific cause on this VM is therefore **not determined**; neither missing administrator rights nor the German language nor a broken policy is claimed as the cause.

The user ran the following targeted read-only query and then reported exit code `0`; it does not need to be repeated:

```powershell
& "$env:SystemRoot\System32\auditpol.exe" /get '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}' /r
$LASTEXITCODE
```

The first line uses the Windows system program and the [official GUID for `Audit_Logon_Logon`](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants). It reads the system logon auditing specifically, without relying on a language-dependent subcategory name. The GUID argument stays entirely within single quotes. The second line shows the exit code of the immediately preceding call. On successful output, record the line for **Logon / Audit Logon** including its success/failure status; "Logoff" or "Credential Validation" does not replace it.

The local help was also read and supplied:

```powershell
& "$env:SystemRoot\System32\auditpol.exe" /get /?
```

Do not try guessed translated switches or any `/set` commands. The generic full query `auditpol /get '/category:*'` in the capture guide is another documented read-only option, not yet a successfully tested guest call.

**Criteria reached:** targeted system audit query successful; success and failure enabled; network adapter confirmed as still disconnected; activation display recorded. This does not confirm successful activation or a suitable license. No change to the audit setting is needed for the observed system state. Further account-specific checks and genuine coverage of the required fields remain part of the later pilot.

## Storage recommendation — deferred for the chosen pilot

**Subsequent user decision:** the small pilot stays at **40 GiB**. The current next step is the [host-only configuration and address check](windows-network-step.md). The capacity increase below is only the earlier optional recommendation; it was not carried out and is not requested now.

**Clarification:** the following increase to 64 GB is a recommendation for the official Windows 11 minimum configuration. It is not technically required for the bounded SMB logon pilot on the already running VM; with 40 GiB and the observed 19.48 GiB free on C:, this small experiment can take place with a documented deviation. The recommendation and its success criteria below are not an additional technical blocker of the detection rule. The user asked for the reasoning but did not report a completed resize.

1. Shut Windows down **normally via Start → Power → Shut down**. Do not treat suspension as powered off and do not power off hard.
2. Wait in Fusion for the **powered off** state; keep the network adapter disconnected. No disk, firmware, account or policy change yet, and no failed logon.
3. The user stated explicitly: **no external storage and no VM backup exist; the test VM is disposable and may be used for experiments**. At the user's request we therefore plan without a backup or second copy. The vendor's backup recommendation is documented but not treated as an additional approval requirement or indispensable block.
4. Confirmed read-only: `nvme0:0.fileName = "Virtual Disk.vmdk"`, descriptor `createType="twoGbMaxExtentSparse"`. The existing disk is already space-saving and grows with the data written. Increasing the virtual capacity does not immediately reserve another 24 GiB. Host space is still needed as the disk fills; no conversion to a fully preallocated disk. The limited check of the top-level bundle files found no `.vmsn`; that does not replace a complete snapshot check in Fusion.
5. With the VM powered off, open the VM settings in Fusion and its hard disk **NVMe / `Virtual Disk.vmdk`**. If there are no snapshots and resizing is available, set **40 to 64 GB** and apply. Keep preallocation off or the existing sparse type; do not create a second disk and do not format a partition. If the function is locked, a space or snapshot message appears, or a conversion is requested, check the exact state first and make no guessed file change.

**Success criteria of this next step:** Windows shut down normally, Fusion shows the VM as powered off, adapter disconnected, the existing disk shows 64 GB with the sparse type preserved. This manual step is **not yet confirmed as done**. The Windows C: partition does not grow automatically; its extensibility is checked in the guest only after the change. No Internet access needs to be established for the activation display now.

Source for the extension: [Broadcom KB 344854](https://knowledge.broadcom.com/external/article/344854); sparse vs. preallocated: [KB 311483](https://knowledge.broadcom.com/external/article/311483/making-a-fusion-virtual-disk-preallocate.html). The linked Fusion 25H2-specific guide returned HTTP 403; the exact labels of the installed 26.0.0 interface were not seen here. No current UI check is claimed.

Still open after that: a suitable license and successful activation, sufficient host space as the disk grows, the actual disk extension including the guest partition, the planned firmware/isolation check, time check, accounts/SMB/firewall and the account-specific audit check, as well as the genuine pilot and export. Secure Boot capability and system audit for logon are observed. The adapter and the Splunk execution remain pending. No tests were repeated for this documentation-only continuation.
