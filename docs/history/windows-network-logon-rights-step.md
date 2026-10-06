# Network rights diagnosis closed: successful logon path

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

Status: **2026-10-05**. The user reports an actually successful network logon from the Mac **192.168.243.1** against **DESKTOP-7HFI2UV / 192.168.243.129** with the local standard account **lab-auth01**. The recorded successes are **4624 / LogonType 3**, RecordIDs **53314** (pilot) and **53330** (main run). The required logon path is therefore functional in this observed account/source/target context; no effective Deny prevented these specific successes.

**Do not run Read-LabNetworkRightsExport.ps1 anymore.** No further rights export, MMC repair attempt, guard/diagnostic script or Windows step is needed to process this existing capture. The exact Allow/Deny assignment list was not read and is not invented. For this experiment, the successful path replaces the functional check that was open before; it does not prove the rights of all accounts or future states.

## Historical error

`secpol.msc` could not open the local group policy object: **"Unknown error"**, even after a reported start as administrator. Afterwards `secedit /export /mergedpolicy /areas USER_RIGHTS` succeeded with **ExportExitCode 0**. The downstream reader stopped with **Expected exactly one Privilege Rights section**. The cause was not determined; the existing INF no longer needs to be examined for this task.

The prepared diagnosis is therefore superseded, without claiming a successful rights evaluation. Do not repeat the firewall/share setup and the Allow address correction that already passed either.

## Current work

Private originals are under **data/lab-captured/pilot-01/** as **events.xml** and **capture-manifest.json**. The user reports 12 exported events: eight complete account events for lab-auth01 and four SYSTEM/type-5 events outside the rule scope. Local adapter/analysis results and tests are in the [project status](../project-status.md) and in [validation](../validation.md). The accepted import with truncation to microseconds, original time and RecordID is described in the [XML contract](../windows-export-format.md).

Splunk remains pending. No policy change, new logon, invented rights, AI authorship information, Co-authored-by trailers or Git identity change are part of this continuation.
