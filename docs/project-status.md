# Project status

Status date: **2026-10-06**. Repository root: this directory (`lab/` in the original workspace); the original project specification is kept privately outside the repository. This current summary supersedes earlier manual-step instructions; dated history and its evidence limits remain in [validation.md](validation.md).

## Current milestone

**Milestone 1 remains complete. Milestone 2's native Windows capture, XML adapter, local Python comparison and the Splunk execution/comparison are now verified; the detection query is `lab-validated` for the capture and the synthetic boundary dataset on Splunk 10.2.6. Publication is prepared up to the first commit, and the Splunk installation has been removed.** Milestone 3 remains roadmap only.

The historical adapter/schema/order/report suite was executed once after those changes: **155 passed in 5.40s**, Python **3.14.7**, pytest **9.1.1**, pluggy **1.6.0**. Of these, **21 new adapter tests** use a small hand-authored synthetic fixture. Genuine captured data was not added to automated fixtures. The historical Milestone 1 result remains **95 passed in 7.62s**; its demo had 3 alerts from 24 lines (23 unique events, 1 duplicate), and its independent evaluation matched 2 manually expected alerts.

## Actual owned Windows experiment

The user supplied successful execution results for SMB authentication and export; local inspection and adapter/analysis verification independently confirmed the available files and event evidence. No Windows action was performed by the agent during this continuation.

| Item | Observed or explicitly confirmed value |
| --- | --- |
| Host inventory, historical 2026-10-01 | macOS 15.8.1, Intel i5-8257U, 4 physical / 8 logical CPUs, 8 GiB RAM, Fusion 26.0.0 |
| Owned disposable target | Windows 11 Pro 25H2, winver build 26200.8037, x64, `DESKTOP-7HFI2UV`, WORKGROUP |
| VM allocation / storage | 2 vCPUs, approximately 4 GiB RAM, existing 40-GiB sparse disk; no resize performed |
| Lab source / target | Mac `192.168.243.1` → Windows `192.168.243.129/24`, SMB TCP 445 |
| Private network | Host-only `192.168.243.0/24`; Mac bridge100; user confirmed Internet Sharing off and no other running VMs |
| Test identity | `DESKTOP-7HFI2UV` / `lab-auth01`, local enabled Users member, not Administrators; password not recorded |
| Audit / lockout, earlier user observations | System Audit Logon success and failure; lockout threshold 10, duration 10 min, reset window 10 min |
| Actual field coverage | Events 4624/4625, LogonType 3, source `192.168.243.1`, account `lab-auth01`, domain and Computer `DESKTOP-7HFI2UV` |
| Actual bad-password context | One smbutil invocation produced one 4625; Status `0xc000006d`, SubStatus `0xc000006a` |
| Pilot | 4625 RecordID **53293**, `02:45:23.5203912Z`; 4624 **53314**, `02:45:37.3433482Z` |
| Main run | Five 4625 records **53325–53329**, `02:51:04.8433762Z`–`02:51:30.7764054Z`; 4624 **53330**, `02:51:42.4779345Z` |
| Export | `Export-LogonEvents.ps1`, UTC interval `2026-10-05T02:44:00Z`–`2026-10-05T02:53:00Z`, 12 events |

The successful network authentication establishes that the needed right is effective and no network-logon Deny prevents **this account/path**. The failed MMC/rights-export parser is no longer an active blocker. **Do not execute `Read-LabNetworkRightsExport.ps1`, repeat rights diagnostics, or introduce further Windows steps for this captured experiment.** This result does not enumerate every stored right or establish policy behavior for other accounts.

The user confirmed a suitable owned Windows 11 Pro license. Historical technical activation was Notification rather than Licensed; no new activation result is asserted. The 40-GiB guest remains below the documented Windows 11 64-GB platform baseline, accepted explicitly for this bounded test. Earlier resource, platform-support and activation observations remain dated in [host inventory](host-inventory.md), [guest preflight](history/windows-preflight-2026-10-02.md) and [the lab plan](windows-lab-plan.md).

## Adapter and fixed-expectation verification

Private original: `data/lab-captured/pilot-01/events.xml` plus `capture-manifest.json`. Original SHA-256, unchanged and equal to the manifest and reported transfer hash:

`c34c38bede02b97dc474b946b135e2e134e2e01bdfa5ca2dc17c19bf014102f5`

`adapt-windows-xml` emits only complete eligible Security events from the expected provider, IDs 4624/4625 and types 3/10. It reports every excluded event with reasons. The real conversion produced **8 normalized records and 4 exclusions**, all four outside scope: SYSTEM/type-5 RecordIDs **53294, 53316, 53318, 53323**, each with original source IP `-`. No placeholder was substituted. Analysis then processed all 8 records with **0 duplicates, 0 exclusions and 0 errors**.

**The user's predeclared expectation was fulfilled unchanged:**

- Exactly **one alert**, success **53330**, failures **53325, 53326, 53327, 53328, 53329**.
- Complete key `DESKTOP-7HFI2UV / lab-auth01 / 192.168.243.1 / DESKTOP-7HFI2UV / 3`; domain and host are represented as `desktop-7hfi2uv` by the existing documented casefold policy.
- No alert for success **53314**; its window contains only failure **53293**.
- Four SYSTEM/type-5 records explicitly outside scope, rather than silently disappearing during analysis.

The accepted precision decision uses **string truncation to six fractional digits, never rounding**. Schema 1.0 now permits optional `timestamp_raw` and positive-integer `record_id`; the adapter always retains both. A lower record ID breaks an equal-microsecond failure/success tie when both IDs exist; legacy records retain the original exclusive success timestamp. Truncation changes time by less than 1 µs. In this capture the next relevant event to the main success's **lower 300-second window boundary** is 65.1345863 s away; there are no same-microsecond collisions. The inspector continues to report exact-precision limitations in the original XML (11/12 timestamps); conversion truncates all 8 emitted native timestamps, preserving their originals.

UID is `windows-xml:` plus SHA-256 of raw `Computer|Channel|integer EventRecordID`. Record IDs may recur after clearing/restoring a log, so reuse can collide across log generations; this bounded lab accepts that limitation. Details: [schema](data-model.md), [adapter contract](windows-export-format.md), [rule logic](detection-logic.md).

From `lab/`, the actual successful integration commands were:

```sh
.venv/bin/python -m soc_detection_lab adapt-windows-xml --input data/lab-captured/pilot-01/events.xml --output reports/lab-captured/pilot-01/adapter --data-origin lab-captured
.venv/bin/python -m soc_detection_lab analyze --input reports/lab-captured/pilot-01/adapter/events.jsonl --output reports/lab-captured/pilot-01/analysis
```

Private outputs: `reports/lab-captured/pilot-01/adapter/{events.jsonl,adapter-result.json}`, `analysis/{results.json,report.md,normalized.jsonl,splunk-import.jsonl}` and `expectation-check.json` (**matched: true**). The independent expectation check compares the fixed success/failure IDs, complete key, exclusions, pilot count and original hash. JSON and Markdown evidence include RecordID and original SystemTime.

## Splunk execution, 2026-10-06

Splunk Enterprise **10.2.6** (build bcdcf0552e0c, Intel `.tgz`, not the planned 10.2.7) runs from `~/soc-splunk-lab/splunk`, bound to `127.0.0.1`, with the Windows VM shut down. The linked updated `enttrial.lic` did not resolve; the first start created a Trial license itself, shown active until **2026-12-05** (500 MB/day). Both transport files were imported once (8 and 14 events). Inventory matched **8/8 and 14/14** including original indexed `_time` at microsecond precision. The detection query matched Python: **1 alert** for the capture (53330 ← 53325–53329, none for 53314) and **2 alerts** for the boundary dataset. The fixed expectation was met unchanged.

Execution found two query defects, both fixed and re-run: the inventory's parsed-time check depended on the search user's time zone, and 10.2.6 rejects `json_extract` inside `mvmap`. A failed CLI search also exited 0 with empty output. Details, hashes and job IDs: [validation record](splunk-validation.md#validation-record-2026-10-06); private evidence under `reports/lab-captured/splunk-01/`. Test suite after the SPL changes: **178 passed** (including the comparator tests).

## Publication preparation, 2026-10-06

Documentation was brought up to the executed state; all relative links resolve. With the current `.gitignore`, 86 files would be tracked and no private or generated path is among them. A copy of exactly those files ran the README demo and the full suite (**178 passed**). Decided and done: MIT license, repository root `lab/`, real lab identifiers stay, Windows setup notes moved to [`docs/history/`](history/README.md). A fresh install of the 88 trackable files with `pip install -e '.[dev]'` ran the demo and **178 tests** successfully. Splunk was removed to the macOS Trash. The repository is now English-only; with `README.de.md` removed, Git sees **87 files** and none of them is private or generated. Git was initialized in this directory by the user; open: the first commit and the GitHub push.

## Splunk preparation, 2026-10-05 (historical)

The user's decisions are fixed: Splunk Enterprise 10.x on this Intel Mac, `.tgz` in a user directory, **Trial**, no root/service/autostart, and the Windows VM shut down during Splunk use. No alternative platform or license is selected. The user performs the account-dependent download. The official current download page only showed ARM64 for macOS; its official archive offers **splunk-10.2.7-c0bff5b0fac3-darwin-intel.tgz**, concretizing the available 10.x Intel package. Archive macOS releases need the vendor's updated **enttrial.lic**. Download, installation, license activation and every actual Splunk job are **pending**.

Host recheck: macOS **15.8.1 / build 24H32**, Darwin **24.6.0**, x86_64; disk observation about **17 GiB free**. The Darwin table is checked in [the concrete macOS runbook](splunk-macos-runbook.md): the chosen Intel Trial combination is **not officially listed**; the user expressly permits this documented lab test. This is not a formal support certification or an executed-runtime result.

Local changes are verified: revised SPL sorts by time then RecordID and retains `timestamp_raw`; the result comparator checks paired native metadata, and a separate inventory comparator checks original indexed `_time`, parsed timestamp, all UIDs/keys and native fields. Props use `%6N`, exact JSON `timestamp` prefix, UTC and `ADD_EXTRA_TIME_FIELDS=subseconds`; the own index is **soc_lab**, sourcetype **soc_lab:normalized:json**. Templates and queries are ready, not installed.

Latest complete suite: **178 passed in 5.20s**, Python 3.14.7 / pytest 9.1.1. The synthetic dataset **data/splunk-boundaries/events.xml** has **14 events**; the same adapter/analysis/export pipeline emits all 14 with no exclusions/errors and yields exactly **2 manually expected alerts**: success 1006 with failures 1001–1005, success 2006 with failures 2001–2005. Evaluate returned **matched: true**. Actual SPL may differ; no simulated result is presented as a Splunk job.

Planned Oneshot sources: **soc-lab-pilot-01** for the 8 real normalized records, **soc-lab-boundaries-01** for the 14 synthetic records. Before detection, compare imported inventory including original `_time`; afterwards compare complete JSON alert exports. Preserve version, job messages, queries and hashes under private **reports/lab-captured/splunk-01/**. Stop Splunk after the run and remove the user installation using the runbook when no longer needed. These steps were carried out on 2026-10-06 (see above).

## Remaining work and publication limits

No further Windows capture or diagnostic is required to finish this requested local slice. Splunk import, SPL execution and comparison were completed on 2026-10-06 for the two prepared datasets; general Python/SPL equivalence is not claimed. Splunk has been stopped and moved to the Trash. See [Splunk validation](splunk-validation.md) and [limitations](limitations.md). The exported `splunk-import.jsonl` is a transport artifact, not evidence of an executed Splunk job.

`lab/.gitignore` excludes both **`data/lab-captured/` and `reports/lab-captured/`**. The workspace still has no Git repository (`git status` reports not a git repository), so no private file is currently tracked here. If Git is later initialized or the project moved into a repository, confirm those paths remain untracked before publication; ignoring a previously tracked file does not untrack it. Originals and derived reports remain private local artifacts, and no publish/push occurred.

No AI author/co-author metadata or commit trailer was added, no commit was created, and no Git identity was changed. The original master prompt is unchanged.
