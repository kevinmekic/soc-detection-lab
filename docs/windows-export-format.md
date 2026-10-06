# Windows Security XML export and adapter contract

Updated **2026-10-05** after the user's owned Windows experiment. The first capture is present privately under `data/lab-captured/pilot-01/`; it is not a versioned fixture. The original format was checked against official Microsoft documentation on **2026-10-01**. Local integration results and tests belong in [validation](validation.md) and [current status](project-status.md).

The user supplied the following capture results: **12 events**, including **8 complete `lab-auth01` network-logon events** and **4 SYSTEM/type-5 events outside this rule**. The reported pilot was failure **53293** followed by success **53314**; the main run was failures **53325–53329** followed by success **53330**. Native event inspection found nonzero submicrosecond places in **11/12** timestamps. These reported results are distinct from the independently executed adapter/analysis verification.

## Selected original format

Use **UTF-8 Windows Event XML**: one project-defined, unnamespaced `Events` container enclosing the unchanged XML returned by `EventLogRecord.ToXml()` for each selected Security record. Each `Event` has the namespace `http://schemas.microsoft.com/win/2004/08/events/event`. The container groups records; it is not a new Windows event field. PowerShell `Export-Clixml` serialization, Event Viewer display text, CSV and EVTX are different formats and must not be supplied as Event XML.

Microsoft documents [ToXml()](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogrecord.toxml) as the event XML representation and defines its structure in the [Windows Event schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema). [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) supports selecting Security events using event IDs and start/end times.

Preserve original export bytes, SHA-256, extraction interval, target Windows build, account mapping and capture notes. Do not clear the Security log to simplify capture. Private originals belong under `data/lab-captured/` and private derived results under `reports/lab-captured/`; both are excluded by `lab/.gitignore`. Ignoring files does not remove previously tracked files, so any later Git repository must also be checked for tracked private paths before publication.

## Field mapping

Read named `EventData/Data` nodes, not display order or localized Event Viewer labels. `TargetUserName` and `TargetDomainName` identify the attempted/logged-on account; do not substitute the subject reporting the operation.

| Normalized field | XML/source | Policy |
| --- | --- | --- |
| `schema_version` | Adapter contract | Literal `1.0`, not a Windows field. |
| `event_uid` | Identity formula below | Adapter-generated identity, not Event ID. |
| `timestamp` | `System/TimeCreated/@SystemTime` | String-based truncation to microseconds, then canonical UTC; never round. |
| `timestamp_raw` | `System/TimeCreated/@SystemTime` | Optional schema field preserving the original complete string. Emitted by this adapter. |
| `record_id` | `System/EventRecordID` | Optional positive integer schema field. Emitted by this adapter and used for ties. |
| `event_id` | `System/EventID` | Integer; 4624 is success, 4625 is failure. |
| `provider` | `System/Provider/@Name` | `Microsoft-Windows-Security-Auditing` for this rule. |
| `channel` | `System/Channel` | `Security` for this rule. |
| `destination_host` | `System/Computer` | Recording computer; never substitute `WorkstationName`. |
| `target_user` | `EventData/Data[@Name='TargetUserName']` | Keep separate from domain. |
| `target_domain` | `EventData/Data[@Name='TargetDomainName']` | Local account context may be the target computer name. |
| `source_ip` | `EventData/Data[@Name='IpAddress']` | Never invent from workstation name, target IP or filename. |
| `logon_type` | `EventData/Data[@Name='LogonType']` | Observed integer, not the planned connection method. |
| `status` / `sub_status` | Named `Status` / `SubStatus` payload fields | Optional context; absent values normalize to JSON `null`. |
| `data_origin` | Required CLI declaration | `synthetic` or `lab-captured`; a declaration alone does not prove authenticity. |

The core schema normalizer applies its existing account/host casefold and canonical-IP policies. The adapter emits only complete rule-scope events: the expected provider/channel, IDs **4624/4625**, types **3/10**, and usable domain/user/source-IP/target-host. Missing, empty, `-` or invalid correlation values never become plausible replacements. Other events are counted and their exclusion reasons are reported in `adapter-result.json`; they are not emitted as JSONL placeholder records. Per-record conversion failures are excluded with an explicit reason in the adapter result, rather than repaired or emitted. Structural XML ambiguities, unreadable input and file/limit failures abort the command. Original excluded content remains in `events.xml`.

The official [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) examples document field names. Their type-2/localhost examples establish structure, not the project's network-logon results.

## Event identity and provenance

For this lab the adapter uses the explicitly chosen identity:

```text
"windows-xml:" + sha256(UTF-8(Computer + "|" + Channel + "|" + EventRecordID))
```

`Computer` and `Channel` are the XML identity strings; `EventRecordID` is its parsed integer representation. The payload and timestamp are excluded so contradictory content for the same UID remains a detectable conflict. Identical source identities across overlapping exports produce the same UID. The report records the original input path and hash; emitted rows retain `timestamp_raw` and `record_id` for original-event lookup.

**Lab limitation:** record IDs can recur after clearing a log or restoring a VM/snapshot. This formula contains no log-generation/source-context field and cannot distinguish those generations. Do not combine such generations as if these UIDs were globally unique. A generation-aware identity remains a possible later change, outside this implementation request.

## Accepted precision policy

The user's decision on **2026-10-05** is to retain the microsecond schema/engine and **truncate**, rather than round, additional fractional digits using their string representation. For example, `.9999999Z` becomes `.999999Z`, never the next second. `timestamp_raw` preserves the full original `SystemTime`; the original XML is unchanged. Direct normalized `timestamp` values remain limited to six fractional digits.

The introduced time error is **less than 1 microsecond**. The nearest relevant event to the real capture’s **lower 300-second lookback boundary** is **65.1345863 seconds** away: the distance from success **53314** to success **53330**, less 300 seconds. This is over 65 seconds and supports that specific lower-boundary comparison; it is not a statement about every time boundary or a general native-precision guarantee. The inspector still shows exact microsecond representability warnings, because it inspects the unaltered original. Those warnings do not block the adapter under this accepted transformation policy.

When eligible events have the same normalized microsecond, `record_id` is the tiebreaker. A failure with a lower record ID than a same-microsecond success may precede that success; a higher/equal record ID does not. Existing legacy records without both record IDs retain the original exclusion of simultaneous failures. The lower time boundary stays inclusive. Record order approximates the intended ordering of this log; it does not guarantee original 100-ns chronological ordering in every Windows log or across log generations. `timestamp_raw` is retained as evidence and is not used to reintroduce exact native time arithmetic into this rule.

## Commands and artifacts

From `lab/` with the existing virtual environment activated:

```sh
python -m soc_detection_lab adapt-windows-xml --input data/lab-captured/pilot-01/events.xml --output reports/lab-captured/pilot-01/adapter --data-origin lab-captured
python -m soc_detection_lab analyze --input reports/lab-captured/pilot-01/adapter/events.jsonl --output reports/lab-captured/pilot-01/analysis
```

The adapter writes **`events.jsonl`** and **`adapter-result.json`** into its output directory. The latter exposes input provenance, accepted/excluded counts and reasons. Default input limits remain 10 MiB and 100000 XML events. Review output counts and reasons, as well as command success. No Windows step, new login or rights diagnostic is required for this existing capture.

The independently defined expectation is exactly one alarm: success **53330**, failures **53325–53329**, key **DESKTOP-7HFI2UV / lab-auth01 / 192.168.243.1 / DESKTOP-7HFI2UV / 3**, with textual identifiers casefolded in normalized output. Success **53314** must not alert because its window has only one matching failure. Four SYSTEM/type-5 events must be visibly outside scope. Do not adjust this expectation to make integration pass.

## Original-field inspection

```sh
python -m soc_detection_lab inspect-windows-xml --input data/documentation-examples/security-structure.xml
```

This versioned sample is [constructed synthetic material](../data/documentation-examples/README.md). The inspector writes no files, keeps selected raw strings, and labels inspection origin `unverified-export`; it does not certify authenticity or emit normalized events. For the private capture, use `data/lab-captured/pilot-01/events.xml` instead. Each `xml_event_index` is an input-event ordinal, not an XML line number.

Review missing correlation fields, source-IP validity, rule-scope flags, exact timestamp representability and issues. Scope checks alone do not certify field completeness. Exit 0 means inspection completed and can include visible quality/precision issues; exit 2 signals structural, unreadable-input or limit errors.

## Validation and remaining work

Tests use a small **synthetic** fixture, including truncation rather than rounding, scope exclusions, deterministic UIDs and record-ID ties. Private capture contents must not be copied into test fixtures. The complete-suite and real integration results are recorded separately in [validation](validation.md) and [project status](project-status.md).

The SPL query includes the same-microsecond record-ID exception and native evidence. The genuine capture has no normalized timestamp collisions; the separate synthetic boundary dataset exercises this branch. On 2026-10-06 both matched Python on Splunk 10.2.6 ([validation record](splunk-validation.md#validation-record-2026-10-06)). Successful local Windows/Python/Splunk work is not a claim of production SIEM validation or general detection coverage.
