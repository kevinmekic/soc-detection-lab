# Normalized lab data model

Schema version: `1.0`. Each physical JSONL line represents one security event in a deliberately small **normalized lab schema**. Empty files are accepted as zero events; blank lines are invalid records. This is neither a native Windows export nor an EVTX parser. The supported use case is based on the Microsoft Windows Security Auditing provider and Security channel, using event IDs 4624 (success) and 4625 (failure). See the primary [sources](sources.md) for the Windows fields and logon types.

| Field | Meaning and policy |
|---|---|
| `schema_version` | String `1.0`; unsupported versions are structural errors. |
| `event_uid` | Non-empty string identifying one event within the logical input source; not the Event ID. |
| `timestamp` | ISO 8601 event time with an explicit UTC offset or `Z`; normalized to UTC at microsecond precision. |
| `timestamp_raw` | Optional original timestamp string, preserving native fractional digits. The Windows XML adapter emits it; detection still uses `timestamp`. |
| `record_id` | Optional positive integer Windows record number, used to break equal-microsecond ties when both events provide it. The XML adapter emits it. |
| `event_id` | Integer event kind, 4624 or 4625 for this rule. Other event IDs are outside this rule. |
| `provider` | Windows provider; this rule expects `Microsoft-Windows-Security-Auditing`. |
| `channel` | `Security` for this rule. |
| `destination_host` | Recording/target computer, not the remote client. Critical correlation field. |
| `target_user` | Target account name, separate from its domain. Critical correlation field. |
| `target_domain` | Account domain or local-account context. Critical correlation field. |
| `source_ip` | IP address of the remote source when available; critical for this rule. |
| `logon_type` | Integer Windows logon type; defaults select 3 and 10 separately. |
| `status`, `sub_status` | Optional failure context where present; not used to infer success. |
| `data_origin` | `synthetic` or `lab-captured`; all supplied fixtures are `synthetic`. |

Logon type 3 is Network and type 10 is RemoteInteractive. They do not describe the same activity and are never combined into one correlation group. Event 4624/4625 determines success/failure, regardless of context or filenames. These are Windows Security events, not Sysmon events or Entra sign-in records. A Windows event field can be absent or represented by a placeholder depending on authentication path; the schema does not invent a replacement.

## Normalization

1. Parse timezone-aware timestamps and convert them to UTC. A timestamp without a timezone is an error, not an assumption about the operator's local time.
2. Strip surrounding whitespace from textual correlation fields and apply Unicode `casefold()` to domain, user and host. This explicit lab policy is not a universal identity-resolution system.
3. Keep domain and user separate. `LAB/analyst01` and `OTHER/analyst01` are different identities. Do not split or resolve arbitrary account representations from native exports in this milestone.
4. Parse IP addresses with Python's `ipaddress` module, produce canonical addresses, and map IPv4-mapped IPv6 to the equivalent IPv4 address. No hostname lookup, NAT attribution, or source-ownership inference occurs.
5. Treat missing, empty, or placeholder (`-`) critical correlation values as unusable. Invalid source IPs are also excluded with a data-quality reason. Retain raw excluded records and source line information so they can be investigated.

Timestamps require uppercase `T`, seconds, optional one-to-six fractional digits, and `Z` or a numeric `±HH:MM` offset. Canonical UTC output always includes six fractional digits. Finer precision in a direct normalized `timestamp` is rejected. The Windows XML adapter explicitly truncates original fractional digits to six using strings, never rounding, and preserves the original in `timestamp_raw`; see [the accepted adapter policy](windows-export-format.md). Text fields reject control characters and unpaired Unicode surrogates. Scoped IPv6 addresses are excluded as invalid sources. Provider and channel spelling is exact; UID case is preserved, with surrounding whitespace stripped. Unknown schema fields, duplicate JSON keys, invalid UTF-8 and nonstandard JSON constants are structural errors. `timestamp_raw` and `record_id` are the two optional additions to schema `1.0`; existing synthetic/legacy inputs do not require them. If supplied, `record_id` must be a positive integer and `timestamp_raw` must be an explicit-timezone timestamp whose string-truncated, UTC-normalized microsecond value equals `timestamp`. Optional fields are retained in normalized output and canonical content, so contradictory original timestamps or record IDs for a UID remain detectable conflicts. Missing optional status fields normalize to null; missing critical string fields are quality exclusions. Required identity/time/version/origin and integer fields must validate structurally.

Neither `scenario` labels nor ground truth are detector inputs. Scenario descriptions and expected matches live in separate `context.json` and `expected.json` files. The dedicated evaluation fixture uses other identities, dates and combinations.

## Provenance and identity

The input path and physical line number accompany evidence and diagnostics. The report records a SHA-256 hash of the input bytes and declared data origins. File order therefore changes the input hash and line references; that is expected even when the event set and alerts are the same. `data_origin` is a declaration, not proof of authenticity.

The CLI reads one input file as a logical source. In that source, repeated UIDs with canonically equivalent normalized content count as duplicates and contribute only once. A repeated UID with different canonical content is a **data conflict** and aborts processing, including in `--skip-invalid` mode. Different UIDs remain distinct events even when all other fields happen to match. UID spelling/case is not an account-normalization target.

If a parseable but structurally invalid object shares a usable UID with another record, that identity is disputed and analysis also aborts in either input order. An unreadable JSON line has no reliable identity; explicit skip mode reports and omits it. Duplicate diagnostics retain both first and duplicate provenance. The first equivalent copy supplies the main evidence reference.

The Windows XML adapter implements the lab identity `windows-xml:` followed by SHA-256 of UTF-8 `Computer|Channel|EventRecordID`. Record IDs can repeat after log clearing or VM restore; this chosen formula has no log-generation field and is not globally unique. Do not concatenate those generations as one unambiguous input. Preserve original XML and its hash separately; emitted `timestamp_raw` and `record_id` permit lookup of the original event.

## Native timestamp ordering

Schema `1.0` remains a microsecond model. The adapter's truncation error is less than 1 microsecond; raw native strings retain original evidence, without making detection arithmetic native-precision aware. The nearest relevant event to the first real capture’s **lower 300-second lookback boundary** is **65.1345863 seconds** away: the distance from success 53314 to success 53330, less 300 seconds. This supports that specific lower-boundary comparison and does not establish safety at every boundary or a universal harmlessness guarantee.

For equal normalized microseconds, `record_id` supplies ordering when both records have one. A failure with a lower record ID may precede the success; equal/higher IDs do not. The lower lookback boundary is inclusive. For legacy events without both record IDs, simultaneous failures remain excluded. Record-number ordering is a lab approximation for this source, not a general guarantee of original 100-ns chronology across arbitrary logs or restored generations.

## Error and exclusion policy

Structural errors include invalid JSON, unsupported schema, invalid field types, and invalid/timezone-free timestamps. The default is strict: diagnostics identify the source line and cause and the command fails. Explicit `--skip-invalid` permits dropping structurally malformed lines with reported counts and issues. Missing critical correlation values, invalid source IPs and events outside the configured rule scope are visible exclusions, not security alerts. The raw excluded evidence is retained in the report.

The byte and event limits apply to input processing, not just the final deduplicated event count. Exceeding a limit is fatal rather than a partial success. Defaults are 10 MiB (`10485760` bytes) and `100000` events; CLI options make these bounds explicit. Sorting and keeping evidence in memory remain batch operations, not a streaming design.

Counts partition input lines into `processed` (eligible unique events), `duplicates`, `excluded` (unique quality/scope exclusions), and `errors` (invalid/conflicting records). Thus their sum is `input_lines` for a completed read. Multiple diagnostic messages can concern one line. Analysis additionally guards against more than 100000 total evidence references; it aborts without partial alerts. Export artifacts are written only after successful validation and detection, one file atomically at a time; the set of files is not a transactional bundle, so always check the command exit status.

`normalized.jsonl` contains only eligible deduplicated schema records without line metadata. `splunk-import.jsonl` adds two documented transport fields (`timestamp_epoch_us`, `candidate_alert_id`) for the later comparison; it is not a direct validator input. See [the SPL input contract](splunk-validation.md).

Exit codes are `0` for completed processing (which can include exclusions), `2` for invalid input/configuration, data conflicts or limits, and `3` for an evaluation mismatch. Always review the issue list and counts; a zero exit code alone does not certify complete telemetry.
