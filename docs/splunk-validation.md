# Splunk transfer and comparison

| Query | Language / documentation version | Status | Execution evidence |
| --- | --- | --- | --- |
| [`repeated-failed-logons-then-success.spl`](../queries/splunk/repeated-failed-logons-then-success.spl) | SPL; original 10.0 reference, executed on Splunk Enterprise **10.2.6** (build bcdcf0552e0c), macOS Intel | **lab-validated** for the two datasets below on this version | [Validation record 2026-10-06](#validation-record-2026-10-06) |

Original review: **2026-10-01**; native ordering/export revision: **2026-10-05**. Official command/function references and the reviewed
sections are in [sources](sources.md). Python tests and a tested comparison
script do not count as execution of SPL. The user has chosen a user-directory macOS Intel `.tgz` installation, Trial license, no root, service or autostart, with Windows shut down during Splunk use. The [macOS runbook](splunk-macos-runbook.md) gives the concrete installation/import/stop/removal steps. Installation, import and searches were performed on 2026-10-06; see the validation record. The original private capture has **8** transport events, and the [synthetic boundary dataset](../data/splunk-boundaries/README.md) has **14**. Their sources are `soc-lab-pilot-01` and `soc-lab-boundaries-01`, respectively.

## Validation record 2026-10-06

- **Instance:** Splunk Enterprise 10.2.6, build bcdcf0552e0c, Darwin-x86_64, `.tgz` under the user's home, bound to `127.0.0.1` (listeners 8000, 8089, 8065, 8191 verified). The 10.2.7 archive named in earlier planning was not used.
- **License:** the archive contained no license file, and the linked updated `enttrial.lic` host did not resolve (DNS NXDOMAIN). The first start created `etc/licenses/download-trial/enttrial.lic` itself. License Manager showed the Trial group active until 2026-12-05, 500 MB/day, no violations.
- **Import:** one Oneshot each into index `soc_lab`, sourcetype `soc_lab:normalized:json`; no timestamp or line-breaking warnings in `splunkd.log`.
- **Inventory:** `compare_inventory.py` matched **8/8** (`soc-lab-pilot-01`) and **14/14** (`soc-lab-boundaries-01`) UIDs, keys, native metadata, original indexed `_time` and parsed `timestamp` at microsecond precision.
- **Detection:** executed with `splunk search "<query>" -earliest_time 0 -maxout 0 -output json`; JSONL rows were converted to JSON arrays and originals retained. `compare_results.py` matched **1** alert for the capture (success RecordID 53330, failures 53325–53329, no alert for 53314) and **2** alerts for the boundary dataset (1006 ← 1001–1005, 2006 ← 2001–2005; 1007 and 2000 excluded). Scan counts 8 and 14; the detection jobs' `search.log` contained no warnings apart from KV-store certificate verification and the `soc_lab` bucket-size notice (default `maxDataSize` 750 MB above the 128 MB index cap; irrelevant for 22 events).
- **Corrections found by execution** (both queries re-run after the fix; first outputs retained privately):
  1. `inspect_import.spl` parsed the literal `Z` without a time zone, so `strptime` used the search user's local zone (CEST) and was 7,200 s off. It now parses `+0000` with `%z`. Index-time `_time` was correct throughout.
  2. Splunk 10.2.6 rejects `json_extract` inside `mvmap` (`The arguments to the 'mvmap' function are invalid`). `failure_uids` are now taken from one JSON array via `json_array_to_mv(json_extract(..., "{}.event_uid"))`; a separate check confirmed exact round-trips for UIDs with quotes, backslashes, commas, brackets and non-ASCII characters.
- **CLI caveat:** for the failed search, `splunk search` exited 0 with empty stdout; the error was only visible in the job's dispatch `search.log`. An empty CLI result therefore needs the job log, not just the exit code.
- **Query SHA-256 after the fixes:** `inspect_import.spl` a6ea5386cc13f283c30ee5f763e5073d3f397180a5a7f285a070c18cf0410f38, `repeated-failed-logons-then-success.spl` b7f944dbd0257e39f7dd675564dd7345c2f8e51c127e054f709ef6eb5fbc92d9.
- **Evidence (private, not versioned):** `reports/lab-captured/splunk-01/` with raw and converted exports, job IDs, copied `search.log` files and `run-record.json` (input/output hashes).

This validates this query on these two inputs and this Splunk version; it does not claim general Python/SPL equivalence or vendor support for the platform.

## Input contract

Run the offline Python analysis first. Import its `splunk-import.jsonl`, with
the accompanying `results.json`, rather than the original input file. The
export contains only valid, eligible, normalized and deduplicated events.
Python has already rejected conflicting UIDs. Preserve the original input,
its hash, excluded records and quality messages in the Python report: the SPL
query does not replace the validator or independently test its normalization.

`splunk-import.jsonl` adds two transport fields to the lab schema:

- `timestamp_epoch_us`: exact UTC microseconds since 1970-01-01, derived from
  `timestamp`. Correlation uses integer arithmetic; `_time` is this value
  divided by 1,000,000. The query requires nonnegative values no greater than
  9,007,199,254,740,991, to remain in Splunk's exact integer range. This bound is
  narrower than the Python date range.
- `candidate_alert_id`: the deterministic Python ID for **every** eligible
  success, even those below the threshold; null for failures. It encodes the
  rule, effective configuration and success content. It is an identity, not a
  detection label. SPL independently selects qualifying successes but carries
  this digest; it does not independently reproduce Python's JSON serialization
  and SHA-256 identity implementation.

`normalized.jsonl` remains the plain lab schema, suitable for re-analysis.
The transport also retains optional **record_id** and **timestamp_raw** from the schema. Present record IDs must be positive integers no greater than **9007199254740991** for exact numerical ordering in this SPL, a narrower contract than Python. Neither file is native Windows XML/EVTX; the implemented XML adapter supplies normalized native events first.

## Later import procedure

1. Record Splunk's actual version, input SHA-256, exact query and effective
   Python parameters. Use a disposable, private lab dataset with **at most
   1,000 events**. This intentionally bounded batch method materializes all
   failures for each key and is not suitable for production-scale searches.
2. Use the runbook's **Oneshot CLI** to import each exported JSONL once,
   with one complete JSON object per event. Use the own index `soc_lab`,
   sourcetype `soc_lab:normalized:json` and source `soc-lab-pilot-01`. Give another
   batch a different source and change the query's source filter accordingly.
3. Preview timestamp extraction from `timestamp`, which is canonical UTC ISO
   8601 with six fractional digits and a `Z` suffix. Verify `_time` represents
   that same instant; the search explicitly sets `_time` from
   `timestamp_epoch_us` as well. **Use All time for this isolated source.** A
   search-time correction cannot restore records already removed by an
   incorrect index-time timestamp or a restrictive time picker.
4. Before running detection, run [`inspect_import.spl`](../queries/splunk/inspect_import.spl) with **All time** and the selected source. It copies original indexed `_time` **before any correction**, extracts all UIDs, times, key fields and native metadata, and reports integer-microsecond projections for original `_time` and independently parsed `timestamp`. Export every row as JSON and run:

   ```sh
   .venv/bin/python queries/splunk/compare_inventory.py --normalized reports/lab-captured/pilot-01/analysis/splunk-import.jsonl --splunk-results reports/lab-captured/splunk-01/pilot-inventory.json
   ```

   For boundaries use the corresponding generated transport and `boundaries-inventory.json`. The verifier rejects missing/extra/duplicate UIDs, differing keys/native metadata, or `_time`/parsed-time values that disagree with the original canonical timestamp at microsecond precision. Floating-point `_time` is projected using `round(...*1000000)`; transported integer microseconds remain exact within the bound. This checks the chosen microsecond schema, not original 100-ns accuracy. The configured `TIME_FORMAT` uses `%6N`, and `ADD_EXTRA_TIME_FIELDS=subseconds` retains subsecond indexing fields. Do not overwrite `_time` with the supplied epoch before this check, as that would conceal incorrect ingestion.
5. Paste the saved detection query into Search. Its defaults are threshold 5,
   window 300 seconds, types 3 and 10. If Python parameters change, update the
   SPL threshold/window and both the `logon_types` metadata string and allowed
   type condition. Recreate the export so candidate IDs encode the same
   configuration. Do not compare different configurations.
6. Inspect job messages/Job Inspector. Any truncation, extraction, memory or
   other search warning invalidates the comparison; do not merely increase
   limits or accept a partial result. The query also surfaces `invalid-batch`
   rows for missing correlation fields, duplicate import, more than 1,000 rows,
   invalid time range or incomplete per-key failure aggregates. Investigate
   these instead of interpreting the output as security alerts. An empty
   result is meaningful only after the complete import check succeeded.

The own index and sourcetype templates were installed as the local app `soc_detection_lab` for the 2026-10-06 run. No service
or autostart was created. Splunk Enterprise and Splunk
Enterprise Security have different scopes; this search promises no ES
integration. The chosen Trial/platform and setup findings are documented in the runbook and the validation record.

## Why the correlation matches the rule

The query groups by all five normalized fields: domain, user, source IP, destination host and logon type. It gathers distinct paired failure evidence and evaluates it separately for each success. A failure counts at `t-window <= failure_time < t`, plus the explicitly accepted native case at `failure_time=t` when both IDs exist and the failure has a smaller RecordID. Missing IDs retain the legacy exclusive success timestamp. Earlier successes reset nothing.

Sorting uses numeric event time, ID-presence flag, numeric RecordID and UID. The token prefix holds a 20-digit time, one ID-presence flag and a 20-digit ID slot, followed by a JSON evidence object. Missing IDs use an internal prefix slot only; the JSON evidence retains null. `values` keeps distinct tokens together, `mvmap` applies the time/ID predicate, and `mvfilter` removes rejected tokens. `failure_uids` are extracted from one JSON array of the evidence objects, because 10.2.6 does not accept `json_extract` inside `mvmap`. UID/time/native metadata stay paired through JSON, including legacy records with absent fields and UIDs containing colons or quotes.

The private capture has no same-microsecond collisions. The separate synthetic dataset exercises five smaller-ID failures and an excluded larger-ID failure in one microsecond, and the exact 300-second boundary with one error just outside it. Python produced its two predeclared alerts, and Splunk 10.2.6 produced the same two on 2026-10-06.
There are no fixed five-minute buckets, `list` truncation after 100 entries or
`streamstats` event-window caps. `values` and `eventstats` still have deployment
resource/configuration limits: aggregate count checks, the 1,000-record scope,
complete import verification and clean job messages are required. The semantic
equivalence is conditional on this input contract and a complete successful
search, including the separate boundary dataset. It was demonstrated for these two datasets on Splunk 10.2.6; beyond them it remains reasoned from documentation.

## Export and compare

Export the complete detection table as a **JSON array of objects**, preserving
multivalue fields as JSON arrays. Do not export a truncated table or flatten
the evidence into comma-delimited text. If a Splunk export facility wraps rows
in another object or emits JSONL, convert that container explicitly to the
documented array format while preserving each row; retain the original export.

Required fields are `result_status`, `rule_id`, `rule_version`, `threshold`,
`window_seconds`, `logon_types` (for defaults, the string `3,10`), `alert_id`,
`success_uid`, `success_time_us`, the five correlation fields, `failure_count`,
`failure_uids` and `failure_times_us`. The latter two arrays have matching
positions. The revision additionally exports **success_record_id**, **success_timestamp_raw** and **failure_evidence**. Each failure-evidence entry is a JSON object string with `event_uid`, decimal-string `timestamp_epoch_us`, decimal-string/null `record_id` and original-string/null `timestamp_raw`; the paired objects avoid shifting metadata when optional fields are absent. The comparator requires native metadata when present in the Python reference and cross-checks these objects against the UID/time arrays. Legacy exports with no native metadata remain compatible. Times are decimal integer strings. A singleton multivalue may be
exported as a scalar; the comparator accepts either representation.

From the project directory, after a real export exists:

```bash
python queries/splunk/compare_results.py --python-results reports/generated/results.json --splunk-results /path/to/splunk-results.json
```

The script fails with exit 1 on missing/extra alerts, duplicate success rows,
an invalid batch, differing rule parameters, keys, failure counts,
success times, time/UID evidence pairs or native metadata. Input/export hashes must be recorded independently; the comparator does not receive or verify file hashes. Success exits 0. It matches by success
identity and compares full evidence, allowing only harmless row ordering
differences. Matching `alert_id` verifies that the selected success carries
the reference digest; because the digest was transported from Python, this is
not an independent test of ID generation. Checking input completeness and job
status remains a separate required step.

Record the query, actual Splunk version, input/export hashes, job messages,
comparison command and observed output in a new validation record. Only then
may this specific query/data/version combination be marked `lab-validated`.

## Search horizon and arrival limits

To analyze successes during `[A, B)`, source data must include failures from
`A - 300 seconds` and successes through `B`; restrict successes to `[A, B)`
only **after** correlation. For the prepared small-file comparison, searching
the whole isolated source is simpler and avoids a horizon mismatch. A late
failure can change evidence and cause a previously unqualified success to
qualify. Version 1 expects the complete batch; it defines no live scheduling,
lateness watermark, suppression or automatic response.
