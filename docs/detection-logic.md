# Detection specification

Name: **Repeated failed logons followed by a successful logon**.
Rule ID: `repeated-failed-logons-then-success`. Version: `1.0`.

This rule detects a temporal authentication pattern. It does not identify a person or prove guessing, credential theft, brute force, or compromise. The defaults are educational settings, not empirically tuned enterprise thresholds.

| Parameter | Default |
|---|---|
| Minimum failures | 5 |
| Lookback | 300 seconds |
| Selected logon types | 3 and 10, correlated separately |
| Correlation key | normalized domain, user, source IP, destination host, logon type |
| Preliminary alert priority | `medium` |

For every eligible deduplicated success `s` at time `t`, let `K(s)` be its correlation key. Its evidence failures are exactly:

```text
F(s) = { f | f.event_id = 4625
             and K(f) = K(s)
             and (t - window <= f.timestamp < t
                  or (f.timestamp = t
                      and f and s both have record_id
                      and f.record_id < s.record_id)) }
```

Emit one alert for that success if `len(F(s)) >= threshold`. Include every matching failure, the success, their UIDs, times and input provenance. Use the earliest included failure as the beginning of the demonstrated pattern and the success as its end. Dedupe before counting. Batch sorting uses normalized event time and, at equal microseconds, supplied record IDs before UID order. Arrival/file order is not evidence of causal order. Original `timestamp_raw` is retained as evidence but not used for native-precision detection arithmetic.

## Boundaries and grouping

At success time `09:05:00Z`, a failure at `09:00:00Z` counts; one at `08:59:59.999999Z` does not. The upper time boundary remains exclusive for legacy records without both record IDs: a failure at `09:05:00Z` does not count merely because it appears before the success in the file.

For native records, the accepted exception is a same-microsecond failure when **both events have `record_id` and the failure ID is smaller**. Equal/higher record IDs and ties without both IDs are excluded. This approximates ordering in the chosen Windows log after string-based timestamp truncation; it is not a universal guarantee of original 100-ns chronology across logs or restored generations. A failure with a later normalized timestamp never counts for that success. The lower time boundary remains inclusive. See [the native precision contract](windows-export-format.md).

Five failures spread across different users, domains, sources, targets or logon types do not combine into five failures for one key. Type 3 and type 10 failures cannot jointly cross the threshold. Missing or unusable key values exclude an event rather than creating a shared unknown-identity bucket.

An earlier success **does not reset the counter**. Two successes can each match the same preceding failures while those failures remain in their respective windows. Each success receives a separate alert. There is no suppression timer or deduplicating of alerts across successful events. These would be separate, versioned design changes.

## Configuration and stable identity

A threshold and time window must be positive integers. Selected logon types must be a nonempty subset of 3 and 10; order and repeated type arguments normalize to the same configuration. Invalid or unsupported parameter values fail explicitly; the CLI does not silently fall back to defaults.

Alert IDs are hashes over the rule ID, version, effective configuration and normalized successful event. They exclude generation time, source filename and input-line position. Changing input ordering therefore preserves alert IDs and the event/time evidence; changing rule parameters changes identity. The input hash and source-line references describe the actual run and can differ. Configuration and rule metadata appear in the report so an ID is interpretable in context.

Precisely, SHA-256 hashes ASCII-escaped canonical JSON with sorted keys and compact separators over `rule_id`, `rule_version`, `parameters`, and `success` (all normalized schema fields, without provenance). There is no report-generation timestamp. A fixed limit of 100000 total failure/success evidence references aborts analysis rather than truncating alerts when overlapping windows would create excessive output.

Rule results remain separate from human interpretation. `medium` means the demonstrated transition warrants context gathering because it may represent misuse; it is not a numeric probability. Sufficient benign context can explain a correct rule match, as [SYN-002](../reports/examples/SYN-002-legitimate.md) demonstrates. Missing context stays unresolved, as in [SYN-003](../reports/examples/SYN-003-unresolved.md).

## How this is checked

Tests specify manual expected UIDs for threshold, window, legacy simultaneous-time exclusion, native lower-record-ID ties, key separation, duplicates, conflicts, ordering, two successes, normalization, invalid records and parameter failures. End-to-end CLI checks exercise file generation, validation, analysis, and evaluation. The separate evaluation data tests another small set of manually defined expectations; it is not a generalization benchmark. Refer to [actual executed validation](validation.md) for observed results.

The SPL query consumes the normalized transport events and implements the same rule, including the native same-microsecond record-ID exception. On Splunk 10.2.6 it reproduced the Python alerts for the private capture and for a synthetic dataset that exercises the same-microsecond tie and the exact 300-second lower boundary; full semantic equivalence beyond these inputs is not claimed. A fixed five-minute bucket would not be equivalent to the rolling interval. Execution evidence and the comparison procedure are documented [separately](splunk-validation.md).
