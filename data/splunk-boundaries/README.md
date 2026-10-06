# Synthetic Splunk boundary dataset

These **14 hand-specified synthetic events** are not Windows capture evidence. They use the same XML adapter → normalized analysis/transport → Oneshot import pipeline as the private capture. XML order is deliberately scrambled; all source identities and IPs are fictitious. Expectations are specified independently of detection.

| Case | Expected success | Expected failures | Explicit exclusions from that alert |
| --- | --- | --- | --- |
| Same normalized microsecond, type 3 | RecordID 1006 | 1001–1005 | 1007 has a higher RecordID in that microsecond |
| Exact 300-second lower boundary, type 10 | RecordID 2006 | 2001–2005 | 2000 is one microsecond before the lower boundary |

The first case truncates `.9999991` through `.9999997` to `.999999`; rounding would incorrectly advance some events to the next second. The second has failure 2001 exactly 300 seconds before success 2006; their matching fractional digits truncate identically. Failure 2000 truncates to `.123455` while the lower boundary is `.123456`. Both expected alerts contain exactly five failures. Earlier successes reset nothing, and the two accounts/types are separate keys.

From `lab/`:

```sh
.venv/bin/python -m soc_detection_lab adapt-windows-xml --input data/splunk-boundaries/events.xml --output reports/generated/splunk-boundaries/adapter --data-origin synthetic
.venv/bin/python -m soc_detection_lab analyze --input reports/generated/splunk-boundaries/adapter/events.jsonl --output reports/generated/splunk-boundaries/analysis
.venv/bin/python -m soc_detection_lab evaluate --input reports/generated/splunk-boundaries/adapter/events.jsonl --expected data/splunk-boundaries/expected.json
```

Import the analysis `splunk-import.jsonl` once with source **soc-lab-boundaries-01**, isolated from **soc-lab-pilot-01**. Use the same configured sourcetype, query and default parameters; change only the source filter. A passing Python evaluation does not establish an executed Splunk result; Splunk 10.2.6 produced the same two alerts on 2026-10-06 ([validation record](../../docs/splunk-validation.md#validation-record-2026-10-06)). See [the macOS runbook](../../docs/splunk-macos-runbook.md).
