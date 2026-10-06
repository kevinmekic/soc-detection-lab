# SYN-001: evidence and code walkthrough

Read-only review on **2026-10-01**. The current `analyze_file` result was compared once in memory with the saved fixture and generated demo JSON. Both matched exactly, including IDs, times, provenance, counts and rationale; both also matched the separately authored success/failure/key expectations. No existing test suite was repeated for this review because no discrepancy was found.

The normalized key is `lab / analyst01 / 192.0.2.10 / lab-server-01 / logon_type 3`. All event times below are UTC on 2026-01-15.

| Time | UID | Event | Fixture line | Seconds before success |
| --- | --- | --- | --- | --- |
| 09:00:00 | demo-001 | 4625 failure | 11, repeated identically at 15 | 180 |
| 09:00:20 | demo-002 | 4625 failure | 16 | 160 |
| 09:00:50 | demo-003 | 4625 failure | 18 | 130 |
| 09:01:30 | demo-004 | 4625 failure | 20 | 90 |
| 09:02:30 | demo-005 | 4625 failure | 21 | 30 |
| 09:03:00 | demo-006 | 4624 success | 7 | 0 |

For success `demo-006`, the window is `[08:58:00, 09:03:00)`. The five distinct failures share the complete key and fall inside it. The duplicate does not create a sixth failure. File order is not chronology; line 7's success is processed using sorted event times. Earlier successful events do not reset this rule's failure list.

The stable alert ID is `c0a6ec57dff9aee313b2243a7ac4a4dee6d5036ef86bf850254ebdb60451e652`. The full demo has 24 lines, 23 processed unique events, one duplicate, no exclusions/errors and three alerts. The four-failure account has no alert.

## Responsible code

References below were verified against the current source. The Python line numbers are also supplied for navigation:

| Responsibility | Source and lines |
| --- | --- |
| Defaults 5 / 300 / types 3 and 10 | [engine.py](../src/soc_detection_lab/engine.py), 35–39 |
| Complete key | `KEY_FIELDS`, line 21; `correlation_key`, 272–273 |
| Account/domain/host case normalization | `_text`, 105–117; call sites 140–141 |
| Dedupe before counting | `load_file`, 241–253 |
| Sort event time and UID | `load_file`, 264 |
| Collect failures by complete key | `detect`, 284–288 |
| Check only successful 4624 records | `detect`, 291–295 |
| Inclusive lower, exclusive success boundary | `detect`, 297–303: `bisect_left(start)` and `bisect_left(t)` |
| Exact evidence and preliminary medium priority | `detect`, 307–316 |
| Stable hash independent of file order and provenance | `candidate_alert_id`, 82–86 |

The analyzer loads the event input only. `expected.json` is used by the separate evaluator; `context.json` is not consumed by detection. The [full analyst report](../reports/examples/SYN-001-suspicious.md) calls this suspicious because of separately supplied fictional source-assignment/change context. Five failures followed by success can also reflect stale credentials. No attack, actor or compromise is established by this sequence alone.
