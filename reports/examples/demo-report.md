# Logon pattern analysis

Detected **3** rule matches. These are preliminary investigation leads, not confirmed attacks.

Input: data/fixtures/events.jsonl

SHA-256: `bb9afcdde3c036a125edeb99c92d59fc7d2a1948c358db7f93d16c50623b348d`

Origin: synthetic

Rule: `repeated-failed-logons-then-success` version `1.0`. Parameters: `{"logon_types": [3, 10], "threshold": 5, "window_seconds": 300}`.

| Input lines | Processed | Duplicate | Excluded | Invalid/conflicting |
| --- | --- | --- | --- | --- |
| 24 | 23 | 1 | 0 | 0 |

## Alert c0a6ec57dff9aee313b2243a7ac4a4dee6d5036ef86bf850254ebdb60451e652

Preliminary priority: **medium**. A success following repeated failures warrants triage; neither account impact nor malicious intent is established.

Key: target_domain=lab; target_user=analyst01; source_ip=192.0.2.10; destination_host=lab-server-01; logon_type=3

5 matching failures in \[2026-01-15T08:58:00.000000Z, 2026-01-15T09:03:00.000000Z\) precede this success; this pattern warrants triage but does not prove compromise.

### Observed evidence

| UTC time | Event UID | Event | Input line |
| --- | --- | --- | --- |
| 2026-01-15T09:00:00.000000Z | demo-001 | 4625 failure | data/fixtures/events.jsonl:11 |
| 2026-01-15T09:00:20.000000Z | demo-002 | 4625 failure | data/fixtures/events.jsonl:16 |
| 2026-01-15T09:00:50.000000Z | demo-003 | 4625 failure | data/fixtures/events.jsonl:18 |
| 2026-01-15T09:01:30.000000Z | demo-004 | 4625 failure | data/fixtures/events.jsonl:20 |
| 2026-01-15T09:02:30.000000Z | demo-005 | 4625 failure | data/fixtures/events.jsonl:21 |
| 2026-01-15T09:03:00.000000Z | demo-006 | 4624 success | data/fixtures/events.jsonl:7 |

### Suggested investigation (not confirmed observations)

- Was this activity expected and authorized?
- Were stored credentials recently changed?
- What do endpoint, authentication and change records show?
- Review authorization, credential changes and endpoint records before deciding on escalation.
- Consider stale credentials or user mistakes as benign explanations. No response action is executed.

## Alert f463f23efe71bdff826b94ebc97b7e8328768f81405f14adb40e5558fbb06f48

Preliminary priority: **medium**. A success following repeated failures warrants triage; neither account impact nor malicious intent is established.

Key: target_domain=lab; target_user=analyst02; source_ip=192.0.2.20; destination_host=lab-server-02; logon_type=3

5 matching failures in \[2026-01-15T09:08:00.000000Z, 2026-01-15T09:13:00.000000Z\) precede this success; this pattern warrants triage but does not prove compromise.

### Observed evidence

| UTC time | Event UID | Event | Input line |
| --- | --- | --- | --- |
| 2026-01-15T09:10:00.000000Z | demo-007 | 4625 failure | data/fixtures/events.jsonl:6 |
| 2026-01-15T09:10:20.000000Z | demo-008 | 4625 failure | data/fixtures/events.jsonl:23 |
| 2026-01-15T09:11:00.000000Z | demo-009 | 4625 failure | data/fixtures/events.jsonl:24 |
| 2026-01-15T09:11:40.000000Z | demo-010 | 4625 failure | data/fixtures/events.jsonl:10 |
| 2026-01-15T09:12:20.000000Z | demo-011 | 4625 failure | data/fixtures/events.jsonl:3 |
| 2026-01-15T09:13:00.000000Z | demo-012 | 4624 success | data/fixtures/events.jsonl:8 |

### Suggested investigation (not confirmed observations)

- Was this activity expected and authorized?
- Were stored credentials recently changed?
- What do endpoint, authentication and change records show?
- Review authorization, credential changes and endpoint records before deciding on escalation.
- Consider stale credentials or user mistakes as benign explanations. No response action is executed.

## Alert f0925d7deacacbd14a5c6c34fdb42031e13d0c034bd978b48773fb9faad61afd

Preliminary priority: **medium**. A success following repeated failures warrants triage; neither account impact nor malicious intent is established.

Key: target_domain=lab; target_user=analyst03; source_ip=198.51.100.30; destination_host=lab-server-03; logon_type=10

5 matching failures in \[2026-01-15T09:17:00.000000Z, 2026-01-15T09:22:00.000000Z\) precede this success; this pattern warrants triage but does not prove compromise.

### Observed evidence

| UTC time | Event UID | Event | Input line |
| --- | --- | --- | --- |
| 2026-01-15T09:20:00.000000Z | demo-013 | 4625 failure | data/fixtures/events.jsonl:12 |
| 2026-01-15T09:20:15.000000Z | demo-014 | 4625 failure | data/fixtures/events.jsonl:17 |
| 2026-01-15T09:20:45.000000Z | demo-015 | 4625 failure | data/fixtures/events.jsonl:9 |
| 2026-01-15T09:21:15.000000Z | demo-016 | 4625 failure | data/fixtures/events.jsonl:14 |
| 2026-01-15T09:21:45.000000Z | demo-017 | 4625 failure | data/fixtures/events.jsonl:2 |
| 2026-01-15T09:22:00.000000Z | demo-018 | 4624 success | data/fixtures/events.jsonl:19 |

### Suggested investigation (not confirmed observations)

- Was this activity expected and authorized?
- Were stored credentials recently changed?
- What do endpoint, authentication and change records show?
- Review authorization, credential changes and endpoint records before deciding on escalation.
- Consider stale credentials or user mistakes as benign explanations. No response action is executed.

## Data quality

| Kind | Input line | Explanation |
| --- | --- | --- |
| duplicate | 15 | identical normalized event ignored |

## Limits

Only equal domain, user, source IP, destination host and logon type correlate. The lower time boundary is inclusive; the success timestamp is excluded. Previous successes do not reset the window.

Missing logs, distributed sources, slow attempts, password spraying and other logon types can evade this rule. Legitimate retries can trigger it. This bounded in-memory batch result is not a streaming SIEM or proof of compromise. Synthetic data and Python verification do not validate Windows ingestion or SPL execution.
