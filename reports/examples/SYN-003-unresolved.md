# SYN-003 — A matching pattern with insufficient context

**Origin:** entirely synthetic. **Assessment:** unresolved. **Preliminary priority:** medium. **Success event:** `demo-018`. Find the stable alert ID by success UID in [demo-results.json](demo-results.json).

## Summary and question

Five failed type-10 logons for `LAB/analyst03` from `198.51.100.30` to `LAB-SERVER-03` precede a successful type-10 logon at `2026-01-15T09:22:00Z`. The events meet the rule definition. Type 10 is RemoteInteractive, but these synthetic records are not proof that a real Remote Desktop session took place.

The question is whether the success was intended activity or unauthorized access. Source ownership, authentication intent, endpoint follow-up and session actions are absent. Those gaps prevent a defensible final classification.

## Evidence and timeline

Source: [data/fixtures/events.jsonl](../../data/fixtures/events.jsonl). [context.json, SYN-003](../../data/fixtures/context.json) explicitly supplies no corroborating context. Key: normalized domain `lab`, user `analyst03`, source `198.51.100.30`, target `lab-server-03`, type `10`. This key is separate from every type-3 scenario.

All times below are UTC on **2026-01-15**. Line numbers refer to the checked-in seed-42 fixture.

| Time | Event UID | Event ID | Fixture line | Seconds before success |
|---|---|---:|---:|---:|
| 09:20:00 | `demo-013` | 4625 | 12 | 120 |
| 09:20:15 | `demo-014` | 4625 | 17 | 105 |
| 09:20:45 | `demo-015` | 4625 | 9 | 75 |
| 09:21:15 | `demo-016` | 4625 | 14 | 45 |
| 09:21:45 | `demo-017` | 4625 | 2 | 15 |
| 09:22:00 | `demo-018` | 4624 | 19 | 0 |

Rule `repeated-failed-logons-then-success` `1.0` counts five failures in `[09:17:00, 09:22:00)`. The readable review predicate is:

```text
domain=lab AND user=analyst03 AND source_ip=198.51.100.30
AND destination_host=lab-server-03 AND logon_type=10
AND event_id=4625
AND 2026-01-15T09:17:00Z <= timestamp < 2026-01-15T09:22:00Z
```

Compare success UID `demo-018` and the five failure UIDs with [expected.json](../../data/fixtures/expected.json) and generated output. This predicate describes the review, not a claim of SPL execution. The [SPL status](../../docs/splunk-validation.md) remains separate from Python validation.

## Observations, hypotheses and unknowns

**Observed in the supplied events:** five unique failed records precede one successful record with identical normalized key fields. They span two minutes before the success and meet the didactic threshold. The pattern itself is established.

**Context status:** no additional corroborating context is supplied. There is no real asset lookup, approved change, user confirmation or EDR evidence in this case. Absence of such context is a limitation of the investigation, not evidence that no approved activity existed.

**Suspicious hypothesis:** an unauthorized person may have tried credentials and eventually gained access. The pattern is compatible with that explanation but does not demonstrate it.

**Plausible harmless hypothesis:** an authorized remote user may have mistyped or reused a stale password and then logged on successfully. A shared source or reassigned address may further complicate attribution. Those possibilities are also unconfirmed.

**Assumptions:** the fixture timestamps and key fields are interpreted according to the lab schema. The source address is not treated as an identified person or a verified endpoint. There is no basis to assume account privilege, post-login behavior, real clock accuracy or complete surrounding telemetry.

## Assessment and evidence requests

Keep the case **unresolved at provisional medium priority**. A success after repeated failures merits review; missing context does not justify either confirmed-compromise status or benign closure. No numerical confidence or attack probability is assigned.

For a real equivalent case, request source ownership at the event time, the account's expected access/privilege, authorization and intent for this target, capture/audit completeness, and available session/endpoint activity immediately after the success. Record each source of context separately. These requests have not been sent in this lab.

Assign a review owner and follow-up time under the organization's actual process; neither an owner nor a service deadline is invented here. Escalate if verified access was unauthorized, account privilege increases the impact, further suspicious session activity appears, or repeated unexplained activity broadens the scope. If the requested data cannot be obtained, document that residual uncertainty and disposition explicitly instead of silently closing as benign.

An account restriction would reduce further account access but could stop authorized remote work and dependent services. Host isolation could interrupt the remote session and other network functions while aiming to limit further misuse. Credential rotation could invalidate a potentially exposed secret but require coordinated updates. Each needs evidence, authorization and a recovery plan proportionate to impact. None is executed automatically or recommended solely because context is missing.

## Limits and disposition

Disposition: **open/unresolved in the synthetic exercise**. The technical rule match is certain under the fixture and configuration; malicious intent and actual session consequences remain unknown. This report demonstrates how to preserve a useful alert without inventing investigative evidence or overstating what authentication logs establish.
