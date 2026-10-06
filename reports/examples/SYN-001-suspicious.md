# SYN-001 — A suspicious network-logon pattern

**Origin:** entirely synthetic event and context data. **Assessment:** suspicious; compromise is unconfirmed. **Preliminary priority:** medium. **Success event:** `demo-006`. Case identifiers and event identifiers are different from the generated stable alert ID; locate that ID by `success.event_uid = demo-006` in [demo-results.json](demo-results.json).

## Summary and question

Five distinct failed Network logons for `LAB/analyst01` from `192.0.2.10` to `LAB-SERVER-01` occur within three minutes before a successful logon at `2026-01-15T09:03:00Z`. The defined rule matches. In the separately supplied fictional context, the client is not assigned to this account and no matching scheduled activity is listed. This warrants investigation, but neither the sequence nor the contextual inconsistency proves unauthorized access.

The investigation asks: **Does this success follow a legitimate retry sequence or potentially unauthorized authentication, and what evidence would distinguish those explanations?**

## Scope and evidence provenance

The event source is [data/fixtures/events.jsonl](../../data/fixtures/events.jsonl), a seed-42 normalized lab fixture. It is not an actual Windows export. The semantic grouping is normalized domain `lab`, user `analyst01`, source `192.0.2.10`, target `lab-server-01`, and logon type `3` (Network). No other account, domain, address, target or type contributes to the five failures.

The source-IP-to-client mapping `192.0.2.10` → `LAB-CLIENT-01` exists only in [context.json, case SYN-001](../../data/fixtures/context.json). The event records do not prove device ownership. All provider/channel values identify the intended Windows Security Auditing/Security source, but their synthetic origin remains explicit.

## Timeline

All times are UTC on **2026-01-15**. Line numbers refer to the checked-in seed-42 fixture above, not arbitrary regenerated input order.

| Time | Event UID | Event ID | Fixture line(s) | Seconds before success | Observation |
|---|---|---:|---|---:|---|
| 09:00:00 | `demo-001` | 4625 | 11, 15 | 180 | One failure; the second copy is a duplicate. |
| 09:00:20 | `demo-002` | 4625 | 16 | 160 | Failure with the same key. |
| 09:00:50 | `demo-003` | 4625 | 18 | 130 | Failure with the same key. |
| 09:01:30 | `demo-004` | 4625 | 20 | 90 | Failure with the same key. |
| 09:02:30 | `demo-005` | 4625 | 21 | 30 | Fifth distinct qualifying failure. |
| 09:03:00 | `demo-006` | 4624 | 7 | 0 | Success; triggers the retrospective check. |

The input is deliberately not sorted by time. The extra copy of `demo-001` cannot increase the count. Each of the five distinct failures lies in `[08:58:00, 09:03:00)`. There is no need to assume an ordering among simultaneous events in this case.

## Rule and review filter

Applied rule: `repeated-failed-logons-then-success`, version `1.0`, threshold `5`, window `300` seconds, selected types `3,10` separately. The logical evidence filter used for this write-up is:

```text
domain=lab AND user=analyst01 AND source_ip=192.0.2.10
AND destination_host=lab-server-01 AND logon_type=3
AND event_id=4625
AND 2026-01-15T08:58:00Z <= timestamp < 2026-01-15T09:03:00Z
```

This is a readable predicate, not a claim of executed SPL. Select success UID `demo-006` in the generated JSON and compare its five failure UIDs/times with the table. Running the README analysis command evaluates all cases; it does not consume the scenario assessment. [expected.json](../../data/fixtures/expected.json) independently lists these expected UIDs. The [SPL query](../../docs/splunk-validation.md) remains reviewed but unexecuted in Splunk.

## Observations, context and hypotheses

**Observed in the supplied events:** five unique 4625 records precede one 4624 record with the same complete key. The pattern meets the declared threshold and time condition. Failure status fields are synthetic metadata; the event ID determines success/failure. There is no captured session activity after the success in this dataset.

**Separately supplied synthetic context:** the fictional inventory assigns `192.0.2.10` to `LAB-CLIENT-01`; the fictional access matrix does not assign that client to `analyst01`; the fictional change calendar has no scheduled activity for this account, target and time. These are invented scenario facts, not real asset lookups, user conversations or approved change records.

**Working hypothesis:** the unexpected client context increases concern that the successful login may be unauthorized. Repeated failures could fit attempts to find or reuse valid credentials. This remains a hypothesis; no technique or actor has been proven.

**Plausible benign alternative:** an authorized person may have used another shared client whose saved credentials were stale, then corrected them. An incomplete access matrix or unrecorded legitimate activity could explain the contextual mismatch. No actual user confirmation or endpoint capture is available to resolve that alternative.

**Assumptions and missing evidence:** the synthetic fields and timing represent the fixture accurately; they do not establish real clock accuracy, capture completeness, source ownership at the time, account privilege, or the actions performed in the successful session. Absence from a change calendar alone does not establish lack of authorization.

## Assessment and requested next steps

Keep provisional priority at **medium**: the event sequence and inconsistent expected access merit timely review, while the small count, missing session activity and plausible benign alternative do not justify a confirmed-compromise label. No numeric attack probability is assigned.

1. In a future real lab, preserve the original relevant export and determine audit coverage/time range. Purpose: prevent a misleading interpretation based on an incomplete sequence. Operational impact: scoped read access and storage only.
2. Verify source ownership at the event time, intended account usage and any actual approved change with independently recorded evidence. Purpose: test the shared-client/stale-credential explanation. There has been no such contact or lookup here.
3. Review available session and endpoint activity after `09:03:00Z`, account role and additional targets within the authorized scope. Purpose: determine whether the success led to unusual access. This evidence is absent from the fixture.
4. Escalate for incident-response review if verified source/account use is unauthorized, unexpected privileged activity appears, or the sequence recurs across targets. Retain the rule evidence and distinguish any new facts from the original hypothesis.

An account restriction would aim to prevent further access but could interrupt the user's work or services. Credential rotation could reduce reuse of an exposed credential but could also break clients with cached credentials. Host isolation could restrict further access but interrupt network functions and evidence collection. Such measures require additional justification and the applicable authorization process; **none has been executed or is automatically triggered by this rule**.

## Limits and disposition

Disposition: **suspicious, investigation required in a real equivalent case**. This report demonstrates reasoning from synthetic evidence, not resolution of a real incident. The rule cannot identify an actor, prove brute force, verify a password was guessed or stolen, see distributed/slow attempts, or establish what the successful session did. A validated benign explanation could change the assessment without changing the technically correct rule match.
