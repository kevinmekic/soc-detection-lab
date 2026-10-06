# SYN-002 — A legitimate retry sequence that matches the rule

**Origin:** entirely synthetic. **Assessment:** explained as legitimate using explicitly fictional context. **Rule priority:** medium before context; analyst follow-up priority is low within this constructed scenario. **Success event:** `demo-012`. Find the generated alert by its success UID in [demo-results.json](demo-results.json).

## Summary and question

Five failed Network logons for `LAB/analyst02` from `192.0.2.20` to `LAB-SERVER-02` precede a success at `2026-01-15T09:13:00Z`. This correctly triggers the same rule as SYN-001. The supplied fictional explanation is a scheduled network-drive reconnect with stale credentials after an approved lab password rotation; the fictional operator corrects the cache before the success.

The question is whether sufficient context explains the repeated failures and eventual success. In this educational scenario it does. The account activity is **not declared benign by the detector**: the detector sees only the events, and the analyst interpretation uses a separate context document.

## Evidence and timeline

Event source: [data/fixtures/events.jsonl](../../data/fixtures/events.jsonl). Context: [context.json, SYN-002](../../data/fixtures/context.json). Normalized key: `lab`, `analyst02`, `192.0.2.20`, `lab-server-02`, type `3` (Network). No client hostname or real source-owner confirmation is established by the supplied events.

All times below are UTC on **2026-01-15**. Line numbers refer to the checked-in seed-42 fixture.

| Time | Event UID | Event ID | Fixture line | Seconds before success |
|---|---|---:|---:|---:|
| 09:10:00 | `demo-007` | 4625 | 6 | 180 |
| 09:10:20 | `demo-008` | 4625 | 23 | 160 |
| 09:11:00 | `demo-009` | 4625 | 24 | 120 |
| 09:11:40 | `demo-010` | 4625 | 10 | 80 |
| 09:12:20 | `demo-011` | 4625 | 3 | 40 |
| 09:13:00 | `demo-012` | 4624 | 8 | 0 |

Applied rule: `repeated-failed-logons-then-success` `1.0`, five failures in 300 seconds. All five distinct failures match the full key and lie in `[09:08:00, 09:13:00)`. The review predicate is:

```text
domain=lab AND user=analyst02 AND source_ip=192.0.2.20
AND destination_host=lab-server-02 AND logon_type=3
AND event_id=4625
AND 2026-01-15T09:08:00Z <= timestamp < 2026-01-15T09:13:00Z
```

This predicate documents the evidence selection; it is not executed SPL. Compare success `demo-012` and failure UIDs `demo-007`–`demo-011` with [independent expectations](../../data/fixtures/expected.json) and the generated JSON. The general CLI analysis is described in the README; the detector must still alert if the analyst assessment is changed or the context file is unavailable.

## Distinguishing evidence from explanation

**Observed in events:** five failures, then one success, for one key. The data supports the rule match and its timing. It does not itself show a password change, a scheduled reconnect, a corrected credential cache or user intent.

**Supplied fictional context:** an approved lab password rotation precedes the failures; a scheduled network-drive reconnect uses old saved credentials; the fictional lab operator updates them before the success. These are scenario facts in a synthetic context file. No real ticket, actual operator conversation or endpoint capture is claimed.

**Benign hypothesis supported by that context:** the reconnect first fails using stale credentials and succeeds after correction. This explains both stages of the observed pattern. The supplied explanation is accepted for the exercise only; a real case would require its own corroboration.

**Alternative requiring attention without that context:** unauthorized credential use could also produce the sequence. An attacker could coincidentally act near a password change. A nominally approved change is insufficient by itself if the source, account or later actions differ from the expected activity.

**Assumptions and missing evidence:** real change records, source mapping, operator confirmation, cache-remediation logs and post-success endpoint/session activity are unavailable. The fixture cannot independently validate the narrative. No earlier/later activity beyond the dataset is inferred.

## Assessment, action and escalation

Within the explicitly fictional scenario, classify this as **legitimate activity producing a correct rule match**, and lower the analyst follow-up priority to low once that context is accepted. This illustrates an operational false-positive source, not an error in the implementation or reason to remove the expected alert from tests.

In a real equivalent case, first corroborate the change, source and corrected retry mechanism. Remediate the stale credential storage or reconnect configuration through the authorized owner to prevent repeated failures and accidental lockouts. This can require a brief reconnection or service interruption; plan the change so required network access is restored. Document the verified explanation and retain the alert evidence.

Do not disable the rule globally because one legitimate workflow triggers it. If future tuning is considered, scope it to independently verified behavior and test whether it could hide misuse; automatic suppression is outside version 1. Reopen/escalate if failures continue after correction, the source or target differs from the approved scope, the contextual claim cannot be verified, or unexpected post-logon activity emerges.

Account restriction or host isolation would seek to stop unauthorized access but would interrupt the known network-drive workflow and could affect other services. The present synthetic benign explanation does not justify such actions. No restrictions, changes, user contacts or automated responses have been performed.

## Limits and disposition

Disposition: **explained as legitimate in the supplied synthetic scenario**. A production closure could not rely on this invented context. This case shows why rule correctness and incident classification must be evaluated separately: the same five-failures-then-success sequence may be suspicious or routine depending on independently supported circumstances.
