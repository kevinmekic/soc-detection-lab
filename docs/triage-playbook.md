# Triage playbook

Use this playbook for this rule, not as a general incident-response policy. All supplied cases are synthetic. Suggested actions are investigative recommendations; the application does not lock accounts, block addresses, isolate hosts, or contact users.

## Establish what is actually observed

1. Record the rule/version/parameters, input hash, alert ID, success UID and failure UIDs. Check that all keys match and all failures fall in `[success − window, success)`.
2. Review duplicates, exclusions, errors, byte/event limits and input coverage before interpreting absence of other activity. Confirm timezone normalization and whether the source is synthetic or actually captured.
3. Identify account, domain/local context, destination, source and logon type. Type 3 describes Network; type 10 describes RemoteInteractive. A source IP is not a verified user or a durable device identity.
4. Keep direct event evidence distinct from context assertions. An external change calendar, asset register or user statement would need its own provenance and timestamp. This lab only supplies explicitly synthetic context examples.

## Test alternatives

Investigate stale saved credentials, an approved password change, a scheduled task or service reconnect, user typing errors, shared devices, and address reuse/NAT alongside unauthorized attempts. Ask whether source ownership, expected access, timing, authentication mechanism and post-logon activity support the proposed explanation. Do not infer intent from count alone.

Additional data to request in a real authorized lab includes the capture scope and audit state, source/destination asset mapping at the event time, account role/privilege, a genuine change record, authorized confirmation of the intended activity, and endpoint/session events after the successful logon. Request only relevant scoped information and preserve the original export. None of these inputs is fabricated by this project.

## Assess and act proportionately

| Assessment | Reasoning and next step |
|---|---|
| Suspicious, incomplete | Matching events plus inconsistent expected access/activity justify investigation. Escalate for source attribution and post-logon review; compromise remains unconfirmed. |
| Explained as legitimate | Matching events plus sufficient, separately sourced context support a benign explanation. Document it and remedy the retry source. Retain the evidence and rule result. |
| Unresolved | The event pattern is established but ownership, intent or later behavior is missing. Keep the case open with an explicit information request and review point. |

Every new alert starts at provisional `medium`. Priority may change with verified context such as account privilege, unexpected execution, scope or business impact. Do not assign invented probability scores or close a case solely because its source is private or familiar.

Temporary account restriction aims to stop further unauthorized access but can interrupt user work, services or recovery. Credential rotation aims to remove the usefulness of a potentially exposed secret but can break applications with stored credentials. Host isolation aims to reduce further access but can remove critical business connectivity and complicate evidence collection. Propose such actions only when additional evidence and the applicable authorization process justify them; explain the affected functions and restoration path. No action of this kind is necessary merely to demonstrate the synthetic rule.

## Close or hand off with evidence

A handoff should state observed events, contextual facts and their sources, current hypothesis, plausible benign alternative, missing evidence, provisional priority, requested next step and rationale. If closed as legitimate, record why the context resolves the pattern and what would reopen it. If logs are missing, say so; do not convert missing evidence into a clean bill of health. Keep technical rule correctness separate from the final case assessment.
