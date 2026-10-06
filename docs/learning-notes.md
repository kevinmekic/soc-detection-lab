# Learning notes

These notes are an answer framework for reviewing the subject matter oneself. They do not claim that a personal review has already happened or that a particular level of knowledge exists.

## 1. Processing events

The project uses a normalized JSONL lab schema with validation, UTC time handling, separate domains and users, IP normalization and provenance. This keeps it traceable which line was treated as evidence and which as a data-quality issue. A missing source value is never replaced by an invented address.

What can be shown is the behavior on the supplied synthetic data and error cases, and on one genuine Windows XML capture from an owned test VM. Not shown are compatibility with every Windows export path or the completeness of real logs. Check it yourself: generate and validate the demo, compare the original lines with the JSON report, and run the normalization tests.

## 2. Making a hypothesis precise

The hypothesis: many failed logons before a success for the same key are worth investigating. This became the interval `[t − 300 seconds, t)` with five failures. The decision makes boundary cases testable: exactly 300 seconds before counts; the same instant does not count, unless both events carry Windows RecordIDs and the failure's RecordID is lower. Earlier successes do not reset the counter.

What is shown is that the code matches this definition on the test cases. A compromise is not shown. Check it yourself: find the five failure IDs of SYN-001 in the fixture, compute the time gaps and compare the success with the outputs. Then look at the four-failure case.

## 3. Investigations and false positives

The three reports separate log evidence, explicitly synthetic context and hypotheses. The legitimate case exceeds the same threshold. That is technically correct and operationally a possible source of false positives. Missing information in the unresolved case is not replaced by invented follow-up answers or EDR findings.

Check it yourself: read [SYN-001](../reports/examples/SYN-001-suspicious.md) and assign every statement to an event, the context document or a clearly labeled hypothesis. Consider which additional data would change the assessment and what effect a proposed measure would have.

## 4. Reproducibility and translation

Separate expectation files, a dedicated evaluation dataset and tests check the technical rules without labels inside the detector. Stable alert IDs make comparisons easier; the file hash and line number, by contrast, describe the concrete input and may change when the input is reordered.

The SPL translation was executed on Splunk Enterprise 10.2.6 and matched Python for the native capture and a synthetic boundary dataset. That validates these inputs on that version, not general equivalence. The run also found two query defects that documentation review had missed. Check it yourself: read the [validation record](validation.md), run the quickstart and look at the [Splunk validation](splunk-validation.md) to see what was compared and what was fixed.

## Five interview questions

1. **Why do five failed logons and a success not prove an attack?** The pattern carries no reliable intent. Stale stored credentials after a password change can produce the same sequence. Context and subsequent activity have to be assessed separately.
2. **Why are domain, destination host and logon type part of the key?** Equal names are not necessarily equal identities; other targets and types belong to other logon contexts. Merging them could turn independent events into a false rule match.
3. **What do missing or late logs cause?** Missing failures can push the count below the threshold. A missing success prevents this rule entirely. Late events can change the evidence when a batch is re-evaluated. A narrow search time range can cut off the lookback.
4. **How was a false positive investigated?** In the synthetic legitimate case, concrete event IDs are linked to separately labeled context about password rotation and stored credentials. The rule stays correct; the analyst assessment explains the match. In real operations this context would have to be verified.
5. **What distinguishes these tests from a real SIEM test?** The unit tests check defined Python functions and CLI flows with synthetic data. A SIEM test also has to cover generation, export, extraction, time assignment, search bounds, product version and an actually executed query. The Splunk comparison in this project covers those steps for two small datasets on one version.

## Possible CV bullet points

Use only after your own review and against the current [validation record](validation.md); do not derive professional production experience from them:

- Personal SOC learning project: built a Python batch analysis of Windows logon events with validation, normalization, stable alert IDs and automated tests for time windows, correlation and error cases.
- Captured genuine 4624/4625 events from an owned Windows 11 test VM, converted them with a precision-aware XML adapter and met a detection expectation fixed in advance.
- Translated the rule to SPL and validated it on Splunk Enterprise 10.2.6 against the Python results, including microsecond timestamp parsing and boundary cases; fixed two query defects found in the run.
- Wrote three traceable investigation reports on suspicious, legitimate and unresolved logon patterns and documented the rule's limits.
