# Roadmap

## Milestone 1 — local synthetic detection and investigation

The current implementation scope is a bounded offline Python analysis of repeated 4625 failures before a 4624 success, with exact grouping/window rules, normalized synthetic data, quality diagnostics, deduplication, reports, tests and three worked analyst cases. The [validation record](validation.md) and [project status](project-status.md) are authoritative for the actual completed checks. The SPL translation was executed and compared later, in Milestone 2.

## Milestone 2 — Windows, Python and Splunk comparison verified

The owned Fusion/Windows target, controlled network logons, original XML export and precision-aware adapter are verified. The private capture emits 8 scope events and four explicit SYSTEM/type-5 exclusions; Python produces the fixed expected alert 53330 with failures 53325–53329. Rights diagnostics and further Windows attempts are not current tasks.

On 2026-10-06 the capture and a 14-event synthetic boundary dataset were imported into Splunk Enterprise 10.2.6 (Intel macOS user-directory `.tgz`, Trial, loopback-only, no root/service/autostart). Inventory matched every UID and the indexed `_time` at microsecond precision; the detection query matched the Python alerts for both datasets. The query is `lab-validated` for that version/query/data combination; see the [validation record](splunk-validation.md#validation-record-2026-10-06).

Publication preparation is done up to the first commit: documentation updated, MIT license, repository root `lab/`, private data excluded by `.gitignore`, demo and tests verified from a fresh install. The Splunk installation was removed per the [runbook](splunk-macos-runbook.md). Milestone 3 remains separate.

## Milestone 3 — future ideas, not implemented

- Investigate a suspicious PowerShell process-start pattern with harmless comparison cases and an explicitly selected event source.
- Correlate account creation with subsequent addition to a privileged group, preserving exact identity and time evidence.
- Add selected Sigma rules with documented provenance/licensing and actual positive/negative examples.
- Consider a separate KQL implementation only once its data source, schema and authorized environment are defined.
- Add a small network investigation using Zeek or Wireshark to connect authentication questions with network evidence.

Each new rule needs its own hypothesis, schema contract, evidence assertions, benign alternatives and limitations. Alarm suppression or incident grouping would be explicit versioned changes; neither silently modifies the first rule.
