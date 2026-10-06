# Limits of this milestone

Versioned fixture data and worked-case context are synthetic. A private owned-Windows capture now supplies a concrete native-event experiment; neither these small fixtures nor that capture measure production accuracy, incident prevalence or general detection coverage. Passing synthetic tests alone does not validate Windows audit configuration, real extraction or Splunk execution. Actual capture and local integration results are documented separately in [validation](validation.md).

The rule establishes repeated failures followed by success for one exact key. It does not establish an attack, identify an actor, authenticate a source IP, or inspect activity after logon. Stored credentials, approved password changes and legitimate retries can trigger it. The legitimate example is an intended rule match and a possible operational false positive, not an implementation error.

Known gaps include:

- Distributed attempts across IPs, source changes and some proxy/NAT effects.
- Slow attempts below the rolling threshold and spraying over many accounts.
- Failures without a subsequent success, successes outside the window, and unselected logon types.
- Missing, disabled, dropped or malformed audit records; authentication paths that do not expose the required source/account fields.
- Different ways of representing one identity, hostname aliases and account renames; case normalization is not directory resolution.
- Clock inaccuracies between sources. Normalization fixes timezone representation, not incorrect clocks.
- Malicious or accidental mislabelling of `data_origin`; this field is not an authenticity guarantee.
- Post-authentication behavior, process execution, network movement and authorization decisions.

The Windows XML adapter deliberately truncates original timestamp strings to microseconds, never rounds, and retains `timestamp_raw` plus `record_id`. The time error is less than 1 microsecond. For this capture, the nearest relevant event to the **lower 300-second lookback boundary** is **65.1345863 seconds** away: the distance from success 53314 to success 53330, less 300 seconds. That specific margin does not establish safety at every possible time boundary. Same-microsecond ordering uses a lower failure record ID only when both events provide IDs; legacy simultaneous failures remain excluded. Record-number order is an approximation, not a general guarantee of original 100-ns chronology.

The adapter UID is SHA-256 of `Computer|Channel|EventRecordID`, prefixed `windows-xml:`. Record IDs can recur after log clearing or a VM/snapshot restore. There is no source-generation component in this deliberately limited lab identity; mixing such generations can create misleading duplicates or conflicts. Original XML and hashes must be retained.

Each success is evaluated independently; an earlier success does not reset failures. Two nearby qualifying successes can create two alerts for overlapping evidence. Suppression and incident grouping are not implemented.

This is a bounded **in-memory batch** application. It sorts and retains data and reports, and does not implement ingestion queues, state persistence, exactly-once stream processing, scheduling, access control, endpoint collection or operational retention. Default limits are 10 MiB/100000 input events; raising them does not make it a production SIEM.

Overlapping alerts repeat evidence. A separate fixed limit of 100000 total evidence references aborts excessive report expansion, without truncating the detection result. The SPL comparison has its own smaller 1000-event input contract and timestamp range. The query implements the native same-microsecond record-ID exception and preserves paired native evidence. Present record IDs must also fit the exact 53-bit integer range. The first real capture has no normalized timestamp collisions; the separate synthetic boundary dataset exercises that branch. Both datasets matched Python on Splunk 10.2.6; this does not establish general semantic equivalence for other data, larger batches or other Splunk versions.

For a complete batch lookback, include at least the configured window before the earliest success under investigation and all relevant events. A narrow export or Splunk time picker can omit failures. A later-arriving event may change evidence when a batch is rerun; a prior absence of an alert is not proof that the pattern never happened. See [Splunk validation](splunk-validation.md) for the executed comparison.

The query uses the normalized lab schema, not arbitrary native Windows sourcetypes. Splunk Enterprise and Splunk Enterprise Security have different product scopes; this milestone promises no ES deployment or integration. The lab ran Splunk Enterprise 10.2.6 on macOS 15/Intel, a combination not listed for Trial use in the vendor's system requirements; the successful run is a local observation, not vendor support. No Defender, Sigma, KQL, Zeek or live Windows integration has been implemented.

There is no production SOC-experience claim, employer affiliation, certification or automatically confirmed incident in this repository. [Milestone 2](roadmap.md) has its Windows, Python and Splunk comparisons completed and is prepared for publication; Milestone 3 remains roadmap work.
