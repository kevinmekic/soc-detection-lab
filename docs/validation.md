# Validation record

Current validation date: **2026-10-06** (Europe/Berlin): Splunk Enterprise 10.2.6 import, inventory and detection comparison executed and matched for both datasets; latest suite **178 passed in 5.21s** after the resulting SPL fixes. Before that, **178 passed in 5.20s** after Splunk preparation. The preceding native-adapter suite had **155 passed in 5.40s**, and the private genuine capture matched the user's fixed expectation. See the final dated sections for commands and observed results. Earlier sections preserve the state and limits of their own dates; their pending Windows/adapter instructions are superseded by the current [project status](project-status.md).

## Historical environment and scope — 2026-10-01

- Development host: macOS, Darwin 24.6, x86_64.
- Available interpreter: Python **3.14.7**; supported project minimum: Python **3.11**.
- Initial workspace contained the master specification, with no application virtual environment or Git repository found. The application was created in the separate `lab/` directory to preserve the original input.
- Runtime is Python standard library only; `pytest` is a development dependency in the virtual environment.
- Locally executable scope: synthetic generation, validation, detection, report writing, evaluation and automated tests. No Windows capture or Splunk instance was available for product-level checks.

## Historical Milestone 1 verification — 2026-10-01

Milestone 1 verification completed locally. The final suite reported **95 passed in 7.62s**, using **Python 3.14.7, pytest 9.1.1 and pluggy 1.6.0**. All default test paths were collected, including the future Splunk-export comparison helper. The helper tests use fabricated test dictionaries and do not execute SPL.

The following README commands were actually executed from `lab/`. The first pip attempt could not resolve PyPI in the restricted environment. After network approval, installation into `.venv` succeeded; no runtime dependency was added. Demo, analysis, evaluation and tests then ran locally without credentials or network requests.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m soc_detection_lab generate --output data/generated --seed 42
python -m soc_detection_lab validate --input data/generated/events.jsonl
python -m soc_detection_lab analyze --input data/generated/events.jsonl --output reports/generated
python -m soc_detection_lab evaluate --input data/evaluation/events.jsonl --expected data/evaluation/expected.json
python -m pytest
```

| Executed operation | Observed result |
| --- | --- |
| Create venv and install editable package plus dev extra | Successful; package version `0.1.0`; no runtime dependencies |
| `generate --output data/generated --seed 42` | 24 JSONL records, declared synthetic |
| `validate --input data/generated/events.jsonl` | Exit 0; 23 processed, 1 duplicate, 0 excluded, 0 errors |
| `analyze --input data/generated/events.jsonl --output reports/generated` | Exit 0; 3 alerts and JSON, Markdown, plain normalized and Splunk transport files |
| `evaluate --input data/evaluation/events.jsonl --expected data/evaluation/expected.json` | Exit 0; 2 expected / 2 actual alerts, no mismatches; 20 lines, 19 unique, 1 duplicate |
| `python -m pytest` (executed with the venv interpreter) | 95 passed in 7.62s: 21 CLI, 49 engine, 11 integrity/export and 14 comparison-helper tests |
| General CLI help and `analyze --help` | Successful; documented commands/options present |
| Versioned example generation through the real CLI | Produced `reports/examples/demo-results.json` and `demo-report.md` from `data/fixtures/events.jsonl` |
| Independent documentation/data checks | All 18 analyst timeline rows match fixture UID, event ID, time and line; all relative Markdown file links resolve |
| Repeatability check | Generated seed-42 events, context and expected files equal the versioned fixtures byte for byte |
| Project metadata inspection | No authors, maintainers or contributors fields; no AI author/commit-credit entries added; no commits or Git identity changes |

Observed input hashes (SHA-256):

- Demo/fixture: `bb9afcdde3c036a125edeb99c92d59fc7d2a1948c358db7f93d16c50623b348d`.
- Independent evaluation: `e4eb6ee7fe40de2e5afdadf0d0384d71c9812b8cb14b63078895d5689550f582`.

Manual expectations identify demo successes `demo-006`, `demo-012`, `demo-018` and evaluation successes `eval-008`, `eval-009`, with their exact failure UIDs and keys. These expectations were not computed by the detector. Unit tests additionally assert exact evidence timestamps and boundaries. The CLI integration tests also compare the generated demo against its separate expectations and verify that changing the context/expectation files cannot influence analysis.

Review found and fixed two edge cases before the final run: a structurally invalid second copy of a UID could be skipped without identity-conflict rejection, and unpaired Unicode surrogates could survive validation but fail Markdown encoding. Regression tests cover both UID input orders and surrogate rejection. A fixed total-evidence guard also prevents excessive repeated-window output; it fails explicitly instead of truncating results.

## Milestone 1 acceptance

- [x] Locally installed application and executed README commands.
- [x] Offline runtime without credentials or external services.
- [x] Documented schema, declared origin, normalization and error policy.
- [x] Separate events, manual expectations and synthetic context; no detector labels.
- [x] Exact correlation key, inclusive lower and exclusive upper boundary.
- [x] Positive, negative, ambiguous, malformed, duplicate and conflict cases.
- [x] Stable IDs, explicit effective configuration and timestamped event evidence.
- [x] JSON/Markdown output, input hash, provenance and explicit quality counts.
- [x] Three fully referenced analyst reports and clear legitimate/unknown interpretations.
- [x] SPL file and bounded import/comparison procedure, `reviewed-not-executed` only.
- [x] Actual checks and limitations recorded; generated examples linked from README.
- [x] Synthetic identities and documentation IPs; no secrets or operational data supplied.
- [x] No AI authorship metadata, Git identity modification, commit or publication.
- [x] Milestones 2 and 3 explicitly pending; no product installation or live capture begun.

There is no remaining external blocker for Milestone 1. Real Windows and Splunk validation are intentionally future work, not missing evidence concealed as completed work.

## What the checks mean

Technical verification covers exact threshold and window behavior, domain/user/source/host/type separation, ordering, duplicate suppression, contradictory UIDs, timezone/IP/account normalization, invalid input, configured limits and parameters, stable alert IDs, repeated successes and CLI output. Central fixtures assert expected success and failure identities; count-only checks would be insufficient. A separately defined evaluation set adds other identities/times/combinations without becoming a production performance benchmark.

An alert for the legitimate synthetic case is expected technically. Its analyst interpretation is a separate question. No accuracy percentage, attack probability or production detection rate is derived from these small datasets.

## Not executed or claimed at Milestone 1 — 2026-10-01

- Windows VM setup, audit configuration, controlled real authentication activity, native export parsing or sanitized real event capture.
- SPL execution, comparison against actual Splunk output, ingestion timing or Splunk Enterprise Security integration.
- Windows PowerShell quickstart, a Python-version support matrix, a remote CI pipeline, GitHub publication or production deployment.
- Personal user review or confirmation of the synthetic context.

The SPL status and exact version/documentation basis are in [splunk-validation.md](splunk-validation.md). Pending product checks belong to [Milestone 2](windows-lab-plan.md).

## Milestone 2 preparation verification — 2026-10-01

The full 95-test result above is the historical Milestone 1 run. For this continuation, the unchanged detection logic was reviewed first. One read-only, in-memory calculation on each saved demo input matched the saved result exactly, including input hash, counts, alarm IDs, keys, failure/success timestamps and provenance. The success/failure/key projections also matched independent expectations. No discrepancy justified repeating the engine suite.

Read-only machine inventory used `sw_vers`, `uname`, approved read-only `sysctl`, `memory_pressure -Q`, `vm_stat`, `df`, application plist inspection and selected VMX/VMDK fields. Results are in [host-inventory.md](host-inventory.md). The sandbox initially blocked hardware/process queries; only `sysctl` was retried with approval. No installation, VM startup, system policy change or VM modification occurred.

The documented native XML timestamp examples expose a specific precision limitation. A standard-library XML inspector was added instead of silently reducing native timestamps or shipping an adapter that cannot correctly represent them. After that code/CLI change, the affected checks ran:

```sh
.venv/bin/python -m pytest tests/test_windows_xml.py tests/test_cli.py
.venv/bin/python -m soc_detection_lab inspect-windows-xml --input data/documentation-examples/security-structure.xml
```

Observed: **60 passed in 5.43s** on Python 3.14.7 / pytest 9.1.1; 37 XML tests and 23 CLI tests. The fixture command exited 0 with 2 records, no missing fields/scope issues or incompatible timestamps. The fixture SHA-256 is `57c44967ea5f291a18b3c5a47ea23f290d1c05d06adc1e908692ded3a0a529b2`. It is independently constructed **synthetic structural test material**; the separate documented native timestamp strings are tested to produce exact-precision warnings.

These tests cover namespace/container structure, raw field preservation, missing/placeholding/invalid correlation fields, optional failure fields, ambiguous duplicates, malformed XML/UTF-8/DTD, bounded input, timestamp precision and CLI success/error routing. They do not establish Windows event generation or captured authenticity. The engine, rule parameters and SPL correlation were not changed. No full-suite rerun or CI result is claimed for this continuation.

Prepared guest commands and `scripts/windows/Export-LogonEvents.ps1` were source-reviewed only. No Windows runtime or PowerShell was available here; the script has not been executed or empirically syntax-validated on Windows. Real pilot capture, exact native adapter and Splunk execution remain open.

## User-provided guest preflight — 2026-10-02

The user ran the console preflight and supplied text output plus a visible `winver` screenshot. [The dated guest record](history/windows-preflight-2026-10-02.md) preserves the relevant values without copying the screenshot or its personal account email. Windows 11 Pro 25H2 build 26200.8037 boots; the guest reports x64, DESKTOP-7HFI2UV in WORKGROUP without domain membership, approximately 4 GiB RAM, a 40-GiB GPT disk, C: 39.79 GiB with 19.48 GiB available, TPM present/ready and Secure Boot disabled. Lockout is 10 failures, 10-minute duration and 10-minute reset window; Security is enabled with 33545 records and a 20-MiB circular limit.

The user's initial `auditpol /get /subcategory:* /r` failed with `0x00000057`. Microsoft's syntax permits the supplied switches; the error code means invalid parameter without establishing a localization, PowerShell, privilege or policy cause. The user then executed the quoted Audit Logon GUID query successfully: **System / Anmelden / Erfolg und Fehler** (German UI: System / Logon / Success and Failure), empty exclusion column, **exit 0**, and supplied local `/get /?` help. System Audit Logon success/failure is now observed; per-user exclusions and actual native event coverage remain open. The user confirms the NIC remains disconnected. Activation UI reports **Verbindung nicht möglich** (German UI: Unable to connect), establishing no successful activation or license suitability. Its visible guest date is 2026-10-01 21:58; capture time/timezone are unknown, so a future UTC check is needed without claiming proven clock drift. No controlled SMB sequence, original XML export, actual event-field coverage or Splunk execution has been demonstrated.

Read-only follow-up `df -k` on the VM bundle path found **19200364 KiB (about 18.31 GiB) free**, 92% capacity used. Selected VMX and small VMDK descriptor reads confirm the existing NVMe `Virtual Disk.vmdk` is `twoGbMaxExtentSparse` with 40-GiB capacity. No `.vmsn` was found in the bounded top-level bundle check; full snapshot inventory is not claimed. The user explicitly reports no external storage/backup and permits experimentation with the disposable test VM. The plan now proceeds without backup/second copy, preserving sparse allocation. Normal shutdown, 64-GiB expansion, C: extension and other VM changes have **not** been performed or confirmed; the next manual step has explicit success criteria in the plan.

This continuation changes documentation only. No code, rule, schema, script or fixture was changed; no automated tests were rerun because no code change or concrete ambiguity in the detector justified them. Existing 95-test Milestone 1 and 60-test targeted XML/CLI results remain historical, with their actual scopes above. No installation, system/VM configuration change, authorship metadata, commit trailer or Git-identity edit was made by the agent.

The user's follow-up question prompted a storage clarification: the official Windows-11 VM requirement is 64 GB, rechecked in Microsoft Learn on 2026-10-02. It is a recommended platform baseline, not a detector requirement or indispensable gate for a few real SMB logons on the running 40-GiB guest with 19.48 GiB free on C:. The earlier mandatory pilot wording has been corrected; any run below the baseline must record that deviation. No further tests or VM changes were made for this clarification.

The user then accepted proceeding with the existing **40-GiB** guest; no resize is planned for the bounded pilot. Read-only networking follow-up observed Mac IPv4/IPv6 forwarding **0/0** after an approved retry of the sandbox-blocked query. Fusion configuration has private VNET 1 **192.168.243.0/24**, DHCP enabled; filtered interface output shows **bridge100, 192.168.243.1/24, active**. `vmnet1` was absent; bridge101 **192.168.57.1/24** is also present in the separately configured NAT subnet. These are local host observations, not proof of guest host-only attachment, no Internet path or SMB source fields. The new [manual network step](history/windows-network-step.md) prepares the VM-only host-only/HGFS changes and read-only guest adapter/IP/route queries; those actions/results remain pending. No code, fixture, tests, VM settings, forwarding, host policy or firewall were changed or executed anew by the agent.

## Private network and next account step — 2026-10-03

The user supplied **Ethernet0 / ifIndex 8 / Up**, Windows IPv4 **192.168.243.128/24 / Preferred**, and no active IPv4/IPv6 standard-route rows (same query executed twice). Read-only current VMX fields show **hostonly**, one present ethernet0 and **global HGFS disable TRUE** while retaining a saved share entry. No runtime host-folder access was tested. The Mac bridge100 is active at **192.168.243.1/24**; an approved retry of the sandbox-blocked local route lookup to **192.168.243.128** returned **bridge100**. No packet test or route modification was performed. The user confirms Internet Sharing is off and no other VMs run; the current target is intentionally running.

These facts meet the basic private-network/address setup checks, without claiming absolute isolation or generated type-3 event coverage. Remaining routes, guest UTC/timezone, integrations, licensing and future account-specific rights/audit/SMB conditions remain explicit. The [standard-account block](history/windows-account-step.md) was reviewed against official PowerShell 5.1 APIs and independently source-reviewed; it is **not executed or empirically syntax-validated in Windows here**. It uses a scoped error/variable context, guards existing names, hidden password input, Users SID membership and an Administrators SID check. Its sample output is marked expected, not genuine account evidence. No account/share/ACL/firewall change is claimed. No automated tests were rerun for this documentation continuation; engine/CLI/schema/export code and fixtures remain unchanged. No authorship metadata, Git identity or commit trailers were changed.

## User-executed standard account and SMB preparation — 2026-10-03

The user supplied the complete account-script transcript. The first execution failed at the minimum-length guard before `New-LocalUser`; no account creation is claimed for that attempt. The second returned **Name lab-auth01, Enabled True, PrincipalSource Local, UsersMember True, AdministratorsMember False**. This establishes the documented local account/membership checks from actual guest output. No password, screenshot or personal login identity is stored. It does not establish every possible privilege or a native type-3 authentication event.

The next [SMB readiness block](history/windows-smb-step.md) reads service, SMB server settings, existing probe path/share, connection profile and ActiveStore firewall profiles. The block was reviewed against official APIs and independently source-reviewed; it has not been executed or empirically syntax-validated in Windows here. Effective TCP-445 rules remain to be read before share creation; no share/ACL/firewall change, controlled SMB login or real XML export is claimed. Existing account creation must not be repeated.

Documentation only: no application, schema, fixture or export-script changes; no automated tests rerun. Local documentation links were checked after the update. No AI authorship metadata, commit trailers or Git identity changes. Splunk execution remains pending.

## User-executed SMB readiness and active-rule preparation — 2026-10-03

The user supplied the completed readiness-block output: **LanmanServer Running / Automatic; EnableSMB1Protocol False; EnableSMB2Protocol True; RequireSecuritySignature True; EncryptData False; ProbePathExists False; SOC_LABShareCount 0**. Ethernet0/index 8 is Public, IPv4/IPv6Connectivity NoTraffic. Domain, Private and Public each report **Enabled True, DefaultInboundAction Block, AllowInboundRules True, AllowLocalFirewallRules True**. This establishes selected service/protocol/path/share/profile values from actual guest output; it does not establish Mac connectivity, effective individual-rule coverage, successful authentication or native field coverage. NoTraffic is not treated as an observed SMB failure. Account/SMB readiness queries need not be repeated.

The next [active firewall-candidate block](history/windows-firewall-step.md) is read-only and retains enabled inbound rules from ActiveStore, both actions/all profiles, TCP/Any, exact/numeric ports including leading zeros, ranges and unresolved expressions. Associated-filter count guards and scoped Stop avoid an incomplete silent result; null/empty ports are marked for review. Joined address/interface/application/service/security conditions are reported with personal application paths/package SIDs hidden. Candidates are not a complete WFP access simulation. Official APIs and the source were reviewed independently; the block has not been executed or empirically syntax-validated on Windows here. Two source-review refinements covered null/empty ports and numeric 00445 without claiming a runtime test.

Only documentation changed. No application/schema/fixtures/export-script changes and no automated suite rerun. Local documentation links and the current status were checked after the update. No VM/host policy change by the agent, account creation repetition, share/ACL/firewall mutation, real authentication/export, AI author metadata, commit trailer, Git-identity change or Splunk execution.

## User-executed firewall candidates and source-bound rule preparation — 2026-10-03

The full pasted attachment was read without copying its raw contents into the project. It contains **EnabledInboundRuleCount 127 / CandidateCount 38**, with exactly 38 printed candidates; all have Action Allow and OverrideBlockRules False. The Public TCP445/System/LocalSubnet rule is an existing broader allowance condition. NETDIS-UPnPHost-In-TCP-Teredo and WiFiDirect-KM-Driver-In-TCP have System/Any-port candidate conditions. Additional app/dynamic/user restrictions are not inferred away. No Block candidate was printed, but no universal WFP access or packet-connectivity proof is claimed.

The earlier PackageRestricted False projection only means no nonempty .Package value was found; it does not prove absent package-family/trust/user conditions. Program/package values were masked, but some rule names in the raw output contained local user SIDs. The raw attachment is retained only in its user-provided attachment location, not copied into repository evidence or fixtures. The project records only necessary counts/conditions and system rule names. No native logon export was received.

To preserve existing rules while controlling the actual pilot source, the [prepared setup](history/windows-firewall-configure.md) creates three NEW rules: inbound TCP445 on Ethernet0, IPv4 complement of Mac 192.168.243.1 blocked on all local IPv4 addresses, IPv6 blocked on the interface, and exact Mac-to-guest IPv4 allowed. Both blocks precede the allow. Explicit Block precedence over ordinary Allow and the observed absence of override candidates avoid relying on a narrower Allow to constrain older broad ones. All-profile interface/port binding keeps the scope narrow; other ports/interfaces and existing rules remain unchanged.

Official range/IPv6/precedence APIs and the exact PowerShell block were independently source-reviewed. Guards, ActiveStore condition/status readback, partial-error handling and exact-name cleanup are documented. **No creation, PowerShell execution or empirical syntax validation was performed here.** Actual guest range acceptance/active statuses and the later IPv4 connection remain pending. The IPv4 complement was checked arithmetically in documentation QA; this is not a Windows firewall test. Existing detector, schema, XML inspector, fixtures and export script are unchanged; no automated suite rerun. No AI authorship fields, commit trailers or Git-identity changes. Splunk remains pending.

## User-executed firewall setup failure and read-only recovery — 2026-10-04

The full user attachment was read. New-NetFirewallRule returned an invalid address prefix, HRESULT **0x80070057**. Get-NetFirewallRule subsequently reported **SOC-Lab-SMB-Block-IPv6** missing; the assertion for three rules failed before filter/status output. The script continued despite its scoped Stop preference. The IPv4 rules may have been created, but their presence/conditions have not been read back. No successful three-rule setup or source restriction is established. The separately pasted closing Markdown fence caused only an unknown-command error; it is not a cleanup action.

The official FW_IPV6_SUBNET definition requires prefix lengths **1–128**. This supports the proposed ::/0 as the parameter-error cause; the transcript does not identify which of the two IPv6 address arguments was rejected. The earlier source review missed this constraint. The creation snippet has been withdrawn, and [current recovery](history/windows-firewall-recovery.md) prohibits blind repetition/deletion or share/authentication attempts before verification.

Added [Read-LabFirewallState.ps1](../scripts/windows/Read-LabFirewallState.ps1): only exact lab-name reads from PersistentStore and ActiveStore; counts/missing names and existing associated port/address/interface/security conditions/status. Get-all then exact filtering avoids missing-name CIM errors. Every NetSecurity query specifies -ErrorAction Stop, and associated filters require exactly one result. The raw script contains no Markdown fences, mutation commands or password handling. Source and independent PowerShell/API review found no required correction; **no Windows execution or empirical syntax validation was performed here**. No query results are invented. The next output is needed before preparing a targeted repair.

The raw attachment remains in its user-provided location, not copied into project evidence/fixtures. Application/schema/XML inspector/fixtures/export script are unchanged; no detector test rerun was justified by this guest-only failure. Existing 95-test and focused 60-test results retain their original scope/date. No host/VM mutation by the agent, AI-author metadata, commit trailer or Git-identity edit; genuine logon capture, adapter and Splunk remain pending.

Local documentation QA checked **59 relative links** across the eight updated guides/records, all resolving. Static script checks found exactly five NetSecurity reads, each with explicit Stop, no mutation commands or Markdown fences, and no authorship metadata. The withdrawn creation block is no longer executable content in the guide. This is file/source QA, not a PowerShell parser test or Windows firewall execution.

## User-executed partial-state readback and targeted repair preparation — 2026-10-04

The subsequent user attachment contains a complete error-free execution of Read-LabFirewallState.ps1. Both stores return **LabRuleCount 2 / MissingNames SOC-Lab-SMB-Block-IPv6**. Allow matches local 192.168.243.128/remote 192.168.243.1. Block matches the two expected IPv4 remote ranges but returns local **0.0.0.0**. Both rules have the intended common Enabled/Inbound/Any-profile/TCP445/Ethernet0/security fields, PrimaryStatus OK; PersistentStore reports NotApplicable, ActiveStore **ProfileInactive,Enforced**. No numeric status values or application/package/service/interface-type fields were in that output. No runtime firewall change occurred in this diagnostic step; no TCP/authentication/event proof is claimed. Raw transcript remains only in the attachment location.

Official IPv4 subnet semantics also reject a zero mask; a single returned 0.0.0.0 is not accepted as proof of all local IPv4 addresses. Prepared [Repair-LabFirewall.ps1](../scripts/windows/Repair-LabFirewall.ps1) therefore changes only the own IPv4 Block's local scope to documented Any, then creates the absent IPv6 Block with local Any and remote ::2 through the maximal IPv6 address. This range excludes unspecified/loopback as endpoints, complying with the documented range constraint; no Windows acceptance is claimed yet. Existing Allow and IPv4 remote scopes are preserved.

Target/address/profile guards and both-store rule/filter checks precede the two mutation sites. Explicit Stop is used at each NetSecurity call. Source review additionally required application/package/service/interface-type reads and Any guards so an unexpected restriction is not silently accepted; those values remain unobserved until the user runs the new block. Selected full readback follows and ActiveStore is checked numerically for 1 with optional 5, avoiding a required spelling Full. Two independent source/API reviews found no PowerShell 5.1 scope/cast/array/splatting error in the core block; the additional filter guards were added after one reviewer identified their absence. These are static reviews, not actual parser/Windows tests. command -v pwsh returned exit 1/no path; no PowerShell runtime is available here. The script has not been run on Windows by the agent or user.

The diagnostic step is passed, the firewall configuration remains **not passed**. Next manual action and failure/partial-state handling are in [windows-firewall-repair.md](history/windows-firewall-repair.md). No unchanged detector suite rerun; application/schema/fixtures/XML/export code unchanged. No host or guest mutation by the agent, AI authorship/trailers, Git identity changes, genuine logon capture or Splunk execution.

Final local QA passed: the IPv4 ranges cover exactly 2^32−1 addresses excluding only the Mac, and the IPv6 interval covers integers 2 through 2^128−1 with permitted endpoints. Static checks found nine explicit-Stop firewall reads, exactly one scoped Set and one New mutation site, no reset/removal, /0 prefix, Markdown fence or authorship metadata. All **68** relative links across nine updated guides/records resolve. The added filter guard changes also received independent source review with no required correction. These checks are arithmetic/file/source checks, not a PowerShell parser, Windows rule execution or new Python detector test result.

## User-executed repair preflight failure and status fix — 2026-10-04

The complete new user transcript shows **InvalidCastFromStringToInteger** from ForEach-Object at the attempted `[int]` conversion of **NotApplicable**. This is in the first Read-LabState/PersistentStore call while constructing its first output row. Both stores' preconditions must complete before the Set/New sites; the stopping error occurred before either mutation. **No rule change was made by this repair attempt.** No ConfigurationReadback success or three-rule evidence was returned.

The static review's assumption that the cmdlet-rendered status values were integer-castable was wrong. A protocol/WMI numeric definition does not establish the actual PowerShell property representation. Removed EnforcementStatusValues and every status-number conversion from Repair-LabFirewall.ps1. The final ActiveStore guard now splits/trims the preserved status names, requires the actually observed **Enforced**, permits **ProfileInactive** alongside it, and rejects unknown/empty names. PersistentStore NotApplicable remains a text value. The existing condition/address guards and the two targeted write sites are unchanged. On a condition mismatch the actual selected row is printed before throwing, so the error has useful diagnostic values instead of only a generic message.

The status-fix approach received independent source review; it needs no extra read-only VM round because the actual stopping location establishes that no repair writes occurred. The next manual step is the updated guarded Repair-LabFirewall.ps1, not the withdrawn original three-rule setup. No actual Windows syntax/runtime success is claimed for this revision. No unchanged Python suite rerun, application/schema/XML/fixture/export change, AI author metadata/trailer or Git-identity change. The firewall setup, share/authentication capture, native adapter and Splunk remain pending.

Local file/source QA passed: no status integer casts remain; original text is preserved, both before-store guards precede the unchanged write sites, nine firewall reads retain explicit Stop, and **68** relative documentation links resolve. This does not execute PowerShell or establish guest repair success.

## User-executed Package guard failure and typed readback preparation — 2026-10-04

The complete latest transcript prints the first PersistentStore SOC-Lab-SMB-Allow-Mac row. All selected original settings match; Program Any, Service Any and InterfaceType Any are now observed for this row. The projected Package is blank. The guard's Package=Any assumption alone caused **Unexpected rule conditions**. This is still before Set and New, after collecting the first store but before completing both-store preconditions. **No rule change occurred in this attempt.** No three-rule or configuration success result was returned.

The previous additional-filter source review incorrectly recommended requiring Package Any. Official MSFT_NetApplicationFilter defines Package as a string containing an application SID; FW_RULE documents a real null package ID as no such condition. The old string projection collapses absent property/null/empty text, so the blank row alone is not accepted as unrestricted and no guessed alternate field is substituted. Two independent contract reviews agree that a bounded typed readback is needed.

Prepared Read-LabApplicationFilters.ps1, read-only for exactly the two own rules in both stores. It validates names/one filter, emits actual CIM class/property names, Package presence and its actual CIM/value type/null/empty/nonempty/value-JSON distinction, plus existing application-related properties on filter/rule. No absent property is invented or implicitly accepted. The repair draft is withdrawn with an immediate throw pending this evidence. The next manual action is [windows-application-filter-step.md](history/windows-application-filter-step.md); no account/share/connection attempt yet. The diagnostic has not been executed or empirically syntax-validated on Windows here. No genuine event export, schema/engine/XML/fixture/export change, unchanged detector-test rerun, AI authorship/trailer or Git-identity edit.

Independent static review found the diagnostic scope/guards/raw-property handling sound and identified a PowerShell 5.1 null-serialization detail: ValueJson now explicitly emits the JSON token null only when the actual value is null, preserving that distinction without relying on serializer output. Local file/source QA passed: two explicit-Stop firewall calls, no mutation commands, original value/type handling, immediate withdrawn-repair stop and **70** resolving relative links. These are source checks, not Windows execution or a PowerShell parser test.

## User-executed typed application readback and evidence-based repair revision — 2026-10-04

The complete subsequent user transcript contains an error-free execution of Read-LabApplicationFilters.ps1. Both rules in both stores return actual class **MSFT_NetApplicationFilter** and PackagePropertyPresent True. In all four store/rule combinations, actual filter properties **AppPath/Package** and rule properties **PackageFamilyName/PolicyAppId** are present, CimType String, ValueIsNull True, ValueKind Null, ValueType <null>, ValueJson null. These are real null values, not empty strings or missing properties. Additional LocalOnlyMapping/LooseSourceMapping properties are Boolean false. The diagnostic changed no rules. The raw transcript remains in its attachment location, not copied into repository fixtures or event evidence.

Revised Repair-LabFirewall.ps1 to require precisely these observed raw CIM properties. Read-RequiredNullString requires exactly one property, actual CimType String and actual null Value; it does not cast the value to string or substitute Any. Unexpected non-null values print typed/JSON diagnostics through Out-Host before stopping. All four successful helper return objects are assigned, so only rule rows enter Read-LabState's success stream. Filter class and property checks apply to both preflight stores, the intermediate IPv4 readback and the final three-rule readback. The incorrect Package Any guard and temporary unconditional withdrawal throw are removed. Optional Program/Service/InterfaceType creation arguments are omitted, matching the original creation form; actual new defaults remain subject to readback, not an asserted runtime result.

Both stores' preconditions still precede the only two write sites: Set of the own IPv4 Block's LocalAddress to Any, and New of the absent IPv6 Block. Existing Allow and IPv4 remote ranges are preserved. Explicit per-call Stop and observed status-name checks are retained. Two independent reviews of the saved revision found no necessary source correction, including PowerShell 5.1 expression/scoping, helper output and pre-write ordering. These are source/API reviews, not a PowerShell parser or runtime test. command -v pwsh returned exit 1/no path; no PowerShell was installed. The revised repair has **not** been executed in the guest. Three rules, ConfigurationReadback Passed, packet access and Security event fields remain unobserved.

Documentation now records the diagnostic as completed and routes the next manual step to the full current [repair script](../scripts/windows/Repair-LabFirewall.ps1) with [explicit acceptance criteria](history/windows-firewall-repair.md). No Python engine, schema, XML inspector, fixture or export-script changes; unchanged detector tests were not repeated. Existing historical test results keep their original scope. No host/guest mutation by the agent, AI author metadata/trailers or Git-identity edits. Real share/authentication/capture, native adapter and Splunk execution remain pending.

Final local documentation QA checked **82 relative Markdown links** across the ten updated guides/records, all resolving; code spans/fences were excluded from link parsing. Static inspection found nine explicit-Stop firewall read sites, exactly one scoped Set and one New site, and four assigned null-helper calls. No old Package Any guard or withdrawal throw remains. New's splat retains ErrorAction Stop. These are file/source checks, not Windows runtime or detector tests. Opening the current raw repair file through the app returned queued; no actual tab display is asserted.


## User-executed successful firewall repair and accepted readback — 2026-10-04

The new complete user transcript shows an error-free execution of the corrected Repair-LabFirewall.ps1 and a final **ConfigurationReadback : Passed**. It contains three unique rule names in PersistentStore and three in ActiveStore, all six full rows. Own IPv4 Block now has LocalAddress Any and the unchanged exact two remote complement ranges. Newly created IPv6 Block has LocalAddress Any and the exact remote range ::2 through the maximal IPv6 address. Mac Allow retains local 192.168.243.128/remote 192.168.243.1. New-rule range acceptance and Program/Service/InterfaceType Any defaults are now actually observed.

All six rows have Enabled True, Inbound, Profile Any, PrimaryStatus OK, TCP/445/RemotePort Any, Ethernet0, Program/Service/InterfaceType Any, EdgeTraversal Block, Authentication/Encryption NotRequired and OverrideBlockRules False. For each row AppPath, Package, PackageFamilyName and PolicyAppId have CimType String and IsNull True; the executed helper checked actual presence/type/raw null before that projection. PersistentStore reports NotApplicable for each rule; ActiveStore ProfileInactive,Enforced for each. No output error is present.

The complete result was read and independently reviewed against the saved script and acceptance criteria. A bounded local in-memory text extraction additionally compared all six actual rows, store/name/counts, common conditions, actions/addresses/statuses and terminal Passed against explicit documented expectations: **6 rows, counts 3/3, zero field mismatches, final_passed True**. This is verification of supplied evidence, not a detector test or new Windows command. The raw transcript remains in its user attachment location; no event fixture, Security export or claimed authentication record was created.

The selected firewall **configuration acceptance is now passed**. Packet reachability, full WFP/IPsec/third-party behavior, actual SMB authentication and native 4624/4625 field coverage remain untested. The user performed the guest mutation; the agent only inspected the evidence and edited project files. The repair and completed diagnostics should not be rerun. The next manageable manual action is a new empty C:\SOC-Lab\Probe / SOC-LAB share with restricted lab-auth01 read access, prepared in a separate source script/guide. Its guest execution is still pending.

No engine/schema/XML/fixture/export-script changes or unchanged detector-suite rerun. Historical test results retain their date/scope. Splunk, real capture/export, exact native adapter and real-data detector comparison remain pending. No AI author metadata/trailer or Git-identity changes.


## Next manual empty probe/share step prepared — 2026-10-04

Added scripts/windows/New-LabProbeShare.ps1 and docs/windows-share-step.md for manual use in the owned guest. Pre-write guards cover the known computer, elevated 64-bit Windows PowerShell 5.1, enabled local standard lab-auth01, existing SMB1/SMB2/signing state, ordinary non-reparse parents, absent Probe and absent SOC-LAB. Existing parent content/ACLs stay untouched; a missing parent is newly created with normal inherited permissions. No existing Probe/share is taken over.

Only the new empty Probe receives a fresh protected DACL, Administrators owner SID and exactly three explicit SID-based Allow ACEs: SYSTEM/Admins FullControl and lab-auth01 ReadAndExecute. Expected rights come from actual constructed FileSystemAccessRule objects, accounting for Synchronize. Typed ACEs, owner/protection/inheritance and emptiness are checked before sharing and again after. New-SmbShare grants only the qualified local lab account Read, with CachingMode None; returned AccountName is translated to an actual SID and checked. Exactly one Allow/Read share entry, correct path, three checked NTFS entries and emptiness are required before ShareSetupReadback Passed. On error, ShareSetupStopped names the stage and rethrows; no automatic deletion/retry or cleanup is performed.

The saved source received creator review, root review and an independent PowerShell/API source review with no necessary script fix. A rights statement in the guide was narrowed to the configured entries/share Read: the untouched parent ACL is not a proof of every local effective permission. This does not require an extra guest diagnostic or broaden the next step. All reviews are static; the new block has **not** run on Windows and no actual share/ACL success output is claimed. No authentication, packet test, secret handling, system policy change or installation is part of the script.

Local file/source QA checked **89 relative Markdown links** across the eleven updated guides/records, all resolving. The new 180-line script has two fresh-directory New-Item sites, one Set-Acl limited to the new Probe and one New-SmbShare; no authentication/policy/reset/removal commands or Markdown fences. Mutating cmdlets use explicit ErrorAction Stop. The app file-opening request returned queued; actual display is not asserted. These checks do not parse/execute PowerShell and are not new detector test results. Python engine/schema/XML/fixtures/export script unchanged; historical tests retain their original scope. No AI authorship/trailers, Git-identity changes or fabricated native events.

## User-executed successful probe/share setup and license reply — 2026-10-04

The complete subsequent user transcript contains the actual New-LabProbeShare.ps1 execution without errors, ending **ShareSetupReadback : Passed**. Returned ShareName SOC-LAB, ProbePath C:\SOC-Lab\Probe, DirectoryEmpty True, OwnerSID S-1-5-32-544, NtfsInheritanceProtected True, NtfsEntryCount 3 and ShareEntryCount 1 satisfy the selected configuration acceptance. SYSTEM and Administrators have Allow/FullControl; the actual lab account has Allow/ReadAndExecute,Synchronize. The single SMB entry is Allow/Read for DESKTOP-7HFI2UV\lab-auth01, whose translated SID matches the actual local account.

The NTFS table is cropped at right by console width. The actually executed helper checked owner/protection, each original ACE identity/rights/inheritance/propagation/IsInherited and count before printing Passed; this is not a reason for another guest diagnostic. Root and an independent reviewer accepted the complete supplied result against the saved script. Whether the parent C:\SOC-Lab already existed is not separately reported and remains unknown. The raw transcript and dynamic account SID are not copied into repository fixtures or event evidence. Setup is completed; do not rerun its fresh-path/share guards. Selected ACL/share acceptance does not establish every local effective right through unchanged parents or a packet/authentication result.

The user also explicitly confirms an owned suitable Windows-11-Pro license. This is recorded as a user assertion, separately from the still-unread technical activation state; no key is requested, retrieved or stored. No new license purchase is planned.

## Remaining pilot-prerequisite read prepared — 2026-10-04

Added [Read-LabPilotPrerequisites.ps1](../scripts/windows/Read-LabPilotPrerequisites.ps1) and [its manual guide](history/windows-pilot-prerequisites.md). The block is read-only: actual local/UTC time and timezone, two existing LSA values with presence/type/null preserved, documented native WinNT IADsUser BadLoginCount/IsAccountLocked getters through DirectoryEntry.InvokeGet, selected installed-product license status without any output key/ID, every active IPv4/IPv6 route, and SID-braced per-user auditpol /get for Audit Logon. Native getter errors are reported Unavailable; no null-to-zero conversion, guessed Win32 field, lockout budget or automatic readiness is generated. Auditpol exit is captured immediately and a nonzero result stops the collection. Complete means collection complete, explicitly not PilotReadiness passed. Two network-logon-right lists are read separately in secpol.msc; policy assignments or exports are not changed.

Official contracts and the saved source received root plus two independent reviews with no required correction. The documentation distinguishes per-user inclusion from exclusion, a known Boolean false from an unknown lock state, and owned licensing from technical activation. It preserves historical setup failures without repeating successful queries or mutations. **This new block has not run or been parsed on Windows.** No genuine prerequisite values, successful SMB authentication, 4624/4625 records or export are invented. Engine/schema/XML/fixtures/export script remain unchanged, so their existing tests were not repeated. Native adapter and Splunk execution remain pending. No AI author metadata, commit trailers or Git-identity changes.

Final local QA checked **107 relative Markdown links in 12 updated documents**, all resolving. Static inspection of the 108-line read block found no mutation/authentication/export commands, preserved raw nullable getter values and native exit, a read-only registry open, and a licensing SELECT without keys/IDs. These are file/source checks, not Windows execution, parser validation or detector tests. The app opening request for the new read file returned queued; no actual tab display is asserted.

## User-executed partial pilot collection and address-drift follow-up — 2026-10-04

The complete next attachment contains the actual read-block execution. Guest local time 2026-10-04T20:33:13.4066612+02:00 equals its returned UTC 18:33:13.4066612; W. Europe Standard Time reports base offset+1. No simultaneous Mac-time comparison is available. ForceGuest is present DWord 0; SCENoApplyLegacyAuditPolicy is absent, not read as 0. IsAccountLocked returned actual System.Boolean false. BadLoginCount returned Unavailable with the actual property-cache exception; counter and measured budget remain unknown. The prior general WinNT contract/source review did not prove this getter would work through InvokeGet in this guest; that inference is corrected, not silently replaced by another field/cast.

One licensing row: Windows Professional, RETAIL channel, LicenseFamily Professional, LicenseStatus 5, GracePeriodRemaining 0. Official SoftwareLicensingProduct defines 5 Notification, not Licensed 1. The user's owned-license assertion remains separate; activation is now an observed unresolved status rather than merely unread. No activation/network operation or key retrieval occurred.

All 15 route rows were read: only interfaces 1/8, Loopback/host-only subnet/link-local/multicast/broadcast, NextHops 0.0.0.0 or::, no visible default/external gateway route. Crucially, Ethernet0 has a **192.168.243.129/32** self-route, whereas the previously measured guest IP and own Mac-Allow LocalAddress were .128. This indicates possible address drift, not a current Preferred IP/causal DHCP finding. The prior firewall acceptance is historical; the matching current IP/rule relation needs a bounded fresh read.

The actual per-user auditpol message explicitly says no policy is defined for this account, with **exit 2**. AuditQueryPerUserPolicy documents error 2 for no per-user policy; the observed text plus code supports that interpretation. It does not negate the separately observed system Audit Logon success/failure. The script's strict nonzero guard then stopped before Complete. Its earlier mandatory exit 0 acceptance was too strict for this state. The original logic is retained as historical code with a do-not-rerun header; no fictitious corrected Windows run is claimed.

Prepared [Read-LabAddressDrift.ps1](../scripts/windows/Read-LabAddressDrift.ps1) and [its small manual step](history/windows-address-drift-step.md). Only Ethernet0 adapter/IP/DHCP and exact SOC-Lab-SMB-Allow-Mac address-filter reads in both stores; one-rule/one-filter guards, explicit Stop, original status names, no mutation/connection/authentication. Multiple real address rows remain visible. Complete means collection, not readiness. Root and two independent saved-source reviewers found no required fix. **No PowerShell parser or Windows execution of the new follow-up here.** No entire-collector or successful setup repetition is requested.

An optional measured counter is no longer an invented hard prerequisite for the small owned-account pilot: a specifically confirmed quiet interval exceeding the observed 10-minute reset period plus freshly checked unlock state can support the bounded next trial. This is a policy-based condition, not measured counter 0; no quiet period is falsely marked observed. Network-logon rights, current address/rule binding, time comparison/audit precedence and activation remain separately tracked; no authentication is allowed by this record. Actual event count must be inspected after each future single invocation. No interop/new provider implementation was added merely to obtain a speculative replacement count.

The raw transcript remains in its attachment; no dynamic SID or genuine event fixture/export was copied or fabricated. Application/schema/XML/fixtures/export script unchanged, so no detector tests rerun. Native adapter and Splunk execution remain pending. No AI author metadata, commit trailers, Git identity, host or guest policies changed by the agent.

Final local QA: **119 relative links in 14 documents resolve**. The new 44-line read block has five explicit-Stop read sites, exact own-rule/address-filter count guards and both stores, no write/auth commands or numeric status casts. Navigation review identified and removed two stale collector-run instructions; current paths now request only the bounded address read. These are source/file checks, not Windows parsing/execution or new detector tests. Opening the new raw file through the app returned queued; no actual display is asserted.

## User-executed address diagnosis completed — 2026-10-05

The complete user message contains the error-free Read-LabAddressDrift.ps1 run and final **AddressDriftCollection Complete, NetworkOrFirewallChanged False, PilotReadiness Not decided**. Ethernet0 is Up, index 8, Connected, Dhcp Enabled. Get-NetIPAddress directly returns **192.168.243.129/24 Preferred, PrefixOrigin Dhcp, SuffixOrigin Dhcp**. This now confirms the actual address and DHCP provenance; it does not establish a particular lease-renewal/reboot cause. No guest execution timestamp is printed in this diagnostic; the record date is the received continuation date.

Each of PersistentStore and ActiveStore has RuleCount 1 and AddressFilterCount 1 for SOC-Lab-SMB-Allow-Mac, EnabledTrue, Inbound, Allow, ProfileAny, PrimaryStatusOK. **LocalAddress 192.168.243.128, RemoteAddress 192.168.243.1** in both stores. PersistentStore EnforcementStatus NotApplicable, ActiveStore ProfileInactive Enforced. The whitespace-separated rendered Active value is retained as observed, not converted to numeric status. Root reviewed all returned fields against the source and criteria; an independent review agrees the own-rule address mismatch is confirmed. This is configuration evidence, not a global SMB-block, packet/authentication result or Security event.

The diagnosis is passed and should not be repeated. Historical .128-era firewall acceptance remains dated; it does not imply this old local binding matches the currently preferred .129. No network or firewall mutation occurred in the diagnostic; no raw user-message fixture or invented logon evidence was created.

## One-property Mac Allow correction prepared — 2026-10-05

Added [Update-LabMacAllowAddress.ps1](../scripts/windows/Update-LabMacAllowAddress.ps1) and [its manual guide](history/windows-address-repair-step.md). The single scoped setter modifies only LocalAddress of the own named rule in PersistentStore to **Any**. Source remains exact Mac 192.168.243.1, Ethernet0, inbound TCP445; DHCP, existing blocks and all other unpassed rule parameters are not modified. Any avoids repeating the stale binding on the next DHCP change; it does not broaden the remote source or require a static address/reservation.

Preflight checks known guest/elevation, running adapter, one preferred DHCP IPv4 in the known /24, and enabled firewall profiles. Both stores must expose exactly one named Allow and each of its four selected filters; actual source/ports/interface/edge/security/override fields must match. Only observed .128 or already Any is accepted, with the stores agreeing. Already Any skips the setter. The helper prints diagnostics through Out-Host, returning only its row. Active enforcement is split on commas or whitespace, requiring Enforced with optional ProfileInactive; no status-number casts or Package-Any guesses. Both stores are reread and require Any plus all selected retained conditions before MacAllowAddressReadback Passed. This is deliberately scoped configuration acceptance, not a new complete WFP/application-filter audit or pilot result.

Root plus two independent saved-source reviews found no required correction after adding Active enforcement and clarifying early error behavior. The early machine/admin/adapter/IP/profile guards are before try, with direct error output; the stage marker covers subsequent rule checks, setter and readback. Failure after a setter may leave the address changed; a false SetterReturnedSuccessfully is not claimed as proof of no mutation. No automatic rollback/reset is included. **The correction has not executed or been empirically parsed on Windows.** Prepared criteria do not assert Passed as observed.

Application, schema, XML inspector, fixtures and export script are unchanged; their tests were not repeated. Remaining rights/audit/time/lockout-trial conditions precede any actual logon; activation Notification is separately tracked. Native export, exact adapter and Splunk execution remain pending. No AI author metadata, commit trailers or Git identity changed.

Final local file QA: **147 relative links in 15 updated documents resolve**. The 128-line correction has eight explicit-Stop read sites and exactly one own-name/PersistentStore/LocalAddress-only Set site, with both-store checks before and after. No other mutations, numeric enforcement casts, raw dynamic SID or Markdown fences. Navigation marks the completed diagnosis consistently and does not request its repetition. These are static file/source checks, not Windows parsing/execution or detector tests. App opening returned queued; actual tab display is not asserted.


## User-executed Mac Allow correction accepted — 2026-10-05

The complete supplied transcript contains the actual Update-LabMacAllowAddress.ps1 execution without errors, ending **MacAllowAddressReadback Passed / RuleChanged True**. Ethernet0 is **192.168.243.129/24 Preferred**, with both address origins Dhcp. Both before rows have LocalAddress 192.168.243.128; both after rows have **LocalAddress Any**. In PersistentStore and ActiveStore, RemoteAddress 192.168.243.1, Ethernet0, inbound Allow/EnabledTrue/ProfileAny/PrimaryStatusOK, TCP445/RemotePortAny, EdgeTraversalBlock, Authentication/EncryptionNotRequired and OverrideBlockRulesFalse are retained. Persistent enforcement is NotApplicable; active enforcement is ProfileInactive,Enforced before and after. The receipt date is recorded; no unprinted guest execution timestamp is invented.

Root and an independent reviewer read the complete attachment and compared all four selected rows with the saved source and acceptance criteria. Selected configuration acceptance is passed; this does not establish packet reachability, full WFP behavior, successful SMB authentication or Security-event field coverage. The guest change was performed by the user, not the agent. The raw attachment is not copied into native-event fixtures. Do not rerun the correction, address diagnosis or completed setup.

Prepared [the next small read-only GUI step](history/windows-network-logon-rights-step.md): open secpol.msc, read both complete network-logon Allow/Deny account/group lists and close with Cancel. No policy export or modification, new collector, password or logon is required. The actual lists have not yet been supplied; official defaults are not treated as guest observations. Their group applicability and Deny precedence must be assessed before the pilot. Remaining audit/time/quiet-interval/unlocked-state conditions remain tracked; the unknown failed-logon counter is not converted to zero. Technical activation Notification remains separate from the user's owned-license confirmation.

The correction script received only a do-not-repeat header update; its executed logic is unchanged. Application, schema, XML inspector, fixtures and export script are unchanged, so detector tests were not repeated. Genuine 4624/4625 capture/export, precision-preserving adapter, real-data detector comparison and Splunk execution remain pending. No AI author metadata, coauthor trailers or Git-identity changes.

Final local documentation QA checked **144 relative Markdown links in 16 updated documents**, all resolving; code spans/fences were excluded. Current navigation consistently marks the selected correction completed and routes only to the two GUI rights lists. These are documentation checks, not new detector tests or Windows execution.


## User-observed MMC failure and built-in rights-export fallback prepared — 2026-10-05

Two supplied screenshots show the local group-policy object cannot be opened, with generic German details **Unbekannter Fehler** ("Unknown error"), followed by the local-security-policy console with red error icons and no requested lists. The user reports the same failure when running secpol.msc as administrator; the visible background PowerShell has an Administrator title. No specific permissions, edition, activation or database-corruption cause is proven. No actual Allow/Deny assignment was obtained. The earlier accepted firewall address correction remains completed and is not repeated.

Prepared [Export-LabNetworkLogonRights.ps1](../scripts/windows/Export-LabNetworkLogonRights.ps1) and replaced [the current rights guide](history/windows-network-logon-rights-step.md) with one manual fallback. The built-in secedit /export /mergedpolicy /areas USER_RIGHTS uses the default system security database and unique new TEMP INF/log paths. It reads stored assignments, not applying a template or changing policy. Known-machine/admin and new-path guards precede export; native exit is captured immediately, failure shows at most 25 log lines and stops. File presence/size up to 1 MiB, actual UTF-16LE BOM, exactly one Privilege Rights section and no duplicate selected keys are checked. Only two original assignment lines are printed, with raw names/SIDs retained; missing keys are explicitly NotPresentInExport, never assumed empty. Collected is a collection state, not pilot readiness or a direct independent LSA/SMB result.

Root and an independent reviewer read the complete saved 61-line source and the official contracts, with no required fix. No PowerShell runtime is available here (command-v check exit 1/no path); nothing was installed. These are source/API reviews, not PowerShell parser or guest runtime tests. The fallback has not run in the guest; no actual INF, rights values, policy-repair result or native logon event is fabricated. Remaining group applicability/audit/time/quiet-interval/unlock gates precede a trial. Application/schema/XML/fixtures/event-export script are unchanged, so their existing tests were not repeated. Splunk/native capture/adapter remain pending; no AI author metadata/trailers or Git-identity edits.

Local file QA checked **158 relative Markdown links in 16 updated documents**, all resolving. The saved 61-line fallback contains exactly one native secedit /export call and no import/configure/reset/setup action. Current overview navigation requests the prepared diagnostic export, not another MMC attempt or completed setup. These are local documentation/source checks, not a PowerShell execution or detector-test result. App opening of the prepared source returned queued; actual display is not asserted.


## Native capture adapter and fixed-expectation verification — 2026-10-05

The user's status update supersedes the unsuccessful rights-export parser diagnosis. The real SMB success proves the needed network-logon right is effective and no Deny prevents this account/path; stored assignments were not enumerated. `Read-LabNetworkRightsExport.ps1` is retired for this experiment. No additional Windows, authentication, policy, installation or diagnostic action was performed by the agent in this continuation.

The user reports Mac `192.168.243.1` → `DESKTOP-7HFI2UV` (`192.168.243.129`), account `lab-auth01`, with one 4625 per smbutil invocation, Status `0xc000006d` / SubStatus `0xc000006a`. The private original XML actually contains the stated 12 events in the manifest interval **2026-10-05T02:44:00Z–02:53:00Z**. The observed hash equals the manifest and the user's post-transfer hash:

`c34c38bede02b97dc474b946b135e2e134e2e01bdfa5ca2dc17c19bf014102f5`

Local original-file inspection confirmed **8 complete scope events**, **4 SYSTEM/type-5 events with source IP `-` outside scope**, and **11/12 original timestamps not exactly representable at microsecond precision**. This checks the available captured content and integrity against the supplied manifest, rather than independently observing every Windows command or authenticating the source of an arbitrary file.

The already accepted precision policy is implemented by string truncation to six fractional digits, never rounding. Optional schema-1.0 `timestamp_raw` retains complete SystemTime; positive integer `record_id` supplies the native equal-microsecond tiebreaker. Legacy records keep the original exclusive success timestamp. UIDs hash raw `Computer|Channel|integer EventRecordID`; record reuse after log clearing/restoration is a documented collision limitation. Original XML bytes were not modified. The next relevant event to the main success's lower 300-second boundary is **65.1345863 seconds** away; truncation is less than 1 µs. There are no equal-microsecond collisions in this capture.

After code and CLI changes, the complete suite ran **once**, from `lab/`:

```sh
.venv/bin/python -m pytest
```

Observed: **155 passed in 5.40s**, Python **3.14.7**, pytest **9.1.1**, pluggy **1.6.0**. Collection includes 23 CLI, 49 engine, 11 integrity/export, **21 adapter**, 37 XML and 14 Splunk-comparison-helper tests. Adapter tests use only `data/fixtures/windows-adapter-synthetic.xml`, a small hand-authored synthetic file with neutral identities and documentation IPs. They cover `.9999999 → .999999`, original time consistency, malformed native time exclusion, complete mapping, scope/missing-field exclusions, deterministic identity, input limits, equal-microsecond record ordering independent of line order, legacy ordering, the inclusive lower boundary, invalid RecordIDs and CLI artifacts/evidence. No real capture was copied into a test fixture, and helper tests still do not execute SPL.

The actual integration commands then exited **0**:

```sh
.venv/bin/python -m soc_detection_lab adapt-windows-xml --input data/lab-captured/pilot-01/events.xml --output reports/lab-captured/pilot-01/adapter --data-origin lab-captured
.venv/bin/python -m soc_detection_lab analyze --input reports/lab-captured/pilot-01/adapter/events.jsonl --output reports/lab-captured/pilot-01/analysis
```

| Independently specified check | Observed result |
| --- | --- |
| Adapter input / emitted / excluded / outside scope | **12 / 8 / 4 / 4** |
| Emitted timestamps truncated / with discarded nonzero digits | **8 / 8**; all retain `timestamp_raw` |
| Analysis input / processed / duplicates / excluded / errors | **8 / 8 / 0 / 0 / 0** |
| Expected alert count | Exactly **1** |
| Expected success | **53330**, original `2026-10-05T02:51:42.4779345Z` |
| Expected failure records | Exactly **53325, 53326, 53327, 53328, 53329**, in order |
| Expected full key | Domain `DESKTOP-7HFI2UV`, user `lab-auth01`, source `192.168.243.1`, target `DESKTOP-7HFI2UV`, type **3**; domain/host casefold to `desktop-7hfi2uv` |
| Pilot success 53314 | **No alert**, only failure **53293** in its window |
| Excluded SYSTEM/type-5 records | **53294, 53316, 53318, 53323**, all with explicit outside-scope reasons |
| Original hash after integration | Unchanged and equal to manifest / supplied transfer hash |
| JSON / Markdown evidence | RecordID, normalized time and complete original SystemTime present |

The predeclared expectation was not changed to fit the detector. A separate local comparison read actual artifacts and the raw SYSTEM/type-5 record identities; it compared fixed IDs/key/counts/hash and wrote **`reports/lab-captured/pilot-01/expectation-check.json`, matched: true**, with all ten checks true. The alert ID is `917eb058a8c56e5de02b3d2ea8d2cd435b595d08a218e36af677905218cc52ea`. The normalized input hash is `12b78734c54e76cdea9476e5b910c94f53de211d02c71b1be9787b7653d14010`.

All originals and derived results remain private under **`data/lab-captured/` and `reports/lab-captured/`**, both excluded by `lab/.gitignore`. No Git repository exists in this workspace; no private path is currently tracked here. A future repository/publication must still check tracked paths. No publication, commit, AI author/co-author credit, commit trailer or Git identity edit occurred.

**Splunk remains not executed.** Producing a transport JSONL is not an import/job proof. The existing SPL has not yet implemented the native equal-microsecond RecordID exception, so no general equivalence assertion is made; this real capture has no such ties. The requested Windows→adapter→Python comparison is complete, while the Splunk portion of Milestone 2 remains pending a suitable environment.

Final local file checks found **97 relative Markdown links in ten updated documents**, all resolving. The exact ignore rules were exercised on five private path names in a disposable temporary Git repository, all ignored; only the ignore file was copied, no capture content, and no user Git identity was changed. These are documentation/privacy checks, not another detector-suite run.


## Splunk native ordering and Intel macOS preparation — 2026-10-05

The user fixed the setup: Enterprise 10.x `.tgz` in a user directory on the Intel Mac, Enterprise Trial, no root/service/autostart, Windows shut down while Splunk runs, user-managed account-dependent download. This choice is not reevaluated. Read-only host observations confirm macOS 15.8.1/build 24H32, Darwin 24.6.0, x86_64 and about 17 GiB free on the workspace volume. No matching archive was found in the Downloads search; three selected possible installation directories were absent. This bounded search does not prove absence everywhere.

Official current download content only supplied a macOS ARM64 package; the official archive specifically supplies **splunk-10.2.7-c0bff5b0fac3-darwin-intel.tgz**. Its non-Linux note requires an updated **enttrial.lic**. The 10.2 Darwin table lists macOS 15/x86 64-bit as Developer/deprecated, with the Trial column empty: this selected Trial combination is documented as **not officially listed**, with the requested lab test still planned. Archive/license download, actual package architecture, effective Trial, startup and search results remain unobserved. Exact sources and manual steps are in [sources](sources.md) and [the macOS runbook](splunk-macos-runbook.md).

The revised SPL now sorts by time/RecordID, implements the accepted smaller-ID same-microsecond failure branch, and exports paired JSON native evidence. The comparator checks native metadata in addition to complete UID/time/key/configuration evidence. A separate inventory search preserves original indexed `_time` before any correction; its Python verifier rejects incomplete imports, changed fields and disagreement between original index time, parsed timestamp and exact transport epoch at microsecond precision. The own sourcetype/index/Web templates are prepared for later copy, with explicit `%6N`, exact timestamp prefix, UTC and `ADD_EXTRA_TIME_FIELDS=subseconds`, index soc_lab and loopback-only Web. Configuration was not installed or empirically validated by Splunk.

After these local code changes, the complete suite ran once:

```sh
.venv/bin/python -m pytest
```

Observed **178 passed in 5.20s** on Python 3.14.7 / pytest 9.1.1 / pluggy 1.6.0. The additional 23 tests are one synthetic-boundary pipeline test, 11 import-verifier tests and 11 native-result-comparator tests. Artificial inventory/result exports in tests are explicitly labeled synthetic and do not count as executed SPL.

The 14-event synthetic dataset was also actually run through the same adapter/analysis/evaluation CLI:

```sh
.venv/bin/python -m soc_detection_lab adapt-windows-xml --input data/splunk-boundaries/events.xml --output reports/generated/splunk-boundaries/adapter --data-origin synthetic
.venv/bin/python -m soc_detection_lab analyze --input reports/generated/splunk-boundaries/adapter/events.jsonl --output reports/generated/splunk-boundaries/analysis
.venv/bin/python -m soc_detection_lab evaluate --input reports/generated/splunk-boundaries/adapter/events.jsonl --expected data/splunk-boundaries/expected.json
```

All commands exited 0. Adapter 14 input / 14 emitted / 0 excluded; all 14 raw fractions truncated with originals retained. Analysis 14 processed / 0 duplicates / 0 excluded / 0 errors, exactly 2 alerts. Evaluate **matched: true**, two expected / two actual / no mismatches, normalized input SHA-256 **90ab7834c0fdaf9ea703604ffaf83c4d19bc7fd7c725862945aa0c217206b05a**. Exact expected evidence: success 1006 / failures 1001–1005 (type 3, same µs) and success 2006 / failures 2001–2005 (type 10, exact 300 s lower boundary). Failure 1007 has a higher RecordID in the success microsecond; failure 2000 is 1 µs outside the lower boundary. Expectations were specified separately, not obtained from the detector. Original 8-event real transport/results are unchanged and were not needlessly regenerated.

Current runtime status remains **reviewed-not-executed**: no installer/license downloaded by the agent, no process/service/autostart, no index import, no Splunk job/export, and no actual stop/removal observed. The next small user step is the exact Intel archive/checksum/updated Trial download. The runbook supplies subsequent installation, Oneshot for 8 and 14 events, original-time inventory and alert comparisons, then stop and removal; those criteria remain pending. Private exports stay under reports/lab-captured/splunk-01. Added *.lic ignore protects accidental license files; no license content, credentials, AI authorship credit, Git identity change or publication was introduced.

Final documentation checks found **112 relative links across 13 reviewed documents**, all resolving. The real original XML hash was rechecked unchanged; synthetic alerts retain the exact declared RecordID sets. No additional suite run was needed after documentation-only edits.


## Splunk execution and comparison — 2026-10-06

The user downloaded `splunk-10.2.6-bcdcf0552e0c-darwin-intel.tgz` (10.2.7 was not used), extracted it to `~/soc-splunk-lab/splunk`, copied the prepared app configuration, bound Splunk to `127.0.0.1` and started it with the Windows VM shut down. The updated `enttrial.lic` link returned DNS NXDOMAIN; the first start created a Trial license itself, shown active until 2026-12-05. Observed: `bin/splunkd` Mach-O x86_64 signed by Splunk Inc.; version **10.2.6 (build bcdcf0552e0c)**; listeners 8000/8089/8065/8191 on loopback only. The user ran one Oneshot per transport file (8 and 14 events).

With the user's permission, the inventory and detection searches ran via `splunk search "<query>" -earliest_time 0 -maxout 0 -output json` in the user's CLI session. JSONL rows were converted to JSON arrays; originals retained.

| Check | Observed result |
| --- | --- |
| Inventory `soc-lab-pilot-01` / `soc-lab-boundaries-01` | `compare_inventory.py`: **8/8** and **14/14** matched, including indexed `_time` and parsed `timestamp` at microsecond precision |
| Detection, capture | `compare_results.py`: **1** alert matched — success 53330, failures 53325–53329; none for 53314 |
| Detection, boundaries | `compare_results.py`: **2** alerts matched — 1006 ← 1001–1005, 2006 ← 2001–2005; 1007 and 2000 excluded |
| Job logs | Scan counts 8 and 14; no warnings apart from KV-store certificate verification and the `soc_lab` bucket-size notice |

The first runs failed in two ways, both fixed in the queries and re-run:

1. The inventory's parsed-time projection was 7,200 s early for every row: `strptime` ignored the literal `Z` and used the search user's local zone (CEST). Indexed `_time` was correct. The query now parses `+0000` with `%z`.
2. Both detection searches failed with `The arguments to the 'mvmap' function are invalid`: 10.2.6 rejects `json_extract` inside `mvmap`. The CLI still exited 0 with empty output; the error was only in the job's `search.log`. `failure_uids` now come from `json_array_to_mv(json_extract(<array of evidence>, "{}.event_uid"))`, checked separately for exact round-trips of UIDs with quotes, backslashes, commas, brackets and non-ASCII characters.

After the SPL changes the complete suite ran once: **178 passed in 5.21s**. Details, query hashes and job IDs are in the [Splunk validation record](splunk-validation.md#validation-record-2026-10-06); private exports, copied job logs and `run-record.json` are under `reports/lab-captured/splunk-01/`. Afterwards the CLI session was logged out and Splunk stopped; no listener remained. The installation itself has not been removed yet.

## Publication preparation: documentation and clean-copy check — 2026-10-06

Current-status statements in README, German summary, roadmap, limitations, detection logic, export contract, lab plan, sources and runbook were updated to the executed Splunk run; dated historical sections were left as history apart from spacing fixes. Absolute home-directory paths were replaced with `~`/`$HOME`. All **263 relative Markdown links and anchors** resolve.

A scratch Git directory outside `lab/` evaluated the current `.gitignore`: **86 files** would be tracked, none under `data/lab-captured/`, `reports/lab-captured/`, generated outputs, virtual environment, caches or license files. Exactly those files were copied to a temporary directory. There, with the existing interpreter and `PYTHONPATH` pointing at the copy's `src`, the README demo (`generate`, `validate`, `analyze`, `evaluate`) exited 0, produced 24 input lines / 23 processed / 1 duplicate / 3 alerts with alert IDs and evidence identical to `reports/examples/demo-results.json`, and the suite passed (**178 passed in 6.13s**). Not covered: a fresh `pip install -e '.[dev]'`, which needs network access to fetch pytest.

## Repository structure, license, fresh install and Splunk removal — 2026-10-06

User decisions: MIT license (`LICENSE`, copyright Kevin Mekic), repository root `lab/` with the private workspace files outside it, real lab identifiers kept in the documentation, and the dated Windows setup/troubleshooting notes kept as history. The 15 notes moved to [`docs/history/`](history/README.md) with a banner and an overview page; all links were rewritten, and all **317 relative links and anchors** resolve.

With the current `.gitignore`, **88 files** would be tracked, again without private or generated paths. A copy of exactly those files was installed from scratch with the system Python 3.14.7: `python3 -m venv .venv`, `python -m pip install -e '.[dev]'` (pytest 9.1.1 fetched from PyPI with the user's permission). The README demo commands and the `soc-detection-lab` console script exited 0; the demo again produced 24 lines / 23 processed / 1 duplicate / 3 alerts with alert IDs identical to the versioned example; `python -m pytest` passed **178 tests in 5.84s**.

Before removal, `splunkd.log`, `search_messages.log` (containing the two failed detection jobs' `mvmap` errors, whose dispatch directories had already expired) and `first_install.log` were copied to the private `reports/lab-captured/splunk-01/`. With Splunk stopped and no listener on 8000/8089, `~/soc-splunk-lab/`, the empty `~/.splunk/` and the downloaded archive were moved to the macOS Trash. No launchd entries or other Splunk paths remained in the home directory. Emptying the Trash and clearing browser site data for `127.0.0.1:8000` are left to the user.

## English-only repository and README rewrite — 2026-10-06

At the user's request the repository is English-only. `README.de.md` was removed (moved to the macOS Trash), the README was rewritten as a project overview with results, quickstart, layout and CLI behavior, and the remaining German documents were translated: `windows-lab-plan.md`, `learning-notes.md` and the 15 notes in `docs/history/` including their banner and overview page. Quoted German Windows UI output keeps the original wording with an English gloss. The lab plan's historical checklist now records the final state of each item. Earlier entries in this record that mention the German summary describe the state of their date.

