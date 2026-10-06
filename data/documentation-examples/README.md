# Documentation-derived structural test data

`security-structure.xml` is a **synthetic fixture constructed for inspection tests**. It was not exported by Windows. XML names, nesting, namespace and event-version examples follow Microsoft's official [4624 XML](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [4625 XML](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) documentation, checked on 2026-10-01.

This is an independently constructed minimal example, not a copy of the complete documentation examples. Account, computer, IP, record IDs, date/time, type 3 and failure-context values are explicitly synthetic test inputs. Fields not needed by the inspector were omitted. Microsoft's original examples instead use type 2 and localhost; their original timestamp strings are used separately in tests to expose the microsecond incompatibility. The `Events` grouping root is our export contract, not an additional Windows event field.

Passing inspection of this fixture proves only the selected field-reading branches. It does not prove audit configuration, network authentication, genuine event capture, normalization into schema 1.0, detection of real events or Splunk execution.
