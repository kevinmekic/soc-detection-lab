# Logon pilot: address change confirmed

> **Historical working note** from setting up and troubleshooting the Windows test VM. Instructions and anything labeled "current" or "next step" reflect the state on the note's date and are superseded. Current state: [project status](../project-status.md); overview: [setup history](README.md).

**Continuation, 2026-10-05:** the address diagnosis and the following [Allow correction](windows-address-repair-step.md) completed successfully: Preferred DHCP .129/24 observed, the previous .128 condition corrected to Any and both stores read back with **MacAllowAddressReadback Passed / RuleChanged True**. Do not repeat the diagnosis or the setter. The later administrative MMC attempt failed with "Unknown error". The subsequent rights export has been run by the user: **ExportExitCode 0**; file/size/UTF-16LE BOM checks passed. Only the parser stopped with **Expected exactly one Privilege Rights section**, before both rights lines and **NetworkRightsExport Collected**. The section count was not printed; parser cause and actual rights values remain unknown. Now run only the complete current [Read-LabNetworkRightsExport.ps1](../../scripts/windows/Read-LabNetworkRightsExport.ps1) in the guest according to the [rights guide](windows-network-logon-rights-step.md). The new diagnostic block has **not yet been run**. It only reads section headers, selected possible rights lines and the end of the log of the existing export files. No export, no file write, policy change or logon. Supply the complete diagnostic console output, not the complete INF. No pilot approval.

Status: **2026-10-04**. The user read the [pilot prerequisites](windows-pilot-prerequisites.md). The collection stopped after the account-specific audit query; the generic exit-code guard was too strict for the explicitly reported state without a per-user policy. The results already supplied are usable. **Do not repeat the whole collection block.**

The earlier .129/32 route triggered the diagnosis but was not yet proof of a Preferred IP. The later actual Get-NetIPAddress output confirmed **192.168.243.129/24 Preferred**, DHCP origin and the own allow rule, still bound to **.128** at the time, in both stores; the subsequent correction to Any has since been accepted. Why DHCP assigned this address is not established by this.

## Small query that was run

The user ran the complete block from [Read-LabAddressDrift.ps1](../../scripts/windows/Read-LabAddressDrift.ps1) and supplied the output without errors. Do not run the diagnostic block again. Keep the VM running on the host-only network; after the later successful export with the parser stop, now only [diagnose the existing rights export files](windows-network-logon-rights-step.md). The separate Allow correction has also passed. Do not repeat the export and MMC. Do not trigger a logon.

The block only reads Ethernet0, its IPv4/DHCP state and the address filters of **SOC-Lab-SMB-Allow-Mac** in PersistentStore and ActiveStore. It changes neither the address nor the firewall. The own rule and its associated address filter must exist exactly once per store; otherwise it stops with a count/error. No firewall reset, no new rule and no repetition of the earlier repair.

**Success of this read step actually observed:** IPv4 .129/24 Preferred, PrefixOrigin/SuffixOrigin Dhcp; per store RuleCount 1, AddressFilterCount 1, LocalAddress .128 and RemoteAddress .1; finally **AddressDriftCollection : Complete**. Complete only means collection, no checked pilot readiness or packet behavior.

The preferred .129 and the rule LocalAddress .128 at the time were confirmed: before the correction, this own allow did not match the assigned address. That is no proof that SMB as a whole is blocked: other allow conditions observed earlier may still exist. This readback justified the subsequently successful correction of only the own Allow LocalAddress to Any. The diagnostic block changed nothing. The IPv4/IPv6 blocks were configured with local Any and are not recreated here.

## Results already supplied

| Finding, 2026-10-04 | Assessment |
| --- | --- |
| LocalTime 20:33:13.4066612+02:00, UtcTime 18:33:13.4066612+00:00; W. Europe Standard Time, BaseUtcOffset +01:00 | UTC/daylight saving conversion consistent. No simultaneously measured Mac time comparison. |
| ForceGuest present, DWORD 0 | Classic account model; no observed Guest-only mapping. |
| SCENoApplyLegacyAuditPolicy not present | Missing, not a read value of 0. The current system audit was separately Success and Failure; its long-term precedence is not established by this. No registry change. |
| BadLoginCount Unavailable, cache exception | Counter unknown; not 0 and no attempt budget derived from it. |
| IsAccountLocked Returned, System.Boolean false | The test account was not locked when read. Not an immutable state for later attempts. |
| Windows Professional, RETAIL, LicenseStatus 5, GracePeriodRemaining 0 | Technical **Notification** state, not Licensed / status 1. Own suitable Pro license confirmed by the user; activation open separately. Do not request keys or change the isolation for an activation now. |
| 15 active routes, interfaces 1 and 8; all NextHops 0.0.0.0 or :: | Loopback, host-only subnet, link-local and multicast; no visible default or external gateway route. Ethernet0 self route now .129/32. No claim of complete isolation. |
| auditpol: "No audit policy is defined for the user account."; exit 2 | No per-user override returned. This specific finding is consistent with the documented API meaning of error 2; it does not follow that system-wide auditing is off. The old block then stopped before Complete. |

The raw file stays in the user's attachment. No dynamic account SID or genuine Security events were created from it as a project fixture.

## Still open afterwards

The address deviation and the limited Allow correction are complete; do not repeat. After the failed GUI attempt, the secedit export succeeded with exit code 0 and existing TEMP INF/log files; only the parser stopped before the rights lines / Collected. Now only read the existing files in a targeted way; do not repeat the export or write files. Actual rights values and parser cause remain open; the section count was not printed. Afterwards assess audit precedence and time alignment, handle the activation need separately and plan the bounded attempt. The unavailable failure counter does not justify an invented substitute query: alternatively, before the pilot there must be an explicitly confirmed quiet period **longer than the observed reset window of 10 minutes** without test-account logon attempts, and the lockout state must be freshly checked. This is a justified experimental condition derived from the reset policy, not a measured counter-0 proof. Only then check a single wrong logon and its actual event count; one SMB call can cause several authentications. Do not run a logon yet.

Native events and Security event export, a precision-preserving adapter, a Python comparison with genuine evidence and the Splunk execution remain pending. Existing application code and its tests are unchanged; these tests are not repeated. No AI authorship information, Co-authored-by trailers or Git identity change.

## Sources and check limits

Checked on 2026-10-04: [Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=windowsserver2025-ps), [Get-NetIPInterface](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipinterface?view=windowsserver2025-ps), [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps) and the [associated address filter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter?view=windowsserver2025-ps). These APIs return the current configuration, not a connection test.

[AuditQueryPerUserPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditqueryperuserpolicy) documents error 2 for a missing per-user policy; the assessment of the specific auditpol result additionally relies on the message actually supplied. [SoftwareLicensingProduct](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct) defines status 5 as Notification. [Reset account lockout counter after](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/reset-account-lockout-counter-after) explains the reset after a period without further failed logons; 10 minutes were observed.

The address block has since actually been run by the user without errors and is accepted; the coding tool checked the complete output but ran no Windows commands itself. The partial findings and the abort of the earlier collection block are preserved. The separate Allow setter has since also been run successfully by the user and shows Any in both stores; the selected acceptance has passed, no logon proof.
