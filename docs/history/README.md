# Windows test environment: setup history

These notes record, in chronological order, how the owned Windows 11 test VM was prepared for the capture of 2026-10-05: account, network, SMB, firewall, troubleshooting and the first logon attempts. They are kept as a learning and working record, including the approaches that failed.

All instructions in them are **historical**. The current state is in the [project status](../project-status.md) and the [validation record](../validation.md); the export format and adapter are described in [windows-export-format.md](../windows-export-format.md), the overall plan in [windows-lab-plan.md](../windows-lab-plan.md). The related PowerShell scripts are in [scripts/windows](../../scripts/windows/).

| File | Content |
| --- | --- |
| [windows-preflight-2026-10-02.md](windows-preflight-2026-10-02.md) | Guest preflight: version, resources, TPM, Secure Boot, audit policy |
| [windows-network-step.md](windows-network-step.md) | Host-only network and address checks |
| [windows-account-step.md](windows-account-step.md) | Local standard account for the logon attempts |
| [windows-smb-step.md](windows-smb-step.md) | SMB service and share prerequisites |
| [windows-firewall-step.md](windows-firewall-step.md) | Reading the active inbound firewall rules |
| [windows-firewall-configure.md](windows-firewall-configure.md) | Limited firewall configuration and its failed first attempt |
| [windows-firewall-recovery.md](windows-firewall-recovery.md) | Reading the partial state after the failed setup |
| [windows-firewall-repair.md](windows-firewall-repair.md) | Targeted repair and readback |
| [windows-application-filter-step.md](windows-application-filter-step.md) | Application filters of the lab rules |
| [windows-share-step.md](windows-share-step.md) | Empty probe folder and test share |
| [windows-pilot-prerequisites.md](windows-pilot-prerequisites.md) | Remaining pilot prerequisites |
| [windows-address-drift-step.md](windows-address-drift-step.md) | Diagnosing the DHCP address change |
| [windows-address-repair-step.md](windows-address-repair-step.md) | Adapting the allow rule to the new address |
| [windows-network-logon-rights-step.md](windows-network-logon-rights-step.md) | Network logon rights, closed by a successful logon |
| [windows-first-capture.md](windows-first-capture.md) | Procedure for the first logon attempts and the export |
