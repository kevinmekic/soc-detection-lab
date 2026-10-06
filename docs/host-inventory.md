# Host inventory for Milestone 2

Host observed on **2026-10-01**, Europe/Berlin. These are local read-only observations, not Windows guest or incident evidence. During that host inventory no application was installed, VM started, VM configuration edited, policy changed or license purchased. User-provided guest observations from **2026-10-02** are recorded separately below.

| Item | Observed value | Interpretation |
| --- | --- | --- |
| Host OS | macOS 15.8.1, build 24H32 | Intel macOS host |
| Architecture | `x86_64`; Intel Core i5-8257U, 1.40 GHz | Use Windows x64, not Windows ARM |
| CPU | 4 physical cores, 8 logical CPUs | Retain the existing two guest vCPUs |
| Physical RAM | 8589934592 bytes = 8 GiB | One 4 GiB Windows VM is a constrained configuration; close memory-heavy apps first |
| Memory at observation | `memory_pressure -Q`: 45% system-wide free; `vm_stat`: 40501 free pages of 4096 bytes | The first is a pressure/reclaimability indicator, not a guaranteed 3.6 GiB allocation. Immediately unused pages were about 158 MiB; caches and compression complicate availability. Recheck before running Windows |
| Hardware virtualization | `kern.hv_support: 1` | Host hypervisor capability present; guest boot was unobserved at this inventory, then confirmed by the user's 2026-10-02 preflight |
| Host disk | 233 GiB volume, about 21 GiB available, 91% capacity used | Avoid a second VM or full local duplicate; storage is a practical gate |
| Installed hypervisor | `/Applications/VMware Fusion.app`, version 26.0.0, build 25388279 | Existing application can be reused; latest-version status is not asserted |
| App-declared minimum OS | `LSMinimumSystemVersion = 13.00.0` | Host exceeds the installed vendor bundle's minimum; this is not the full support matrix |
| Existing VM | `~/Virtual Machines.localized/Windows 11 x64.vmwarevm` | User confirmed it is an owned, dedicated test VM |
| Selected VM configuration | Windows-11-x64 guest declaration, 2 vCPU, 4096 MiB RAM, EFI, vTPM present, hardware version 22 | Guest edition/build, activation, Secure Boot state and actual health require console inspection |
| Virtual disk | VMDK descriptor: 40 GiB capacity; bundle about 26.6 GiB allocated | Below Microsoft's 64 GB Windows-11 baseline; expansion is recommended for that baseline, not technically indispensable for the bounded pilot on the already-running guest |
| Current integration/network | NIC present with NAT; shared folders enabled | Planned lab uses one host-only NIC and disables shared folders during the exercise |
| Other solutions | No Parallels, VirtualBox, UTM or QEMU app/CLI found in checked locations; empty `/Users/Shared/Parallels` | This bounded inventory does not prove absence in every possible location |

## Read-only evidence commands

```sh
sw_vers
uname -m
sysctl hw.memsize hw.physicalcpu hw.logicalcpu hw.optional.arm64 kern.hv_support machdep.cpu.brand_string sysctl.proc_translated
memory_pressure -Q
vm_stat
df -h ~/Documents/Projekte/soc-detection-lab
/usr/bin/smbutil help view
```

The sandbox blocked `sysctl`; the same read-only query succeeded after approval. The ARM and translation OIDs are absent on this Intel host, so that combined command exits 2 despite returning the useful hardware values. `ps` was denied and was not retried because application and file inventory supplied the necessary evidence. `ifconfig vmnet1` reported no such interface at observation; host-only addressing must be observed after Fusion enables that network. No guessed live IP addresses are recorded.

Application names and selected bundle plist values were read under `/Applications` and `~/Applications`. Known VM directories were inspected, and only relevant resource/network fields were read from the `.vmx`; encryption keys, MAC addresses, product keys and unrelated personal contents were not printed. The 40 GiB capacity comes from summing sectors in the small VMDK descriptor, not from assuming that physical sparse-file size equals virtual capacity. Bundle size is allocated disk blocks and is not a backup/snapshot-space guarantee.

## Support and cost findings

Reviewed official sources are recorded in [sources.md](sources.md). Fusion 26H1 is free for all stated use categories, but Windows licensing remains separate. The installed app supports an Intel executable and declares a minimum macOS version below this host. The current formal Fusion-26 host matrix and numerical host installation requirements were not accessible because the linked vendor release documentation returned HTTP 403. The older 13.6 host matrix must not be substituted as a Fusion-26 certification. Before any update/reinstallation, confirm the exact combination in the vendor portal; no update or installation is needed for the next console preflight.

Windows-11 VM prerequisites include at least two vCPUs, 4 GB RAM, 64 GB virtual disk, Secure-Boot capability and vTPM. The current disk is the observed discrepancy. Guest preflight now confirms TPM ready and Secure Boot supported but disabled; existing activation/licensing remains pending. A VM name and `guestOS` setting do not establish these facts.

## User-provided guest preflight — 2026-10-02

The [dated guest record](history/windows-preflight-2026-10-02.md) records Windows 11 Pro 25H2 build 26200.8037, computer DESKTOP-7HFI2UV in WORKGROUP without domain membership, approximately 4 GiB RAM, GPT disk 40 GiB, C: about 39.79 GiB with 19.48 GiB available, TPM present/ready and Secure Boot disabled. Guest startup is now observed. The record also preserves lockout 10/10/10, the active 20-MiB circular Security log, the initial AuditPol error and the subsequent successful System Audit Logon query: success/failure enabled, exit 0. The NIC remains disconnected according to the user. Activation UI reports a connection problem, with no successful activation established.

These guest values came from the user's console output and visible screenshots, not a native event export. No personal screenshot/account email is stored. Host RAM pressure and shared-folder configuration were not rechecked; current NIC disconnection is user-confirmed, not a completed host-only setup. Activation/license suitability remains open.

## Read-only storage follow-up — 2026-10-02

`df -k` on the VM bundle path reported **19200364 KiB available, approximately 18.31 GiB**, 92% capacity used on `/System/Volumes/Data`. This supersedes the earlier 21-GiB free-space estimate for current planning. Selected VMX/disk-descriptor reads show the boot disk on `nvme0:0`, filename `Virtual Disk.vmdk`, type **`twoGbMaxExtentSparse`**, still 40 GiB. No snapshot-state `.vmsn` file was found in the bundle's top level; this is a bounded check, not full snapshot inventory. No disk expansion or VM modification was performed.

The user reports no external storage/backup and explicitly treats the pure test VM as disposable. After the storage clarification, the selected small pilot keeps **40 GiB** without a backup/second copy. No resize/guest partition extension occurred; the next manual step is [host-only networking](history/windows-network-step.md).

## Read-only networking follow-up — 2026-10-02

The sandbox blocked `sysctl net.inet.ip.forwarding net.inet6.ip6.forwarding`; the same read-only query was approved and returned **0 / 0**. Neither value was changed. Selected Fusion networking configuration shows VNET 1 DHCP enabled and private subnet **192.168.243.0/24**, plus the separate VNET 8 NAT network **192.168.57.0/24**. `ifconfig vmnet1` found no such interface; filtered `ifconfig -a` observed **bridge100 active at 192.168.243.1/24**, **bridge101 active at 192.168.57.1/24**, and bridge0 inactive. MAC addresses and unrelated physical interface addresses are not recorded here.

The private Mac address is now observed; it is not an invented Windows address or a captured SMB source. The VM's selected private connection, Windows IP/routes, other VMs and Internet Sharing/host-proxy context are still to be confirmed. No networking file, VM setting, route, policy or forwarding value was changed by the agent. No network connection test or authentication attempt was performed.

## Read-only network result — 2026-10-03

User-provided Windows output now reports **Ethernet0, ifIndex 8, Up**, **192.168.243.128/24, Preferred**; only the loopback address is additionally shown. The IPv4/IPv6 standard-route query returned no rows twice. Selected current VMX fields show **ethernet0.connectionType = hostonly**, adapter present and **isolation.tools.hgfs.disable = TRUE**. A saved shared-folder definition remains; runtime access was not tested and no host path recorded.

The current Mac bridge100 remains **active at 192.168.243.1/24**. `/sbin/route -n get 192.168.243.128` initially failed with a sandbox socket denial; after approved read-only retry it showed **interface bridge100**. This is a local route lookup, not an authentication/reachability test. The user confirms **Internet Sharing off and no additional VMs running**; the target VM remains running intentionally for the next guest configuration. Other guest routes, guest UTC/timezone and actual SMB event source/type remain unverified. Forwarding 0/0 is the historical 2026-10-02 observation, not a fresh query. No VM file, host policy, forwarding or firewall change was made by the agent.
