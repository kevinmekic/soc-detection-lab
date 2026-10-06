# Splunk Enterprise on the Intel Mac — manual lab runbook

Prepared on **2026-10-05**, executed on **2026-10-06** with Splunk Enterprise
**10.2.6** (build bcdcf0552e0c). The commands below reflect that run; results
and corrections are in the [validation record](splunk-validation.md#validation-record-2026-10-06).

## Fixed setup and platform observation

The selected setup is a `.tgz` installation under the existing user's home,
with an Enterprise Trial license. Run it manually without root, a service or
boot startup. Shut down the Windows VM before starting Splunk and leave it off
throughout this run. The Mac supplies the complete exported batches; no new
Windows authentication is needed.

Read-only `sw_vers` and `uname -m` on 2026-10-05 confirmed **macOS 15.8.1,
build 24H32, x86_64**. The [host inventory](host-inventory.md) records **8 GiB
RAM**, four physical CPU cores and eight logical CPUs. This is a small,
temporary comparison lab; it is not a production sizing claim.

The [10.2 Darwin requirements table](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises)
lists macOS 15/x86 64-bit with **D in the Developer column**, meaning deprecated,
and an empty Trial column. Consequently this chosen Trial combination is
**not officially listed**. The requested lab experiment still proceeds; success
will establish the observed local behavior, not vendor support.

The public [current download page](https://www.splunk.com/en_us/download/splunk-enterprise.html)
shows an ARM64 macOS archive; it does not show an Intel archive for its displayed
10.4/10.6 offerings. The [previous releases page](https://www.splunk.com/en_us/download/previous-releases.html)
does show **10.2.7, build c0bff5b0fac3**, for Intel macOS 14/15:
`splunk-10.2.7-c0bff5b0fac3-darwin-intel.tgz`, advertised as **1002.93 MB**.
On 2026-10-06 the user downloaded **splunk-10.2.6-bcdcf0552e0c-darwin-intel.tgz** from the same page; that is the package actually installed. 10.2.7 was the highest Intel macOS 10.x package visible at the 2026-10-05 review;
it is not claimed to be the newest Splunk release on every platform. A
`darwin-arm64` package or a `linux-amd64` package cannot substitute for this
Intel macOS executable.

## 1. User download

Log in to Splunk's website and download these files into
`~/Downloads/`:

- The **Enterprise** archive
  Intel `.tgz` from the previous releases page (used: `splunk-10.2.6-bcdcf0552e0c-darwin-intel.tgz`).
- Its vendor SHA-512 checksum via the package's **Download SHA512** link.
- The updated [enttrial.lic](https://coverall1.splunk.com/web_assets/product/enttrial.lic)
  linked near the top of the same previous releases page.

The page explicitly says its non-Linux archives no longer include an active
Trial license and gives the replacement destination below. Keep the license
outside the project and out of Git. The advertised Trial is **60 days and
500 MB/day**, with no credit card required; this exercise requires no purchase.
The actual License Manager must confirm the installed license's effective
expiry and quota. No later conversion or paid license is selected.

Observed 2026-10-06: the `enttrial.lic` link failed with DNS NXDOMAIN, and the 10.2.6 archive contains no `etc/licenses`. The first start created `etc/licenses/download-trial/enttrial.lic` itself; License Manager showed an active Trial until 2026-12-05. Skip the license copy below if the file cannot be downloaded, and check License Manager after the first start.

Next manageable success criterion: the Intel `.tgz`, its checksum and
`enttrial.lic` are available locally. No account password or license contents
should be pasted into a chat.

## 2. Extract under the user's home

After the download, use Terminal. These task variables do not change `HOME`,
the shell profile or a system setting:

```sh
soc_lab_root="$HOME/Documents/Projekte/soc-detection-lab/lab"  # adjust to your checkout
soc_splunk_home="$HOME/soc-splunk-lab/splunk"
soc_archive="$HOME/Downloads/splunk-10.2.6-bcdcf0552e0c-darwin-intel.tgz"
shasum -a 512 "$soc_archive"
tar -tzf "$soc_archive" | head -n 8
```

Compare the checksum with the vendor file. The archive listing should show one
Splunk top-level directory. The following extraction removes that single
directory component to give a stable, lowercase installation path; the vendor's
[manual tar installation](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/install-splunk-enterprise-on-linux-or-macos/install-on-macos)
otherwise uses the archive directory name, which can be `Splunk` on macOS.
Use a new empty lab installation directory, rather than extracting over an
existing installation.

```sh
mkdir -p "$soc_splunk_home"
tar -xzf "$soc_archive" -C "$soc_splunk_home" --strip-components=1
file "$soc_splunk_home/bin/splunkd"
mkdir -p "$soc_splunk_home/etc/licenses/download-trial"
cp "$HOME/Downloads/enttrial.lic" "$soc_splunk_home/etc/licenses/download-trial/enttrial.lic"
```

Success criterion: `bin/splunkd` exists and `file` identifies an **x86_64
Mach-O** executable; the updated Trial license is in the stated installation
directory. This step does not start Splunk or create a macOS service account.

## 3. Configure, then start manually

Configure the dedicated sourcetype before importing either batch. The explicit
timestamp settings for canonical six-digit UTC JSON timestamps are:

```ini
[soc_lab:normalized:json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp"\s*:\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ
MAX_TIMESTAMP_LOOKAHEAD = 27
TZ = UTC
ADD_EXTRA_TIME_FIELDS = subseconds
KV_MODE = json
```

`%6N` is the documented microsecond width. `TIME_PREFIX` matches the exact
`timestamp` key, rather than `timestamp_raw`. `ADD_EXTRA_TIME_FIELDS=subseconds`
preserves subsecond index-time data without adding Splunk's extra generated
timestamp fields. Setting it to `false`/`none` would discard subsecond `_time`
information. See [timestamp recognition](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.2/configure-timestamps/configure-timestamp-recognition)
and [props.conf 10.2.7](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.7-configuration-file-reference/props.conf).

Use only search-time JSON extraction (`KV_MODE=json`); do not also add
`INDEXED_EXTRACTIONS=JSON`. Keep both datasets under the same sourcetype and
configuration. Copy the project's prepared sourcetype and index configuration
before first startup:

```sh
mkdir -p "$soc_splunk_home/etc/apps/soc_detection_lab/local"
cp "$soc_lab_root/queries/splunk/macos-local-app/local/props.conf" "$soc_splunk_home/etc/apps/soc_detection_lab/local/props.conf"
cp "$soc_lab_root/queries/splunk/macos-local-app/local/indexes.conf" "$soc_splunk_home/etc/apps/soc_detection_lab/local/indexes.conf"
cp "$soc_lab_root/queries/splunk/macos-local-app/local/web.conf" "$soc_splunk_home/etc/apps/soc_detection_lab/local/web.conf"
```

The index is `soc_lab`, capped at 128 MB, with its three data paths under
`$SPLUNK_DB/soc_lab/`. The installation's default `SPLUNK_DB` stays inside
this temporary installation. The cap is index retention, not a cap on total
Splunk process memory or all internal log/index storage.

Bind this local instance to loopback so its Web and management ports are not
opened on the Mac's physical or host-only interfaces. Put
`SPLUNK_BINDIP=127.0.0.1` in the installation's `etc/splunk-launch.conf` before
first start. The archive ships only `splunk-launch.conf.default`; copy it first, otherwise the new file would contain only the bind line and lose `SPLUNK_SERVER_NAME`, `PYTHONHTTPSVERIFY` and `PYTHONUTF8`. The copied app's `web.conf` supplies the matching Web settings:

```sh
cp "$soc_splunk_home/etc/splunk-launch.conf.default" "$soc_splunk_home/etc/splunk-launch.conf"
printf '\nSPLUNK_BINDIP=127.0.0.1\n' >> "$soc_splunk_home/etc/splunk-launch.conf"
```

Resulting Web settings:

```ini
[settings]
server.socket_host = 127.0.0.1
mgmtHostPort = 127.0.0.1:8089
httpport = 8000
```

This matches the documented [IP binding behavior](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/bind-splunk-to-an-ip).
The expected Web address is `http://127.0.0.1:8000`, management
`https://127.0.0.1:8089`; the actual listeners still need inspection after start.

With the Windows VM shut down:

```sh
"$soc_splunk_home/bin/splunk" start
"$soc_splunk_home/bin/splunk" version
"$soc_splunk_home/bin/splunk" status
lsof -nP -iTCP:8000 -iTCP:8089 -sTCP:LISTEN
```

Review and accept the displayed terms yourself. The documented alternative
`start --accept-license` accepts them automatically; it does not suppress the
interactive administrator-credential prompts. Create a dedicated local Splunk
administrator name and password at those prompts, not through a password CLI
argument or a plaintext project file. This account is separate from the Mac,
Windows test account and splunk.com account. See [first startup](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/start-using-splunk-enterprise/start-splunk-enterprise-for-the-first-time).

Success criterion: the local Web login works, version/build are recorded,
License Manager shows an active Enterprise Trial, and ports 8000/8089 listen
on `127.0.0.1`. If startup fails, preserve the concrete error. Do not change
macOS security policy or silently swap the package architecture.

## 4. Oneshot import and timestamp check

The real input is the Python export
`reports/lab-captured/pilot-01/analysis/splunk-import.jsonl`, containing eight
deduplicated eligible events. This carries `timestamp_epoch_us` and
`candidate_alert_id` transport fields; it is derived from the adapter's
normalized eight events, not the twelve-event raw XML.

Use the dedicated index `soc_lab`; keep its data under the Splunk installation
so later removal is contained. Set two distinct sources, **soc-lab-pilot-01**
and **soc-lab-boundaries-01**, and import each file once:

```sh
"$soc_splunk_home/bin/splunk" add oneshot "$soc_lab_root/reports/lab-captured/pilot-01/analysis/splunk-import.jsonl" -index soc_lab -sourcetype 'soc_lab:normalized:json' -rename-source soc-lab-pilot-01
"$soc_splunk_home/bin/splunk" add oneshot "$soc_lab_root/reports/generated/splunk-boundaries/analysis/splunk-import.jsonl" -index soc_lab -sourcetype 'soc_lab:normalized:json' -rename-source soc-lab-boundaries-01
```

Supply local Splunk credentials interactively when requested. The documented [oneshot CLI](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.2/get-data-from-files-and-directories/monitor-splunk-enterprise-files-and-directories-with-the-cli)
supports exact local file paths, `-index`, `-sourcetype` and `-rename-source`.
It does not set up continuing file monitoring.

Before the detection query changes `_time`, search **All time** for the isolated
source using [inspect_import.spl](../queries/splunk/inspect_import.spl). This
copies the original indexed `_time` before any correction and returns
`indexed_time_us`, `parsed_time_us` and the original `timestamp_epoch_us`.
Export all eight inventory rows as a JSON array to
`reports/lab-captured/splunk-01/pilot-inventory.json`. Repeat the query with only
its source filter changed to `soc-lab-boundaries-01`; export all **14** rows to
`reports/lab-captured/splunk-01/boundaries-inventory.json`.

If the exporter produces JSONL or a REST wrapper, retain it and convert its
container explicitly to a JSON array of result objects. Do not flatten its
fields or treat the wrapper as a result row. Then run:

```sh
cd "$soc_lab_root"
.venv/bin/python queries/splunk/compare_inventory.py --normalized reports/lab-captured/pilot-01/analysis/splunk-import.jsonl --splunk-results reports/lab-captured/splunk-01/pilot-inventory.json
.venv/bin/python queries/splunk/compare_inventory.py --normalized reports/generated/splunk-boundaries/analysis/splunk-import.jsonl --splunk-results reports/lab-captured/splunk-01/boundaries-inventory.json
```

Require matches for all eight and all 14 events, including their indexed times,
parsed times, keys and native metadata. The rounding in the inventory search
only converts Splunk's binary floating-point `_time` back into an integer for
comparison; it does not change the adapter's string truncation policy. The
detection continues to correlate using exact integer `timestamp_epoch_us`.
The synthetic same-microsecond records must retain equal `_time` and distinct
RecordIDs.

Do not infer a complete import from a successful CLI return or just a total
count. On 10.2.6 a failed `splunk search` also exited 0 with empty output; the
error was only in `var/run/splunk/dispatch/<sid>/search.log`. Check every UID and capture Job Inspector/messages. Duplicate imports,
timestamp mismatches or job truncation require a concrete diagnosis, not an
adjusted expected result.

## 5. Detection, comparison and exit

Run [repeated-failed-logons-then-success.spl](../queries/splunk/repeated-failed-logons-then-success.spl)
with source `soc-lab-pilot-01`, then with `soc-lab-boundaries-01`. Use All time
for each isolated source. Export complete detection results as JSON arrays,
preserving multivalue arrays, to
`reports/lab-captured/splunk-01/pilot-results.json` and
`reports/lab-captured/splunk-01/boundaries-results.json`.

```sh
cd "$soc_lab_root"
.venv/bin/python queries/splunk/compare_results.py --python-results reports/lab-captured/pilot-01/analysis/results.json --splunk-results reports/lab-captured/splunk-01/pilot-results.json
.venv/bin/python queries/splunk/compare_results.py --python-results reports/generated/splunk-boundaries/analysis/results.json --splunk-results reports/lab-captured/splunk-01/boundaries-results.json
```

The real capture must produce one alarm with success RecordID **53330**
and failures **53325–53329**, and none for **53314**. Confirm native metadata
is retained in `success_record_id`, `success_timestamp_raw` and the coupled
`failure_evidence` entries. The [synthetic dataset](../data/splunk-boundaries/README.md)
must produce exactly two alarms: success **1006** with failures **1001–1005**,
and success **2006** with failures **2001–2005**. Failure **1007** is later by
RecordID within the same normalized microsecond; failure **2000** is one
microsecond before the 300-second lower boundary. Those two records must be
excluded from the respective alert evidence. The Python evaluation has checked
these expectations; Splunk 10.2.6 met them on 2026-10-06.

After recording versions, license status, input/output hashes, job messages and
comparison results, log out the CLI if it was used, then stop this instance:

```sh
"$soc_splunk_home/bin/splunk" logout
"$soc_splunk_home/bin/splunk" stop
"$soc_splunk_home/bin/splunk" status
lsof -nP -iTCP:8000 -iTCP:8089 -sTCP:LISTEN
```

Success criterion: this Splunk instance is stopped and its listeners are gone.
No `enable boot-start`, launchd registration, installer package or root command
is part of this procedure.

## Remove the temporary installation

Once any wanted validation exports are saved outside the installation, stop
Splunk as above. Move **only** `~/soc-splunk-lab/` to the Trash
and empty it when deletion is intended. The installation, local license,
configuration, indexes and search-job data are within that directory. Remove
the three downloaded installer/checksum/license files from Downloads as well.
Splunk's [manual uninstall instructions](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/uninstall-splunk-enterprise/uninstall-splunk-enterprise)
require stopping the instance and removing its directory plus any externally
configured datastores. This runbook deliberately keeps the datastores inside.

The documented [administrative CLI commands](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/administer-splunk-enterprise-with-the-command-line-interface-cli/administrative-cli-commands)
include `logout`. Inspect `~/.splunk/` for any client token/cache
created during this lab; that location has not been observed in a real run yet.
Remove this lab's artifacts, and remove the directory itself only if it was
newly created solely for this lab. Clear the local Web session/site data for
`127.0.0.1:8000` if complete local cleanup is desired. Keep the project sources
and chosen private validation reports; they are separate lab artifacts.

Removal success criterion: the installation directory and its downloaded
license/archive are absent, this instance has no remaining process/listener,
and its CLI/browser session artifacts are gone. No service, login item,
extra macOS user or system policy needs to be reverted because none is created
by this procedure.
