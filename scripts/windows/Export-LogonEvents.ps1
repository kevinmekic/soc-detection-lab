<#
Prepared for Windows PowerShell 5.1; not executed on Windows in this project yet.
Reads local Security records and writes their unchanged ToXml representations.
No audit, firewall, account, lockout or execution-policy changes are performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')]
    [string]$StartUtc,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')]
    [string]$EndUtc,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$start = [DateTimeOffset]::ParseExact($StartUtc, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
$end = [DateTimeOffset]::ParseExact($EndUtc, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
if ($end -le $start -or ($end - $start).TotalMinutes -gt 15) {
    throw 'Choose a positive capture window no longer than 15 minutes.'
}

$records = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
    StartTime = $start.LocalDateTime
    EndTime = $end.LocalDateTime
} -MaxEvents 1001 | Sort-Object RecordId)
if ($records.Count -eq 0) {
    throw 'No selected records were returned; do not claim a successful capture.'
}
if ($records.Count -gt 1000) {
    throw 'More than 1000 records match. Narrow the time window; no partial export is written.'
}

$xml = "<Events>`n" + (($records | ForEach-Object { $_.ToXml() }) -join "`n") + "`n</Events>`n"
$encoding = [Text.UTF8Encoding]::new($false)
if ($encoding.GetByteCount($xml) -gt 10485760) {
    throw 'Export would exceed 10 MiB. Narrow the scope; no partial export is written.'
}
$directory = [IO.Path]::GetFullPath($OutputDirectory)
$xmlPath = Join-Path $directory 'events.xml'
$manifestPath = Join-Path $directory 'capture-manifest.json'
if ((Test-Path -LiteralPath $xmlPath) -or (Test-Path -LiteralPath $manifestPath)) {
    throw 'Output files already exist. Choose a new capture directory to preserve evidence.'
}
[IO.Directory]::CreateDirectory($directory) | Out-Null
[IO.File]::WriteAllText($xmlPath, $xml, $encoding)
$os = Get-CimInstance Win32_OperatingSystem
$manifest = [ordered]@{
    capture_method = 'Get-WinEvent Security IDs 4624/4625, unchanged EventLogRecord.ToXml'
    start_utc = $StartUtc
    end_utc = $EndUtc
    event_count = $records.Count
    first_record_id = $records[0].RecordId
    last_record_id = $records[-1].RecordId
    computer = $env:COMPUTERNAME
    windows_caption = $os.Caption
    windows_version = $os.Version
    windows_build = $os.BuildNumber
    exported_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    xml_sha256 = (Get-FileHash -LiteralPath $xmlPath -Algorithm SHA256).Hash.ToLowerInvariant()
    notes_required = 'Record actual source/account/target/type, audit and lockout settings, manual actions and log generation context separately. This manifest alone does not prove complete or authorized activity.'
}
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 4) + "`n", $encoding)
$manifest | ConvertTo-Json -Depth 4
