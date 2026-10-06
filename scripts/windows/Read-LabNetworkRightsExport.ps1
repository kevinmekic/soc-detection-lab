# Inspect the existing rights export after its section-reader stop.
# Read-only: no new export, policy changes or authentication.
& {
    $ErrorActionPreference = 'Stop'
    if ($env:COMPUTERNAME -ne 'DESKTOP-7HFI2UV') { throw 'Wrong lab computer.' }
    $stem = 'C:\Users\kevin\AppData\Local\Temp\SOC-Lab-Rights-ee422524e30340119e73985f50c09c27'
    $cfg = $stem + '.inf'
    $log = $stem + '.log'
    if (-not (Test-Path -LiteralPath $cfg -PathType Leaf)) { throw 'Existing export not found; do not export again.' }
    $length = (Get-Item -LiteralPath $cfg -ErrorAction Stop).Length
    if ($length -lt 2 -or $length -gt 1MB) { throw 'Unexpected existing export size.' }
    $bytes = [System.IO.File]::ReadAllBytes($cfg)
    if ($bytes[0] -ne 0xFF -or $bytes[1] -ne 0xFE) { throw 'Existing export no longer has the observed UTF-16LE BOM.' }
    $lines = @(Get-Content -LiteralPath $cfg -Encoding Unicode -ErrorAction Stop)

    $sectionCount = 0
    $candidateCount = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            if ($Matches[1] -eq 'Privilege Rights') { $sectionCount++ }
        }
        $separator = $line.IndexOf('=')
        $key = if ($separator -ge 0) { $line.Substring(0, $separator).Trim() } else { '' }
        if ($line.TrimStart().StartsWith('[') -or $key -in @('SeNetworkLogonRight', 'SeDenyNetworkLogonRight')) {
            Write-Output ('Line {0}: {1}' -f ($i + 1), ($line | ConvertTo-Json -Compress))
        }
        if ($key -in @('SeNetworkLogonRight', 'SeDenyNetworkLogonRight')) { $candidateCount++ }
    }
    [pscustomobject]@{
        ExportBytes = $length
        Utf16LeBom = 'FF FE'
        LineCount = $lines.Count
        ExactPrivilegeRightsSections = $sectionCount
        CandidateAssignmentLines = $candidateCount
        RightsAssessment = 'Unknown; diagnose actual file content before interpretation'
    } | Format-List
    if (Test-Path -LiteralPath $log -PathType Leaf) {
        Write-Output 'Existing export log: last 25 lines'
        Get-Content -LiteralPath $log -Tail 25 -ErrorAction Stop
    } else {
        Write-Output 'Existing export log not found; no new log was created.'
    }
}
