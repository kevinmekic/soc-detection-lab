# Manual read-only policy export after the observed secpol.msc failure.
# User output received 2026-10-05: export succeeded, section count stopped; do not repeat.
& {
    $ErrorActionPreference = 'Stop'
    if ($env:COMPUTERNAME -ne 'DESKTOP-7HFI2UV') { throw 'Wrong lab computer.' }
    $principal = [System.Security.Principal.WindowsPrincipal]::new(
        [System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open Windows PowerShell as Administrator.'
    }

    $labRightsStem = Join-Path $env:TEMP ('SOC-Lab-Rights-' + [guid]::NewGuid().ToString('N'))
    $cfg = $labRightsStem + '.inf'
    $log = $labRightsStem + '.log'
    if ((Test-Path -LiteralPath $cfg) -or (Test-Path -LiteralPath $log)) {
        throw 'Diagnostic paths already exist; no export was started.'
    }

    & "$env:SystemRoot\System32\secedit.exe" /export /mergedpolicy /cfg $cfg /areas USER_RIGHTS /log $log
    $exportExit = $LASTEXITCODE
    [pscustomobject]@{ ExportExitCode = $exportExit; ExportPath = $cfg; LogPath = $log } | Format-List
    if ($exportExit -ne 0) {
        if (Test-Path -LiteralPath $log -PathType Leaf) {
            Get-Content -LiteralPath $log -Tail 25 -ErrorAction Stop
        }
        throw 'Rights export failed; assignments remain unknown.'
    }
    if (-not (Test-Path -LiteralPath $cfg -PathType Leaf)) { throw 'Export file is missing.' }
    $length = (Get-Item -LiteralPath $cfg -ErrorAction Stop).Length
    if ($length -lt 2 -or $length -gt 1MB) { throw 'Unexpected rights-export file size.' }
    $bytes = [System.IO.File]::ReadAllBytes($cfg)
    if ($bytes[0] -ne 0xFF -or $bytes[1] -ne 0xFE) {
        throw 'Expected UTF-16LE security INF with BOM; no encoding was guessed.'
    }

    $found = @{}
    $inRights = $false
    $sectionCount = 0
    foreach ($line in Get-Content -LiteralPath $cfg -Encoding Unicode -ErrorAction Stop) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $inRights = ($Matches[1] -eq 'Privilege Rights')
            if ($inRights) { $sectionCount++ }
        } elseif ($inRights -and $line -match '^\s*(SeNetworkLogonRight|SeDenyNetworkLogonRight)\s*=') {
            $right = $Matches[1]
            if ($found.ContainsKey($right)) { throw "Duplicate assignment for $right." }
            $found[$right] = $line
        }
    }
    if ($sectionCount -ne 1) { throw 'Expected exactly one Privilege Rights section.' }
    foreach ($right in @('SeNetworkLogonRight', 'SeDenyNetworkLogonRight')) {
        if ($found.ContainsKey($right)) {
            Write-Output $found[$right]
        } else {
            Write-Output "$right = <NotPresentInExport; not assumed empty>"
        }
    }
    [pscustomobject]@{
        NetworkRightsExport = 'Collected'
        PilotReadiness = 'Not decided by this stored-policy export'
    } | Format-List
}
