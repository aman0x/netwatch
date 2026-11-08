# Shared helpers for netwatch.ps1 and checkup.ps1.

# "Microsoft Defender Antivirus (MsMpEng), signed by Microsoft Corporation" + whether it's trusted
function Get-Who([string]$name, [string]$path) {
    if (-not $path -or -not (Test-Path $path)) { return @{ Text = "$name (location hidden)"; Signed = $false } }
    $desc = (Get-Item $path).VersionInfo.FileDescription
    $label = if ($desc -and $desc -ne $name) { "$desc ($name)" } else { $name }
    $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
    if ($sig.Status -eq 'Valid') {
        $org = if ($sig.SignerCertificate.Subject -match 'O="?([^",]+)') { $Matches[1] } else { 'a verified publisher' }
        return @{ Text = "$label, made by $org (verified)"; Signed = $true }
    }
    # Store apps are verified through their package, not the exe; only the Store can install into WindowsApps.
    if ($path -match '^(.*\\WindowsApps\\[^\\]+)\\') {
        $manifest = Join-Path $Matches[1] 'AppxManifest.xml'
        if ((Test-Path $manifest) -and ((Get-Content $manifest -Raw) -match 'Publisher="[^"]*?(?:O|CN)=([^,"]+)')) {
            return @{ Text = "$label, Store app by $($Matches[1]) (verified)"; Signed = $true }
        }
    }
    return @{ Text = "$label, maker NOT verified"; Signed = $false }
}
