# NetWatch checkup: a one-off "am I already hacked?" scan with plain-English findings and fixes.
#   .\checkup.ps1                 scan and print a report (run as admin for a fuller scan)
#   .\checkup.ps1 -Fix            also offer to fix what can be fixed (asks before each; prompts for admin)
#   .\checkup.ps1 -Fix -Yes       fix without asking
#   .\checkup.ps1 -OpenSignOut    open the "sign out everywhere" pages of sites you have saved logins for
#   .\checkup.ps1 -Days 30        how far back to look (default 90)
param([switch]$Fix, [switch]$Yes, [switch]$OpenSignOut, [int]$Days = 90)

. (Join-Path $PSScriptRoot 'common.ps1')

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Fix -and -not $admin) {
    $argList = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`" -Fix -Days $Days" + $(if ($Yes) { ' -Yes' })
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    "Fixing needs admin: continuing in a new elevated window."
    return
}

$since    = (Get-Date).AddDays(-$Days)
$findings = [Collections.Generic.List[object]]::new()
function Add-Finding([string]$level, [string]$title, [string]$detail, [string]$todo, [scriptblock]$fixIt) {
    $findings.Add([pscustomobject]@{ Level = $level; Title = $title; Detail = $detail; Todo = $todo; FixIt = $fixIt })
}
$userWritable = '\\(AppData|Temp|Downloads|Desktop|ProgramData|Users\\Public)\\'
$stealerTodo  = 'Assume saved passwords and logged-in sessions were stolen. Run .\checkup.ps1 -OpenSignOut, then on each site change the password AND sign out all other sessions.'

Write-Host "NetWatch checkup - looking back $Days days$(if (-not $admin) { ' (not admin: some checks are limited)' })...`n"

# ---- 1. Microsoft Defender ------------------------------------------------
$st = Get-MpComputerStatus -ErrorAction SilentlyContinue
if (-not $st) {
    Add-Finding AMBER 'Microsoft Defender status unavailable' 'Another antivirus may be in charge, or Defender is broken.' 'Make sure an antivirus is on and up to date.'
} else {
    if (-not $st.RealTimeProtectionEnabled) {
        Add-Finding RED 'Defender real-time protection is OFF' 'Malware often switches it off first.' 'Windows Security > Virus & threat protection > Manage settings > turn Real-time protection on.' { Set-MpPreference -DisableRealtimeMonitoring $false }
    }
    if ($st.AntivirusSignatureAge -gt 7) { Add-Finding AMBER "Defender definitions are $($st.AntivirusSignatureAge) days old" 'It cannot recognise recent malware.' 'Run Windows Update.' { Update-MpSignature } }
    if (-not $st.IsTamperProtected) { Add-Finding AMBER 'Tamper protection is off' 'Programs can change Defender settings behind your back.' 'Windows Security > Virus & threat protection > Manage settings > Tamper protection: On.' }
}

# Detections: password stealers and trojans are red; piracy tools and adware amber.
$threats = @{}; Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $threats[$_.ThreatID] = $_.ThreatName }
Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt $since } | Group-Object ThreatID | ForEach-Object {
    $name  = $threats[[long]$_.Name]
    $first = ($_.Group | Sort-Object InitialDetectionTime | Select-Object -First 1)
    $where = ($_.Group.Resources | Select-Object -Unique) -join '; '
    if ($where -match '^rootcert:') { return }   # Defender's 2026 DigiCert root-certificate false positive
    $when  = $first.InitialDetectionTime.ToString('yyyy-MM-dd')
    if ($name -match 'PWS|Stealer|Trojan|Backdoor|Spy|RAT|Ransom|Infostealer|Lumma|Redline|Vidar|Raccoon') {
        Add-Finding RED "Defender caught $name on $when" "Where: $where. A password stealer runs once and uploads browser data before it's caught." $stealerTodo
    } elseif ($name -match 'HackTool|AutoKMS|KMS|Crack|Keygen') {
        Add-Finding AMBER "Piracy tool detected: $name ($when)" "Where: $where. Pirated tools are the most common way malware gets in." 'Uninstall pirated software and activators; use genuine licences or free alternatives.'
    } else {
        Add-Finding AMBER "Defender detected $name ($when)" "Where: $where." 'Check Windows Security > Protection history; never choose "Allow on device" unless you are sure.'
    }
}

# Threats someone told Defender to ignore ("Allow on device").
$pref = Get-MpPreference -ErrorAction SilentlyContinue
for ($i = 0; $pref.ThreatIDDefaultAction_Ids -and $i -lt @($pref.ThreatIDDefaultAction_Ids).Count; $i++) {
    $id = $pref.ThreatIDDefaultAction_Ids[$i]
    if ($pref.ThreatIDDefaultAction_Actions[$i] -eq 6) {
        $n = if ($threats[$id]) { $threats[$id] } else { "threat $id" }
        Add-Finding AMBER "Defender is set to ignore $n" 'Someone clicked "Allow on device", or malware did it to protect itself.' 'Remove the allow so Defender blocks it again.' ([scriptblock]::Create("Remove-MpPreference -ThreatIDDefaultAction_Ids $id"))
    }
}

# Exclusions: readable as admin only; their history is readable by anyone.
if ($admin) {
    foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
        foreach ($x in @($pref.$kind | Where-Object { $_ })) {
            Add-Finding AMBER "Defender skips $x" "Defender does not scan this ($kind). Malware adds exclusions to hide." 'Remove it unless you added it on purpose (e.g. a dev or game folder).' ([scriptblock]::Create("Remove-MpPreference -$kind '$($x -replace "'", "''")'"))
        }
    }
}
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'New value:\s*HKLM[^\r\n]*?\\Exclusions\\(Paths|Processes|Extensions)\\([^\r\n=]+)' } |
    ForEach-Object { Add-Finding AMBER "Something added a Defender exclusion on $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" "Excluded: $($Matches[2].Trim())" 'If you did not add it, treat that folder as suspicious and scan it.' }

# ---- 2. Pirated activators -------------------------------------------------
$spp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -ErrorAction SilentlyContinue
if ($spp.KeyManagementServiceName -match '^(127\.|172\.16\.0\.2$|0\.0\.0\.0|localhost)') {
    Add-Finding AMBER 'Windows/Office activated by a pirated KMS activator' "Activation server: $($spp.KeyManagementServiceName). These tools hook into Windows and often come bundled with malware." 'Activate with a genuine key; clear the fake server with: slmgr /ckms' { cscript //nologo "$env:SystemRoot\System32\slmgr.vbs" /ckms }
}

# ---- 3. Hijacks that load code into Windows ------------------------------
$ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    if ($p.Debugger -or $p.VerifierDlls) {
        $key = $_.PSPath
        Add-Finding RED "$($_.PSChildName) is hijacked" "Windows runs '$($p.Debugger)$($p.VerifierDlls)' whenever $($_.PSChildName) starts (used by malware and activators)." 'Remove the hijack (skip if you set up a tool like Process Explorer on purpose).' ([scriptblock]::Create("Remove-ItemProperty '$key' -Name Debugger, VerifierDlls, GlobalFlag -ErrorAction SilentlyContinue"))
    }
}
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wl.Shell -ne 'explorer.exe' -or $wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') {
    Add-Finding RED 'Windows sign-in has been changed' "Shell: $($wl.Shell); Userinit: $($wl.Userinit). Malware uses this to start on every sign-in." 'Restore the Windows defaults.' { $k = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Set-ItemProperty $k Shell 'explorer.exe'; Set-ItemProperty $k Userinit 'C:\Windows\system32\userinit.exe,' }
}
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Where-Object Name -ne 'SCM Event Log Consumer' | ForEach-Object {
    $n = $_.Name
    Add-Finding RED "Hidden WMI autostart: $n" "Runs: $($_.CommandLineTemplate)$($_.ScriptText)" 'Remove it unless your IT department installed it.' ([scriptblock]::Create("Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Where-Object { `$_.Consumer.Name -eq '$n' } | Remove-CimInstance; Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Where-Object Name -eq '$n' | Remove-CimInstance"))
}

# ---- 4. Startup entries and scheduled tasks ------------------------------
$sneaky = '-enc(odedcommand)?\s|FromBase64|IEX|Invoke-Expression|DownloadString|DownloadFile|mshta|wscript|cscript.*\.(js|vbs)|regsvr32.*/i:http|rundll32.*,#'
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
    $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($v in $props.PSObject.Properties | Where-Object Name -notmatch '^PS') {
        $exe = if ($v.Value -match '^"?([^"]+?\.exe)') { $Matches[1] } else { '' }
        $who = Get-Who $v.Name $exe
        if ($v.Value -match $sneaky -or ($exe -match $userWritable -and -not $who.Signed)) {
            $kk = $k; $vn = $v.Name
            Add-Finding RED "Suspicious startup entry: $($v.Name)" "Runs at sign-in: $($v.Value)" 'Remove it unless you recognise it.' ([scriptblock]::Create("Remove-ItemProperty '$kk' -Name '$($vn -replace "'", "''")'"))
        }
    }
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '^\\Microsoft\\' } | ForEach-Object {
    $a = $_.Actions | Select-Object -First 1
    $cmd = "$($a.Execute) $($a.Arguments)"
    $exe = [Environment]::ExpandEnvironmentVariables(($a.Execute -replace '"', ''))
    if ($cmd -match $sneaky -or ($exe -match $userWritable -and (Test-Path $exe) -and -not (Get-Who $_.TaskName $exe).Signed)) {
        $tp = $_.TaskPath; $tn = $_.TaskName
        Add-Finding RED "Suspicious scheduled task: $tp$tn" "Runs: $cmd" 'Disable it unless you recognise it (disabling is reversible).' ([scriptblock]::Create("Disable-ScheduledTask -TaskPath '$tp' -TaskName '$($tn -replace "'", "''")' | Out-Null"))
    }
}

# ---- 5. What's running right now ----------------------------------------
$remoteTools = 'anydesk|teamviewer|rustdesk|screenconnect|connectwise|atera|splashtop|ultravnc|tightvnc|tvnserver|meshagent|ngrok|ammyy|supremo'
$rats        = 'remcos|njrat|quasar|asyncrat|darkcomet|nanocore|xworm|dcrat|xmrig|nbminer|lolminer'
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object ExecutablePath | Group-Object ExecutablePath | ForEach-Object {
    $path = $_.Name; $name = $_.Group[0].Name
    if ($name -match $rats) { Add-Finding RED "Known malware or miner running: $name" "From: $path" 'Disconnect from the internet, run a Defender offline scan (Start-MpWDOScan), then change passwords from another device.' }
    elseif ($name -match $remoteTools) { Add-Finding AMBER "Remote-control tool running: $name" "From: $path. If you didn't install it, someone may be able to control this PC." 'Uninstall it unless you use it yourself.' }
    elseif ($path -match $userWritable -and -not (Get-Who $name $path).Signed) {
        Add-Finding AMBER "Unverified program running from a user folder: $name" "From: $path" 'If you do not recognise it, end it in Task Manager and scan the file with Defender (right-click > Scan).'
    }
}

# ---- 6. Network and browser tampering ------------------------------------
$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
if ($inet.ProxyEnable -eq 1 -or $inet.AutoConfigURL) {
    Add-Finding AMBER 'A web proxy is set' "Proxy: $($inet.ProxyServer) $($inet.AutoConfigURL). Malware uses this to read your web traffic." 'Remove it unless your work requires it.' { $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Set-ItemProperty $k ProxyEnable 0; Remove-ItemProperty $k AutoConfigURL -ErrorAction SilentlyContinue }
}
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
Get-Content $hosts -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*(\d[\d.:a-f]+)\s+(\S+)' -and $Matches[1] -notmatch '^(127\.|0\.0\.0\.0|::1)' -and $Matches[2] -notmatch '(docker|kubernetes|localhost|\.local$|\.internal$)' } | ForEach-Object {
    Add-Finding AMBER "Hosts file redirects a website: $($_.Trim())" 'Malware edits this file to send you to fake login pages.' "Remove the line from $hosts (as admin) unless you added it."
}
foreach ($b in 'Google\Chrome', 'Microsoft\Edge', 'BraveSoftware\Brave') {
    foreach ($hive in 'HKCU', 'HKLM') {
        $k = "${hive}:\Software\Policies\$b\ExtensionInstallForcelist"
        if (Test-Path $k) {
            $list = (Get-ItemProperty $k).PSObject.Properties | Where-Object Name -notmatch '^PS' | ForEach-Object Value
            Add-Finding RED "Extensions are force-installed in $($b.Split('\')[-1])" "IDs: $($list -join ', '). On a home PC this is how malicious extensions stay installed." 'Remove the policy, then remove the extensions.' ([scriptblock]::Create("Remove-Item '$k' -Recurse -Force"))
        }
    }
}

# ---- 7. Risky installers you ran ------------------------------------------
# UserAssist records programs started from Explorer; names are ROT13-encoded.
function Rot13([string]$s) { -join ($s.ToCharArray() | ForEach-Object { $c = [int]$_; if ($c -ge 65 -and $c -le 90) { [char](65 + ($c - 65 + 13) % 26) } elseif ($c -ge 97 -and $c -le 122) { [char](97 + ($c - 97 + 13) % 26) } else { $_ } }) }
$risky = 'setup|install|crack|keygen|patch|activat|kms|loader|cheat|hack|repack|archive|free|torrent|unlock|mod[ _-]?menu|trainer|injector|driver.*installer'
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count' -ErrorAction SilentlyContinue | ForEach-Object {
    $key = $_
    foreach ($v in $key.GetValueNames()) {
        $path = Rot13 $v; $data = $key.GetValue($v)
        if ($data.Length -lt 68 -or $path -notmatch '\.exe$' -or $path -match '^\{') { continue }
        $t = [DateTime]::FromFileTime([BitConverter]::ToInt64($data, 60))
        if ($t -lt $since) { continue }
        $leaf = Split-Path $path -Leaf
        $fromRisky = $path -match '\\(Downloads|Temp|Desktop)\\' -or $path -notmatch '^C:\\'
        if ($fromRisky -and $leaf -match $risky) {
            if ((Test-Path $path) -and (Get-Who $leaf $path).Signed) { continue }   # genuine, signed installer
            $gone = if (Test-Path $path) { ' It is not signed by a verified maker.' } else { ' The file is gone now (stealers often delete themselves), so its maker cannot be checked.' }
            Add-Finding AMBER "You ran a downloaded installer: $leaf ($($t.ToString('yyyy-MM-dd HH:mm')))" "Path: $path.$gone" "If it came from a crack, piracy, Telegram or Discord link, treat it as a password stealer: $stealerTodo"
        }
    }
}

# ---- 8. Saved browser logins (what a stealer would take) ----------------
# ponytail: reads hostnames straight out of the SQLite bytes (no SQLite library on stock Windows); good enough to list sites, can't read passwords.
$loginFiles = @()
foreach ($root in "$env:LOCALAPPDATA\Google\Chrome\User Data", "$env:LOCALAPPDATA\Microsoft\Edge\User Data", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data", "$env:LOCALAPPDATA\Vivaldi\User Data") {
    $loginFiles += Get-ChildItem $root -Recurse -Depth 1 -File -Include 'Login Data', 'Login Data For Account' -ErrorAction SilentlyContinue
}
$loginFiles += Get-ChildItem "$env:APPDATA\Opera Software" -Recurse -Depth 2 -File -Filter 'Login Data' -ErrorAction SilentlyContinue
$sites = @{}
foreach ($f in $loginFiles) {
    $tmp = [IO.Path]::GetTempFileName()
    try {
        Copy-Item $f.FullName $tmp -Force
        $text = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($tmp))
        [regex]::Matches($text, 'https?://([a-z0-9-]+(?:\.[a-z0-9-]+)+)') | ForEach-Object {
            $h = $_.Groups[1].Value.ToLower()
            if ($h -notmatch '^(localhost|\d+\.\d+\.\d+\.\d+)$') { $p = $h.Split('.'); $sites[($p[-2..-1] -join '.')] = 1 }
        }
    } catch {} finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}
foreach ($ff in Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json" -ErrorAction SilentlyContinue) {
    (Get-Content $ff -Raw | ConvertFrom-Json).logins | ForEach-Object { $p = ([uri]$_.hostname).Host.Split('.'); $sites[($p[-2..-1] -join '.')] = 1 }
}
if ($sites.Count) {
    Add-Finding AMBER "Your browsers store passwords for $($sites.Count) sites" 'Saved browser passwords are exactly what password stealers take.' 'Move them to a password manager (e.g. Bitwarden), then delete them from the browser and passwords.google.com.'
}

# ---- Report ------------------------------------------------------------------
$order  = @{ RED = 0; AMBER = 1 }
$sorted = $findings | Sort-Object { $order[$_.Level] }
$red    = @($findings | Where-Object Level -eq 'RED').Count
$amber  = @($findings | Where-Object Level -eq 'AMBER').Count
$verdict = if ($red) { "HIGH RISK: $red serious finding(s). Act on the red items now." }
           elseif ($amber) { "SOME RISK: $amber thing(s) to look at, nothing clearly malicious." }
           else { 'NO SIGNS OF COMPROMISE found in what this checkup can see.' }

$report = @("NetWatch checkup - $(Get-Date -Format 'yyyy-MM-dd HH:mm') - last $Days days$(if (-not $admin) { ' (not admin)' })", $verdict, '')
$n = 0
foreach ($f in $sorted) {
    $n++
    $report += "[$n] $($f.Level): $($f.Title)"
    $report += "    $($f.Detail)"
    $report += "    What to do: $($f.Todo)$(if ($f.FixIt) { '  (fixable with -Fix)' })"
    $report += ''
}
if ($red) { $report += 'Change passwords from a device you trust, starting with email, then banking, then everything else.' }
if (-not $admin) { $report += 'Tip: run from an admin PowerShell to also check Defender exclusions.' }
$report | Set-Content (Join-Path $PSScriptRoot 'checkup-report.txt')

foreach ($line in $report) {
    $color = if ($line -match '^\[\d+\] RED|^HIGH') { 'Red' } elseif ($line -match '^\[\d+\] AMBER|^SOME') { 'Yellow' } elseif ($line -match '^NO SIGNS') { 'Green' } else { 'Gray' }
    Write-Host $line -ForegroundColor $color
}
Write-Host "Saved to $(Join-Path $PSScriptRoot 'checkup-report.txt')"

# ---- Fixes ----------------------------------------------------------------------
if ($Fix) {
    $n = 0
    foreach ($f in $sorted) {
        $n++
        if (-not $f.FixIt) { continue }
        if (-not $Yes -and (Read-Host "Fix [$n] $($f.Title)? y/n") -notmatch '^y') { continue }
        try { & $f.FixIt; Write-Host "  fixed [$n]" -ForegroundColor Green } catch { Write-Host "  could not fix [$n]: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# ---- Sign out everywhere ---------------------------------------------------------
if ($OpenSignOut) {
    $pages = [ordered]@{
        'google.com' = 'https://myaccount.google.com/device-activity';         'microsoft.com' = 'https://account.microsoft.com/security'
        'live.com' = 'https://account.microsoft.com/security';                 'apple.com' = 'https://account.apple.com/account/manage'
        'github.com' = 'https://github.com/settings/sessions';                 'gitlab.com' = 'https://gitlab.com/-/user_settings/active_sessions'
        'facebook.com' = 'https://accountscenter.facebook.com/password_and_security/login_activity'
        'instagram.com' = 'https://accountscenter.instagram.com/password_and_security/login_activity/'
        'x.com' = 'https://x.com/settings/sessions';                           'twitter.com' = 'https://x.com/settings/sessions'
        'linkedin.com' = 'https://www.linkedin.com/mypreferences/d/sessions'; 'amazon.com' = 'https://www.amazon.com/your-account'
        'paypal.com' = 'https://www.paypal.com/myaccount/security';            'netflix.com' = 'https://www.netflix.com/account'
        'openai.com' = 'https://chatgpt.com/#settings/Security';              'chatgpt.com' = 'https://chatgpt.com/#settings/Security'
        'steampowered.com' = 'https://store.steampowered.com/twofactor/manage'; 'steamcommunity.com' = 'https://store.steampowered.com/twofactor/manage'
        'epicgames.com' = 'https://www.epicgames.com/account/password';       'dropbox.com' = 'https://www.dropbox.com/account/security'
        'slack.com' = 'https://my.slack.com/account/settings';                 'reddit.com' = 'https://www.reddit.com/settings/account'
    }
    $open = @('https://myaccount.google.com/device-activity')   # email first: it resets every other password
    foreach ($s in $sites.Keys) { if ($pages[$s] -and $open -notcontains $pages[$s]) { $open += $pages[$s] } }
    $open | ForEach-Object { Start-Process $_ }
    "Opened $($open.Count) sign-out pages. Other sites with saved logins (change their passwords too):"
    ($sites.Keys | Where-Object { -not $pages[$_] } | Sort-Object) -join ', '
    'Discord: in the app, Settings > Devices > Log out all known devices.'
}
