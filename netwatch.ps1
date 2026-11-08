# NetWatch: at a random moment, list processes talking to public internet IPs and
# alert on (1) a process never seen before, (2) an exe running from Temp/Downloads,
# (3) a pinned app talking to anything other than its allowed host. Since the previous run
# it also alerts on new unverified programs in Downloads/Desktop/other drives, and on
# Defender detections, protection being turned off, or new exclusions/allows.
param([switch]$Now)   # -Now: skip the random wait (for testing)

$dir   = $PSScriptRoot

# Settings come from config.json (written by install.ps1); missing keys fall back to these defaults.
$cfg = @{ SkipWhile = @(); PinnedApps = @{}; WatchFolders = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop"); WatchOtherDrives = $true; IntervalMinutes = 30 }
$cfgFile = Join-Path $dir 'config.json'
if (Test-Path $cfgFile) {
    $j = Get-Content $cfgFile -Raw | ConvertFrom-Json
    foreach ($k in 'SkipWhile', 'WatchFolders', 'WatchOtherDrives', 'IntervalMinutes') { if ($null -ne $j.$k) { $cfg[$k] = $j.$k } }
    if ($j.PinnedApps) { $j.PinnedApps.PSObject.Properties | ForEach-Object { $cfg.PinnedApps[$_.Name] = $_.Value } }
}
$SkipWhile  = @($cfg.SkipWhile | Where-Object { $_ })   # process names, without .exe
$PinnedApps = $cfg.PinnedApps                            # process name -> the only host it may talk to

$log   = Join-Path $dir 'netwatch.log'
$known = Join-Path $dir 'known.txt'
$state = Join-Path $dir 'lastrun.txt'

if (-not $Now) { Start-Sleep -Seconds (Get-Random -Maximum ([int]$cfg.IntervalMinutes * 50)) }   # random wait up to 5/6 of the interval, so it ends before the next run
if ($SkipWhile -and (Get-Process $SkipWhile -ErrorAction SilentlyContinue)) { exit }   # checked after the wait, so a game started meanwhile is respected

function Test-Public([string]$ip) {
    $ip = $ip -replace '^::ffff:', ''
    if ($ip -match '^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)') { return $false }
    if ($ip -match '^(::1?$|fe80:|f[cd][0-9a-f]{2}:)') { return $false }
    return $true
}

# Protected processes (Defender etc.) hide their path from Get-Process; fall back to the service's exe.
function Get-ExePath($p, [int]$procId) {
    if ($p -and $p.Path) { return $p.Path }
    $svc = Get-CimInstance Win32_Service -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($svc -and $svc.PathName -match '^"?([^"]+?\.exe)') { return $Matches[1] }
    $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
    if ($wp -and $wp.ExecutablePath) { return $wp.ExecutablePath }
    return ''
}

. (Join-Path $PSScriptRoot 'common.ps1')

# Name the PC actually looked up (DNS cache) beats reverse DNS, which big clouds rarely set.
$dnsCache = @{}
Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Data -and $_.Type -in 1, 28 } | ForEach-Object { if (-not $dnsCache[$_.Data]) { $dnsCache[$_.Data] = $_.Entry } }

function Get-RemoteHost([string]$ip) {
    $ip = $ip -replace '^::ffff:', ''
    $h = $dnsCache[$ip]
    if (-not $h) { try { $h = (Resolve-DnsName $ip -Type PTR -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost } catch {} }
    if ($h) { $parts = $h.TrimEnd('.').Split('.'); return ($parts[-2..-1] -join '.') }   # keep "microsoft.com", drop the server prefix
    return $ip
}

function Show-Toast([string]$title, [string]$body) {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] > $null
    $esc = { param($s) [Security.SecurityElement]::Escape($s) }
    $logUri = 'file:///' + ($log -replace '\\', '/')
    $xml = [Windows.Data.Xml.Dom.XmlDocument]::new()
    $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$(& $esc $title)</text><text>$(& $esc $body)</text></binding></visual><actions><action content='Open log' activationType='protocol' arguments='$(& $esc $logUri)'/></actions></toast>")
    $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
}

$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_ }
$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { Test-Public $_.RemoteAddress }

$pinnedIps = @{}
foreach ($app in $PinnedApps.Keys) {
    try { $pinnedIps[$app] = [Net.Dns]::GetHostAddresses($PinnedApps[$app]) | ForEach-Object { $_.ToString() } } catch { $pinnedIps[$app] = @() }
}

$seen = @{}; if (Test-Path $known) { Get-Content $known | ForEach-Object { $seen[$_] = 1 } }
$firstRun = -not (Test-Path $known)
$alerts = [ordered]@{}   # one alert per program+reason, keeps the first connection seen

foreach ($c in $conns) {
    $p = $procs[[int]$c.OwningProcess]
    $name = if ($p) { $p.Name } else { "pid$($c.OwningProcess)" }
    $hit = @{ Name = $name; Pid = [int]$c.OwningProcess; Proc = $p; Ip = $c.RemoteAddress }

    if ($pinnedIps.ContainsKey($name) -and $pinnedIps[$name] -notcontains $c.RemoteAddress) { $alerts["PIN|$name"] = $hit + @{ Kind = 'PINNED' } }
    if ($p -and $p.Path -match '\\(Temp|Downloads)\\')                  { $alerts["ODD|$name"]    = $hit + @{ Kind = 'ODD-PATH' } }
    if (-not $seen.ContainsKey($name)) {
        $seen[$name] = 1
        if (-not $firstRun) { $alerts["NEW|$name"] = $hit + @{ Kind = 'NEW' } }
    }
}

# Since the previous run (runs skipped by SkipWhile are caught up here): unverified downloads and Defender changes.
$since = if (Test-Path $state) { [datetime](Get-Content $state) } else { (Get-Date).AddMinutes(-30) }
$extra = @()

# Other drives hold big game libraries, so only look inside top-level items created since the last run.
$drops = @($cfg.WatchFolders | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) })
if ($cfg.WatchOtherDrives) {
    $drops += Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "$env:SystemDrive\" -and $_.Free -and -not $_.DisplayRoot } |
        ForEach-Object { Get-ChildItem $_.Root -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt $since } | ForEach-Object FullName }
}
foreach ($d in $drops) {
    Get-ChildItem $d -Recurse -Depth 2 -File -Include *.exe, *.msi, *.scr, *.com, *.bat, *.cmd, *.ps1, *.vbs, *.js, *.hta -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -gt $since -and $_.FullName -notmatch '\\(SteamLibrary|steamapps)\\' } |
        ForEach-Object {
            if ((Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue).Status -ne 'Valid') {
                $extra += "Unverified program downloaded: $($_.FullName) - don't run it unless you trust where it came from  CHECK THIS"
            }
        }
}

Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 5001, 5007; StartTime = $since } -ErrorAction SilentlyContinue |
    ForEach-Object {
        if ($_.Id -eq 1116) {
            $detail = ($_.Message -split "`n" | Where-Object { $_ -match '^\s*(Name|Path):' } | ForEach-Object { $_.Trim() }) -join ' '
            $extra += "Defender found a threat: $detail  CHECK THIS"
        } elseif ($_.Id -eq 5001) {
            $extra += 'Defender real-time protection was turned OFF  CHECK THIS'
        } elseif ($_.Message -match 'New value:\s*(HKLM[^\r\n]*?\\(?:Exclusions|ThreatIDDefaultAction)\\[^\r\n]*)') {
            $extra += "Defender was told to skip something: $($Matches[1].Trim())  CHECK THIS"
        }
    }
(Get-Date).ToString('o') | Set-Content $state

$lines = @(); $worry = $false
foreach ($a in $alerts.Values) {
    $path = Get-ExePath $a.Proc $a.Pid
    $who  = Get-Who $a.Name $path
    $to   = Get-RemoteHost $a.Ip
    switch ($a.Kind) {
        'NEW'      { $msg = "New: $($who.Text) -> $to"; if (-not $who.Signed) { $worry = $true; $msg += '  CHECK THIS' } }
        'ODD-PATH' { $msg = "Running from Downloads/Temp: $($who.Text) -> $to  CHECK THIS"; $worry = $true }
        'PINNED'   { $msg = "$($a.Name) talked to $to (expected only $($PinnedApps[$a.Name]))  CHECK THIS"; $worry = $true }
    }
    $lines += $msg
    Add-Content $log "$stamp ALERT $msg  [$path, $($a.Ip)]"
}

foreach ($e in $extra | Select-Object -Unique) { $lines += $e; $worry = $true; Add-Content $log "$stamp ALERT $e" }

$seen.Keys | Sort-Object | Set-Content $known
Add-Content $log "$stamp checked $(@($conns).Count) public connections, $($lines.Count) alerts$(if ($firstRun) {' (first run: baseline saved to known.txt)'})"
if ($lines) {
    $title = if ($worry) { 'NetWatch: check this' } else { "NetWatch: $($lines.Count) new program(s) online - verified, likely safe" }
    $more  = if ($lines.Count -gt 3) { "`n+$($lines.Count - 3) more in the log" } else { '' }
    Show-Toast $title ((($lines | Select-Object -First 3) -join "`n") + $more)
}
