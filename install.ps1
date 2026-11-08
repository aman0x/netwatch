# NetWatch setup. Asks a few questions, saves config.json, and registers a hidden scheduled task
# for the current user (no admin needed). Any answer passed as a flag skips that question.
#
#   .\install.ps1                                   ask everything
#   .\install.ps1 -Yes                              take every default, ask nothing
#   .\install.ps1 -SkipWhile dota2,cs2 -Yes         defaults, but pause while those games run
#   .\install.ps1 -PinApp 'MyUpdater=api.github.com' alert if MyUpdater talks to any other host
#   .\install.ps1 -Harden                           also apply Defender hardening (UAC prompt)
#   .\install.ps1 -Uninstall                        remove the task (folder and log stay)
param(
    [int]$IntervalMinutes,
    [string[]]$SkipWhile,
    [string[]]$PinApp,
    [string[]]$WatchFolder,
    [switch]$NoOtherDrives,
    [switch]$Harden,
    [switch]$Yes,
    [switch]$Uninstall
)

$name = 'NetWatch'
if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    "Removed scheduled task '$name'. Delete this folder to remove NetWatch completely."
    return
}

# Ask unless the answer came as a flag or -Yes was given; Enter keeps the default.
function Ask([string]$question, [string]$default) {
    if ($Yes) { return $default }
    $a = Read-Host "$question [$default]"
    if ($a) { $a } else { $default }
}
function List([string]$s) { @($s -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne 'none' }) }

"NetWatch setup - press Enter to keep the default in [brackets].`n"

if (-not $IntervalMinutes) { $IntervalMinutes = [int](Ask 'Check every how many minutes?' '30') }
if ($IntervalMinutes -lt 5) { $IntervalMinutes = 5 }

if (-not $PSBoundParameters.ContainsKey('SkipWhile')) {
    $SkipWhile = List (Ask 'Pause checks while these programs run (process names, comma-separated, e.g. a game)' 'none')
}
$SkipWhile = @(List ($SkipWhile -join ',') | ForEach-Object { $_ -replace '\.exe$', '' })   # 'powershell -File' passes a,b as one string

if (-not $PSBoundParameters.ContainsKey('PinApp')) {
    $PinApp = List (Ask 'Apps that may only talk to one host (Name=host, comma-separated)' 'none')
}
$pinned = [ordered]@{}
foreach ($p in List ($PinApp -join ',')) {
    $n, $h = $p -split '=', 2
    if ($n -and $h) { $pinned[($n.Trim() -replace '\.exe$', '')] = $h.Trim() } else { "  skipped '$p' (use Name=host)" }
}

$defaultFolders = '%USERPROFILE%\Downloads, %USERPROFILE%\Desktop'
if (-not $PSBoundParameters.ContainsKey('WatchFolder')) { $WatchFolder = Ask 'Folders to watch for new unverified programs' $defaultFolders }
$WatchFolder = List ($WatchFolder -join ',')

$otherDrives = -not $NoOtherDrives
if (-not $NoOtherDrives -and -not $Yes) { $otherDrives = (Ask 'Also watch new folders on other drives (D:, E:, ...)? y/n' 'y') -match '^y' }

$config = [ordered]@{
    IntervalMinutes  = $IntervalMinutes
    SkipWhile        = $SkipWhile
    PinnedApps       = $pinned
    WatchFolders     = $WatchFolder
    WatchOtherDrives = $otherDrives
}
$config | ConvertTo-Json | Set-Content (Join-Path $PSScriptRoot 'config.json')

$script   = Join-Path $PSScriptRoot 'netwatch.ps1'
$action   = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument "--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$script`""
$trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes ($IntervalMinutes + 5))
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null

# First run records what's already online, so only later newcomers raise alerts.
& $script -Now
"`nInstalled: checks every $IntervalMinutes minutes, hidden, as $env:USERNAME."
"Settings:  $(Join-Path $PSScriptRoot 'config.json')  (edit it, or run install.ps1 again)"
"Log:       $(Join-Path $PSScriptRoot 'netwatch.log')"

if (-not $Harden -and -not $Yes) { $Harden = (Ask 'Apply Microsoft Defender hardening now? Needs admin (UAC prompt). y/n' 'n') -match '^y' }
if ($Harden) {
    $h = Join-Path $PSScriptRoot 'harden-defender.ps1'
    Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$h`""
}
