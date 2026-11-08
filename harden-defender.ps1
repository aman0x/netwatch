# One-time Microsoft Defender hardening for a home PC. Run in an elevated PowerShell.
#   .\harden-defender.ps1         apply
#   .\harden-defender.ps1 -Undo   remove the ASR rules and restore the other settings to Windows defaults
param([switch]$Undo)

# Attack surface reduction rules. Action: 1 = block, 6 = warn (the user can still allow).
$rules = [ordered]@{
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 6  # executables that are rare, new or untrusted: warn
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 1  # credential stealing from lsass
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 1  # obfuscated scripts
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 1  # JS/VBS launching downloaded executables
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 1  # Office apps creating child processes
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 1  # executable content from email and webmail
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 1  # untrusted, unsigned processes from USB
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 1  # persistence through WMI event subscriptions
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 6  # ransomware-like behaviour: warn
}

if ($Undo) {
    Remove-MpPreference -AttackSurfaceReductionRules_Ids @($rules.Keys) -ErrorAction SilentlyContinue
    Set-MpPreference -PUAProtection Disabled -EnableNetworkProtection Disabled -CloudBlockLevel Default -CloudExtendedTimeout 0
    "Hardening removed."
    return
}

foreach ($id in $rules.Keys) {
    try   { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $rules[$id] -ErrorAction Stop }
    catch { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions 1 }   # warn unsupported for this rule: block
}
Set-MpPreference -PUAProtection Enabled -EnableNetworkProtection Enabled -MAPSReporting Advanced `
                 -SubmitSamplesConsent SendSafeSamples -CloudBlockLevel High -CloudExtendedTimeout 50

$m = Get-MpPreference
for ($i = 0; $i -lt $m.AttackSurfaceReductionRules_Ids.Count; $i++) { "ASR {0} = {1}" -f $m.AttackSurfaceReductionRules_Ids[$i], $m.AttackSurfaceReductionRules_Actions[$i] }
"PUA=$($m.PUAProtection) NetworkProtection=$($m.EnableNetworkProtection) CloudBlockLevel=$($m.CloudBlockLevel)"
