# NetWatch

**Am I hacked? Find out in 15 seconds, fix it in plain English, and get warned next time.**

Free, open-source PowerShell tools for Windows home PCs. No install, no account, no admin rights needed.

Built after a real incident. A fake game installer ran once, stole every saved browser password and login session, then deleted itself. Antivirus missed it, and weeks later strangers were adding their email to the owner's GitHub and trying his Gmail. These tools would have flagged it on day one.

| Tool | What it does |
| --- | --- |
| `checkup.ps1` | **Am I already hacked?** A one-off scan with a red/amber/green report and a "what to do" for every finding |
| `checkup.ps1 -Fix` | Undoes what can safely be undone, asking before each change |
| `checkup.ps1 -OpenSignOut` | Opens the "sign out everywhere" page of every site you have saved logins for |
| `install.ps1` | Sets up **NetWatch**, a hidden watchdog that alerts you before the next infection |
| `harden-defender.ps1` | Turns on Microsoft Defender protections that home PCs leave off |

## Quick start: am I hacked?

1. [Download this repo as a ZIP](../../archive/refs/heads/main.zip) and unzip it, e.g. to `C:\Tools\NetWatch`.
2. In that folder, Shift + right-click → **Open PowerShell window here**, then run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\checkup.ps1
   ```

3. Read the verdict at the top, then the numbered findings. The same report is saved to `checkup-report.txt`.

For a fuller scan that also checks Defender exclusions, run it from an **admin** PowerShell.

### What the checkup looks for

| Check | Why it matters |
| --- | --- |
| Password stealers and trojans Defender caught (last 90 days) | A stealer only needs to run once. If one was caught, your logins were probably taken first |
| **Installers you ran from Downloads, Desktop or other drives** that are unsigned or have since vanished | How most stealers arrive: "Setup.exe" from a crack, game repack, or Telegram or Discord link |
| Threats someone set to **"Allow on device"**, and Defender exclusions, past and present | Malware hides by telling Defender to look away |
| Defender switched off, tamper protection off, old definitions | Basic protection missing |
| Pirated Windows/Office activators | Common carriers of malware, and they hook into Windows itself |
| Hijacks: debugger and DLL injection keys, changed sign-in shell, hidden WMI autostarts | Ways malware survives a reboot |
| Suspicious startup entries and scheduled tasks (encoded PowerShell, scripts, unsigned programs in user folders) | Same |
| Remote-control tools (AnyDesk, TeamViewer, …) and known RATs or crypto-miners running | Someone else may be in control |
| Unverified programs running from user folders | Same |
| Web proxy, hosts-file redirects, force-installed browser extensions | Ways to read your traffic or fake login pages |
| How many sites your browsers store passwords for | What a stealer would have taken |

Example report:

```text
SOME RISK: 3 thing(s) to look at, nothing clearly malicious.

[1] AMBER: You ran a downloaded installer: Setup.exe (2026-10-17 13:45)
    Path: E:\Some_Game_Archive_full\Setup.exe. The file is gone now (stealers often delete themselves), so its maker cannot be checked.
    What to do: If it came from a crack, piracy, Telegram or Discord link, treat it as a password stealer: ...

[2] AMBER: Your browsers store passwords for 51 sites
    What to do: Move them to a password manager (e.g. Bitwarden), then delete them from the browser ...

[3] AMBER: Windows/Office activated by a pirated KMS activator
    What to do: Activate with a genuine key; clear the fake server with: slmgr /ckms  (fixable with -Fix)
```

### If the checkup finds something

1. **Fix what can be fixed on the PC:** run `.\checkup.ps1 -Fix`. It asks for admin, then asks before each change. Add `-Yes` to skip the questions.
2. **Lock your accounts:** run `.\checkup.ps1 -OpenSignOut`. It opens the "sign out everywhere" pages for Google, Microsoft, Apple, GitHub, Facebook, Instagram, X, Steam and others, for every site you have saved logins for. On each one, **change the password and sign out all other sessions.** A stolen session keeps working after a password change until you do.
3. **Do your email first.** Whoever controls your email can reset every other password.
4. **Stop saving passwords in the browser.** Move them to a password manager, then delete them from the browser and from passwords.google.com.
5. **Rule out hidden rootkits:** run a Defender offline scan from an admin PowerShell with `Start-MpWDOScan`.

## NetWatch: get warned next time

A watchdog that runs hidden every few minutes and pops a plain-English notification when something looks wrong, so you hear about it **before** a stolen password turns into a hacked account.

- Runs at a random moment each interval, and can pause while you game
- Every alert says who made the program and whether that's verified

### What it alerts on

| Alert | When it fires |
| --- | --- |
| **New program online** | A program it has never seen before connects to the internet. Signed by a known maker → "likely safe"; unsigned → **CHECK THIS** |
| **Running from Downloads/Temp** | Something running straight out of Downloads or Temp talks to the internet |
| **Unverified program downloaded** | A new unsigned `.exe`, `.msi`, `.bat`, `.ps1`, `.vbs`, `.js`… lands in a watched folder, or in a new folder on another drive. Warns you *before* you run it |
| **Defender found a threat** | Microsoft Defender logs a detection |
| **Real-time protection turned off** | Defender is switched off |
| **Defender told to skip something** | A new exclusion or "allow" appears, a classic malware trick |
| **Pinned app off course** | An app you pinned to one host (e.g. an updater) talks to anywhere else |

Example notification:

> **NetWatch: check this**
> Unverified program downloaded: C:\Users\you\Downloads\Setup.exe - don't run it unless you trust where it came from

### Install

1. Download or clone this repo to a folder you'll keep, e.g. `C:\Tools\NetWatch`.
2. Open PowerShell in that folder and run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1
   ```

3. Answer the questions, or press Enter to keep each default:

   | Question | Default |
   | --- | --- |
   | Check every how many minutes? | 30 |
   | Pause checks while these programs run | none |
   | Apps that may only talk to one host (`Name=host`) | none |
   | Folders to watch for new unverified programs | Downloads, Desktop |
   | Also watch new folders on other drives? | yes |
   | Apply Microsoft Defender hardening now? | no |

The first run records what's already online, so you're only alerted about newcomers.

#### Skip the questions

Every question has a flag. Pass it and that question is skipped; add `-Yes` to accept defaults for everything else.

```powershell
.\install.ps1 -Yes                                            # all defaults, no questions
.\install.ps1 -Yes -SkipWhile dota2,cs2                       # pause while those games run
.\install.ps1 -Yes -PinApp 'MyUpdater=api.github.com'         # alert if MyUpdater talks elsewhere
.\install.ps1 -Yes -IntervalMinutes 15 -NoOtherDrives
.\install.ps1 -Yes -WatchFolder 'C:\Games','%USERPROFILE%\Downloads'
.\install.ps1 -Harden                                         # also apply Defender hardening (UAC prompt)
```

Change settings later by editing `config.json`, or by running `install.ps1` again.

#### Test it

```powershell
powershell -ExecutionPolicy Bypass -File .\netwatch.ps1 -Now
```

Drop any unsigned `.bat` into Downloads first and you should get an alert.

#### Uninstall

```powershell
.\install.ps1 -Uninstall      # removes the scheduled task; delete the folder to finish
```

## Optional: Defender hardening

`harden-defender.ps1` turns on protections that Windows leaves off on home PCs. Run it from an **admin** PowerShell, or say yes in the installer.

- Attack surface reduction rules:
  - **warn** before running rare or new programs, and on ransomware-like behaviour
  - **block** password theft from Windows memory (lsass), obfuscated scripts, scripts launching downloads, Office macros starting programs, programs from email, unsigned programs from USB, and WMI persistence
- Potentially unwanted app (adware) blocking
- Network protection (blocks known malware and phishing sites)
- Stronger cloud checks for unknown files

Undo it any time with `.\harden-defender.ps1 -Undo`.

## Files

| File | Purpose |
| --- | --- |
| `checkup.ps1` | One-off "am I hacked?" scan, fixes, and sign-out pages |
| `checkup-report.txt` | The last checkup's report |
| `netwatch.ps1` | The watchdog check |
| `install.ps1` | Setup wizard and scheduled task for the watchdog |
| `common.ps1` | Shared helper: who made a program, and is it verified |
| `harden-defender.ps1` | Optional one-time Defender hardening |
| `config.json` | Your settings (created by the installer) |
| `netwatch.log` | One line per check, plus every alert |
| `known.txt` | Programs already seen online; delete a line to be alerted about it again |
| `lastrun.txt` | When the last check ran, so skipped checks catch up |

## Limits

These are an early-warning alarm and a checklist, not an antivirus.

- **A clean checkup isn't a guarantee.** It reads what Windows recorded. Programs started from a command line, or traces deleted by an attacker, may not show up.
- **They can't undo a theft.** If passwords or sessions were already stolen, change those passwords **and** use each site's "sign out of all sessions".
- **It checks at intervals.** A program that runs, steals and exits between checks won't be seen connecting. The download and Defender alerts still catch most of these.
- **It only sees TCP connections.** It doesn't see UDP, and it can't tell when a trusted program misbehaves.
- **It's Windows-only.** It needs Windows 10 1903 or later, with PowerShell 5.1.

## Future improvements

**Next**
- [ ] Checkup: list the exact sites per browser profile, and which Google account each profile is signed into
- [ ] Checkup: look up a vanished installer's download source (Chrome/Edge history) to say where it came from
- [ ] Checkup: optional HTML report that's easy to share with a friend who's helping
- [ ] Real-time download alerts with a file-system watcher, instead of waiting for the next interval
- [ ] Alert when a new program reads browser password or cookie files (needs file auditing, admin)
- [ ] One-click actions on the notification: "Trust this program", "Scan with Defender", "Open folder"
- [ ] Daily summary notification ("12 checks, 0 alerts") so silence is reassuring, not ambiguous

**Later**
- [ ] Look up unknown file hashes on VirusTotal (user's own free API key, opt-in)
- [ ] Flag connections to known-bad IPs using free threat-intel feeds
- [ ] Detect new browser extensions and new scheduled tasks or startup entries
- [ ] Optional notifications to phone (ntfy, Telegram, or email) for when you're away
- [ ] Small local HTML report of the log

**Maybe**
- [ ] Signed releases and a `winget` package
- [ ] macOS and Linux versions of the same checks

Ideas and pull requests are welcome. Open an issue first for anything large.

## License

MIT, see [LICENSE](LICENSE).
