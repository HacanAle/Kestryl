# Installing Kestryl

- [Requirements](#requirements)
- [Which file to download](#which-file-to-download)
- [Install with the setup](#install-with-the-setup)
- ["Windows protected your PC"](#windows-protected-your-pc)
- [Verify your download](#verify-your-download)
- [First start](#first-start)
- [Start with Windows](#start-with-windows)
- [The portable version](#the-portable-version)
- [Updating](#updating)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)

## Requirements

- Windows 10 version 2004 or later, or Windows 11, 64-bit (x64).
- Administrator rights for full monitoring and blocking. Without them Kestryl runs in *limited mode* (see [First start](#first-start)).
- Microsoft Edge WebView2 Runtime, which draws the window. Windows 11 and up-to-date Windows 10 already have it. If it's missing, the setup downloads it from Microsoft.
- About 20 MB of disk space for the program, plus about 12 MB for the country database it downloads later.

## Which file to download

Open the [latest release](https://github.com/HacanAle/Kestryl/releases/latest) and pick one:

| File | Choose it when |
|---|---|
| `Kestryl_<version>_x64-setup.exe` | You want Kestryl installed properly. **Recommended.** It goes to `C:\Program Files\Kestryl`, which only administrators can change. That matters because Kestryl runs with administrator rights. |
| `Kestryl_<version>_x64_portable.exe` | You want to try it without installing, or run it from a USB stick. Read [The portable version](#the-portable-version) first. |
| `SHA256SUMS.txt` | You want to check that your download is exactly what GitHub built. |
| Source code | You want to read it or [build it yourself](BUILDING.md). |

## Install with the setup

1. Download `Kestryl_<version>_x64-setup.exe`.
2. Optional but recommended: [verify it](#verify-your-download).
3. Double-click it. If SmartScreen shows a blue warning, see [the next section](#windows-protected-your-pc).
4. Allow the administrator prompt and follow the setup. It installs for all users of the PC into `C:\Program Files\Kestryl`, adds a Start menu entry and, if you leave the box ticked, an icon on the desktop.
5. Leave **Run Kestryl** ticked on the last page, or start **Kestryl** from the Start menu later.

## "Windows protected your PC"

You may see this blue SmartScreen screen the first time. It appears for any program that isn't signed with a paid code-signing certificate and hasn't been downloaded by many people yet. Kestryl's downloads are not code-signed yet.

To continue, click **More info**, then **Run anyway**.

If you'd rather be sure first, check the file as described below. Every Kestryl download is built by GitHub from the public source code, and you can prove that yourself.

## Verify your download

### 1. Checksum (30 seconds)

Download `SHA256SUMS.txt` from the same release. Then, in PowerShell, in your Downloads folder:

```powershell
Get-FileHash .\Kestryl_1.8.1_x64-setup.exe -Algorithm SHA256
```

The long hexadecimal value must match the line for that file in `SHA256SUMS.txt`, character for character.

### 2. Build provenance (proves GitHub built it from this source)

Each release file carries a signed attestation made by GitHub Actions: which repository, commit and workflow produced it. With the [GitHub CLI](https://cli.github.com):

```powershell
gh attestation verify .\Kestryl_1.8.1_x64-setup.exe --repo HacanAle/Kestryl
```

`Verification succeeded!` means this exact file was built by this repository's [release workflow](../.github/workflows/release.yml) and hasn't been modified since. You can also see the attestations on the repository's **Actions → Attestations** page.

### 3. A second opinion

You can upload the file to [VirusTotal](https://www.virustotal.com). A security tool that watches for password stealers naturally contains the names of the files stealers go for, so an occasional heuristic flag by a lesser-known engine is possible. If Microsoft Defender itself flags it, please [open an issue](https://github.com/HacanAle/Kestryl/issues).

## First start

Windows asks whether Kestryl may make changes to your PC. **Allow it.** Kestryl needs administrator rights to:

- see how many bytes each program sends and receives, over TCP and UDP;
- see the DNS names programs look up;
- see which files a program opens (to catch password and document theft);
- see who connects to your PC;
- add and remove firewall rules.

If you decline, Kestryl starts in **limited mode**: it only lists which programs hold TCP connections. The header then shows **Restart as administrator**.

On the first start Kestryl:

1. runs the Windows security check (Status page);
2. downloads the free threat lists and the country database in the background;
3. spends 10 minutes learning which programs normally go online, so you aren't flooded with "first time online" alerts on day one.

Closing the window keeps Kestryl running in the tray (bottom-right, next to the clock). To quit, right-click the tray icon and choose **Quit**.

## Start with Windows

**Settings → Start with Windows → Turn on.**

This creates a scheduled task, named *Kestryl*, that starts Kestryl hidden in the tray with administrator rights when you sign in, without a UAC prompt each time. Turn it off on the same page.

If Kestryl runs from a folder your own account can change (anything outside *Program Files*, such as a portable copy in Downloads), it warns you. Another program could swap that file before your next sign-in and get administrator rights through the task. Use the setup version to avoid that.

## The portable version

`Kestryl_<version>_x64_portable.exe` is the same program without an installer. Things to know:

- **Put it somewhere safe before you rely on it.** Kestryl runs as administrator, so the folder it runs from should be one only administrators can change: for example, create `C:\Program Files\Kestryl Portable\` (admin prompt) and copy it there. Running it from Downloads is fine for a quick look.
- Settings, history and alerts are stored in `%LOCALAPPDATA%\Kestryl`, the same place as the installed version, not next to the exe.
- It needs the WebView2 Runtime, which Windows 11 and current Windows 10 already have.

## Updating

Kestryl checks its GitHub releases once a day and pops up when a new version is out (Settings → Updates; you can turn the check off there).

- **Installed with Setup:** click **Update now** on the alert or in Settings → Updates. Kestryl downloads the new setup, installs it only if it is signed with Kestryl's update key, and starts again. Your settings, trusted programs, blocks and history are kept.
- **Portable exe, or a release without in-app update files:** click **Open download page** and download the new version yourself.

You can also update by hand at any time: download the new setup and run it. It replaces the old version and keeps your data. To hear about releases on GitHub too: **Watch → Custom → Releases**.

## Uninstall

Uninstalling removes the program, but deliberately not what you set up in Windows with it (firewall blocks keep protecting you until you remove them). For a clean removal:

1. **In Kestryl first:**
   - Settings → **Start with Windows → Turn off**.
   - Blocking → turn off every **analytics** switch you turned on. This puts back the exact previous Windows settings, which Kestryl recorded before changing anything.
   - Blocking → remove the blocks you no longer want; turn off **Script lockdown** and **Cut off internet** if they are on.
2. **Uninstall:** *Settings → Apps → Installed apps → Kestryl → Uninstall*.
3. **Optional leftovers**, in PowerShell **as administrator**:

   ```powershell
   # The start-up task (if you skipped step 1)
   Unregister-ScheduledTask -TaskName 'Kestryl' -Confirm:$false -ErrorAction SilentlyContinue

   # All of Kestryl's firewall rules (blocks, script lockdown, analytics servers)
   Get-NetFirewallRule -Group 'Kestryl' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

   # Only if "Cut off internet" was still on
   Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured

   # Only if Kestryl was closed by force during an HTTPS decryption session and never started again
   Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -like '*Kestryl temporary HTTPS inspection*' | Remove-Item

   # Settings, alerts, history and downloaded lists
   Remove-Item "$env:LOCALAPPDATA\Kestryl" -Recurse -Force
   ```

   If a decryption session was cut short like that, also check *Settings → Network & internet → Proxy*: **Use a proxy server** should be off unless you set one yourself. (Normally Kestryl repairs both the next time it starts.)

## Troubleshooting

| Problem | Fix |
|---|---|
| Header says **Limited mode** | Kestryl runs without administrator rights. Press **Restart as administrator**, or turn on *Start with Windows*. |
| Activity shows no byte counts or DNS names | Same as above: these need administrator rights. |
| **Peek** says Packet Monitor is missing | Peek uses `pktmon`, which comes with Windows 10 version 2004 and later. Another capture (`pktmon`, `netsh trace`, Wireshark's driver session) may also be running. |
| The window is blank or doesn't open | Install or repair the [WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/). |
| Too many alerts about a program you know | On the alert: **Trust this app** (no more alerts, traffic still shown) or **Mute** that kind of alert. |
| A site still works after **Block site** | Big sites use many addresses. Kestryl adds new ones as DNS answers show up, but only while it runs. |
| Something else | [Open an issue](https://github.com/HacanAle/Kestryl/issues/new/choose). Settings → Diagnostics shows the numbers that help. |
