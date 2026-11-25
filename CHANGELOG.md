# Changelog

All notable changes to Kestryl are listed here. Versions follow [Semantic Versioning](https://semver.org).

## [1.8.6] - 2026-11-25

### Fixed
- **False "opened SSH, cloud or FTP login keys" alerts that said *Started by Kestryl.exe*.** Windows reuses process ids. When a short-lived program (for example a Docker helper reading `.docker\config.json`) got the id of one of Kestryl's own finished PowerShell checks, its file open could be blamed on that old check and shown as High. Kestryl now notices that the old program was already gone and waits for the real one. A program that really reads a key file and quits right away is still reported.
- **"Possible DNS tunnelling" for names in the hosts file.** A large hosts blocklist (for example hundreds of `*.adobestats.io` lines) raised the alert whenever a program read the DNS cache. Windows answers hosts-file names itself and never sends them to a DNS server, so they now skip the tunnelling checks. Thanks to @Matteo842 (#9).
- **Programs listed as malware when Defender couldn't scan.** With another antivirus active, Microsoft Defender is off and its scanner fails, but it reports that with the same exit code as "threat found". A failed scan is now shown as an error, not as malware. Thanks to @Matteo842 (#8).

## [1.8.5] - 2026-11-25

### Fixed
- **The home country reset after a Windows restart.** If *Start with Windows* was turned on in another copy of Kestryl (a portable or self-built exe), the sign-in task kept starting that older copy even after a newer one was installed with the setup. The older copy didn't know the home country setting and saved it away, so Settings showed **From Windows** again after every restart. Two fixes:
  - The copy installed in *Program Files* now takes the sign-in task over the first time it runs as administrator. A copy outside *Program Files* never takes it from another one.
  - Kestryl now keeps settings it doesn't recognise in its config file instead of dropping them, so running an older or newer copy can't wipe another version's settings.

  If your home country was reset, pick it again once in Settings → Country and company data → **Home country**.

## [1.8.4] - 2026-11-25

### New
- **Pick your home country.** Settings → Country and company data → **Home country**. Places and "data leaving your country" compare against it. **From Windows** (the default) keeps using Windows' region setting as before; pick a country when that setting isn't where you live, for example on a PC set up abroad or with a region chosen only for the Store.

### Changed
- **The theme follows Windows by default.** New installs, and everyone who never picked a theme in Settings, now get light or dark to match Windows (Settings → Personalization → Colors), and the app switches along when Windows does. Why: an app that ignores the system's light/dark choice feels out of place. The Kestryl theme is still in Settings → Theme, and a theme you picked yourself is kept.
- The window no longer flashes the wrong colours while it opens: it starts in the theme it showed last time.

### Fixed
- **Fewer antivirus false alarms.** Some scanners on VirusTotal flagged the 1.8.3 setup as a backdoor (Huorong and Rising: "Meterpreter", Kaspersky: "Qhost"). Kestryl did nothing wrong, but two things in the program looked like a malware loader:
  - It started PowerShell with `-ExecutionPolicy Bypass -EncodedCommand` and a base64 loader, which is exactly how attack tools launch their scripts. Kestryl now hands its PowerShell checks over as plain text: no base64, no `-EncodedCommand`, no `-ExecutionPolicy Bypass` (none of it was needed; Windows' own modules load under every policy).
  - The program carried malware names as plain text (the suspicious-port notes, a mail-stealer note and the demo's made-up threats). These moved into the detection data that ships compressed inside the app (`ui/rules.json`), like the password-file list already did.
  
  Nothing changes in what Kestryl detects or how it looks. In our test on VirusTotal the setup went from 3 detections to 1 (Huorong).

## [1.8.3] - 2026-11-24

### Fixed
- Minor bug fixes in the UI.

## [1.8.2] - 2026-11-24

### Fixed
- **Settings fits the window.** The Known-safe services table no longer pushes the page sideways. In a narrower window the section menu moves to a row on top, and wide controls move under their label.
- **Page header in a narrow window.** The title is no longer covered by the Simple/Advanced switch, and Upload/Download are no longer cut off: the small traffic graph hides first, then "Limited mode"/"Full monitoring" shrinks to its coloured dot, and the header wraps onto a second line if it still doesn't fit.

## [1.8.1] - 2026-11-24

Coming from 1.8.0: install this version by hand once (Setup below). From now on Kestryl tells you about new versions and can install them itself.

### New
- **Update notifications.** Once a day Kestryl asks its GitHub releases page whether a newer version is out, and tells you with a pop-up and an alert (once per version). Settings → Updates shows what's new, has **Check now**, and can turn the daily check off.
- **Update now** installs a new version from inside Kestryl: it downloads the setup from GitHub, installs it only if it is signed with Kestryl's update key, and restarts. Releases that are not signed for this, and the portable exe, get a link to the download page instead.
- **Known-safe services.** Addresses of Google's, Microsoft 365's and Apple's own services (from the lists these companies publish) and Windows Update and Defender names are tagged on Connections, and alerts that only say a destination looks unusual (timer check-ins, bare IP addresses, uncommon ports) stay quiet for normal programs. Uploads, password-theft, email/FTP, file-sharing and known-malware alerts still fire, and unsigned programs, programs in Temp or Downloads, scripts and Windows tools are never quieted. Google Cloud customer ranges are left out. Settings → Known-safe services: switch it off, switch services off one by one, view every range, and test any address. Connections has **Hide known-safe**.

### Fixed
- Kestryl now tells you every time the camera turns on, also when it is a browser tab (Chrome, Edge, Firefox…), a call app or a Microsoft Store app. These used to be listed on Status but never popped up. A browser notice explains how to find the tab using it. Settings → Protection has "Camera turned on" (on) and "Microphone turned on" (off at first).
- Alerts: clicking an alert lower down the list no longer jumps the list back to the top.
- Threat lists: ThreatFox failed with "response too big for into_string" whenever a week of it was over 10 MB. Lists up to 256 MB are read now, with more time for slow connections.

## [1.8.0] - 2026-11-20

### Look and feel
- New setup wizard: Kestryl's icon on Setup.exe and its uninstaller instead of the generic installer icon, branded welcome, header and finish pages, current Windows controls and font, and the publisher and copyright in the file properties.
- Kestryl opens with a short animation of its logo. It plays once per start, the first time the window appears; a click skips it.
- The Kestryl theme is now the default for everyone, including existing users, until you pick another theme in Settings.
- Screenshots and the banner on GitHub show the Kestryl theme.

## [1.7.9] - 2026-11-20

The first public release.

### Monitoring
- Live upload and download per program, with destinations, countries and companies, publisher (Authenticode) and plain-words descriptions of about 250 common programs.
- Status page: one verdict for the PC, plus checks of Defender, firewall, root certificates, proxy, hosts file, DNS, Remote Desktop, shared folders, UAC, Windows Update, and every start-up place malware uses.
- Places: a world map of where each day's data went, from the offline DB-IP database.
- History for 30 days, DNS lookups, network adapters, devices, listening ports and incoming connections.
- While-you-were-away reports, clipboard guard, camera and microphone watch.
- Simple and Advanced views; Dark, Light, Kestryl and Follow-Windows themes.

### Detection
- More than 25 behavioural rules: password and document theft followed by uploads, stealer-style uploads, known malware servers (abuse.ch, C2IntelFeeds, Spamhaus DROP, Emerging Threats, optional ThreatFox), remote control, beaconing, DNS tunnelling, suspicious ports, Windows tools going online, new start-up entries, tampering with monitoring.
- Microsoft Defender second opinion on new unsigned programs (report only).

### Control
- One-click blocking of apps, IPs, sites and incoming ports through Windows Firewall; script lockdown; cut off internet.
- Analytics and telemetry switches for Windows, Edge, Office and Chrome, with exact undo.
- Peek (short packet capture of one connection) and password-protected HTTPS decryption of one program.

### Security
- Full security audit before release; nine issues fixed, one critical. See [SECURITY.md](https://github.com/HacanAle/Kestryl/blob/main/SECURITY.md#audit-of-v179).
- Setup installs per machine into Program Files.
- Releases are built by GitHub Actions with SHA-256 checksums and build provenance attestations.

[1.8.3]: https://github.com/HacanAle/Kestryl/releases/tag/v1.8.3
[1.8.2]: https://github.com/HacanAle/Kestryl/releases/tag/v1.8.2
[1.8.1]: https://github.com/HacanAle/Kestryl/releases/tag/v1.8.1
[1.8.0]: https://github.com/HacanAle/Kestryl/releases/tag/v1.8.0
[1.7.9]: https://github.com/HacanAle/Kestryl/releases/tag/v1.7.9
