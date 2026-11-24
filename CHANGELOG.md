# Changelog

All notable changes to Kestryl are listed here. Versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

### Fixed
- **Fewer antivirus false alarms.** A few scanners on VirusTotal flagged the 1.8.3 setup as a backdoor (Meterpreter) because of how Kestryl starts PowerShell and because the program carried malware names as plain text. Kestryl now hands its PowerShell checks over as plain text (no `-EncodedCommand`, no base64, no `-ExecutionPolicy Bypass`), and the suspicious-port descriptions and demo malware names moved into the compressed detection data (`ui/rules.json`). Nothing changes in what Kestryl detects.

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
