# Changelog

All notable changes to Kestryl are listed here. Versions follow [Semantic Versioning](https://semver.org).

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
- Full security audit before release; nine issues fixed, one critical. See [SECURITY.md](SECURITY.md#audit-of-v179).
- Setup installs per machine into Program Files.
- Releases are built by GitHub Actions with SHA-256 checksums and build provenance attestations.

[1.7.9]: https://github.com/HacanAle/Kestryl/releases/tag/v1.7.9
