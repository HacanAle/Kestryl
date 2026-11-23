# Privacy

**Kestryl collects nothing about you.** It has no account, no analytics, no crash reporting, no ads and no server of its own. What it sees stays on your PC.

## What stays on your PC

Everything Kestryl records is stored in `%LOCALAPPDATA%\Kestryl\` and never uploaded: settings, trusted programs and destinations, alerts, 30 days of traffic history, "while you were away" reports, the downloaded threat lists and country database, and an error log. Details: [User guide → data](docs/USER_GUIDE.md#where-kestryl-keeps-its-data).

These are kept only in memory and never written to disk:

- HTTPS decryption recordings (at most 400 entries; cleared when you press **Clear** or quit);
- the private key of the temporary decryption certificate.

File monitoring looks at file **names** only (to notice a program opening, say, your browser's password store). It never reads file contents. The clipboard guard examines only copied text that looks like a crypto wallet address or an IBAN, and keeps a shortened form (`bc1qxy…0wlh`) in the alert.

## What leaves your PC, and why

Kestryl itself contacts only these servers, over HTTPS:

| Server | When | What is sent | Why |
|---|---|---|---|
| `feodotracker.abuse.ch` | Every 12 hours | A plain download request | Botnet control-server list |
| `raw.githubusercontent.com` (C2IntelFeeds) | Every 12 hours | A plain download request | Command-and-control server lists |
| `www.spamhaus.org` | Every 12 hours | A plain download request | Spamhaus DROP list of criminal networks |
| `rules.emergingthreats.net` | Every 12 hours | A plain download request | Compromised-hosts list |
| `threatfox-api.abuse.ch` | Every 12 hours, **only if you entered an abuse.ch key** | Your key | ThreatFox malware IOC list |
| `download.db-ip.com` | Once a month | A plain download request | Free country and company (ASN) database for Places. Lookups happen on your PC. |
| `www.gstatic.com` | Once a day, **unless Known-safe services is off** | A plain download request | Google's published lists of its own addresses and of its Cloud customer ranges |
| `endpoints.office.com` | Once a day, **unless Known-safe services is off** | A fixed request id, the same for every copy of Kestryl | Microsoft's published list of Microsoft 365 addresses |
| `api.github.com` | Once a day, **unless you turn update checks off**, and when you press Check now | A plain request for Kestryl's latest release | Tells you when a new version is out |
| `github.com` and GitHub's download servers | **Only when you press Update now** | A plain download request | Downloads the new setup and its signature from Kestryl's GitHub releases |
| `ipinfo.io`, `rdap.org` | **Only when you press IP info** | The one public IP address you look up | Owner, location and abuse contact of that address |
| `www.virustotal.com` | **Only when you press VirusTotal** | The file's SHA-256 hash, in your browser | Opens that file's VirusTotal report page |
| Your usual DNS server | **Only when you block a site** | The site's name | To find the addresses to block |

Nothing else. In particular:

- **No program files, file contents or names of your files are ever uploaded by Kestryl.** Scans use the Microsoft Defender already on your PC, in report-only mode. Defender itself follows its own cloud-protection settings in Windows Security, as it does for any scan.
- **No addresses you talk to are looked up online** except the one you choose with IP info.
- **Updates only when you click.** Kestryl checks once a day whether a new version exists (Settings → Updates can turn this off). It downloads program code only when you press **Update now**, and installs it only if it is signed with Kestryl's update key.

The window is drawn by Microsoft Edge WebView2, a part of Windows. Kestryl loads only its own built-in pages into it.

## Things Kestryl does to Windows, and only when you ask

| Change | Undo |
|---|---|
| Firewall rules in the group *Kestryl* (blocks, script lockdown, analytics servers) | Blocking tab, or `wf.msc` |
| Firewall default outbound action set to Block (**Cut off internet**) | **Restore internet** |
| Scheduled task *Kestryl* (**Start with Windows**) | Settings → Start with Windows → Turn off |
| Analytics policies, the DiagTrack service | Turn the switch off: the exact previous values come back |
| A temporary root certificate and proxy setting during **Decrypt** | Removed automatically when the session ends, or at the next start after a crash |

Kestryl never deletes, moves or quarantines your files.
