# Security

Kestryl runs with administrator rights and sees everything your PC sends, so its own security matters as much as what it detects. This page covers how to report a problem, how Kestryl protects itself, and the audit done before the first public release.

## Reporting a vulnerability

**Please don't open a public issue for security problems.** Report them privately:

1. Go to **[Security → Report a vulnerability](https://github.com/HacanAle/Kestryl/security/advisories/new)** on this repository.
2. Describe the problem, the version, and how to reproduce it. A proof of concept helps.

You'll get a reply in the advisory thread, and fixes are credited to you unless you'd rather stay anonymous. Please give us reasonable time to release a fix before you publish details.

**Supported versions:** only the [latest release](https://github.com/HacanAle/Kestryl/releases/latest) gets security fixes.

**In scope:** anything that lets a program, a website, a network peer or a file make Kestryl do something it shouldn't: run code, change Windows settings, hide activity from it, leak recorded data, or leave the PC less safe than before (for example after HTTPS decryption).

**Out of scope:** a program that already has administrator rights disabling Kestryl (it can disable any user-mode tool; Kestryl does report when its tracing stops), and missing detections. Please report missing detections as normal issues.

## How Kestryl protects itself

**Running with administrator rights**

- **Every helper program is started by full path** from the Windows folder (taken from the API, not from environment variables): PowerShell, Packet Monitor, `taskkill`, Explorer, and Defender's scanner (from Defender's own HKLM registration). Programs placed next to `Kestryl.exe` or in a folder on `PATH` are never picked up.
- **PowerShell is locked down.** No profile, modules only from Windows' own folders (not from your Documents folder), system folder variables reset from the API. Long scripts go through standard input, never through a temp file another program could swap. Every value inserted into a script is quoted with all of PowerShell's quote characters escaped, including the typographic ones, and only Kestryl's own fixed scripts ever run.
- **The window can't be taken over through the environment.** When running elevated, Kestryl removes `WEBVIEW2_*` variables (which could point the window at another "browser" or open a debugging port) before the window starts.
- **Data your account can edit is never trusted for privileged actions.** Settings live in `%LOCALAPPDATA%\Kestryl`, where any program you run could edit them, so undo data for the analytics switches is checked against what each switch actually owns before Kestryl restores it as administrator.
- **Installed where only administrators can change it.** The setup installs into *Program Files*. *Start with Windows* warns you if the exe sits in a folder your own account can change.
- **Capture files go to a fresh folder in Windows' own Temp**, not to your user Temp where links could redirect them.

**The window**

- The window shows only Kestryl's own built-in pages. Its content security policy allows no inline or outside scripts, and every name that comes from the outside (program names, domains, decrypted traffic) is escaped before it is shown.
- A second start of Kestryl only brings the existing window to the front; its command line is ignored.

**HTTPS decryption**

- Off unless you start it: administrator rights, your own password (stored as an Argon2id hash, five wrong tries lock it for 10 minutes), one program, at most 30 minutes, a red banner the whole time, and an alert for every start, stop and password attempt.
- A new certificate authority is made for each session: it can't sign other authorities, it is valid for only a few days, and its private key exists only in memory. It is removed from Windows when the session ends, and again by thumbprint and name at the next start after a crash.
- Kestryl checks the real server's certificate against Windows' trusted roots (not counting its own) before showing the program anything, so decryption never makes a connection less safe. Other programs' traffic is tunnelled untouched. The proxy listens on 127.0.0.1 only.

**Network**

- Every download is HTTPS. No program code is ever downloaded. Threat lists and the country database are parsed as plain data.
- IP lookups go out only when you ask, and private addresses are never looked up. See [PRIVACY.md](PRIVACY.md).

**Releases**

- Built by [GitHub Actions](.github/workflows/release.yml) from the tagged commit, with SHA-256 checksums and a signed [build provenance attestation](docs/INSTALL.md#verify-your-download) for every file.
- Dependencies are watched by Dependabot.

## Audit of v1.7.9

Before the first public release (November 2026), Kestryl's privileged code paths, its window, the decryption feature, its network access, its dependencies and the repository contents were reviewed. These issues were found and fixed in v1.7.9:

| # | Severity | Issue | Fix |
|---|---|---|---|
| 1 | Critical | PowerShell also ends a quoted string at the typographic quotes ‘ ’ ‚ ‛. A program file name containing them could break out of the quotes in the signature check that runs automatically, as administrator, for every new program, so any program could have run code as administrator. | All quote characters are escaped. A unit test, and a live test that runs a hostile name through real PowerShell, guard it. |
| 2 | High | Helpers were started by bare name, so Windows looked in Kestryl's own folder first. A file planted next to a portable copy would have run as administrator. | Full paths from the Windows API. |
| 3 | High | The elevated PowerShell could load modules from the user's Documents folder. | Module path restricted to Windows' own folders. |
| 4 | High | Defender's scanner was located through environment variables that a per-user setting can override. | Located through Defender's HKLM registration. |
| 5 | High | WebView2 settings from environment variables applied to the elevated window. | Removed before the window starts. |
| 6 | High | The analytics "undo" restored whatever registry values, services and firewall rules its backup in the user-editable settings file named, as administrator. | Only entries the switch itself changed are restored. Covered by a test. |
| 7 | Medium | The installer installed per user, so the start-up task (highest privileges) pointed to a file the user's account could replace. | Per-machine install into Program Files; a warning for exes in user-writable folders. |
| 8 | Medium | Packet captures were written to fixed file names in the user's Temp folder. | New unique folder in Windows' own Temp. |
| 9 | Low | The start-up task's account and some system paths came from environment variables. | Taken from the process token and the Windows API. |

**Reviewed and found sound:** HTML escaping and the content security policy of the window; Tauri permissions and single-instance handling; the decryption design (certificate constraints, upstream verification, loopback-only proxy, cleanup, password handling); HTTPS for every download; input checks on IPs, domains, ports and hashes; no temp files in privileged code.

**Dependencies:** all 555 Rust crates and the npm packages were checked against the [OSV](https://osv.dev) vulnerability database on 2026-11-20. There are no known vulnerabilities in code that ships in Kestryl; the only notices are "unmaintained" advisories (including for Linux-only crates that aren't compiled for Windows).

**Repository:** checked for keys, certificates, passwords, personal data and private paths before publishing. The public repository starts from a clean history.

## Known limitations

- **Settings are per user.** A program running under your account can edit `%LOCALAPPDATA%\Kestryl\config.json`, for example to trust itself. Kestryl doesn't let that file make it do anything privileged, but such a program can quiet Kestryl's alerts about itself. Protecting the settings with administrator-only permissions is planned.
- **Administrator-level malware wins.** A program with administrator rights can stop Windows' tracing, delete firewall rules or end Kestryl. Kestryl reports a stopped trace and restarts it, but no user-mode tool can fully defend against an administrator.
- **WebView2 keeps its browser profile in your user folder,** as it does for every app that uses it.
- **The downloads aren't code-signed yet,** so SmartScreen warns. Use the checksums and build attestations to verify them.
- **Kestryl is not an antivirus.** Keep Microsoft Defender on.
