# How Kestryl works

Kestryl is a [Tauri 2](https://tauri.app) app: a Rust backend that does all the watching, and a plain HTML/JavaScript window (no framework, no build step) that shows it. It installs no driver. Everything it knows comes from parts of Windows that are already there.

## Where the information comes from

| Source | Used for |
|---|---|
| **ETW** (Event Tracing for Windows), session `Kestryl-Monitor`: `Microsoft-Windows-Kernel-Network` | Per-process TCP and UDP bytes, connects, accepts (incoming), disconnects |
| ETW: `Microsoft-Windows-DNS-Client` (event 3008) | Which program looked up which name, and the answers, so IPs get names |
| ETW: `Microsoft-Windows-Kernel-Process` | Names of short-lived programs that exit before they can be looked up |
| ETW session `Kestryl-Files`: `Microsoft-Windows-Kernel-File` | Which program opened password stores, wallets, keys and documents (file **names** only, never contents) |
| Socket table (`netstat2`) | Open connections and listening ports; the only source in limited mode |
| Authenticode (`Get-AuthenticodeSignature`, batched) | Publisher of every program, including catalog-signed Windows files |
| Mark of the Web (`Zone.Identifier` stream) | Where a program was downloaded from |
| ConsentStore registry | Which program uses the camera or microphone |
| Clipboard listener | Swapped wallet addresses and IBANs (only text that looks like one is examined) |
| Security check (PowerShell, every 15 min and on change) | Defender, firewall, root certificates, proxy, hosts, DNS, start-up places, services, drivers, WMI, Winlogon, IFEO, accessibility tools, RDP, shares, UAC, Windows Update |
| Windows Firewall | All blocking (rules in the group *Kestryl*) |
| `SetTcpEntry` | Closing a blocked program's open IPv4 TCP connections at once |
| Packet Monitor (`pktmon`) | **Peek**: a few seconds of one connection, analysed in Rust (TLS SNI, HTTP, FTP, SMTP, DNS, entropy) |
| Microsoft Defender (`MpCmdRun -Scan -ScanType 3 -DisableRemediation`) | A second opinion on unsigned or risky programs; report only |

## The pipeline

```
ETW events ─┐
socket table┼─► engine (flows per program × destination, per-second rates,
file opens ─┤             file-access ↔ upload correlation, trust, history)
DNS answers ┘                │
                             ├─► detect.rs rules ─► alerts ─► pop-up + Alerts page
threat lists, geo DB ────────┤
security check ──────────────┘─► Status verdict
```

- **collect.rs** turns raw ETW events and socket polls into facts (process, remote address, bytes, direction).
- **engine.rs** keeps *flows* (program × destination), program stats, the upload window, file-access history per program (including child processes), trust state and daily history, and runs the rules every tick.
- **detect.rs** holds the behavioural rules. Each rule returns a severity that depends on who the program is (signed, unsigned, script host, temp folder, trusted).
- **lib.rs** wires it to the window: Tauri commands, the tray, the pop-up window and the background loops.

## Code map

| File | What it does |
|---|---|
| `src-tauri/src/collect.rs` | ETW (network, DNS, process, file opens), socket polling, process info, services, signatures, tracing health, the `--simulate` demo |
| `engine.rs` | Flows, alerts, file correlation, trust, status |
| `detect.rs` | The alert rules |
| `audit.rs` | The Windows security check and its baseline; a quick fingerprint of start-up places |
| `intel.rs` | Threat lists: download, cache, matching |
| `scan.rs` | SHA-256 and Microsoft Defender file scan (report only) |
| `sensors.rs` | Camera and microphone use |
| `history.rs` | Daily history |
| `peek.rs` | Packet capture and protocol analysis |
| `firewall.rs` | Blocking, network info, the start-up task |
| `geo.rs` | DB-IP country and ASN database: download, lookup, company names, the Places data |
| `away.rs` | Lock and idle detection, the "while you were away" reports |
| `origin.rs` | Mark of the Web |
| `clip.rs` | Clipboard guard |
| `analytics.rs` | Analytics and telemetry switches, with backup and exact restore |
| `decrypt.rs` | HTTPS decryption: session certificate, proxy, TLS relay, HTTP/1.1 reader, password, cleanup |
| `ipinfo.rs` | IP info (ipinfo.io and RDAP), on request only |
| `util.rs` | Helpers, including the one place that runs PowerShell |
| `ui/index.html`, `ui/app.js`, `ui/app.css` | The window |
| `ui/toast.html`, `ui/toast.js` | The pop-up |
| `ui/rules.json` | Lists of sensitive file locations, stealer targets and demo data (see below) |
| `ui/programs.js` | The plain-words library of ~250 programs and the look-alike check |
| `ui/world.js` | Country outlines for the map (Natural Earth 1:110m) |

## Design choices worth knowing

**No driver.** Kernel drivers are powerful, but a bug in one crashes Windows, and they must be signed by Microsoft. ETW plus Windows Firewall cover what Kestryl needs, at the price of not seeing inside encrypted traffic (see Decrypt) and not blocking *before* a rule exists.

**Behaviour over signatures.** Kestryl doesn't try to recognise malware files; Defender does that. It looks at what programs *do*: what they read, where they send, how much, how often, and who they are.

**Blocking is just Windows Firewall.** No hidden filter. Rules have ids `Kestryl-<kind>-<hash>` and descriptions `kestryl:<kind>:<target>` so Kestryl can find its own and nothing else. They survive restarts and uninstalling.

**Kestryl's own helpers are known by process ID.** Every PowerShell, Defender scan or `pktmon` Kestryl starts is registered as it starts, so its own work never raises alerts. A program that only claims Kestryl as its parent isn't trusted, because the parent process can be faked.

**Stealer target lists live in `ui/rules.json`.** A program that carries browser password paths and wallet extension IDs as plain text looks like a stealer to antivirus engines. The UI folder is embedded compressed into the exe, which avoids false positives. Keep such strings out of `.rs` files, tests included.

**Privileged code is defensive.** Kestryl runs as administrator, so anything it does can be an attack path for lower-privileged malware on the same PC. See [SECURITY.md](../SECURITY.md#how-kestryl-protects-itself) for the measures: full system paths for every helper, a locked-down PowerShell, safe quoting, no temp files, and no trust in user-editable data for privileged actions.

## Data and network

What is stored where: [User guide → data](USER_GUIDE.md#where-kestryl-keeps-its-data). What leaves the PC: [PRIVACY.md](../PRIVACY.md).
