# Building Kestryl

## What you need

- Windows 10 or 11, 64-bit. Kestryl uses Windows-only APIs and is built on Windows.
- [Rust](https://rustup.rs) (stable, MSVC toolchain): `winget install Rustlang.Rustup`
- Visual Studio 2022 Build Tools with the **Desktop development with C++** workload: `winget install Microsoft.VisualStudio.2022.BuildTools`
- [Node.js](https://nodejs.org) 20 or later (only for the Tauri command-line tool)
- Git

## Build

```powershell
git clone https://github.com/HacanAle/Kestryl.git
cd Kestryl
npm install

npx tauri build --debug --no-bundle   # quick debug exe: src-tauri\target\debug\Kestryl.exe
npx tauri build --no-bundle           # release exe:     src-tauri\target\release\Kestryl.exe
npx tauri build                       # release exe + installer: src-tauri\target\release\bundle\nsis\Kestryl_<version>_x64-setup.exe
```

The window is plain HTML/CSS/JS in `ui/`, with no bundler and no build step. Tauri embeds that folder into the exe.

## Run

```powershell
src-tauri\target\debug\Kestryl.exe              # normal
src-tauri\target\debug\Kestryl.exe --simulate   # demo with made-up malicious programs
src-tauri\target\debug\Kestryl.exe --hidden     # start in the tray (used by "Start with Windows")
```

`--simulate` is the safest way to work on the UI. It adds fake programs (pids 90001–90008) that trigger about a dozen alerts, a fake clipboard swap, an away report, places and a decryption session. It never saves anything, doesn't need administrator rights, and can run next to a real Kestryl. It still reads the real PC for the Status checks and the socket table, so close other windows before you take screenshots of it.

## Tests

```powershell
cd src-tauri
cargo test --lib                        # unit tests (also run by CI on every push)
cargo test --lib live_ -- --ignored --nocapture
```

The `live_` tests touch the real PC, read-only or under `HKCU\Software\KestrylTest`. They check the list downloads, a Defender scan of `notepad.exe`, the camera record, an ipinfo lookup, download origins, lock and idle state, analytics apply and restore, decryption of a real HTTPS request (in-process client, no system certificate), and that a file name crafted to break PowerShell quoting can't run code.

```powershell
cargo test --lib -- --ignored --nocapture   # NOT elevated: firewall and task changes must fail with "Access is denied"
```

If a real Kestryl runs on the same PC, it will notice the test binary's network lookups and may alert on them. That is expected.

## Antivirus false positives

The lists of files that stealers go for (browser password databases, wallet folders and extension IDs, Telegram data…) live in `ui/rules.json`, which Tauri embeds compressed. Microsoft Defender flags a program that carries such a list as plain text as `Trojan:Win32/Cryware`. **Keep those paths out of `.rs` files, tests included.** Tests read their sample paths from `rules.json`.

## Icons

The source image is `docs/assets/app-icon.png` (1024 × 1024, transparent). To regenerate:

```powershell
npx tauri icon docs/assets/app-icon.png -o src-tauri/icons
```

Then delete the `android`, `ios`, `icon.icns`, `Square*Logo.png` and `StoreLogo.png` outputs; Kestryl is Windows-only. `src-tauri/icons/tray.png` (32 px, bolder) is drawn separately for the tray.

## Setup look

The setup wizard is Tauri's NSIS installer with Kestryl's look on top, set in `tauri.conf.json` (`bundle > windows > nsis`):

- `src-tauri/windows/installer.nsh`: current Windows controls and font, header image on the right, the welcome and finish texts.
- `src-tauri/windows/nsis-sidebar.bmp` (164 × 314, welcome and finish pages) and `nsis-header.bmp` (150 × 57, the other pages): 24-bit BMP at exactly these sizes, because NSIS stretches anything else.
- `src-tauri/icons/icon.ico` is the icon of Setup.exe, the uninstaller and Kestryl.exe.

## Signing your own build (optional)

Official releases are built and published by GitHub Actions (see below). If you ship your own build, you can sign it:

- With a certificate from a commercial authority or Azure Trusted Signing: other PCs then trust it.
- With a self-signed certificate, for your own PCs only. `scripts/signing-setup.ps1` makes one once (the private key goes into a password-protected `.pfx` in your Documents folder, never into the project; `*.pfx` is git-ignored). `scripts/sign.ps1` signs and timestamps `Kestryl.exe` after each release build. Other PCs show such a file as signed by an untrusted publisher.

Kestryl recognises the certificate that signed the running exe, so its own self-signed root is not reported as a "new root certificate". A look-alike root with the same name still is.

## Releasing

1. Bump the version in `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json` (and let `cargo` update `Cargo.lock`).
2. Add a section for it at the top of `CHANGELOG.md`, headed `## [x.y.z] - YYYY-MM-DD`.
3. Commit, then tag and push:

   ```powershell
   git tag v1.8.0
   git push origin main v1.8.0
   ```

4. The [release workflow](../.github/workflows/release.yml) runs the tests, builds the setup and the portable exe on a clean Windows runner, writes `SHA256SUMS.txt`, attaches a build-provenance attestation to each file, and publishes the GitHub release with the changelog section as its notes.
