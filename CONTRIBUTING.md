# Contributing to Kestryl

Thanks for helping. Kestryl is a security tool that runs as administrator, so contributions are held to a careful standard, and small, focused pull requests are the easiest to review.

## Ways to help

- **Report a bug**: [open an issue](https://github.com/HacanAle/Kestryl/issues/new/choose) with your Windows version, Kestryl version, what you did and what happened. *Settings → Diagnostics* has numbers that help.
- **Report a missed detection or a false alarm**: describe the program and what it did. Leave out personal data such as user names, IP addresses you don't want public, and file paths with your name in them.
- **Improve the program library**: `ui/programs.js` describes ~250 programs in plain words. More common programs are always welcome.
- **Translate, document, design**: the docs live in `docs/`.
- **Security problems**: never in a public issue. See [SECURITY.md](SECURITY.md).

## Development setup

See [docs/BUILDING.md](docs/BUILDING.md). In short: Rust (MSVC), VS Build Tools with C++, Node.js, then `npm install` and `npx tauri build --debug --no-bundle`. Run `Kestryl.exe --simulate` to see every page with made-up data.

## Before you open a pull request

- `cargo test --lib` passes in `src-tauri`.
- `node --check ui/app.js` and `node --check ui/toast.js` pass.
- New behaviour has a unit test where possible. Rules in `detect.rs` and anything in `engine.rs` are easy to test.
- The UI is checked in the `--simulate` demo, in both Simple and Advanced view, in the dark and light themes.
- One topic per pull request, with a description of what changed and why.

## Rules for code that runs as administrator

These keep Kestryl from becoming a way into the PC it protects:

1. **Start programs by full path** (`util::system_exe`, `util::windows_dir`), never by bare name, and never from a path built from environment variables.
2. **Run PowerShell only through `util::run_ps` / `run_ps_timeout`**, and put every outside value into a script with `util::ps_quote`. Never build a script from a string the user, a file or the network supplied without it.
3. **No temp files in privileged code.** Pass data through standard input or memory. If a file can't be avoided, create a new, uniquely named folder in a location only administrators can write.
4. **Don't trust `%LOCALAPPDATA%\Kestryl` for privileged actions.** Any program running as the user can edit it. Check values against a fixed list of what is allowed, as `analytics::sanitize_backup` does.
5. **Escape everything shown in the window** with `esc()` in `ui/app.js`. Program names, domains, command lines and decrypted traffic all come from outside.
6. **No new network destinations** without a good reason, HTTPS only, documented in [PRIVACY.md](PRIVACY.md).
7. **Keep stealer target paths out of `.rs` files** (they belong in `ui/rules.json`), or antivirus engines will flag the exe.

## Style

- Rust: `cargo fmt`; clear names; a short comment saying *why*, not *what*.
- JavaScript: plain modern JS, no framework, no build step.
- Text in the UI: plain words, short sentences, written for people who aren't in IT (Simple view). IT detail goes in Advanced view.

## License

By contributing you agree that your contribution is licensed under the [GPL-3.0](LICENSE), like the rest of Kestryl.
