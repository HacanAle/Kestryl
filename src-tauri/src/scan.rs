//! A second look at program files: SHA-256 (matched against ThreatFox, and the key for a
//! VirusTotal lookup the user can open), and a scan of that one file by the Microsoft
//! Defender already on the PC (MpCmdRun custom scan). Nothing is uploaded, and the scan
//! only reports (-DisableRemediation): Kestryl never deletes or quarantines anything.

use crate::util::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Default)]
pub struct Scan {
    /// When it finished (ms).
    pub t: u64,
    /// clean | threat | error | running
    pub state: String,
    pub threat: String,
    pub sha256: String,
    pub err: String,
    /// File size and modified time when scanned: a changed file is scanned again.
    #[serde(skip)]
    pub stamp: (u64, u64),
}

pub fn stamp(path: &str) -> (u64, u64) {
    std::fs::metadata(path)
        .map(|m| {
            let t = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
            (m.len(), t)
        })
        .unwrap_or((0, 0))
}

pub fn sha256_file(path: &str) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("cannot read the file ({e})"))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Defender's command-line scanner: the platform copy Defender itself registered in HKLM,
/// else the newest platform folder, else the classic one. Never found through %ProgramData%
/// or %ProgramFiles%: a per-user variable could point the elevated Kestryl at another exe.
fn mpcmdrun() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let k = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows Defender");
        if let Ok(dir) = k.and_then(|k| k.get_value::<String, _>("InstallLocation")) {
            let p = Path::new(dir.trim().trim_end_matches('\\')).join("MpCmdRun.exe");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let drive = windows_dir().to_string_lossy().chars().take(2).collect::<String>();
    let plat = PathBuf::from(format!(r"{drive}\ProgramData\Microsoft\Windows Defender\Platform"));
    let mut best: Option<PathBuf> = None;
    if let Ok(rd) = std::fs::read_dir(&plat) {
        let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.join("MpCmdRun.exe").is_file()).collect();
        dirs.sort();
        best = dirs.pop().map(|d| d.join("MpCmdRun.exe"));
    }
    best.or_else(|| Some(program_files().join(r"Windows Defender\MpCmdRun.exe")).filter(|p| p.is_file()))
}

/// Threat names from MpCmdRun's output ("Threat                  : Trojan:Win32/X").
pub fn parse_threats(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == "Threat").then(|| v.trim().to_string())
        })
        .filter(|t| !t.is_empty())
        .collect()
}

/// Scans one file. Ok(threat names), empty = clean.
pub fn defender_scan(path: &str) -> Result<Vec<String>, String> {
    if !Path::new(path).is_file() {
        return Err("the file is no longer there".into());
    }
    let exe = mpcmdrun().ok_or("Microsoft Defender's scanner (MpCmdRun.exe) was not found")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"]);
    hide_window(&mut cmd);
    let out = own_output(&mut cmd).map_err(|e| format!("could not start Defender's scanner ({e})"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    read_result(out.status.code(), &text)
}

/// True when MpCmdRun says the scan itself did not run ("CmdTool: Failed with hr = 0x80004005").
/// This part of its output is not translated.
fn scan_failed(out: &str) -> bool {
    out.lines().any(|l| l.contains("Failed with hr") || l.trim_start().starts_with("[Failed]"))
}

/// MpCmdRun's exit code and output: threat names, empty = clean.
fn read_result(code: Option<i32>, text: &str) -> Result<Vec<String>, String> {
    let threats = parse_threats(text);
    match code {
        Some(0) => Ok(vec![]),
        Some(2) if !threats.is_empty() => Ok(threats),
        // Exit code 2 means "threat found", but MpCmdRun also exits with 2 when it cannot
        // scan at all, e.g. while another antivirus has turned Defender off. A failure with
        // no threat listed is an error, not a detection.
        Some(2) if !scan_failed(text) => Ok(vec!["a threat (name not given)".into()]),
        c => {
            let last = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string();
            Err(if last.is_empty() {
                format!("Defender's scanner failed (code {})", c.unwrap_or(-1))
            } else {
                format!("Defender: {last}")
            })
        }
    }
}

/// Hash, then Defender. A failed scan still keeps the hash.
pub fn run(path: &str) -> Scan {
    let mut s = Scan { state: "clean".into(), stamp: stamp(path), ..Default::default() };
    match sha256_file(path) {
        Ok(h) => s.sha256 = h,
        Err(e) => {
            s.state = "error".into();
            s.err = e;
            return s;
        }
    }
    match defender_scan(path) {
        Ok(t) if t.is_empty() => {}
        Ok(t) => {
            s.state = "threat".into();
            s.threat = t.join(", ");
        }
        Err(e) => {
            s.state = "error".into();
            s.err = e;
        }
    }
    s
}

/// The --simulate demo: made-up results, nothing is read or scanned.
pub fn demo(path: &str) -> Scan {
    let bad = path.to_lowercase().contains("invoice_viewer");
    Scan {
        state: if bad { "threat" } else { "clean" }.into(),
        threat: if bad { "Trojan:Win32/AgentTesla (demo)".into() } else { String::new() },
        sha256: format!("{:016x}{:016x}{:016x}{:016x}", fnv(path), fnv(&format!("{path}1")), fnv(&format!("{path}2")), fnv(&format!("{path}3"))),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_lines() {
        let out = "Scan starting...\nScan finished.\nScanning C:\\x\\a.exe found 1 threats.\n\n<==LIST==>\n---- Threat information ----\nThreat                  : Trojan:Win32/AgentTesla!ml\nResources               : 1 total\n    file                : C:\\x\\a.exe\n";
        assert_eq!(parse_threats(out), vec!["Trojan:Win32/AgentTesla!ml".to_string()]);
        assert!(parse_threats("Scanning C:\\x\\b.exe found no threats.").is_empty());
    }

    #[test]
    fn failed_scan_is_not_a_threat() {
        // Defender turned off by another antivirus: exit code 2, but nothing was scanned.
        let out = "[Failed][0x80004005] Errore non specificato.\nCmdTool: Failed with hr = 0x80004005. Check C:\\Temp\\MpCmdRun.log for more information\n";
        let r = read_result(Some(2), out);
        assert!(r.as_ref().is_err_and(|e| e.contains("Failed with hr")), "{r:?}");
        let found = "Scanning C:\\x\\a.exe found 1 threats.\n---- Threat information ----\nThreat                  : Trojan:Win32/AgentTesla!ml\n";
        assert_eq!(read_result(Some(2), found).unwrap(), vec!["Trojan:Win32/AgentTesla!ml".to_string()]);
        assert_eq!(read_result(Some(2), "Scanning C:\\x\\a.exe found 1 threats.\n").unwrap(), vec!["a threat (name not given)".to_string()]);
        assert!(read_result(Some(0), "Scanning C:\\x\\b.exe found no threats.").unwrap().is_empty());
    }

    #[test]
    fn hashes_a_file() {
        let p = std::env::temp_dir().join("kestryl-hash-test.txt");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(sha256_file(&p.display().to_string()).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(test)]
mod live {
    /// Run by hand: Defender scans a clean Windows file, and the hash of the same file.
    #[test]
    #[ignore]
    fn live_defender_scan() {
        let p = r"C:\Windows\System32\notepad.exe";
        let r = super::run(p);
        println!("{r:?}");
        assert_eq!(r.sha256.len(), 64);
        assert!(r.state == "clean" || r.state == "error", "{r:?}");
        let fp1 = crate::audit::quick_fingerprint();
        assert_eq!(fp1, crate::audit::quick_fingerprint());
        println!("fingerprint {fp1:x}");
    }
}
