//! "While you were away": Kestryl notices when the PC is locked, or nobody has touched the
//! keyboard or mouse for 10 minutes, counts what each program sent to the internet in the
//! meantime, and reports it when you are back. The engine does the counting (away_* in
//! engine.rs); this file reads the PC's state and holds the report types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// No keyboard or mouse input for this long counts as "away".
pub const IDLE_MS: u64 = 10 * 60_000;
/// Away periods shorter than this are not reported.
pub const MIN_MS: u64 = 2 * 60_000;
pub const KEEP: usize = 30;

/// (screen locked, milliseconds since the last keyboard or mouse input).
#[cfg(windows)]
pub fn presence() -> (bool, u64) {
    use windows::Win32::System::StationsAndDesktops::{CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, UOI_NAME};
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    let idle = unsafe {
        let mut li = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        if GetLastInputInfo(&mut li).as_bool() {
            GetTickCount().wrapping_sub(li.dwTime) as u64
        } else {
            0
        }
    };
    // While locked, the input desktop is Windows' sign-in screen ("Winlogon"), which a
    // normal program cannot open at all.
    let locked = unsafe {
        match OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(0x0001)) {
            Err(_) => true,
            Ok(h) => {
                let mut buf = [0u16; 64];
                let mut need = 0u32;
                let ok = GetUserObjectInformationW(windows::Win32::Foundation::HANDLE(h.0), UOI_NAME, Some(buf.as_mut_ptr() as *mut _), (buf.len() * 2) as u32, Some(&mut need)).is_ok();
                let _ = CloseDesktop(h);
                let name = String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(0)]);
                ok && !name.eq_ignore_ascii_case("Default")
            }
        }
    };
    (locked, idle)
}
#[cfg(not(windows))]
pub fn presence() -> (bool, u64) {
    (false, 0)
}

/// An away period in progress: internet bytes per process, and per program once the
/// process is known (folded in every few seconds, so programs that exit are not lost).
#[derive(Default)]
pub struct Session {
    pub start: u64,
    pub why: &'static str,
    pub by_pid: HashMap<u32, PidAcc>,
    pub progs: HashMap<String, ProgAcc>,
}

#[derive(Default)]
pub struct PidAcc {
    pub out: u64,
    pub inn: u64,
    pub dests: HashMap<IpAddr, u64>,
}

#[derive(Default)]
pub struct ProgAcc {
    pub name: String,
    pub out: u64,
    pub inn: u64,
    /// Site or address -> (an address of it, bytes sent).
    pub dests: HashMap<String, (IpAddr, u64)>,
    pub own: bool,
    pub trusted: bool,
    pub shady: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct DestReport {
    pub dest: String,
    pub cc: String,
    pub org: String,
    pub out: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ProgReport {
    pub key: String,
    pub name: String,
    pub out: u64,
    #[serde(rename = "in")]
    pub inn: u64,
    pub dests: Vec<DestReport>,
    /// Kestryl itself (threat-list downloads).
    pub own: bool,
    pub trusted: bool,
    /// Unsigned, in a temp/download folder, or a script host: worth a look when it sent data unattended.
    pub flagged: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Report {
    pub id: u64,
    pub start: u64,
    pub end: u64,
    /// "locked" or "idle".
    pub why: String,
    pub out: u64,
    #[serde(rename = "in")]
    pub inn: u64,
    pub progs: Vec<ProgReport>,
    pub flagged: bool,
    pub sim: bool,
}

/// "55 min", "2 h 10 min".
pub fn fmt_dur(ms: u64) -> String {
    let m = ms / 60_000;
    if m < 60 {
        format!("{m} min")
    } else if m % 60 == 0 {
        format!("{} h", m / 60)
    } else {
        format!("{} h {} min", m / 60, m % 60)
    }
}

pub fn load() -> Vec<Report> {
    std::fs::read_to_string(crate::config::dir().join("away.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn save(r: &[Report]) {
    if let Ok(s) = serde_json::to_string(r) {
        crate::config::write_atomic_in(&crate::config::dir(), "away.json", &s);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn durations() {
        assert_eq!(super::fmt_dur(55 * 60_000), "55 min");
        assert_eq!(super::fmt_dur(130 * 60_000), "2 h 10 min");
        assert_eq!(super::fmt_dur(120 * 60_000), "2 h");
    }

    #[test]
    #[ignore]
    fn live_presence() {
        let (locked, idle) = super::presence();
        println!("locked {locked}, idle {idle} ms");
        assert!(!locked, "the test runs at an unlocked desktop");
    }
}
