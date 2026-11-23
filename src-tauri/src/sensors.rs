//! Which programs use the camera and the microphone. Windows records every use per program
//! (Settings → Privacy → Camera/Microphone "recent activity") under
//! HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore:
//! LastUsedTimeStart / LastUsedTimeStop as FILETIMEs, Stop = 0 while in use. Remote-access
//! trojans switch these on to spy, so a program nobody expects turning them on is worth an alert.

use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Use {
    /// "camera" | "microphone"
    pub kind: &'static str,
    /// Exe path for desktop programs, package name for Store apps.
    pub app: String,
    pub packaged: bool,
    pub start: u64,
    /// 0 while it is in use.
    pub stop: u64,
}

impl Use {
    pub fn active(&self) -> bool {
        self.start > 0 && self.stop == 0
    }
    /// Lower-case exe path, the engine's program key.
    pub fn key(&self) -> String {
        self.app.to_lowercase()
    }
}

/// FILETIME (100 ns since 1601) -> ms since 1970.
pub fn filetime_ms(ft: u64) -> u64 {
    if ft == 0 {
        0
    } else {
        (ft / 10_000).saturating_sub(11_644_473_600_000)
    }
}

/// "C:#Program Files#App#app.exe" -> "C:\Program Files\App\app.exe"
pub fn key_to_path(k: &str) -> String {
    k.replace('#', "\\")
}

/// Short name for the UI: file name, or the app part of a package family name.
pub fn label(u: &Use) -> String {
    if u.packaged {
        let n = u.app.split('_').next().unwrap_or(&u.app);
        n.rsplit('.').next().unwrap_or(n).to_string()
    } else {
        u.app.rsplit('\\').next().unwrap_or(&u.app).to_string()
    }
}

/// Programs people use for calls, meetings, streaming and recording: their use is listed,
/// never alerted.
pub fn expected(name_lower: &str) -> bool {
    const OK: [&str; 30] = [
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "arc.exe",
        "ms-teams.exe", "teams.exe", "zoom.exe", "skype.exe", "discord.exe", "slack.exe", "webex.exe", "ciscocollabhost.exe",
        "obs64.exe", "obs32.exe", "whatsapp.exe", "telegram.exe", "signal.exe", "msedgewebview2.exe", "googlemeet.exe",
        "audacity.exe", "lync.exe", "gotomeeting.exe", "g2mcomm.exe", "streamlabs obs.exe", "nvidia broadcast.exe",
        "voicemeeter.exe", "ringcentral.exe",
    ];
    OK.contains(&name_lower)
}

/// Browsers: their camera and microphone use is a website in one of their tabs. Windows records
/// only the browser, never which tab or site.
pub fn browser(name_lower: &str) -> Option<&'static str> {
    Some(match name_lower {
        "chrome.exe" => "Google Chrome",
        "msedge.exe" => "Microsoft Edge",
        "firefox.exe" => "Firefox",
        "brave.exe" => "Brave",
        "opera.exe" => "Opera",
        "vivaldi.exe" => "Vivaldi",
        "arc.exe" => "Arc",
        "msedgewebview2.exe" => "an app's built-in web view (Edge WebView2)",
        _ => return None,
    })
}

#[cfg(windows)]
pub fn read() -> Vec<Use> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;
    const BASE: &str = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
    let hk = RegKey::predef(HKEY_CURRENT_USER);
    let mut out = Vec::new();
    for (kind, sub) in [("camera", "webcam"), ("microphone", "microphone")] {
        let Ok(k) = hk.open_subkey_with_flags(format!(r"{BASE}\{sub}"), KEY_READ) else { continue };
        let times = |key: &RegKey| -> (u64, u64) {
            let s: u64 = key.get_value("LastUsedTimeStart").unwrap_or(0);
            let e: u64 = key.get_value("LastUsedTimeStop").unwrap_or(0);
            (filetime_ms(s), filetime_ms(e))
        };
        for name in k.enum_keys().flatten() {
            let Ok(app) = k.open_subkey_with_flags(&name, KEY_READ) else { continue };
            if name == "NonPackaged" {
                for exe in app.enum_keys().flatten() {
                    if let Ok(x) = app.open_subkey_with_flags(&exe, KEY_READ) {
                        let (start, stop) = times(&x);
                        if start > 0 {
                            out.push(Use { kind, app: key_to_path(&exe), packaged: false, start, stop });
                        }
                    }
                }
            } else {
                let (start, stop) = times(&app);
                if start > 0 {
                    out.push(Use { kind, app: name, packaged: true, start, stop });
                }
            }
        }
    }
    out
}

#[cfg(not(windows))]
pub fn read() -> Vec<Use> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_times() {
        assert_eq!(key_to_path("C:#Program Files#TeamViewer#TeamViewer.exe"), r"C:\Program Files\TeamViewer\TeamViewer.exe");
        // 2026-03-21 per the user's registry: a FILETIME in the 2020s maps to ms in the 2020s.
        let ms = filetime_ms(134_322_628_248_926_968);
        assert!(ms > 1_700_000_000_000 && ms < 1_900_000_000_000, "{ms}");
        assert_eq!(filetime_ms(0), 0);
        let u = Use { kind: "camera", app: "Microsoft.WindowsCamera_8wekyb3d8bbwe".into(), packaged: true, start: 1, stop: 0 };
        assert_eq!(label(&u), "WindowsCamera");
        assert!(u.active());
        assert!(expected("zoom.exe") && !expected("updater.exe"));
        assert_eq!(browser("chrome.exe"), Some("Google Chrome"));
        assert_eq!(browser("zoom.exe"), None);
    }
}

#[cfg(test)]
mod live {
    /// Run by hand: reads this user's camera / microphone record (read-only).
    #[test]
    #[ignore]
    fn live_consent_store() {
        let u = super::read();
        for x in &u {
            println!("{:10} {:5} start={} stop={} {}", x.kind, x.packaged, x.start, x.stop, x.app);
        }
        assert!(u.iter().all(|x| x.start > 1_500_000_000_000));
    }
}
