//! Clipboard guard: catches "clipper" malware, which watches the clipboard and swaps a
//! copied crypto-wallet address or bank account number (IBAN) for the attacker's own, so
//! the payment you paste goes to them. Microsoft reported one in 2026 (CryptoBandits) that
//! checks the clipboard every 500 ms and makes its address look like the copied one.
//!
//! How: Windows tells Kestryl about every clipboard change (AddClipboardFormatListener).
//! Kestryl only looks at short text and only asks "is this a wallet address or IBAN?".
//! It keeps nothing but a fingerprint and a masked form ("bc1qxy…f4kq") for 3 seconds, and
//! skips anything a password manager marks as private. Two signals raise an alert:
//! - swap: an address was copied and, within 3 s, a different address of the same kind
//!   replaced it, put there by another program;
//! - background: an address was put on the clipboard by an unsigned or risky program that
//!   was not the window you were using.

use crate::engine::{lock, Shared};
use crate::util::*;

/// What kind of payment detail a piece of text is, if any.
pub fn kind(s: &str) -> Option<&'static str> {
    let t = s.trim();
    if t.is_empty() || t.len() > 120 {
        return None;
    }
    const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const BECH: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let b58 = |x: &str| !x.is_empty() && x.chars().all(|c| B58.contains(c));
    let len = t.chars().count();
    let lower = t.to_ascii_lowercase();
    if let Some(h) = t.strip_prefix("0x") {
        if h.len() == 40 && h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some("Ethereum-type wallet address");
        }
    }
    for (pre, name) in [("bc1", "Bitcoin address"), ("ltc1", "Litecoin address")] {
        if let Some(rest) = lower.strip_prefix(pre) {
            if (t == lower || t == t.to_ascii_uppercase()) && (11..=71).contains(&rest.len()) && rest.chars().all(|c| BECH.contains(c)) {
                return Some(name);
            }
        }
    }
    if t.contains(char::is_whitespace) {
        // IBANs are often written in groups of four.
        let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        return if iban_ok(&compact) { Some("bank account number (IBAN)") } else { None };
    }
    if iban_ok(t) {
        return Some("bank account number (IBAN)");
    }
    if (t.starts_with("EQ") || t.starts_with("UQ")) && len == 48 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Some("TON wallet address");
    }
    if !b58(t) {
        return None;
    }
    // Base58 alphabets: the first character tells the coin.
    let first = t.chars().next().unwrap_or(' ');
    match (first, len) {
        ('1' | '3', 26..=35) => Some("Bitcoin address"),
        ('T', 34) => Some("Tron (USDT) wallet address"),
        ('D', 34) => Some("Dogecoin address"),
        ('L' | 'M', 26..=34) => Some("Litecoin address"),
        ('r', 25..=35) => Some("XRP address"),
        ('4' | '8', 95 | 106) => Some("Monero address"),
        // Solana: any 32-44 character base58 string with both cases and digits.
        (_, 32..=44) if t.chars().any(|c| c.is_ascii_digit()) && t.chars().any(|c| c.is_ascii_uppercase()) && t.chars().any(|c| c.is_ascii_lowercase()) => {
            Some("Solana wallet address")
        }
        _ => None,
    }
}

/// IBAN: country letters, check digits, 11-30 letters/digits, and the mod-97 check.
fn iban_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if !(15..=34).contains(&b.len()) || !b[..2].iter().all(u8::is_ascii_uppercase) || !b[2..4].iter().all(u8::is_ascii_digit) {
        return false;
    }
    if !b[4..].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return false;
    }
    let mut r: u64 = 0;
    for &c in b[4..].iter().chain(&b[..4]) {
        let v = if c.is_ascii_digit() { (c - b'0') as u64 } else { (c - b'A' + 10) as u64 };
        r = if v >= 10 { (r * 100 + v) % 97 } else { (r * 10 + v) % 97 };
    }
    r == 1
}

/// "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" -> "bc1qxy…0wlh".
pub fn mask(s: &str) -> String {
    let t: String = s.trim().chars().filter(|c| !c.is_whitespace()).collect();
    let n = t.chars().count();
    if n <= 12 {
        return t;
    }
    let head: String = t.chars().take(6).collect();
    let tail: String = t.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

/// One clipboard change that held a payment detail.
#[derive(Clone, Debug)]
pub struct Seen {
    pub t: u64,
    pub kind: &'static str,
    pub hash: u64,
    pub masked: String,
    /// Program that put it there (0 = it did not say), and its file.
    pub owner: u32,
    pub owner_exe: String,
    /// Program whose window you were using at that moment.
    pub fg: u32,
}

/// Windows programs that legitimately put other programs' text on the clipboard.
pub fn relay_tool(name: &str) -> bool {
    matches!(
        name,
        "rdpclip.exe" | "textinputhost.exe" | "explorer.exe" | "applicationframehost.exe" | "vmtoolsd.exe" | "vboxtray.exe"
            | "ditto.exe" | "clipclip.exe" | "keepass.exe" | "keepassxc.exe" | "1password.exe" | "bitwarden.exe" | "anydesk.exe"
            | "teamviewer.exe" | "parsecd.exe" | "phoneexperiencehost.exe" | "msrdc.exe" | "mstsc.exe"
    )
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::sync::OnceLock;
    use windows::core::w;
    use windows::Win32::Foundation::{HGLOBAL, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::DataExchange::{
        AddClipboardFormatListener, CloseClipboard, GetClipboardData, GetClipboardOwner, IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetForegroundWindow, GetMessageW, GetWindowThreadProcessId, RegisterClassW, HWND_MESSAGE, MSG,
        WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLIPBOARDUPDATE, WNDCLASSW,
    };

    static ENG: OnceLock<Shared> = OnceLock::new();
    const CF_UNICODETEXT: u32 = 13;

    fn pid_of(h: HWND) -> u32 {
        if h.0.is_null() {
            return 0;
        }
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(h, Some(&mut pid)) };
        pid
    }

    /// The clipboard's text if it is short and not marked private; (text, owner pid).
    fn read() -> Option<(String, u32)> {
        unsafe {
            IsClipboardFormatAvailable(CF_UNICODETEXT).ok()?;
            // Password managers add this format to say "don't look"; respected.
            let private = RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing"));
            if private != 0 && IsClipboardFormatAvailable(private).is_ok() {
                return None;
            }
            let owner = GetClipboardOwner().map(pid_of).unwrap_or(0);
            // Another program may hold the clipboard for a moment.
            let mut opened = false;
            for _ in 0..5 {
                if OpenClipboard(None).is_ok() {
                    opened = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            if !opened {
                return None;
            }
            let text = (|| {
                let h = GetClipboardData(CF_UNICODETEXT).ok()?;
                let g = HGLOBAL(h.0);
                let size = GlobalSize(g);
                if size == 0 || size > 512 {
                    return None; // longer than any address: not read at all
                }
                let p = GlobalLock(g) as *const u16;
                if p.is_null() {
                    return None;
                }
                let n = size / 2;
                let slice = std::slice::from_raw_parts(p, n);
                let end = slice.iter().position(|&c| c == 0).unwrap_or(n);
                let s = String::from_utf16_lossy(&slice[..end]);
                let _ = GlobalUnlock(g);
                Some(s)
            })();
            let _ = CloseClipboard();
            text.map(|t| (t, owner))
        }
    }

    unsafe extern "system" fn wndproc(h: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        if msg == WM_CLIPBOARDUPDATE {
            let fg = pid_of(GetForegroundWindow());
            if let (Some(eng), Some((text, owner))) = (ENG.get(), read()) {
                if let Some(k) = kind(&text) {
                    let s = Seen { t: now_ms(), kind: k, hash: fnv(text.trim()), masked: mask(&text), owner, owner_exe: exe_of_pid(owner), fg };
                    lock(eng).on_clipboard(s);
                }
            }
            return LRESULT(0);
        }
        DefWindowProcW(h, msg, wp, lp)
    }

    /// Runs on its own thread for as long as Kestryl runs.
    pub fn listen(eng: Shared) -> Result<(), String> {
        let _ = ENG.set(eng);
        unsafe {
            let hinst: HINSTANCE = GetModuleHandleW(None).map_err(|e| e.to_string())?.into();
            let class = w!("KestrylClipboardGuard");
            let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: hinst, lpszClassName: class, ..Default::default() };
            RegisterClassW(&wc);
            let hwnd = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!(""), WINDOW_STYLE(0), 0, 0, 0, 0, Some(HWND_MESSAGE), None, Some(hinst), None)
                .map_err(|e| e.to_string())?;
            AddClipboardFormatListener(hwnd).map_err(|e| e.to_string())?;
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                DispatchMessageW(&msg);
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use win::listen;
#[cfg(not(windows))]
pub fn listen(_eng: Shared) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_details() {
        assert_eq!(kind("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"), Some("Bitcoin address"));
        assert_eq!(kind("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"), Some("Bitcoin address"));
        assert_eq!(kind("0x71C7656EC7ab88b098defB751B7401B5f6d8976F"), Some("Ethereum-type wallet address"));
        assert_eq!(kind("TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"), Some("Tron (USDT) wallet address"));
        assert_eq!(kind("DE89 3704 0044 0532 0130 00"), Some("bank account number (IBAN)"));
        assert_eq!(kind("GB82WEST12345698765432"), Some("bank account number (IBAN)"));
        assert_eq!(kind("GB82WEST12345698765433"), None, "IBAN with a wrong check digit");
        assert_eq!(kind("hello world"), None);
        assert_eq!(kind("https://example.com/path"), None);
        assert_eq!(kind("0x1234"), None);
        assert_eq!(kind("ThisIsJustAVeryLongCamelCaseWordWithoutDigits"), None);
        assert_eq!(mask("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"), "bc1qxy…0wlh");
        assert_eq!(mask("DE89 3704 0044 0532 0130 00"), "DE8937…3000");
    }
}
