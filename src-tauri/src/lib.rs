mod analytics;
mod audit;
mod away;
mod clip;
mod collect;
mod config;
mod decrypt;
mod detect;
mod engine;
mod firewall;
mod geo;
mod history;
mod intel;
mod ipinfo;
mod origin;
mod peek;
mod scan;
mod sensors;
mod util;

use engine::{lock, Adapter, Alert, Engine, Shared, SigInfo};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use util::*;

struct AppState {
    eng: Shared,
}

type Res<T> = Result<T, String>;

async fn bg<T: Send + 'static>(f: impl FnOnce() -> Res<T> + Send + 'static) -> Res<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

fn need_admin(eng: &Shared) -> Res<()> {
    if lock(eng).elevated {
        Ok(())
    } else {
        Err("Blocking changes Windows Firewall, which needs administrator rights. Use \"Restart as administrator\" at the top.".into())
    }
}

fn persist(eng: &Shared) {
    let (alerts, cfg, today, done, away_r) = {
        let mut e = lock(eng);
        if e.sim {
            return; // the --simulate demo never touches real data
        }
        e.hist_dirty = false;
        e.away_dirty = false;
        let done = std::mem::take(&mut e.done_days);
        let away_r: Vec<away::Report> = e.away_reports.iter().cloned().collect();
        (e.alerts.iter().filter(|a| !a.sim).cloned().collect::<Vec<_>>(), e.take_cfg_for_save(), e.today.clone(), done, away_r)
    };
    config::save_alerts(&alerts);
    config::save(&cfg);
    away::save(&away_r);
    for d in &done {
        history::save(d);
    }
    history::save(&today);
}

// ------------------------------------------------------------------ read-only views

#[tauri::command]
fn snapshot(st: State<AppState>) -> Value {
    lock(&st.eng).snapshot(now_ms())
}

#[tauri::command]
fn flows(st: State<AppState>, pid: Option<u32>) -> Value {
    lock(&st.eng).flow_rows(pid)
}

#[tauri::command]
fn alerts(st: State<AppState>) -> Value {
    serde_json::to_value(&lock(&st.eng).alerts).unwrap_or(Value::Null)
}

#[tauri::command]
fn dns(st: State<AppState>) -> Value {
    lock(&st.eng).dns_rows()
}

#[tauri::command]
fn network(st: State<AppState>) -> Value {
    lock(&st.eng).network_rows()
}

#[tauri::command]
async fn network_extra() -> Res<Value> {
    bg(firewall::network_extra).await
}

#[tauri::command]
async fn rules(st: State<'_, AppState>) -> Res<Value> {
    let v = bg(firewall::list).await?;
    let ids: Vec<String> = v["rules"].as_array().map(|a| a.iter().filter_map(|r| r["id"].as_str().map(String::from)).collect()).unwrap_or_default();
    let mut e = lock(&st.eng);
    e.fw_check(now_ms(), ids);
    e.set_blocks(&v);
    Ok(v)
}

#[tauri::command]
fn status(st: State<AppState>) -> Value {
    lock(&st.eng).status(now_ms())
}

/// Runs the security check now (a few seconds) and returns the new status.
#[tauri::command]
async fn audit_now(st: State<'_, AppState>) -> Res<Value> {
    let eng = st.eng.clone();
    bg(move || {
        run_audit(&eng);
        Ok(())
    })
    .await?;
    Ok(lock(&st.eng).status(now_ms()))
}

#[tauri::command]
fn history_days(st: State<AppState>) -> Value {
    let e = lock(&st.eng);
    let mut extra: Vec<history::Day> = e.done_days.clone();
    extra.extend(e.sim_days.iter().cloned());
    Value::Array(history::list(&e.today, &extra, !e.sim))
}

#[tauri::command]
fn history_day(st: State<AppState>, day: String) -> Res<Value> {
    let e = lock(&st.eng);
    if day == e.today.day {
        return Ok(history::view(&e.today));
    }
    if let Some(d) = e.sim_days.iter().chain(e.done_days.iter()).find(|d| d.day == day) {
        return Ok(history::view(d));
    }
    let sim = e.sim;
    drop(e);
    if sim || day.len() != 10 || day_number(&day).is_none() {
        return Err("No history for that day.".into());
    }
    history::load(&day).map(|d| history::view(&d)).ok_or_else(|| "No history for that day.".into())
}

#[tauri::command]
fn ack_startup(st: State<AppState>, key: String, on: bool) -> Res<String> {
    lock(&st.eng).ack_startup(&key, on);
    Ok(if on { "Marked as yours. It no longer counts as a risk; a change to it would be reported again.".into() } else { "Unmarked.".into() })
}

#[tauri::command]
fn proc_extra(st: State<AppState>, pid: u32) -> Value {
    lock(&st.eng).proc_extra(pid)
}

/// A short packet capture of one connection, explained.
#[tauri::command]
async fn peek(st: State<'_, AppState>, ip: String, port: Option<u16>, secs: u64) -> Res<Value> {
    let (sim, elevated) = {
        let e = lock(&st.eng);
        (e.sim, e.elevated)
    };
    if sim {
        let secs = secs.min(3);
        return bg(move || {
            std::thread::sleep(Duration::from_secs(secs));
            Ok(peek::demo(&ip, port))
        })
        .await;
    }
    if !elevated {
        return Err("Peek uses Windows' packet capture, which needs administrator rights. Use \"Restart as administrator\" at the top.".into());
    }
    bg(move || peek::capture(&ip, port, secs.clamp(5, 60))).await
}

#[tauri::command]
fn set_file_watch(st: State<AppState>, on: bool) -> Res<String> {
    let eng = st.eng.clone();
    let live = {
        let mut e = lock(&eng);
        e.cfg.file_watch = on;
        e.dirty_cfg = true;
        e.mode == "full" && !e.sim
    };
    if !live {
        return Ok(if on { "Saved. File monitoring starts with full monitoring (administrator).".into() } else { "File monitoring is off.".into() });
    }
    if on {
        match collect::start_files(&eng) {
            Ok(()) => {
                let mut e = lock(&eng);
                e.health.files = Some(true);
                e.health.files_error.clear();
                Ok("File monitoring is on.".into())
            }
            Err(err) => {
                lock(&eng).health.files_error = err.clone();
                Err(format!("File monitoring could not start: {err}"))
            }
        }
    } else {
        collect::stop_files();
        lock(&eng).health.files = None;
        Ok("File monitoring is off.".into())
    }
}

#[tauri::command]
async fn ip_info(st: State<'_, AppState>, ip: String) -> Res<Value> {
    let ip2 = ip.clone();
    let sim = lock(&st.eng).sim;
    let mut v = if sim { ipinfo::demo(&ip2)? } else { bg(move || ipinfo::lookup(&ip2)).await? };
    if let Ok(addr) = ip.trim().parse() {
        v["seen"] = lock(&st.eng).ip_usage(addr);
    }
    Ok(v)
}

#[tauri::command]
fn settings(st: State<AppState>) -> Value {
    let e = lock(&st.eng);
    json!({
        "upload_mb": e.cfg.upload_mb, "popups": e.cfg.popups, "popup_min": e.cfg.popup_min, "theme": e.cfg.theme,
        "trusted": e.cfg.trusted, "muted": e.cfg.muted, "trusted_dests": e.cfg.trusted_dests,
        "data_dir": config::dir().display().to_string(),
        "exe": std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default(),
        "elevated": e.elevated, "stats": e.stats, "mode": e.mode, "etw_error": e.etw_error,
        "file_watch": e.cfg.file_watch, "health": e.health,
        "abuse_key_set": !e.cfg.abuse_key.is_empty(), "intel": e.intel.lists, "intel_demo": e.intel.demo,
        "scans": e.scans.values().filter(|s| s.state != "running").count(),
        "advanced": e.cfg.advanced, "clip_guard": e.cfg.clip_guard, "geo": e.geo.info(), "home": e.home,
        "sim": e.sim,
    })
}

// ------------------------------------------------------------------ simple / advanced, clipboard, places

#[tauri::command]
fn set_view(st: State<AppState>, advanced: bool) {
    let mut e = lock(&st.eng);
    e.cfg.advanced = advanced;
    e.dirty_cfg = true;
}

#[tauri::command]
fn set_clip_guard(st: State<AppState>, on: bool) -> Res<String> {
    let mut e = lock(&st.eng);
    e.cfg.clip_guard = on;
    e.dirty_cfg = true;
    Ok(if on { "Clipboard guard is on.".into() } else { "Clipboard guard is off.".into() })
}

/// "Where my data went" for a day: per country and per company.
#[tauri::command]
fn data_map(st: State<AppState>, day: Option<String>) -> Res<Value> {
    let e = lock(&st.eng);
    let d = match day.filter(|d| *d != e.today.day) {
        None => e.today.clone(),
        Some(d) => match e.sim_days.iter().chain(e.done_days.iter()).find(|x| x.day == d) {
            Some(x) => x.clone(),
            None if !e.sim && d.len() == 10 && day_number(&d).is_some() => history::load(&d).ok_or("No history for that day.")?,
            None => return Err("No history for that day.".into()),
        },
    };
    let mut v = geo::data_map(&e.geo, &d);
    v["home"] = json!(e.home);
    v["geo"] = e.geo.info();
    Ok(v)
}

#[tauri::command]
fn geo_refresh(st: State<AppState>) -> Res<String> {
    if lock(&st.eng).sim {
        return Ok("Simulation: the demo uses made-up places.".into());
    }
    geo::REFRESH_NOW.store(true, Ordering::Relaxed);
    Ok("Downloading the country and company data (about 12 MB).".into())
}

// ------------------------------------------------------------------ analytics blocking

#[tauri::command]
fn analytics_list(st: State<AppState>) -> Value {
    analytics::list(&lock(&st.eng).cfg.analytics)
}

#[tauri::command]
async fn set_analytics(st: State<'_, AppState>, id: String, on: bool) -> Res<String> {
    let eng = st.eng.clone();
    if lock(&eng).sim {
        let mut e = lock(&eng);
        if on {
            e.cfg.analytics.insert(id, config::AnalyticsState { on: true, t: now_ms(), ..Default::default() });
        } else {
            e.cfg.analytics.remove(&id);
        }
        return Ok("Simulation: shown as changed, but nothing in Windows was touched.".into());
    }
    need_admin(&eng)?;
    if id == analytics::SERVERS_ID {
        return block_servers(eng, on).await;
    }
    let it = analytics::item(&id).ok_or("Unknown item.")?;
    if on {
        if lock(&eng).cfg.analytics.get(&id).is_some_and(|s| s.on) {
            return Ok(format!("{} is already blocked.", it.name));
        }
        let (backup, errs) = bg(move || analytics::apply(it)).await?;
        let mut e = lock(&eng);
        e.cfg.analytics.insert(id, config::AnalyticsState { on: true, t: now_ms(), backup, errors: errs.clone() });
        e.dirty_cfg = true;
        Ok(if errs.is_empty() {
            format!("{}: analytics off. Undo any time with the same switch.", it.name)
        } else {
            format!("{}: mostly done, but {} setting(s) could not be changed: {}", it.name, errs.len(), errs.join("; "))
        })
    } else {
        let backup = lock(&eng).cfg.analytics.get(&id).map(|s| s.backup.clone()).unwrap_or(Value::Null);
        let out = bg(move || analytics::restore(it, &backup)).await?;
        let mut e = lock(&eng);
        e.cfg.analytics.remove(&id);
        e.fw_forget(&analytics::fw_id(it.id));
        e.dirty_cfg = true;
        Ok(if out.trim().is_empty() { format!("{}: back to how it was.", it.name) } else { format!("{}: restored, with problems: {out}", it.name) })
    }
}

/// The firewall part of analytics blocking: one rule per collector domain (kind "tracker"),
/// kept up to date with new addresses like any blocked site.
async fn block_servers(eng: Shared, on: bool) -> Res<String> {
    if on {
        let made = bg(|| {
            use std::net::ToSocketAddrs;
            let mut made = Vec::new();
            for (domain, probes) in analytics::SERVERS {
                let mut ips: Vec<String> = probes
                    .iter()
                    .filter_map(|h| (*h, 443).to_socket_addrs().ok())
                    .flatten()
                    .map(|a| norm_ip(a.ip()))
                    .filter(|ip| scope(ip) == Scope::Internet)
                    .map(|ip| ip.to_string())
                    .collect();
                ips.sort();
                ips.dedup();
                let id = firewall::rule_id("tracker", domain);
                if !ips.is_empty() {
                    firewall::block_ips("tracker", domain, &ips)?;
                }
                made.push(config::DomainBlock { domain: domain.to_string(), id, ips, tracker: true });
            }
            Ok(made)
        })
        .await?;
        let mut e = lock(&eng);
        e.cfg.domain_blocks.retain(|b| !b.tracker);
        let n = made.len();
        e.cfg.domain_blocks.extend(made);
        e.cfg.analytics.insert(analytics::SERVERS_ID.into(), config::AnalyticsState { on: true, t: now_ms(), ..Default::default() });
        e.dirty_cfg = true;
        Ok(format!("{n} analytics services are blocked for every program. New addresses are added as they show up."))
    } else {
        let ids: Vec<String> = lock(&eng).cfg.domain_blocks.iter().filter(|b| b.tracker).map(|b| b.id.clone()).collect();
        bg(move || {
            for id in ids {
                let _ = firewall::remove(&id);
            }
            Ok(())
        })
        .await?;
        let mut e = lock(&eng);
        e.cfg.domain_blocks.retain(|b| !b.tracker);
        e.cfg.analytics.remove(analytics::SERVERS_ID);
        e.fw_forget("Kestryl-tracker-");
        e.dirty_cfg = true;
        Ok("Analytics servers are no longer blocked.".into())
    }
}

// ------------------------------------------------------------------ HTTPS decryption

#[tauri::command]
fn decrypt_state(st: State<AppState>) -> Value {
    let e = lock(&st.eng);
    json!({ "set": !e.cfg.decrypt.hash.is_empty(), "locked_until": e.cfg.decrypt.locked_until, "session": decrypt::current(),
            "elevated": e.elevated, "sim": e.sim, "max": decrypt::MAX_MIN, "now": now_ms() })
}

fn wrong_password(e: &mut engine::Engine, msg: &str) {
    let locked = msg.contains("locked");
    e.raise_sys(
        now_ms(),
        detect::Finding {
            rule: "decrypt_password",
            sev: if locked { 2 } else { 1 },
            title: if locked { "HTTPS decryption locked after wrong passwords".into() } else { "Wrong HTTPS decryption password entered".into() },
            why: "Someone tried to use HTTPS decryption with the wrong password. If that was not you, someone else is using this PC: change the decryption password in Kestryl (Decrypt page) and your Windows password.".into(),
            group: "decrypt-pw".into(),
        },
        "Kestryl",
    );
}

#[tauri::command]
fn decrypt_set_password(st: State<AppState>, old: String, new: String) -> Res<String> {
    let mut e = lock(&st.eng);
    if !e.elevated && !e.sim {
        return Err("Setting the decryption password needs administrator rights. Use \"Restart as administrator\" at the top.".into());
    }
    let had = !e.cfg.decrypt.hash.is_empty();
    if had {
        let r = decrypt::check_password(&mut e.cfg.decrypt, &old, now_ms());
        e.dirty_cfg = true;
        if let Err(m) = r {
            wrong_password(&mut e, &m);
            return Err(m);
        }
    }
    decrypt::password_rules(&new)?;
    e.cfg.decrypt.hash = decrypt::hash_password(&new)?;
    e.dirty_cfg = true;
    let now = now_ms();
    e.raise_sys(
        now,
        detect::Finding {
            rule: "decrypt_password",
            sev: 1,
            title: if had { "The HTTPS decryption password was changed".into() } else { "An HTTPS decryption password was set".into() },
            why: "Whoever knows this password (and has administrator rights) can read what a program sends inside its encrypted connections, one program at a time, for up to 30 minutes, with a red banner shown. If this was not you, change it.".into(),
            group: format!("pw{now}"),
        },
        "Kestryl",
    );
    Ok(if had { "Password changed.".into() } else { "Password set. Keep it to yourself: it is the key to HTTPS decryption.".into() })
}

#[tauri::command]
async fn decrypt_start(st: State<'_, AppState>, exe: String, name: String, minutes: u64, password: String) -> Res<Value> {
    let eng = st.eng.clone();
    {
        let mut e = lock(&eng);
        if !e.sim && !e.elevated {
            return Err("HTTPS decryption needs administrator rights. Use \"Restart as administrator\" at the top.".into());
        }
        if e.is_own_exe(&exe.to_lowercase()) {
            return Err("Kestryl does not decrypt itself.".into());
        }
        let r = decrypt::check_password(&mut e.cfg.decrypt, &password, now_ms());
        e.dirty_cfg = true;
        if let Err(m) = r {
            wrong_password(&mut e, &m);
            return Err(m);
        }
    }
    let e2 = eng.clone();
    let (exe2, name2) = (exe.clone(), name.clone());
    let info = bg(move || decrypt::start(&e2, &exe2, &name2, minutes)).await?;
    let mins = (info.until - info.start) / 60_000;
    lock(&eng).raise_sys(
        now_ms(),
        detect::Finding {
            rule: "decrypt_session",
            sev: 1,
            title: format!("HTTPS decryption started for {name} ({mins} min)"),
            why: format!("Kestryl is reading what {name} sends inside its encrypted connections until {mins} minutes from the start, through a temporary certificate that is removed afterwards. Other programs are not decrypted. Started with the decryption password; if this was not you, press Stop on the Decrypt page and change the password."),
            group: format!("dec{}", info.id),
        },
        "Kestryl",
    );
    Ok(json!(info))
}

fn end_session(eng: &Shared, why: &str) -> Option<decrypt::Info> {
    let info = decrypt::stop(eng)?;
    lock(eng).raise_sys(
        now_ms(),
        detect::Finding {
            rule: "decrypt_session",
            sev: 1,
            title: format!("HTTPS decryption ended for {} ({why})", info.name),
            why: "The temporary certificate was removed from Windows and the proxy setting put back. What was recorded stays visible on the Decrypt page until you clear it or quit Kestryl; it is never saved to disk.".into(),
            group: format!("dec-end{}", info.id),
        },
        "Kestryl",
    );
    Some(info)
}

#[tauri::command]
async fn decrypt_stop(st: State<'_, AppState>) -> Res<String> {
    let eng = st.eng.clone();
    let ended = bg(move || Ok(end_session(&eng, "stopped"))).await?;
    Ok(if ended.is_some() { "Stopped. The temporary certificate is gone and your proxy setting is back.".into() } else { "No session was running.".into() })
}

/// Recorded requests; with the password, passwords, cookies and tokens are shown too.
#[tauri::command]
fn decrypt_entries(st: State<AppState>, password: Option<String>) -> Res<Value> {
    let reveal = match password {
        Some(pw) => {
            let mut e = lock(&st.eng);
            let r = decrypt::check_password(&mut e.cfg.decrypt, &pw, now_ms());
            e.dirty_cfg = true;
            if let Err(m) = r {
                wrong_password(&mut e, &m);
                return Err(m);
            }
            true
        }
        None => false,
    };
    Ok(decrypt::entries(reveal))
}

#[tauri::command]
fn decrypt_clear() {
    decrypt::clear_log();
}

// ------------------------------------------------------------------ threat lists, scans

#[tauri::command]
fn intel_refresh(st: State<AppState>) -> Res<String> {
    if lock(&st.eng).sim {
        return Ok("Simulation: the demo uses made-up lists and downloads nothing.".into());
    }
    intel::REFRESH_NOW.store(true, Ordering::Relaxed);
    Ok("Downloading the threat lists. This takes a few seconds.".into())
}

#[tauri::command]
fn set_abuse_key(st: State<AppState>, key: String) -> Res<String> {
    let key = key.trim().to_string();
    if !key.is_empty() && (key.len() < 16 || key.len() > 128 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')) {
        return Err("That does not look like an abuse.ch Auth-Key (letters and digits, from auth.abuse.ch → Optional → API keys).".into());
    }
    let mut e = lock(&st.eng);
    e.cfg.abuse_key = key.clone();
    e.dirty_cfg = true;
    intel::REFRESH_NOW.store(true, Ordering::Relaxed);
    Ok(if key.is_empty() { "Key removed. ThreatFox is no longer used.".into() } else { "Saved. Downloading ThreatFox now.".into() })
}

/// Hash + Microsoft Defender scan of one program file, now.
#[tauri::command]
async fn scan_file(st: State<'_, AppState>, path: String) -> Res<Value> {
    if path.trim().is_empty() {
        return Err("This process has no file path.".into());
    }
    let sim = lock(&st.eng).sim;
    let p2 = path.clone();
    let r = if sim { scan::demo(&path) } else { bg(move || Ok(scan::run(&p2))).await? };
    lock(&st.eng).on_scan(now_ms(), &path, r.clone());
    Ok(json!(r))
}

/// Opens the file's VirusTotal page in the browser: only the SHA-256 is sent, and only on click.
#[tauri::command]
fn open_virustotal(sha256: String) -> Res<()> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Not a SHA-256 hash.".into());
    }
    let mut cmd = std::process::Command::new(windows_dir().join("explorer.exe"));
    cmd.arg(format!("https://www.virustotal.com/gui/file/{}", sha256.to_lowercase()));
    own_spawn(&mut cmd).map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ alerts

#[tauri::command]
fn alert_read(st: State<AppState>, id: Option<u64>) {
    let mut e = lock(&st.eng);
    for a in e.alerts.iter_mut().filter(|a| id.is_none_or(|i| a.id == i)) {
        a.read = true;
    }
    e.dirty_alerts = true;
}

#[tauri::command]
fn alert_dismiss(st: State<AppState>, id: Option<u64>) {
    let mut e = lock(&st.eng);
    match id {
        Some(i) => e.alerts.retain(|a| a.id != i),
        None => e.alerts.clear(),
    }
    e.dirty_alerts = true;
}

/// Removes every alert of one kind (e.g. after a flood of the same alert).
#[tauri::command]
fn alert_dismiss_rule(st: State<AppState>, rule: String) -> Res<String> {
    let mut e = lock(&st.eng);
    let before = e.alerts.len();
    e.alerts.retain(|a| a.rule != rule);
    e.dirty_alerts = true;
    let n = before - e.alerts.len();
    Ok(format!("Dismissed {n} alert{}.", if n == 1 { "" } else { "s" }))
}

#[tauri::command]
fn trust(st: State<AppState>, exe_key: String, on: bool) -> Res<String> {
    let key = exe_key.to_lowercase();
    if key.is_empty() {
        return Err("Nothing to trust.".into());
    }
    let mut e = lock(&st.eng);
    e.cfg.trusted.retain(|t| *t != key);
    e.cfg.trusted_fp.remove(&key); // recorded again from the file as it is now
    e.trust_broken.remove(&key);
    if on {
        e.cfg.trusted.push(key.clone());
        for a in e.alerts.iter_mut() {
            let k = if a.exe.is_empty() { a.name.to_lowercase() } else { a.exe.to_lowercase() };
            if k == key {
                a.read = true;
            }
        }
        e.dirty_alerts = true;
    }
    e.dirty_cfg = true;
    let name = std::path::Path::new(&key).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or(key);
    Ok(if on {
        format!("{name} is trusted: its traffic is still shown but raises no alerts.")
    } else {
        format!("{name} is no longer trusted.")
    })
}

/// Trust an IP, range or domain. `site` widens a host name to its whole site (cdn.x.com -> x.com).
#[tauri::command]
fn trust_dest(st: State<AppState>, target: String, site: bool) -> Res<String> {
    let raw = target.trim().to_lowercase();
    let entry = match parse_net(&raw) {
        Some((ip, len)) if len == if ip.is_ipv4() { 32 } else { 128 } => ip.to_string(),
        Some((ip, len)) => format!("{ip}/{len}"),
        None => {
            let d = firewall::clean_domain(&raw).ok_or_else(|| format!("\"{}\" is not a domain, IP address or range.", target.trim()))?;
            if site { base_domain(&d) } else { d }
        }
    };
    let mut e = lock(&st.eng);
    if !e.cfg.trusted_dests.iter().any(|t| t.target == entry) {
        e.cfg.trusted_dests.push(config::TrustedDest { target: entry.clone(), show: false });
    }
    e.rebuild_trust();
    e.dirty_cfg = true;
    let what = if parse_net(&entry).is_some() { entry } else { format!("{entry} (and its subdomains)") };
    Ok(format!("Trusted {what}. Its traffic is hidden and never alerted; Settings has a Show traffic switch."))
}

#[tauri::command]
fn untrust_dest(st: State<AppState>, target: String) -> Res<String> {
    let mut e = lock(&st.eng);
    e.cfg.trusted_dests.retain(|t| t.target != target);
    e.rebuild_trust();
    e.dirty_cfg = true;
    Ok(format!("{target} is no longer trusted."))
}

#[tauri::command]
fn set_dest_show(st: State<AppState>, target: String, show: bool) -> Res<String> {
    let mut e = lock(&st.eng);
    let t = e.cfg.trusted_dests.iter_mut().find(|t| t.target == target).ok_or("Not in the trusted list.")?;
    t.show = show;
    e.rebuild_trust();
    e.dirty_cfg = true;
    Ok(if show { format!("Showing traffic to {target}.") } else { format!("Hiding traffic to {target}.") })
}

#[tauri::command]
fn mute(st: State<AppState>, rule: String, on: bool) -> Res<String> {
    let mut e = lock(&st.eng);
    e.cfg.muted.retain(|r| *r != rule);
    if on {
        e.cfg.muted.push(rule.clone());
    }
    e.dirty_cfg = true;
    Ok(if on { "This kind of alert is muted.".into() } else { "Alert type un-muted.".into() })
}

#[tauri::command]
fn set_theme(app: AppHandle, st: State<AppState>, theme: String) -> Res<()> {
    if !matches!(theme.as_str(), "dark" | "light" | "kestryl" | "system") {
        return Err("Unknown theme.".into());
    }
    let mut e = lock(&st.eng);
    e.cfg.theme = theme.clone();
    e.dirty_cfg = true;
    let _ = app.emit_to("toast", "theme", theme);
    Ok(())
}

#[tauri::command]
fn save_settings(st: State<AppState>, upload_mb: u64, popups: bool, popup_min: u8) -> Res<String> {
    let mut e = lock(&st.eng);
    e.cfg.upload_mb = upload_mb.clamp(1, 10_000);
    e.cfg.popups = popups;
    e.cfg.popup_min = popup_min.clamp(1, 3);
    e.dirty_cfg = true;
    Ok("Saved.".into())
}

// ------------------------------------------------------------------ actions

fn is_sim(eng: &Shared, pid: Option<u32>) -> bool {
    pid.is_some_and(|p| lock(eng).procs.get(&p).is_some_and(|i| i.sim))
}

async fn do_block_app(eng: Shared, exe: String, pid: Option<u32>) -> Res<String> {
    if is_sim(&eng, pid) {
        return Err("That is a simulated program from --simulate; there is nothing real to block.".into());
    }
    need_admin(&eng)?;
    let exe2 = exe.clone();
    let mut msg = bg(move || firewall::block_app(&exe2)).await?;
    // Every running copy of the program, not only the one the button was on.
    let pids = {
        let mut e = lock(&eng);
        e.blocked_apps.insert(exe.to_lowercase(), firewall::rule_id("app", &exe));
        let mut p = e.pids_of(&exe);
        p.extend(pid);
        p.sort();
        p.dedup();
        p
    };
    let n = bg(move || Ok(pids.into_iter().map(|p| firewall::drop_tcp(Some(p), None)).sum::<usize>())).await?;
    if n > 0 {
        msg += &format!(" Closed {n} open connection(s).");
    }
    Ok(msg)
}

#[tauri::command]
async fn block_app(st: State<'_, AppState>, exe: String, pid: Option<u32>) -> Res<String> {
    do_block_app(st.eng.clone(), exe, pid).await
}

#[tauri::command]
async fn block_ip(st: State<'_, AppState>, ip: String) -> Res<String> {
    let ip = ip.trim().to_string();
    if !firewall::valid_ip(&ip) {
        return Err(format!("\"{ip}\" is not an IP address."));
    }
    need_admin(&st.eng)?;
    let ip2 = ip.clone();
    let id = bg(move || firewall::block_ips("ip", &ip2, &[ip2.clone()])).await?;
    if let Some(n) = parse_net(&ip) {
        lock(&st.eng).blocked_nets.push((id, n));
    }
    let n = match ip.parse() {
        Ok(addr) => bg(move || Ok(firewall::drop_tcp(None, Some(addr)))).await?,
        Err(_) => 0,
    };
    Ok(format!(
        "Nothing on this PC can reach {ip} any more.{}",
        if n > 0 { format!(" Closed {n} open connection(s).") } else { String::new() }
    ))
}

#[tauri::command]
async fn block_domain(st: State<'_, AppState>, domain: String) -> Res<String> {
    let domain = firewall::clean_domain(&domain).ok_or_else(|| format!("\"{domain}\" is not a domain name."))?;
    need_admin(&st.eng)?;
    let known: Vec<String> =
        lock(&st.eng).dns.iter().filter(|(_, n)| domain_is(n, &domain)).map(|(ip, _)| ip.to_string()).collect();
    let d2 = domain.clone();
    let (id, ips) = bg(move || firewall::block_domain(&d2, known)).await?;
    {
        let mut e = lock(&st.eng);
        e.cfg.domain_blocks.retain(|b| b.domain != domain);
        e.cfg.domain_blocks.push(config::DomainBlock { domain: domain.clone(), id, ips: ips.clone(), tracker: false });
        e.dirty_cfg = true;
    }
    let addrs: Vec<std::net::IpAddr> = ips.iter().filter_map(|i| i.parse().ok()).collect();
    let n = bg(move || Ok(addrs.into_iter().map(|a| firewall::drop_tcp(None, Some(a))).sum::<usize>())).await?;
    Ok(format!(
        "{domain} is blocked ({} address{}). While Kestryl runs it adds the site's new addresses as they show up and closes connections that get through first.{}",
        ips.len(),
        if ips.len() == 1 { "" } else { "es" },
        if n > 0 { format!(" Closed {n} open connection(s).") } else { String::new() }
    ))
}

#[tauri::command]
async fn unblock(st: State<'_, AppState>, id: String) -> Res<String> {
    need_admin(&st.eng)?;
    let id2 = id.clone();
    bg(move || firewall::remove(&id2)).await?;
    let mut e = lock(&st.eng);
    e.fw_forget(&id);
    e.cfg.domain_blocks.retain(|b| b.id != id);
    e.blocked_apps.retain(|_, v| *v != id);
    e.blocked_nets.retain(|(v, _)| *v != id);
    e.dirty_cfg = true;
    Ok("Rule removed.".into())
}

#[tauri::command]
async fn block_port(st: State<'_, AppState>, proto: String, port: u16) -> Res<String> {
    need_admin(&st.eng)?;
    bg(move || firewall::block_port(&proto, port)).await
}

#[tauri::command]
async fn set_lockdown(st: State<'_, AppState>, on: bool) -> Res<String> {
    need_admin(&st.eng)?;
    let msg = bg(move || firewall::set_lockdown(on)).await?;
    if !on {
        lock(&st.eng).fw_forget("Kestryl-script-");
    }
    Ok(msg)
}

#[tauri::command]
async fn set_cutoff(st: State<'_, AppState>, on: bool) -> Res<String> {
    need_admin(&st.eng)?;
    bg(move || firewall::set_cutoff(on)).await
}

#[tauri::command]
fn kill(st: State<AppState>, pid: u32) -> Res<String> {
    if is_sim(&st.eng, Some(pid)) {
        return Err("That is a simulated program from --simulate.".into());
    }
    if pid <= 4 {
        return Err("That is part of Windows and can't be ended.".into());
    }
    let mut cmd = std::process::Command::new(system_exe("taskkill.exe"));
    cmd.args(["/PID", &pid.to_string(), "/F"]);
    hide_window(&mut cmd);
    let out = own_output(&mut cmd).map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(format!("Process {pid} ended."))
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if err.is_empty() { "Could not end the process.".into() } else { err })
    }
}

#[tauri::command]
async fn autostart(st: State<'_, AppState>, on: Option<bool>) -> Res<Value> {
    if let Some(on) = on {
        need_admin(&st.eng)?;
        let msg = bg(move || firewall::set_autostart(on)).await?;
        return Ok(json!({ "on": on, "msg": msg }));
    }
    let on = bg(|| Ok(firewall::autostart_on())).await?;
    Ok(json!({ "on": on }))
}

#[tauri::command]
async fn restart_admin(app: AppHandle, st: State<'_, AppState>) -> Res<()> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
    bg(move || run_ps(&format!("Start-Process -FilePath {} -ArgumentList '--restarted' -Verb RunAs", ps_quote(&exe)))).await?;
    persist(&st.eng);
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn reveal(path: String) -> Res<()> {
    let p = std::path::Path::new(&path);
    if path.contains('"') {
        return Err("Not a file path.".into());
    }
    let mut cmd = std::process::Command::new(windows_dir().join("explorer.exe"));
    if p.is_dir() {
        cmd.arg(&path);
    } else if p.is_file() {
        // explorer.exe reads its own command line: it needs  /select,"C:\Program Files\x.exe".
        // A normal arg gets quoted as a whole ("/select,C:\Program Files\x.exe") when the path
        // has spaces, and explorer then opens Documents instead.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.raw_arg(format!("/select,\"{path}\""));
        }
    } else if let Some(dir) = p.parent().filter(|d| d.is_dir()) {
        cmd.arg(dir);
    } else {
        return Err(format!("{path} no longer exists."));
    }
    own_spawn(&mut cmd).map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ pop-up

#[tauri::command]
fn toast_current(st: State<AppState>) -> Value {
    let e = lock(&st.eng);
    json!({ "alert": e.last_toast, "more": 0, "theme": e.cfg.theme })
}

#[tauri::command]
async fn toast_action(app: AppHandle, st: State<'_, AppState>, id: u64, action: String) -> Res<String> {
    let a = {
        let mut e = lock(&st.eng);
        let a = e.alerts.iter_mut().find(|a| a.id == id).ok_or("That alert is gone.")?;
        a.read = true;
        a.clone()
    };
    match action.as_str() {
        "block" => do_block_app(st.eng.clone(), a.exe, Some(a.pid)).await,
        "details" => {
            show_main(&app);
            let _ = app.emit_to("main", "open-alert", id);
            Ok(String::new())
        }
        _ => Ok(String::new()),
    }
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn show_toast(app: &AppHandle, a: &Alert, more: usize, theme: &str) {
    let Some(w) = app.get_webview_window("toast") else { return };
    if let Ok(Some(m)) = w.primary_monitor() {
        let wa = m.work_area();
        let sf = m.scale_factor();
        let (ww, wh) = ((380.0 * sf) as i32, (156.0 * sf) as i32);
        let margin = (14.0 * sf) as i32;
        let x = wa.position.x + wa.size.width as i32 - ww - margin;
        let y = wa.position.y + wa.size.height as i32 - wh - margin;
        let _ = w.set_position(tauri::PhysicalPosition::new(x, y));
    }
    let _ = app.emit_to("toast", "toast", json!({ "alert": a, "more": more, "theme": theme }));
    let _ = w.show();
}

// ------------------------------------------------------------------ background loop

/// Hides loopback, virtual switches and filter-driver layers ("Ethernet-WFP Packet
/// Filter Driver-0000"), which repeat the real adapter's counters and would double-count.
fn skip_adapter(name: &str) -> bool {
    let n = name.to_lowercase();
    let b = n.as_bytes();
    let filter_layer = b.len() > 5 && b[b.len() - 5] == b'-' && b[b.len() - 4..].iter().all(u8::is_ascii_digit);
    filter_layer
        || [
            "loopback", "-wfp", "-qos", "filter", "-npcap", "kernel debug", "teredo", "isatap", "6to4", "ip-https",
            "vethernet (wsl", "vethernet (default switch)", "-virtual switch extension",
        ]
        .iter()
        .any(|s| n.contains(s))
}

/// Is monitoring intact? ETW sessions alive, events flowing. Restarts what was stopped.
fn health_check(eng: &Shared, traffic: u64, events_before: &mut u64, minute: bool) {
    let (full, sim, files_expected, events) = {
        let e = lock(eng);
        (e.mode == "full", e.sim, e.cfg.file_watch && e.health.files.is_some(), e.stats.events)
    };
    lock(eng).stats.file_events = collect::FILE_EVENTS.load(std::sync::atomic::Ordering::Relaxed);
    if !full || sim {
        return;
    }
    let now = now_ms();
    let net = collect::session_query(collect::SESSION);
    let files = files_expected.then(|| collect::session_query(collect::FILE_SESSION));
    let gone = |r: &Result<(u32, u32), u32>| matches!(r, Err(4201));
    let lost: u64 = [Some(&net), files.as_ref()].into_iter().flatten().filter_map(|r| r.as_ref().ok()).map(|(a, b)| *a as u64 + *b as u64).sum();
    let (restart_net, restart_files) = (gone(&net), files.as_ref().is_some_and(gone));
    // Bytes moving on the adapters but not one network event in a minute: blinded.
    let blind = minute && *events_before > 0 && events == *events_before && traffic >= 20 * MB && !restart_net;
    if minute {
        *events_before = events;
    }
    {
        let mut e = lock(eng);
        e.health.net = Some(!restart_net);
        if files_expected {
            e.health.files = Some(!restart_files);
        }
        e.health.lost = lost;
        e.health.checked = now;
        e.health.blind = blind;
        if restart_net || restart_files || blind {
            e.health.restarts += 1;
            let fd = if blind {
                detect::Finding {
                    rule: "monitor_blind",
                    sev: 1,
                    title: "Kestryl stopped receiving network events".into(),
                    why: "Over 20 MB moved on the network adapters, but Windows sent Kestryl no network events for a whole minute, so it could not see who was talking. Kestryl restarted its tracing. Virtual machines (WSL, Docker, Hyper-V) can cause this when nothing else is online. If it keeps happening while you use the PC, something with administrator rights may be interfering; run a full virus scan.".into(),
                    group: "blind".into(),
                }
            } else {
                detect::Finding {
                    rule: "monitor_stopped",
                    sev: 3,
                    title: "Something stopped Kestryl's monitoring".into(),
                    why: format!("Windows reports that Kestryl's {} tracing session is gone, so for a moment Kestryl could not see {}. Only a program with administrator rights can stop it: malware does this to hide. Kestryl restarted it. If this happens again, run a full virus scan.", if restart_net { "network" } else { "file" }, if restart_net { "network traffic" } else { "which programs open your passwords and files" }),
                    group: "etw".into(),
                }
            };
            e.raise_sys(now, fd, "Kestryl");
        }
    }
    if restart_net || blind {
        if blind {
            collect::stop_etw();
        }
        match collect::start_etw(eng) {
            Ok(()) => lock(eng).health.net = Some(true),
            Err(err) => log(&format!("ETW restart failed: {err}")),
        }
    }
    if restart_files {
        match collect::start_files(eng) {
            Ok(()) => lock(eng).health.files = Some(true),
            Err(err) => log(&format!("file trace restart failed: {err}")),
        }
    }
}

static AUDIT_LOCK: Mutex<()> = Mutex::new(());

/// The security check (antivirus, firewall, certificates, startup, ...), then alerts for changes.
fn run_audit(eng: &Shared) {
    let _one = AUDIT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    match audit::run() {
        Ok(v) => lock(eng).apply_audit(now_ms(), v),
        Err(err) => {
            log(&format!("security check failed: {err}"));
            lock(eng).audit_error = err;
        }
    }
}

/// At start (administrator only): cleans up after a crashed decryption session and
/// re-pushes blocked sites, then reads which programs and IPs are blocked.
fn firewall_start(eng: &Shared) {
    if is_elevated() {
        // A decryption session cut short by a crash: proxy back, certificate gone.
        decrypt::cleanup_after_crash(eng);
        // Every blocked domain's rule gets its saved address list again: a run without
        // administrator rights, or a failed update, may have left the two different.
        let mut e = lock(eng);
        e.clean_domain_blocks();
        let all: Vec<String> = e.cfg.domain_blocks.iter().map(|b| b.domain.clone()).collect();
        for d in all {
            if !e.fw_updates.contains(&d) {
                e.fw_updates.push(d);
            }
        }
    }
    match firewall::list() {
        Ok(v) => lock(eng).set_blocks(&v),
        Err(err) => log(&format!("reading firewall rules failed: {err}")),
    }
}

/// The full check every 15 minutes, and within a minute of a change to a startup place.
fn audit_loop(eng: Shared) {
    std::thread::sleep(Duration::from_secs(3));
    run_audit(&eng);
    let mut last = now_ms();
    let mut fp = audit::quick_fingerprint();
    loop {
        std::thread::sleep(Duration::from_secs(20));
        let now = now_ms();
        let f = audit::quick_fingerprint();
        let changed = f != fp && now >= last + 60_000;
        if changed || now >= last + 15 * 60_000 {
            run_audit(&eng);
            last = now_ms();
            fp = audit::quick_fingerprint();
        }
    }
}

/// Threat lists: the cached copies at once, fresh downloads every 12 hours or on request.
fn intel_loop(eng: Shared) {
    let mut errs = HashMap::new();
    let key_set = !lock(&eng).cfg.abuse_key.is_empty();
    let first = intel::build(key_set, &errs);
    lock(&eng).set_intel(Arc::new(first));
    std::thread::sleep(Duration::from_secs(15));
    loop {
        let force = intel::REFRESH_NOW.swap(false, Ordering::Relaxed);
        let key = lock(&eng).cfg.abuse_key.clone();
        if intel::refresh(&key, force, &mut errs) || force {
            let fresh = intel::build(!key.is_empty(), &errs);
            lock(&eng).set_intel(Arc::new(fresh));
        }
        for _ in 0..1800 {
            std::thread::sleep(Duration::from_secs(1));
            if intel::REFRESH_NOW.load(Ordering::Relaxed) {
                break;
            }
        }
    }
}

/// Country and company data: the saved copy at once, a fresh download once a month.
fn geo_loop(eng: Shared) {
    if lock(&eng).sim {
        lock(&eng).geo = Arc::new(geo::demo());
        return;
    }
    let first = geo::build(); // a second or two of parsing, outside the engine lock
    lock(&eng).geo = Arc::new(first);
    std::thread::sleep(Duration::from_secs(20));
    loop {
        let force = geo::REFRESH_NOW.swap(false, Ordering::Relaxed);
        match geo::refresh(force) {
            Ok(saved) => {
                if let Ok(mut e) = geo::ERR.lock() {
                    e.clear();
                }
                if saved || force {
                    let g = geo::build();
                    lock(&eng).geo = Arc::new(g);
                }
            }
            Err(err) => {
                log(&format!("geo: {err}"));
                if let Ok(mut e) = geo::ERR.lock() {
                    *e = err;
                }
            }
        }
        for _ in 0..6 * 3600 {
            std::thread::sleep(Duration::from_secs(1));
            if geo::REFRESH_NOW.load(Ordering::Relaxed) {
                break;
            }
        }
    }
}

/// Screen lock and idle time, for "while you were away".
fn away_loop(eng: Shared) {
    loop {
        let (locked, idle) = away::presence();
        lock(&eng).on_presence(now_ms(), locked, idle);
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// One file at a time: hash, then Microsoft Defender.
fn scan_loop(eng: Shared) {
    loop {
        let job = lock(&eng).next_scan();
        let Some(p) = job else {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        };
        let sim = lock(&eng).sim;
        let r = if sim { scan::demo(&p) } else { scan::run(&p) };
        lock(&eng).on_scan(now_ms(), &p, r);
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Camera and microphone use, every 3 seconds (a few registry reads).
fn sensor_loop(eng: Shared) {
    loop {
        let uses = sensors::read();
        lock(&eng).on_sensors(now_ms(), uses);
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn tick_loop(app: AppHandle, eng: Shared) {
    let mut nets = sysinfo::Networks::new_with_refreshed_list();
    let mut n: u64 = 0;
    let mut traffic_min: u64 = 0;
    let mut events_before: u64 = 0;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        n += 1;
        nets.refresh(true);
        let (mut up, mut down) = (0u64, 0u64);
        let mut ads = Vec::new();
        let mut locals = HashSet::new();
        for (name, d) in nets.list() {
            for ipn in d.ip_networks() {
                locals.insert(norm_ip(ipn.addr));
            }
            if skip_adapter(name) {
                continue;
            }
            up += d.transmitted();
            down += d.received();
            ads.push(Adapter {
                name: name.clone(),
                mac: d.mac_address().to_string(),
                ips: d.ip_networks().iter().map(|i| format!("{}/{}", i.addr, i.prefix)).collect(),
                rx_rate: d.received(),
                tx_rate: d.transmitted(),
                rx_total: d.total_received(),
                tx_total: d.total_transmitted(),
            });
        }
        ads.sort_by(|a, b| b.rx_total.cmp(&a.rx_total));
        let now = now_ms();
        let (notify, fw, tip, save, theme) = {
            let mut e = lock(&eng);
            e.up = up;
            e.down = down;
            e.history.push_back([up, down]);
            if e.history.len() > 300 {
                e.history.pop_front();
            }
            e.adapters = ads;
            e.local_ips = locals;
            e.tick(now);
            let mut notify = std::mem::take(&mut e.notify);
            notify.sort_by_key(|a| a.sev); // the most severe of this second's alerts is shown
            if let Some(a) = notify.last() {
                e.last_toast = Some(a.clone());
            }
            let fw: Vec<(String, String, Vec<String>)> = std::mem::take(&mut e.fw_updates)
                .into_iter()
                .filter_map(|d| e.cfg.domain_blocks.iter().find(|b| b.domain == d).map(|b| (b.id.clone(), b.domain.clone(), b.ips.clone())))
                .collect();
            let drops = std::mem::take(&mut e.drops);
            if !drops.is_empty() {
                std::thread::spawn(move || {
                    for (pid, ip) in drops {
                        let n = firewall::drop_tcp(Some(pid), Some(ip));
                        if n > 0 {
                            log(&format!("closed {n} connection(s) of pid {pid} to blocked {ip}"));
                        }
                    }
                });
            }
            let unread = e.alerts.iter().filter(|a| !a.read).count();
            let tip = format!(
                "Kestryl: up {}/s, down {}/s{}",
                fmt_bytes(up),
                fmt_bytes(down),
                if unread > 0 { format!(", {unread} new alert(s)") } else { String::new() }
            );
            let save = n % 5 == 0 && (e.dirty_alerts || e.dirty_cfg || e.away_dirty);
            if save {
                e.dirty_alerts = false;
                e.dirty_cfg = false;
            }
            // History: once a minute, and at once when the date changed.
            if e.sim {
                e.done_days.clear();
            } else if !e.done_days.is_empty() || (n % 60 == 0 && e.hist_dirty) {
                e.hist_dirty = false;
                let done = std::mem::take(&mut e.done_days);
                let today = e.today.clone();
                std::thread::spawn(move || {
                    for d in &done {
                        history::save(d);
                    }
                    history::save(&today);
                    if !done.is_empty() {
                        history::prune(&today.day);
                    }
                });
            }
            (notify, fw, tip, save, e.cfg.theme.clone())
        };
        // A decryption session ends by itself when its time is up.
        if decrypt::current().is_some_and(|d| now >= d.until) {
            let e2 = eng.clone();
            std::thread::spawn(move || end_session(&e2, "time is up"));
        }
        traffic_min += up + down;
        if n % 10 == 0 {
            let minute = n % 60 == 0;
            let e2 = eng.clone();
            let t = traffic_min;
            health_check(&e2, t, &mut events_before, minute);
            if minute {
                traffic_min = 0;
            }
        }
        if let Some(a) = notify.last() {
            show_toast(&app, a, notify.len() - 1, &theme);
        }
        if save {
            persist(&eng);
        }
        for (id, domain, ips) in fw {
            std::thread::spawn(move || {
                if let Err(e) = firewall::update_ips(&id, &domain, &ips) {
                    log(&format!("domain rule update failed: {e}"));
                }
            });
        }
        if n % 2 == 0 {
            if let Some(t) = app.tray_by_id("tray") {
                let _ = t.set_tooltip(Some(tip));
            }
        }
    }
}

pub fn run() {
    // Running as administrator, the window's browser engine (WebView2) must not take its
    // settings from the environment: per-user variables can be set by any program the user
    // runs, and WEBVIEW2_BROWSER_EXECUTABLE_FOLDER would start that program's "browser" as
    // administrator (WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS could open a remote-control port).
    // Done first, before any other thread exists.
    if is_elevated() {
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().to_ascii_uppercase().starts_with("WEBVIEW2_") {
                std::env::remove_var(&k);
            }
        }
    }
    let args: Vec<String> = std::env::args().collect();
    let has = |f: &str| args.iter().any(|a| a == f);
    let hidden = has("--hidden");
    let simulate = has("--simulate");
    if has("--restarted") {
        std::thread::sleep(Duration::from_millis(1500)); // let the old instance exit
    }
    let (mut cfg, fresh) = config::load();
    if fresh {
        cfg.learning_until = now_ms() + 10 * 60_000;
    }
    let mut engine = Engine::new(cfg, config::load_alerts());
    engine.elevated = is_elevated();
    engine.sim = simulate;
    engine.home = geo::home_country();
    if !simulate {
        if let Some(d) = history::load(&engine.today.day) {
            engine.today = d; // continue today's numbers after a restart
        }
        history::prune(&engine.today.day);
        engine.away_reports = away::load().into_iter().collect();
    }
    let eng: Shared = Arc::new(Mutex::new(engine));
    if fresh {
        persist(&eng);
    }
    let eng_setup = eng.clone();
    let eng_exit = eng.clone();

    let mut builder = tauri::Builder::default();
    if !simulate {
        // The demo may run next to the real monitor; the real one stays single.
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)));
    }
    builder
        .manage(AppState { eng: eng.clone() })
        .invoke_handler(tauri::generate_handler![
            snapshot,
            flows,
            alerts,
            dns,
            network,
            network_extra,
            ip_info,
            rules,
            settings,
            alert_read,
            alert_dismiss,
            alert_dismiss_rule,
            trust,
            trust_dest,
            untrust_dest,
            set_dest_show,
            mute,
            save_settings,
            set_theme,
            block_app,
            block_ip,
            block_domain,
            block_port,
            unblock,
            set_lockdown,
            set_cutoff,
            kill,
            autostart,
            restart_admin,
            reveal,
            toast_current,
            toast_action,
            status,
            audit_now,
            history_days,
            history_day,
            proc_extra,
            ack_startup,
            peek,
            set_file_watch,
            intel_refresh,
            set_abuse_key,
            scan_file,
            open_virustotal,
            set_view,
            set_clip_guard,
            data_map,
            geo_refresh,
            analytics_list,
            set_analytics,
            decrypt_state,
            decrypt_set_password,
            decrypt_start,
            decrypt_stop,
            decrypt_entries,
            decrypt_clear
        ])
        .setup(move |app| {
            let eng = eng_setup;
            // The demo gets its own WebView2 profile: WebView2 cannot share one between the
            // elevated real monitor and a non-elevated demo.
            let webdir = simulate.then(|| std::env::temp_dir().join("kestryl-simulate-webview"));
            let mut main = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()));
            let mut toast = WebviewWindowBuilder::new(app, "toast", WebviewUrl::App("toast.html".into()));
            if let Some(d) = &webdir {
                main = main.data_directory(d.clone());
                toast = toast.data_directory(d.clone());
            }
            let main = main
                .title(if simulate { "Kestryl (simulation)" } else { "Kestryl" })
                .inner_size(1220.0, 780.0)
                .min_inner_size(940.0, 580.0)
                .center()
                .visible(!hidden)
                .build()?;
            let m2 = main.clone();
            main.on_window_event(move |ev| {
                if let WindowEvent::CloseRequested { api, .. } = ev {
                    api.prevent_close();
                    let _ = m2.hide();
                }
            });
            toast
                .title(if simulate { "Kestryl alert (simulation)" } else { "Kestryl alert" })
                .inner_size(380.0, 156.0)
                .decorations(false)
                .always_on_top(true)
                .skip_taskbar(true)
                .resizable(false)
                .focused(false)
                .focusable(false)
                .visible(false)
                .build()?;

            // Detection data (which files stealers go for) ships inside the app's compressed
            // UI assets rather than as plain text in kestryl.exe; see ui/rules.json.
            let loaded = app.asset_resolver().get("rules.json".into()).map(|a| a.bytes).ok_or_else(|| "rules.json is missing".to_string());
            if let Err(err) = loaded.and_then(|b| detect::load_rules(&b)) {
                log(&format!("detection rules: {err}"));
                lock(&eng).health.files_error = format!("Detection rules could not load: {err}");
            }

            let popups = lock(&eng).cfg.popups;
            let pause =
                MenuItem::with_id(app, "popups", if popups { "Pause pop-ups" } else { "Resume pop-ups" }, true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &MenuItem::with_id(app, "open", "Open Kestryl", true, None::<&str>)?,
                    &pause,
                    &PredefinedMenuItem::separator(app)?,
                    &MenuItem::with_id(app, "quit", "Quit (stops monitoring)", true, None::<&str>)?,
                ],
            )?;
            let eng_menu = eng.clone();
            let pause2 = pause.clone();
            TrayIconBuilder::with_id("tray")
                // A bolder 32 px drawing: the full icon's thin lines vanish at tray size.
                .icon(tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))?)
                .tooltip("Kestryl")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, ev| match ev.id().as_ref() {
                    "open" => show_main(app),
                    "popups" => {
                        let on = {
                            let mut e = lock(&eng_menu);
                            e.cfg.popups = !e.cfg.popups;
                            e.dirty_cfg = true;
                            e.cfg.popups
                        };
                        let _ = pause2.set_text(if on { "Pause pop-ups" } else { "Resume pop-ups" });
                    }
                    "quit" => {
                        end_session(&eng_menu, "Kestryl was closed");
                        collect::stop_etw();
                        collect::stop_files();
                        persist(&eng_menu);
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, ev| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;

            let elevated = lock(&eng).elevated;
            let etw_ok = if elevated && !simulate {
                match collect::start_etw(&eng) {
                    Ok(()) => true,
                    Err(err) => {
                        log(&format!("ETW start failed: {err}"));
                        lock(&eng).etw_error = err;
                        false
                    }
                }
            } else {
                false
            };
            lock(&eng).mode = if etw_ok { "full" } else { "limited" }.into();
            if etw_ok {
                lock(&eng).health.net = Some(true);
                if lock(&eng).cfg.file_watch {
                    match collect::start_files(&eng) {
                        Ok(()) => lock(&eng).health.files = Some(true),
                        Err(err) => {
                            log(&format!("file trace start failed: {err}"));
                            lock(&eng).health.files_error = err;
                        }
                    }
                }
            }

            let e = eng.clone();
            std::thread::spawn(move || collect::poll_loop(e, !etw_ok));
            let (tx, rx) = std::sync::mpsc::channel();
            let e = eng.clone();
            let tx_known = tx.clone();
            std::thread::spawn(move || collect::proc_loop(e, tx));
            // Signatures of every program ever seen online, for the Status page review (slowly,
            // so checks for newly seen programs are not held up).
            let e = eng.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(60));
                let keys: Vec<String> = {
                    let e = lock(&e);
                    e.known.iter().filter(|k| k.contains('\\') && !e.sigs.contains_key(*k)).cloned().collect()
                };
                for chunk in keys.chunks(20) {
                    let ok: Vec<&String> = chunk.iter().filter(|k| std::path::Path::new(k.as_str()).is_file()).collect();
                    {
                        let mut e = lock(&e);
                        for k in &ok {
                            e.sigs.entry((*k).clone()).or_insert(SigInfo { status: "pending".into(), signer: String::new() });
                        }
                    }
                    for k in ok {
                        let _ = tx_known.send(k.clone());
                    }
                    std::thread::sleep(Duration::from_secs(8));
                }
            });
            if !simulate {
                let e = eng.clone();
                std::thread::spawn(move || firewall_start(&e));
            }
            let e = eng.clone();
            std::thread::spawn(move || audit_loop(e));
            let e = eng.clone();
            std::thread::spawn(move || scan_loop(e));
            if !simulate {
                let e = eng.clone();
                std::thread::spawn(move || intel_loop(e));
                let e = eng.clone();
                std::thread::spawn(move || sensor_loop(e));
                let e = eng.clone();
                std::thread::spawn(move || away_loop(e));
                let e = eng.clone();
                std::thread::spawn(move || {
                    if let Err(err) = clip::listen(e) {
                        log(&format!("clipboard guard could not start: {err}"));
                    }
                });
            }
            let e = eng.clone();
            std::thread::spawn(move || geo_loop(e));
            let e = eng.clone();
            std::thread::spawn(move || collect::sig_loop(e, rx));
            let e = eng.clone();
            let handle = app.handle().clone();
            std::thread::spawn(move || tick_loop(handle, e));
            if simulate {
                let e = eng.clone();
                std::thread::spawn(move || collect::simulate(e));
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Kestryl")
        .run(move |_app, ev| {
            if let tauri::RunEvent::Exit = ev {
                end_session(&eng_exit, "Kestryl was closed");
                collect::stop_etw();
                collect::stop_files();
                persist(&eng_exit);
            }
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn adapters() {
        assert!(super::skip_adapter("Ethernet-WFP Packet Filter Driver-0000"));
        assert!(super::skip_adapter("Wi-Fi-WFP Native MAC Layer LightWeight Filter-0000"));
        assert!(super::skip_adapter("vEthernet (Default Switch)"));
        assert!(super::skip_adapter("Loopback Pseudo-Interface 1"));
        assert!(!super::skip_adapter("イーサネット"));
        assert!(!super::skip_adapter("イーサネット 2"));
        assert!(!super::skip_adapter("Wi-Fi"));
    }
}
