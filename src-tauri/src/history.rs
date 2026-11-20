//! Daily traffic history: bytes per program and destination, saved once a minute to
//! %LOCALAPPDATA%\Kestryl\history\YYYY-MM-DD.json, so "what left this PC last night"
//! still has an answer after a restart. Kept for 30 days.

use crate::util::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

pub const KEEP_DAYS: i64 = 30;
const MAX_ROWS: usize = 20_000;
const OTHER: &str = "(other destinations)";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Row {
    /// Lower-case exe path, or the name when the path is not visible.
    pub key: String,
    pub name: String,
    /// Site (base domain) or IP address.
    pub dest: String,
    pub ip: String,
    /// Remote port; for incoming connections the local port.
    pub port: u16,
    /// Another device connected to this PC.
    pub inb: bool,
    pub lan: bool,
    pub out: u64,
    #[serde(rename = "in")]
    pub inn: u64,
    /// Bytes sent between midnight and 6 am.
    pub night: u64,
    pub first: u64,
    pub last: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Day {
    pub day: String,
    /// [sent, received] per local hour.
    pub hours: Vec<[u64; 2]>,
    pub rows: Vec<Row>,
    /// Bytes sent per local hour, per program key (for the stacked charts).
    pub ph: HashMap<String, Vec<u64>>,
    #[serde(skip)]
    idx: HashMap<(String, String, u16, bool), usize>,
}

impl Day {
    pub fn new(day: String) -> Self {
        Day { day, hours: vec![[0, 0]; 24], rows: Vec::new(), ph: HashMap::new(), idx: HashMap::new() }
    }

    fn reindex(&mut self) {
        self.hours.resize(24, [0, 0]);
        self.idx = self.rows.iter().enumerate().map(|(i, r)| ((r.key.clone(), r.dest.clone(), r.port, r.inb), i)).collect();
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add(&mut self, key: &str, name: &str, dest: &str, ip: &str, port: u16, inb: bool, lan: bool, out: u64, inn: u64, hour: usize, now: u64) {
        if let Some(h) = self.hours.get_mut(hour) {
            h[0] += out;
            h[1] += inn;
        }
        if out > 0 && hour < 24 {
            let v = self.ph.entry(key.to_string()).or_insert_with(|| vec![0; 24]);
            v.resize(24, 0);
            v[hour] += out;
        }
        let k = (key.to_string(), dest.to_string(), port, inb);
        let i = match self.idx.get(&k) {
            Some(i) => *i,
            None if self.rows.len() < MAX_ROWS => self.push_row(k, name, ip, lan, now),
            None => {
                let ok = (key.to_string(), OTHER.to_string(), 0, inb);
                match self.idx.get(&ok) {
                    Some(i) => *i,
                    None => self.push_row(ok, name, "", lan, now),
                }
            }
        };
        let r = &mut self.rows[i];
        r.out += out;
        r.inn += inn;
        if hour < 6 {
            r.night += out;
        }
        r.last = now;
    }

    fn push_row(&mut self, k: (String, String, u16, bool), name: &str, ip: &str, lan: bool, now: u64) -> usize {
        self.rows.push(Row {
            key: k.0.clone(),
            name: name.to_string(),
            dest: k.1.clone(),
            ip: ip.to_string(),
            port: k.2,
            inb: k.3,
            lan,
            first: now,
            last: now,
            ..Default::default()
        });
        let i = self.rows.len() - 1;
        self.idx.insert(k, i);
        i
    }

    pub fn totals(&self) -> (u64, u64) {
        self.hours.iter().fold((0, 0), |a, h| (a.0 + h[0], a.1 + h[1]))
    }

    /// The 4 biggest senders' bytes per hour, and everything else as "Other".
    pub fn prog_hours(&self) -> Value {
        let mut tot: Vec<(&String, u64)> = self.ph.iter().map(|(k, v)| (k, v.iter().sum())).collect();
        tot.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let name = |k: &str| self.rows.iter().find(|r| r.key == k).map(|r| r.name.clone()).unwrap_or_else(|| k.rsplit('\\').next().unwrap_or(k).to_string());
        let mut out: Vec<Value> = tot.iter().take(4).map(|(k, _)| json!({ "key": k, "name": name(k), "v": self.ph[*k] })).collect();
        let mut other = vec![0u64; 24];
        for (k, _) in tot.iter().skip(4) {
            for (i, b) in self.ph[*k].iter().enumerate().take(24) {
                other[i] += b;
            }
        }
        if other.iter().any(|b| *b > 0) {
            out.push(json!({ "key": "", "name": "Other", "v": other }));
        }
        Value::Array(out)
    }

    fn programs(&self) -> usize {
        self.rows.iter().map(|r| r.key.as_str()).collect::<HashSet<_>>().len()
    }
}

pub fn dir() -> PathBuf {
    crate::config::dir().join("history")
}

pub fn load(day: &str) -> Option<Day> {
    let s = std::fs::read_to_string(dir().join(format!("{day}.json"))).ok()?;
    let mut d: Day = serde_json::from_str(&s).ok()?;
    d.reindex();
    Some(d)
}

fn load_index() -> BTreeMap<String, Value> {
    std::fs::read_to_string(dir().join("index.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_index(idx: &BTreeMap<String, Value>) {
    if let Ok(s) = serde_json::to_string(idx) {
        crate::config::write_atomic_in(&dir(), "index.json", &s);
    }
}

pub fn save(d: &Day) {
    if let Ok(s) = serde_json::to_string(d) {
        crate::config::write_atomic_in(&dir(), &format!("{}.json", d.day), &s);
    }
    let mut idx = load_index();
    let (o, i) = d.totals();
    idx.insert(d.day.clone(), json!({ "out": o, "in": i, "programs": d.programs() }));
    save_index(&idx);
}

/// Deletes days older than KEEP_DAYS.
pub fn prune(today: &str) {
    let Some(t) = day_number(today) else { return };
    let cutoff = t - KEEP_DAYS;
    if let Ok(rd) = std::fs::read_dir(dir()) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(n) = name.strip_suffix(".json").and_then(day_number) {
                if n < cutoff {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
    let mut idx = load_index();
    let before = idx.len();
    idx.retain(|d, _| day_number(d).is_some_and(|n| n >= cutoff));
    if idx.len() != before {
        save_index(&idx);
    }
}

/// Days with history, newest first. `today` comes from memory; `real` false (demo) skips the disk.
pub fn list(today: &Day, extra: &[Day], real: bool) -> Vec<Value> {
    let mut idx = if real { load_index() } else { BTreeMap::new() };
    for d in extra.iter().chain(std::iter::once(today)) {
        let (o, i) = d.totals();
        idx.insert(d.day.clone(), json!({ "out": o, "in": i, "programs": d.programs() }));
    }
    idx.into_iter()
        .rev()
        .map(|(day, v)| json!({ "day": day, "out": v["out"], "in": v["in"], "programs": v["programs"] }))
        .collect()
}

/// One day for the History tab: hours, and rows grouped per program (biggest senders first).
pub fn view(d: &Day) -> Value {
    let mut progs: HashMap<&str, Vec<&Row>> = HashMap::new();
    for r in &d.rows {
        progs.entry(r.key.as_str()).or_default().push(r);
    }
    let mut list: Vec<Value> = progs
        .into_iter()
        .map(|(key, mut rows)| {
            rows.sort_by(|a, b| b.out.cmp(&a.out).then(b.inn.cmp(&a.inn)));
            let out: u64 = rows.iter().map(|r| r.out).sum();
            let inn: u64 = rows.iter().map(|r| r.inn).sum();
            let night: u64 = rows.iter().map(|r| r.night).sum();
            let first = rows.iter().map(|r| r.first).min().unwrap_or(0);
            let last = rows.iter().map(|r| r.last).max().unwrap_or(0);
            json!({
                "key": key, "name": rows[0].name, "out": out, "in": inn, "night": night, "first": first, "last": last,
                "dests": rows.len(), "incoming": rows.iter().filter(|r| r.inb).count(),
                "rows": rows.iter().take(80).collect::<Vec<_>>(),
            })
        })
        .collect();
    list.sort_by(|a, b| b["out"].as_u64().cmp(&a["out"].as_u64()));
    let mut inbound: Vec<&Row> = d.rows.iter().filter(|r| r.inb).collect();
    inbound.sort_by(|a, b| b.last.cmp(&a.last));
    let (o, i) = d.totals();
    json!({ "day": d.day, "hours": d.hours, "out": o, "in": i, "programs": list, "inbound": inbound.into_iter().take(200).collect::<Vec<_>>(), "prog_hours": d.prog_hours() })
}

/// Today's numbers for the Status page.
pub fn summary(d: &Day) -> Value {
    let mut per: HashMap<&str, (&str, u64, u64, &str, u64)> = HashMap::new(); // name, out, night, top dest, top out
    for r in d.rows.iter().filter(|r| !r.lan) {
        let e = per.entry(r.key.as_str()).or_insert((r.name.as_str(), 0, 0, "", 0));
        e.1 += r.out;
        e.2 += r.night;
        if r.out > e.4 {
            e.3 = r.dest.as_str();
            e.4 = r.out;
        }
    }
    let mut top: Vec<(&&str, &(&str, u64, u64, &str, u64))> = per.iter().filter(|(_, v)| v.1 > 0).collect();
    top.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    let top_v: Vec<Value> = top.iter().take(5).map(|(k, v)| json!({ "key": k, "name": v.0, "out": v.1, "dest": v.3 })).collect();
    let mut night: Vec<(&&str, &(&str, u64, u64, &str, u64))> = per.iter().filter(|(_, v)| v.2 > 0).collect();
    night.sort_by(|a, b| b.1 .2.cmp(&a.1 .2));
    let night_v: Vec<Value> = night.iter().take(3).map(|(k, v)| json!({ "key": k, "name": v.0, "out": v.2 })).collect();
    let night_total: u64 = d.hours.iter().take(6).map(|h| h[0]).sum();
    let mut inbound: Vec<&Row> = d.rows.iter().filter(|r| r.inb).collect();
    inbound.sort_by(|a, b| b.last.cmp(&a.last));
    let (o, i) = d.totals();
    json!({
        "day": d.day, "out": o, "in": i, "programs": d.programs(), "top": top_v,
        "night": night_total, "night_top": night_v,
        "inbound": inbound.iter().take(20).collect::<Vec<_>>(), "inbound_n": inbound.len(),
        "prog_hours": d.prog_hours(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_rows_and_summary() {
        let mut d = Day::new("2026-11-13".into());
        d.add("c:\\a\\up.exe", "up.exe", "example.com", "203.0.113.1", 443, false, false, 5 * MB, KB, 2, 1000);
        d.add("c:\\a\\up.exe", "up.exe", "example.com", "203.0.113.2", 443, false, false, MB, KB, 14, 2000);
        d.add("system", "System", "192.168.1.20", "192.168.1.20", 445, true, true, 2 * MB, 0, 15, 3000);
        assert_eq!(d.rows.len(), 2);
        assert_eq!(d.totals(), (8 * MB, 2 * KB));
        assert_eq!(d.rows[0].night, 5 * MB);
        let s = summary(&d);
        assert_eq!(s["top"][0]["name"], "up.exe");
        assert_eq!(s["night"], 5 * MB);
        assert_eq!(s["inbound_n"], 1);
        let v = view(&d);
        assert_eq!(v["programs"][0]["out"], 6 * MB);
        assert_eq!(v["prog_hours"][0]["name"], "up.exe");
        assert_eq!(v["prog_hours"][0]["v"][2], 5 * MB);
        // survives a save/load round trip through JSON (index rebuilt)
        let mut back: Day = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        back.reindex();
        back.add("c:\\a\\up.exe", "up.exe", "example.com", "203.0.113.1", 443, false, false, 1, 0, 9, 4000);
        assert_eq!(back.rows.len(), 2);
    }
}
