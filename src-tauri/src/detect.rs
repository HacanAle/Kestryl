//! Detection rules. Pure functions over what the engine knows; no I/O.
//! Payloads are never read (almost everything is TLS anyway), so rules look at
//! who is talking, to where, on which port, how much, and how regularly.

use crate::util::*;
use std::collections::VecDeque;
use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    System,
    Installed,
    User,
    Risky,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Script {
    None,
    Interpreter,
    Shell,
    Lolbin,
}

pub fn classify(exe_lower: &str) -> Class {
    let p = exe_lower;
    if p.is_empty() {
        return Class::Unknown;
    }
    const RISKY: [&str; 6] = [
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\downloads\\",
        "\\users\\public\\",
        "$recycle.bin",
        "\\inetcache\\",
    ];
    if RISKY.iter().any(|r| p.contains(r)) {
        return Class::Risky;
    }
    // A bare exe directly in %APPDATA% / %LOCALAPPDATA% (no vendor folder) is a classic malware spot.
    for root in ["\\appdata\\roaming\\", "\\appdata\\local\\"] {
        if let Some(i) = p.find(root) {
            if !p[i + root.len()..].contains('\\') {
                return Class::Risky;
            }
        }
    }
    if p.starts_with("c:\\windows\\") || p.starts_with("\\systemroot\\") {
        return Class::System;
    }
    if p.contains(":\\program files\\") || p.contains(":\\program files (x86)\\") || p.contains("\\windowsapps\\") {
        return Class::Installed;
    }
    Class::User
}

pub fn script_kind(name: &str) -> Script {
    match name {
        "mshta.exe" | "rundll32.exe" | "regsvr32.exe" | "certutil.exe" | "bitsadmin.exe" | "wscript.exe"
        | "cscript.exe" | "msbuild.exe" | "installutil.exe" | "regasm.exe" | "regsvcs.exe" | "wmic.exe"
        | "cmstp.exe" | "odbcconf.exe" | "hh.exe" | "forfiles.exe" | "msxsl.exe" | "ieexec.exe"
        | "finger.exe" | "ftp.exe" | "tftp.exe" | "esentutl.exe" | "desktopimgdownldr.exe" | "autoit3.exe" => {
            Script::Lolbin
        }
        "powershell.exe" | "pwsh.exe" | "powershell_ise.exe" | "cmd.exe" | "curl.exe" | "wget.exe" => Script::Shell,
        "python.exe" | "pythonw.exe" | "py.exe" | "node.exe" | "java.exe" | "javaw.exe" | "ruby.exe"
        | "perl.exe" | "php.exe" | "deno.exe" | "bun.exe" | "autohotkey.exe" | "autohotkey64.exe" => {
            Script::Interpreter
        }
        _ => Script::None,
    }
}

pub fn is_browser(name: &str) -> bool {
    matches!(
        name,
        "chrome.exe" | "msedge.exe" | "firefox.exe" | "brave.exe" | "opera.exe" | "opera_gx.exe" | "vivaldi.exe"
            | "iexplore.exe" | "arc.exe" | "librewolf.exe" | "waterfox.exe" | "chromium.exe"
            | "msedgewebview2.exe" | "yandex.exe" | "thorium.exe" | "zen.exe"
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DestKind {
    Share,
    Paste,
    Bot,
    Catcher,
    Tunnel,
    IpLookup,
}

use DestKind::*;
const DESTS: &[(&str, DestKind)] = &[
    ("transfer.sh", Share), ("file.io", Share), ("filebin.net", Share), ("gofile.io", Share),
    ("anonfiles.com", Share), ("catbox.moe", Share), ("0x0.st", Share), ("temp.sh", Share),
    ("tmpfiles.org", Share), ("bashupload.com", Share), ("oshi.at", Share), ("mega.nz", Share),
    ("mega.io", Share), ("mediafire.com", Share), ("sendspace.com", Share), ("wetransfer.com", Share),
    ("we.tl", Share), ("ufile.io", Share), ("pixeldrain.com", Share), ("sendgb.com", Share),
    ("filetransfer.io", Share), ("anonymfile.com", Share), ("krakenfiles.com", Share), ("upload.ee", Share),
    ("easyupload.io", Share), ("dropmefiles.com", Share), ("swisstransfer.com", Share), ("qu.ax", Share),
    ("uguu.se", Share), ("files.fm", Share), ("filemail.com", Share),
    ("pastebin.com", Paste), ("paste.ee", Paste), ("hastebin.com", Paste), ("ghostbin.co", Paste),
    ("rentry.co", Paste), ("paste.rs", Paste), ("dpaste.org", Paste), ("controlc.com", Paste),
    ("justpaste.it", Paste), ("pastes.io", Paste), ("privatebin.net", Paste), ("termbin.com", Paste),
    ("ix.io", Paste), ("sprunge.us", Paste),
    ("api.telegram.org", Bot), ("discord.com", Bot), ("discordapp.com", Bot), ("hooks.slack.com", Bot),
    ("webhook.site", Catcher), ("requestbin.com", Catcher), ("pipedream.net", Catcher), ("interact.sh", Catcher),
    ("oast.fun", Catcher), ("oast.me", Catcher), ("oast.pro", Catcher), ("oast.live", Catcher),
    ("oast.site", Catcher), ("oast.online", Catcher), ("oastify.com", Catcher), ("burpcollaborator.net", Catcher),
    ("dnslog.cn", Catcher), ("ceye.io", Catcher), ("canarytokens.com", Catcher), ("beeceptor.com", Catcher),
    ("mockbin.org", Catcher), ("hookbin.com", Catcher), ("requestcatcher.com", Catcher),
    ("ngrok.io", Tunnel), ("ngrok-free.app", Tunnel), ("ngrok.app", Tunnel), ("ngrok-free.dev", Tunnel),
    ("trycloudflare.com", Tunnel), ("serveo.net", Tunnel), ("loca.lt", Tunnel), ("localhost.run", Tunnel),
    ("lhr.life", Tunnel), ("pinggy.link", Tunnel), ("bore.pub", Tunnel), ("playit.gg", Tunnel),
    ("localtonet.com", Tunnel), ("portmap.io", Tunnel), ("duckdns.org", Tunnel), ("ddns.net", Tunnel),
    ("hopto.org", Tunnel), ("zapto.org", Tunnel), ("sytes.net", Tunnel),
    ("ipify.org", IpLookup), ("ipinfo.io", IpLookup), ("ip-api.com", IpLookup), ("icanhazip.com", IpLookup),
    ("checkip.amazonaws.com", IpLookup), ("ifconfig.me", IpLookup), ("ifconfig.co", IpLookup),
    ("myexternalip.com", IpLookup), ("wtfismyip.com", IpLookup), ("ipapi.co", IpLookup), ("geoplugin.net", IpLookup),
    ("api.myip.com", IpLookup), ("ipwho.is", IpLookup), ("freegeoip.app", IpLookup), ("ident.me", IpLookup),
    ("checkip.dyndns.org", IpLookup), ("ip.sb", IpLookup), ("ipecho.net", IpLookup), ("ipgeolocation.io", IpLookup),
];

pub fn dest_kind(domain: &str) -> Option<DestKind> {
    if domain.is_empty() {
        return None;
    }
    DESTS.iter().find(|(d, _)| domain_is(domain, d)).map(|(_, k)| *k)
}

/// Ports malware is known for, with why. The table lives in ui/rules.json (see `Rules`).
pub fn bad_port(port: u16) -> Option<&'static str> {
    rules().ports.iter().find(|(p, _)| p.contains(&port)).map(|(_, why)| why.as_str())
}

pub fn is_common_tcp(port: u16) -> bool {
    matches!(
        port,
        20 | 21 | 22 | 25 | 53 | 80 | 110 | 143 | 443 | 465 | 587 | 853 | 993 | 995 | 1433 | 1935 | 2083
            | 2087 | 2096 | 3000 | 3306 | 3389 | 5000 | 5060 | 5061 | 5222 | 5223 | 5228 | 5432 | 5938
            | 6379 | 7680 | 8000 | 8080 | 8443 | 8801..=8810 | 8888 | 9418 | 27017
    )
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub rule: &'static str,
    pub sev: u8, // 1 low, 2 medium, 3 high
    pub title: String,
    pub why: String,
    /// What repeats of the same alert are grouped by (domain, IP, "volume", ...).
    pub group: String,
}

#[derive(Clone, Debug)]
pub struct ProcView {
    pub name: String, // lower-case file name
    pub exe_key: String,
    pub sig: String, // signed | unsigned | invalid | untrusted | unknown | pending
    pub class: Class,
    pub script: Script,
    pub browser: bool,
}

impl ProcView {
    /// Something about the program itself is off.
    pub fn shady(&self) -> bool {
        self.class == Class::Risky
            || matches!(self.sig.as_str(), "unsigned" | "invalid" | "untrusted")
            || self.script == Script::Lolbin
    }
    pub fn well_known(&self) -> bool {
        self.class == Class::System || (self.sig == "signed" && self.class == Class::Installed)
    }
}

pub struct FlowFacts<'a> {
    pub ip: IpAddr,
    pub port: u16,
    pub udp: bool,
    pub domain: &'a str,
    pub out: u64,
    pub inb: u64,
    pub new_connect: bool,
    pub connects: &'a VecDeque<u64>,
}

fn f(rule: &'static str, sev: u8, title: String, why: String, group: String) -> Finding {
    Finding { rule, sev, title, why, group }
}

/// Rules for one remote destination of one process.
pub fn flow_rules(p: &ProcView, x: &FlowFacts) -> Vec<Finding> {
    let mut v = Vec::new();
    if scope(&x.ip) != Scope::Internet {
        return v;
    }
    let ip = x.ip.to_string();
    let dest = if x.domain.is_empty() { ip.clone() } else { x.domain.to_string() };
    let group = if x.domain.is_empty() { ip.clone() } else { base_domain(x.domain) };
    let name = &p.name;
    let shady = p.shady();

    if let Some(kind) = dest_kind(x.domain) {
        match kind {
            IpLookup if !p.browser && x.new_connect => v.push(f(
                "ip_lookup",
                if shady || p.script != Script::None { 3 } else { 2 },
                format!("{name} looked up your public IP address"),
                format!("{name} contacted {dest}, a service that tells a program this PC's public IP and rough location. Info-stealing malware does this first to tag its victim; most normal apps never do."),
                group.clone(),
            )),
            Catcher if x.new_connect || x.out > 0 => v.push(f(
                "catcher",
                if p.browser { 1 } else { 3 },
                format!("{name} contacted a request-catcher service"),
                format!("{dest} records every request sent to it so someone can read it later. Attackers and test tools use these services to receive stolen data without running a server of their own."),
                group.clone(),
            )),
            Tunnel if x.new_connect => v.push(f(
                "tunnel",
                if p.browser { 1 } else if shady || x.out >= MB { 3 } else { 2 },
                format!("{name} connected to a tunnel or dynamic-DNS host"),
                format!("{dest} belongs to a tunnelling / dynamic-DNS service. These hide the real server behind them and are a favourite of remote-access trojans."),
                group.clone(),
            )),
            Share | Paste | Bot if x.out >= 20 * KB => {
                let own_app = kind == Bot && matches!(name.as_str(), "discord.exe" | "telegram.exe" | "slack.exe");
                if !own_app {
                    let label = match kind {
                        Share => "a file-sharing site",
                        Paste => "a paste site",
                        _ => "a bot / webhook API",
                    };
                    v.push(f(
                        "exfil_site",
                        if p.browser { 1 } else if shady || p.script != Script::None || x.out >= MB { 3 } else { 2 },
                        format!("{name} uploaded {} to {label}", fmt_bytes(x.out)),
                        format!("{dest} is {label}. Stealer malware sends files, screenshots and saved passwords to services like this because they need no server of its own."),
                        group.clone(),
                    ));
                }
            }
            _ => {}
        }
    }

    match p.script {
        Script::Lolbin if x.new_connect || x.out > 0 => v.push(f(
            "lolbin",
            3,
            format!("Windows tool {name} is talking to the internet"),
            format!("{name} is a built-in Windows tool that malware abuses to download payloads or send data out (a \"living off the land\" binary). It rarely needs the internet in normal use. Destination: {dest}:{}.", x.port),
            group.clone(),
        )),
        Script::Shell if x.new_connect => v.push(f(
            "script",
            if x.out >= MB { 3 } else { 2 },
            format!("{name} connected to {dest}"),
            "Command-line scripts can download or send anything. If you did not just run a script or tool yourself, look at the command line below.".to_string(),
            group.clone(),
        )),
        _ => {}
    }

    if let Some(desc) = bad_port(x.port) {
        if x.new_connect || x.out > 0 {
            v.push(f(
                "bad_port",
                if name == "tor.exe" { 2 } else { 3 },
                format!("Connection on suspicious port {}", x.port),
                format!("{name} talked to {dest}:{}; {desc}.", x.port),
                format!("port{}", x.port),
            ));
        }
    } else if !x.udp && !is_common_tcp(x.port) && x.out >= 5 * MB && x.out >= 2 * x.inb {
        v.push(f(
            "odd_port",
            if shady { 3 } else { 2 },
            format!("{} uploaded on non-standard port {}", name, x.port),
            format!("{name} sent {} to {dest}:{}. That is not a normal web port, so the protocol is unknown. Custom or self-encrypted channels like this are a common way to move data out unnoticed.", fmt_bytes(x.out), x.port),
            group.clone(),
        ));
    }

    // Email and FTP straight from a program: a classic way stealers ship what they took.
    if !x.udp && (x.new_connect || x.out > 0) && name != "system" && !p.browser {
        let sev = if shady || p.script != Script::None { 3 } else if p.well_known() { 1 } else { 2 };
        if MAIL_PORTS.contains(&x.port) && !is_mail_client(name) {
            v.push(f(
                "mail_out",
                sev,
                format!("{name} is sending email by itself"),
                format!("{name} connected to the mail server {dest}:{}. Normally only your email app does that. {} Backup and scanner programs sometimes send report emails.", x.port, rules().mail_why),
                group.clone(),
            ));
        } else if FTP_PORTS.contains(&x.port) && !is_ftp_client(name) && p.script != Script::Lolbin {
            v.push(f(
                "ftp_out",
                sev,
                format!("{name} is using FTP to {dest}"),
                "FTP is an old file-upload protocol. Stealers use it to upload stolen passwords and files to the attacker's server; normal programs rarely use it any more. It sends everything unencrypted, the password included.".to_string(),
                group.clone(),
            ));
        }
    }

    if p.class == Class::Risky && x.new_connect {
        v.push(f(
            "risky_folder",
            if p.sig == "signed" { 2 } else { 3 },
            format!("{name} runs from a download/temp folder and went online"),
            "Programs started from Downloads, Temp or a bare AppData folder (email attachments, cracked tools, fake installers) are the most common way PCs get infected.".to_string(),
            "location".into(),
        ));
    }
    if p.sig == "invalid" && x.new_connect {
        v.push(f(
            "bad_signature",
            3,
            format!("{name} has a broken signature and went online"),
            "The file's digital signature does not match its contents, so it was modified after the publisher signed it.".to_string(),
            "signature".into(),
        ));
    } else if matches!(p.sig.as_str(), "unsigned" | "untrusted") && p.class != Class::System && x.out >= 512 * KB {
        v.push(f(
            "unsigned",
            2,
            format!("Unsigned program {name} sent {}", fmt_bytes(x.out)),
            "The program carries no valid publisher signature. Legit software usually does; malware usually does not.".to_string(),
            "signature".into(),
        ));
    }

    if x.domain.is_empty() && !x.udp && !p.browser && name != "system" && x.out >= MB {
        v.push(f(
            "bare_ip",
            if shady { 2 } else { 1 },
            format!("{name} sent {} to a bare IP address", fmt_bytes(x.out)),
            format!("{name} sent data to {ip}:{} without looking up a name first. Hard-coded addresses are typical of malware control servers (some apps and games do it legitimately).", x.port),
            group.clone(),
        ));
    }

    if x.new_connect {
        if let Some((mean, cv)) = beacon(x.connects) {
            v.push(f(
                "beacon",
                if p.well_known() { 1 } else if shady || p.script != Script::None { 3 } else { 2 },
                format!("{name} checks in with {dest} on a timer"),
                format!("{name} reconnected to {dest} {} times, every {} on the dot (±{:.0}%). Malware \"beacons\" to its control server like this while it waits for commands; updaters sometimes do too.", x.connects.len(), fmt_secs(mean), cv * 100.0),
                group,
            ));
        }
    }
    v
}

/// Regular reconnects: last 8 connects, mean interval 10 s..1 h, jitter under 15 %.
pub fn beacon(c: &VecDeque<u64>) -> Option<(f64, f64)> {
    if c.len() < 8 {
        return None;
    }
    let last: Vec<u64> = c.iter().rev().take(8).copied().collect();
    let iv: Vec<f64> = last.windows(2).map(|w| w[0].abs_diff(w[1]) as f64 / 1000.0).collect();
    let mean = iv.iter().sum::<f64>() / iv.len() as f64;
    if !(10.0..=3600.0).contains(&mean) {
        return None;
    }
    let sd = (iv.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / iv.len() as f64).sqrt();
    let cv = sd / mean;
    (cv < 0.15).then_some((mean, cv))
}

/// Whole-process upload volume over the last minute (internet only).
pub fn upload_rule(p: &ProcView, out: u64, inb: u64, threshold: u64, top_dest: &str) -> Option<Finding> {
    if out < threshold || out < 2 * inb {
        return None;
    }
    let sev = if p.well_known() { 1 } else if p.shady() || p.script != Script::None { 3 } else { 2 };
    Some(f(
        "upload",
        sev,
        format!("{} uploaded {} in the last minute", p.name, fmt_bytes(out)),
        format!("Most of it went to {top_dest}. Sending far more than it receives is what a file or photo upload looks like. If you are not uploading or syncing something yourself, block it."),
        "volume".into(),
    ))
}

const DNS_NOISY: &[&str] = &[
    "cloudfront.net", "akamaiedge.net", "akamai.net", "akadns.net", "edgekey.net", "trafficmanager.net",
    "amazonaws.com", "azureedge.net", "azurefd.net", "googlevideo.com", "1e100.net", "gvt1.com", "gvt2.com",
    "googleusercontent.com", "windowsupdate.com", "msedge.net", "microsoft.com", "office.com", "office.net",
    "live.com", "arpa", "local", "sentry.io", "doubleclick.net", "googlesyndication.com", "cloudflare.net",
    "fastly.net", "llnwd.net", "spotify.com", "steamcontent.com", "lan", "home",
];

fn noisy(name: &str) -> bool {
    DNS_NOISY.iter().any(|d| domain_is(name, d))
}

/// One odd-looking lookup: a very long or random label.
pub fn dns_long_label(name: &str) -> Option<(usize, f64)> {
    if noisy(name) {
        return None;
    }
    let lab = name.split('.').max_by_key(|l| l.len())?;
    let (len, ent) = (lab.len(), entropy(lab));
    (len >= 40 || (len >= 24 && ent >= 3.9)).then_some((len, ent))
}

pub fn dns_long_finding(p: &ProcView, q: &str, len: usize) -> Finding {
    f(
        "dns_odd",
        if p.shady() || p.script != Script::None { 2 } else { 1 },
        format!("{} looked up an unusual name", p.name),
        format!("{q} has a {len}-character random-looking part. DNS tunnelling hides data inside names like this; a single case is usually just a tracking ID."),
        base_domain(q),
    )
}

/// A connection to or from a server on a threat list.
pub fn intel_finding(name: &str, inbound: bool, dest: &str, port: u16, h: &crate::intel::Hit) -> Finding {
    let what = if h.what.is_empty() { String::new() } else { format!(", reported as \"{}\"", h.what) };
    if inbound {
        f(
            "known_bad",
            h.sev,
            format!("A known attacker connected to this PC: {dest}"),
            format!("{dest} is on the {} list of {}{what}. It reached {name} on port {port}. Block the address. If {name} is Remote Desktop, file sharing or a server you run, check it is up to date and not open to the internet (Network → Listening ports → Block incoming).", h.list, h.desc),
            dest.to_string(),
        )
    } else {
        f(
            "known_bad",
            h.sev,
            format!("{name} connected to a known malware server"),
            format!("{dest} (port {port}) is on the {} list of {}{what}. Normal programs never talk to these servers: {name} is very likely malware, or something running inside it is, waiting for commands or sending stolen data. Block the program and the address, end it, then run a Microsoft Defender Offline scan (Windows Security → Virus & threat protection → Scan options).", h.list, h.desc),
            dest.to_string(),
        )
    }
}

/// A program looked up the name of a server on a threat list.
pub fn intel_dns_finding(p: &ProcView, q: &str, h: &crate::intel::Hit) -> Finding {
    let what = if h.what.is_empty() { String::new() } else { format!(", reported as \"{}\"", h.what) };
    f(
        "known_bad",
        h.sev,
        format!("{} looked up a known malware server: {q}", p.name),
        format!("{q} is on the {} list of {}{what}. Looking it up is the step right before connecting. If {} is not a security tool, block it and the site, end it, and run a Microsoft Defender Offline scan.", h.list, h.desc, p.name),
        q.to_string(),
    )
}

pub fn dns_burst_threshold() -> usize {
    40
}

pub fn dns_burst_finding(p: &ProcView, base: &str, count: usize) -> Option<Finding> {
    if noisy(base) {
        return None;
    }
    Some(f(
        "dns_tunnel",
        if p.browser { 1 } else { 3 },
        format!("Possible DNS tunnelling to {base}"),
        format!("{} looked up {count} different names under {base} within one minute. Encoding data into DNS lookups is a way to sneak it out even when other traffic is blocked.", p.name),
        base.to_string(),
    ))
}

// ---------------------------------------------------------------- mail / FTP clients

const MAIL_PORTS: [u16; 4] = [25, 465, 587, 2525];
const FTP_PORTS: [u16; 3] = [21, 990, 2121];

pub fn is_mail_client(name: &str) -> bool {
    matches!(
        name,
        "outlook.exe" | "olk.exe" | "hxoutlook.exe" | "hxtsr.exe" | "thunderbird.exe" | "betterbird.exe"
            | "mailbird.exe" | "mailclient.exe" | "thebat.exe" | "thebat64.exe" | "postbox.exe" | "mailspring.exe"
            | "foxmail.exe" | "sylpheed.exe" | "claws-mail.exe" | "seamonkey.exe" | "emclient.exe" | "winmail.exe"
            | "pegasus.exe" | "evolution.exe" | "mailmaster.exe" | "spike.exe"
    )
}

pub fn is_ftp_client(name: &str) -> bool {
    matches!(
        name,
        "filezilla.exe" | "winscp.exe" | "cyberduck.exe" | "coreftp.exe" | "flashfxp.exe" | "smartftp.exe"
            | "totalcmd.exe" | "totalcmd64.exe" | "cuteftp.exe" | "ftprush.exe" | "wsftppro.exe"
            | "freecommander.exe" | "doublecmd.exe" | "explorer.exe"
    )
}

// ---------------------------------------------------------------- remote control

/// Remote-control / screen-sharing tools. Legit, and also what "support" scammers install.
pub fn remote_tool(name: &str) -> Option<&'static str> {
    Some(match name {
        "anydesk.exe" => "AnyDesk",
        "teamviewer.exe" | "teamviewer_service.exe" | "tv_w32.exe" | "tv_x64.exe" | "teamviewer_desktop.exe" => "TeamViewer",
        "rustdesk.exe" => "RustDesk",
        "screenconnect.clientservice.exe" | "screenconnect.windowsclient.exe" | "connectwisecontrol.client.exe" => "ScreenConnect",
        "quickassist.exe" => "Quick Assist",
        "msra.exe" => "Windows Remote Assistance",
        "remoting_host.exe" | "remoting_desktop.exe" => "Chrome Remote Desktop",
        "ultraviewer_service.exe" | "ultraviewer_desktop.exe" | "ultraviewer.exe" => "UltraViewer",
        "supremo.exe" | "supremoservice.exe" | "supremohelper.exe" => "Supremo",
        "aeroadmin.exe" => "AeroAdmin",
        "aa_v3.exe" | "ammyy_admin.exe" => "Ammyy Admin",
        "client32.exe" => "NetSupport",
        "dwagent.exe" | "dwagsvc.exe" => "DWService",
        "meshagent.exe" => "MeshCentral",
        "srservice.exe" | "srstreamer.exe" | "strwinclt.exe" | "srmanager.exe" => "Splashtop",
        "logmein.exe" | "lmiguardiansvc.exe" | "lmi_rescue.exe" => "LogMeIn",
        "tvnserver.exe" => "TightVNC",
        "winvnc.exe" => "UltraVNC",
        "vncserver.exe" | "vncserverui.exe" => "RealVNC",
        "parsecd.exe" => "Parsec",
        "ateraagent.exe" | "atera_agent.exe" => "Atera",
        "rutserv.exe" | "rfusclient.exe" => "Remote Utilities",
        "rserver3.exe" => "Radmin",
        _ => return None,
    })
}

/// Upload in one minute from a remote-control tool that means a screen is being streamed.
pub const SESSION_BYTES: u64 = 600 * KB;

pub fn remote_session_finding(p: &ProcView, label: &str, out: u64, dest: &str) -> Finding {
    f(
        "remote_session",
        3,
        format!("{label} is sending this screen to another computer"),
        format!("{} sent {} in the last minute to {dest}. That is what screen sharing looks like: someone may be watching or controlling this PC right now. If you did not start a support session yourself, close {label}, block it, and change your passwords from another device. Fake bank, Microsoft and delivery \"support\" callers use these tools.", p.name, fmt_bytes(out)),
        "session".into(),
    )
}

/// Local ports that give remote control or a remote command line.
pub fn remote_port(port: u16) -> Option<&'static str> {
    match port {
        3389 => Some("Remote Desktop"),
        5900..=5903 => Some("VNC remote control"),
        5938 => Some("TeamViewer"),
        7070 => Some("AnyDesk"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        5985 | 5986 => Some("WinRM remote management"),
        _ => None,
    }
}

/// Rules for a connection another device opened TO this PC. `x.port` is the local port,
/// `x.out` what this PC sent back over it.
pub fn inbound_rules(p: &ProcView, x: &FlowFacts) -> Vec<Finding> {
    let mut v = Vec::new();
    let ip = x.ip.to_string();
    let who = if x.domain.is_empty() { ip.clone() } else { format!("{} ({ip})", x.domain) };
    let group = format!("in{}", x.port);
    let name = &p.name;
    let svc = remote_port(x.port);
    match scope(&x.ip) {
        Scope::Internet if x.new_connect => {
            let (sev, title, why) = if let Some(s) = svc {
                (3, format!("Someone on the internet connected to {s} on this PC"),
                 format!("{who} opened a {s} connection to this PC (port {}, handled by {name}). That gives remote control or a remote command line. If you did not set this up, turn the feature off, use Block incoming on the Network tab, and change your Windows password.", x.port))
            } else if matches!(x.port, 139 | 445) {
                (3, "File sharing on this PC was reached from the internet".to_string(),
                 format!("{who} connected to Windows file sharing (port {}). It should never be reachable from the internet: your router or firewall lets it through. Use Block incoming on the Network tab.", x.port))
            } else {
                (if p.well_known() { 1 } else if p.shady() || p.script != Script::None { 3 } else { 2 },
                 format!("A device on the internet connected to {name}"),
                 format!("{who} connected to {name} on port {}. Games, file-sharing and some chat apps accept connections like this; remote-access trojans do too. If you don't know why {name} is open to the internet, use Block incoming on the Network tab.", x.port))
            };
            v.push(f("inbound", sev, title, why, group));
        }
        Scope::Lan => {
            if let (Some(s), true) = (svc, x.new_connect) {
                v.push(f("inbound", 2, format!("A device on your network connected to {s}"),
                    format!("{who} opened a {s} connection to this PC (port {}). Fine if that is you or your IT department; otherwise turn the feature off or use Block incoming on the Network tab.", x.port), group));
            } else if matches!(x.port, 139 | 445) && x.out >= 50 * MB {
                v.push(f("smb_copy", 2, format!("Another device copied {} from this PC's shared folders", fmt_bytes(x.out)),
                    format!("{who} read {} from this PC over Windows file sharing. Fine if that is another of your computers; otherwise stop sharing those folders (right-click the folder → Properties → Sharing).", fmt_bytes(x.out)), group));
            }
        }
        _ => {}
    }
    v
}

// ---------------------------------------------------------------- files stealers go for

/// Which files stealers go for, and who may open them; ports and family names malware is known
/// for. Loaded from ui/rules.json (compressed into kestryl.exe like the UI): kept out of the
/// program as plain text because antivirus scanners take a program carrying that list for a
/// stealer or a backdoor.
#[derive(serde::Deserialize, Default, Debug)]
pub struct Rules {
    #[serde(default)]
    pub secrets: Vec<SecretRule>,
    #[serde(default)]
    pub owners: std::collections::HashMap<String, Owner>,
    #[serde(default)]
    pub samples: Vec<(String, String)>,
    #[serde(default)]
    pub demo_mail: String,
    /// (ports, why) for the `bad_port` alert.
    #[serde(default)]
    pub ports: Vec<(Vec<u16>, String)>,
    /// One sentence for the `mail_out` alert: which stealers send email.
    #[serde(default)]
    pub mail_why: String,
    /// The --simulate demo's threat-list entries: [IP list line, ThreatFox family].
    #[serde(default)]
    pub demo_intel: Vec<String>,
}

#[derive(serde::Deserialize, Default, Debug)]
pub struct SecretRule {
    pub kind: String,
    pub label: String,
    /// Every inner list needs one hit (substring of the lower-case path).
    #[serde(default)]
    pub any: Vec<Vec<String>>,
    /// The path ends with one of these (when given).
    #[serde(default)]
    pub end: Vec<String>,
}

#[derive(serde::Deserialize, Default, Debug)]
pub struct Owner {
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub prefix: Vec<String>,
    /// Folder fragments of the program's own path.
    #[serde(default)]
    pub dirs: Vec<String>,
    #[serde(default)]
    pub browser: bool,
    #[serde(default)]
    pub sync: bool,
}

static RULES: std::sync::OnceLock<Rules> = std::sync::OnceLock::new();

pub fn load_rules(bytes: &[u8]) -> Result<usize, String> {
    let r: Rules = serde_json::from_slice(bytes).map_err(|e| format!("rules.json: {e}"))?;
    let n = r.secrets.len();
    RULES.set(r).map_err(|_| "rules were already loaded".to_string())?;
    Ok(n)
}

pub fn rules() -> &'static Rules {
    RULES.get_or_init(|| {
        #[cfg(test)]
        if let Ok(b) = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../ui/rules.json")) {
            if let Ok(r) = serde_json::from_slice(&b) {
                return r;
            }
        }
        Rules::default()
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secret {
    pub kind: &'static str,
    pub label: &'static str,
}

/// What a file holds, when it is something password stealers go for. `p` is a lower-case path.
pub fn secret_file(p: &str) -> Option<Secret> {
    if !p.contains("\\users\\") {
        return None;
    }
    rules()
        .secrets
        .iter()
        .find(|r| {
            (!r.any.is_empty() || !r.end.is_empty())
                && r.any.iter().all(|g| g.iter().any(|s| p.contains(s.as_str())))
                && (r.end.is_empty() || r.end.iter().any(|e| p.ends_with(e.as_str())))
        })
        .map(|r| Secret { kind: r.kind.as_str(), label: r.label.as_str() })
}

/// Who normally opens this kind of file.
pub fn secret_owner_desc(kind: &str) -> &'static str {
    match kind {
        "passwords" | "cookies" | "cards" | "browser_key" => "your web browser",
        "wallet" => "your wallet app or browser",
        "telegram" => "Telegram",
        "discord" => "Discord",
        "steam" => "Steam",
        "keys" => "SSH, git and cloud tools",
        "mailbox" => "Outlook",
        "vault" => "your password manager",
        _ => "Windows itself",
    }
}

const BROWSER_HELPERS: [&str; 6] = [
    "elevation_service.exe", "notification_helper.exe", "chrome_proxy.exe", "chrome_pwa_launcher.exe", "msedge_proxy.exe", "identity_helper.exe",
];

/// Cloud sync and backup clients: reading files and uploading them is their job.
pub fn is_sync_client(name: &str) -> bool {
    matches!(
        name,
        "onedrive.exe" | "dropbox.exe" | "googledrivefs.exe" | "box.exe" | "nextcloud.exe" | "owncloud.exe"
            | "pcloud.exe" | "megasync.exe" | "synologydrive.exe" | "cloudstation.exe" | "idrive.exe"
            | "bztransmit.exe" | "bztransmit64.exe" | "bzfilelist.exe" | "crashplanservice.exe"
            | "veeam.endpoint.service.exe" | "reflectservice.exe" | "icloudphotos.exe" | "icloud.exe"
    )
}

/// The program whose job it is to open this kind of file.
pub fn secret_owner(kind: &str, name: &str, exe: &str) -> bool {
    let Some(o) = rules().owners.get(kind) else { return false };
    (o.browser && (is_browser(name) || BROWSER_HELPERS.contains(&name)))
        || (o.sync && is_sync_client(name))
        || o.names.iter().any(|n| n == name)
        || o.prefix.iter().any(|p| name.starts_with(p.as_str()))
        || o.dirs.iter().any(|d| exe.contains(d.as_str()))
}

/// Virus scanners and Windows Search open every file; their reads mean nothing.
pub fn file_silent(name: &str, exe: &str) -> bool {
    match name {
        // An empty path means a protected process (Defender runs protected; a fake can't).
        "msmpeng.exe" | "mpdefendercoreservice.exe" | "nissrv.exe" | "mpcmdrun.exe" | "mpcopyaccelerator.exe" => {
            exe.is_empty() || exe.contains("\\windows defender") || exe.starts_with("c:\\windows\\")
        }
        "mssense.exe" | "sensendr.exe" => exe.contains("\\windows defender advanced threat protection\\"),
        "searchprotocolhost.exe" | "searchindexer.exe" | "searchfilterhost.exe" => exe.starts_with("c:\\windows\\"),
        "system" | "registry" | "memory compression" => true,
        _ => false,
    }
}

const DOC_EXT: [&str; 28] = [
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".odt", ".ods", ".csv", ".jpg",
    ".jpeg", ".png", ".heic", ".bmp", ".gif", ".webp", ".tif", ".tiff", ".raw", ".cr2", ".nef", ".arw", ".dng", ".mp4", ".mov",
];

/// A document or photo in one of the user's own folders (lower-case path).
pub fn user_doc(p: &str) -> bool {
    p.contains("\\users\\")
        && !p.contains("\\appdata\\")
        && ["\\documents\\", "\\desktop\\", "\\pictures\\", "\\downloads\\", "\\videos\\", "\\onedrive"].iter().any(|d| p.contains(d))
        && DOC_EXT.iter().any(|e| p.ends_with(e))
}

/// Distinct documents one program must read within a few minutes to count as "collecting".
pub const DOCS_COLLECT: usize = 20;

pub fn secret_read_finding(p: &ProcView, s: &Secret, path: &str) -> Finding {
    let sev = if p.shady() || matches!(p.script, Script::Shell | Script::Lolbin) {
        3
    } else if p.script == Script::Interpreter || p.sig != "signed" {
        2
    } else {
        1
    };
    f(
        "secret_read",
        sev,
        format!("{} opened {}", p.name, s.label),
        format!("{} opened {path}. That file holds {}; normally only {} opens it. Password stealers read exactly these files; so do backups and password-manager imports. If you did not just import or back up, block {} and end it.", p.name, s.label, secret_owner_desc(s.kind), p.name),
        s.kind.to_string(),
    )
}

pub fn secret_upload_finding(p: &ProcView, label: &str, path: &str, sent: u64, dest: &str) -> Finding {
    f(
        "secret_upload",
        if p.shady() || p.script != Script::None { 3 } else if p.well_known() { 1 } else { 2 },
        format!("{} read {label} and then sent {} out", p.name, fmt_bytes(sent)),
        format!("{} opened {label} ({path}) and within minutes sent {} to {dest}. That is what a password stealer does. If you were not importing passwords into another app or running a backup: block {} now, end it, then change your passwords and sign out of all sessions from another device.", p.name, fmt_bytes(sent), p.name),
        "secret".into(),
    )
}

pub fn docs_upload_finding(p: &ProcView, n: usize, sent: u64, dest: &str) -> Finding {
    f(
        "docs_upload",
        if p.shady() || p.script != Script::None { 3 } else if p.well_known() { 1 } else { 2 },
        format!("{} read {n} of your documents or photos and then uploaded {}", p.name, fmt_bytes(sent)),
        format!("{} opened {n} files from Documents, Desktop, Pictures, Downloads or OneDrive within a few minutes and then sent {} to {dest}. Cloud backup and photo apps do this; so do file-stealing programs. If you don't know why {} does it, block it.", p.name, fmt_bytes(sent), p.name),
        "docs".into(),
    )
}

/// The internet's root name servers and the .com/.net name servers. A DNS referral can
/// list them next to a looked-up name; they are never that name's own address.
pub fn is_dns_infra(ip: &IpAddr) -> bool {
    const LIST: &[&str] = &[
        // root servers a-m (b's old and new address)
        "198.41.0.4", "170.247.170.2", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241",
        "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33",
        "2001:503:ba3e::2:30", "2801:1b8:10::b", "2001:500:200::b", "2001:500:2::c", "2001:500:2d::d", "2001:500:a8::e",
        "2001:500:2f::f", "2001:500:12::d0d", "2001:500:1::53", "2001:7fe::53", "2001:503:c27::2:30", "2001:7fd::1",
        "2001:500:9f::42", "2001:dc3::35",
        // a-m.gtld-servers.net (.com and .net)
        "192.5.6.30", "192.33.14.30", "192.26.92.30", "192.31.80.30", "192.12.94.30", "192.35.51.30", "192.42.93.30",
        "192.54.112.30", "192.43.172.30", "192.48.79.30", "192.52.178.30", "192.41.162.30", "192.55.83.30",
    ];
    LIST.iter().any(|s| s.parse::<IpAddr>().is_ok_and(|x| x == *ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(name: &str, exe: &str, sig: &str) -> ProcView {
        let exe = exe.to_lowercase();
        ProcView {
            name: name.into(),
            exe_key: exe.clone(),
            sig: sig.into(),
            class: classify(&exe),
            script: script_kind(name),
            browser: is_browser(name),
        }
    }

    fn facts<'a>(ip: &str, port: u16, domain: &'a str, out: u64, c: &'a VecDeque<u64>) -> FlowFacts<'a> {
        FlowFacts { ip: ip.parse().unwrap(), port, udp: false, domain, out, inb: 1000, new_connect: true, connects: c }
    }

    #[test]
    fn classes() {
        assert_eq!(classify(r"c:\users\a\appdata\local\temp\x.exe"), Class::Risky);
        assert_eq!(classify(r"c:\users\a\appdata\roaming\svch0st.exe"), Class::Risky);
        assert_eq!(classify(r"c:\users\a\appdata\local\discord\app-1\discord.exe"), Class::User);
        assert_eq!(classify(r"c:\windows\system32\svchost.exe"), Class::System);
        assert_eq!(classify(r"c:\program files\google\chrome\application\chrome.exe"), Class::Installed);
        assert_eq!(classify(r"c:\users\a\downloads\setup.exe"), Class::Risky);
    }

    #[test]
    fn stealer_upload_is_high() {
        let c = VecDeque::new();
        let p = view("invoice.exe", r"C:\Users\a\Downloads\invoice.exe", "unsigned");
        let r = flow_rules(&p, &facts("203.0.113.5", 443, "transfer.sh", 3 * MB, &c));
        let ex = r.iter().find(|f| f.rule == "exfil_site").expect("exfil");
        assert_eq!(ex.sev, 3);
        assert!(r.iter().any(|f| f.rule == "risky_folder"));
        assert!(r.iter().any(|f| f.rule == "unsigned"));
    }

    #[test]
    fn browser_upload_is_low_and_lan_ignored() {
        let c = VecDeque::new();
        let p = view("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "signed");
        let r = flow_rules(&p, &facts("203.0.113.5", 443, "wetransfer.com", 5 * MB, &c));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].sev, 1);
        assert!(flow_rules(&p, &facts("192.168.1.10", 4444, "", 50 * MB, &c)).is_empty());
    }

    #[test]
    fn script_and_ip_lookup() {
        let c = VecDeque::new();
        let p = view("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "signed");
        let r = flow_rules(&p, &facts("203.0.113.9", 443, "api.ipify.org", 0, &c));
        assert!(r.iter().any(|f| f.rule == "ip_lookup" && f.sev == 3));
        assert!(r.iter().any(|f| f.rule == "script"));
        let m = view("mshta.exe", r"C:\Windows\System32\mshta.exe", "signed");
        assert!(flow_rules(&m, &facts("203.0.113.9", 80, "", 0, &c)).iter().any(|f| f.rule == "lolbin" && f.sev == 3));
    }

    #[test]
    fn ports() {
        let c = VecDeque::new();
        let p = view("app.exe", r"C:\Program Files\App\app.exe", "signed");
        assert!(flow_rules(&p, &facts("198.51.100.7", 4444, "", 10, &c)).iter().any(|f| f.rule == "bad_port"));
        assert!(flow_rules(&p, &facts("198.51.100.7", 7001, "x.example.com", 6 * MB, &c)).iter().any(|f| f.rule == "odd_port"));
        assert!(flow_rules(&p, &facts("198.51.100.7", 443, "x.example.com", 6 * MB, &c)).is_empty());
    }

    #[test]
    fn beacons() {
        let regular: VecDeque<u64> = (0..10).map(|i| 1_000_000 + i * 30_000 + (i % 3) * 200).collect();
        let (mean, cv) = beacon(&regular).unwrap();
        assert!((mean - 30.0).abs() < 1.0 && cv < 0.05);
        let random: VecDeque<u64> = [0u64, 12, 90, 95, 300, 302, 900, 905, 1500].iter().map(|s| s * 1000).collect();
        assert!(beacon(&random).is_none());
        let fast: VecDeque<u64> = (0..10).map(|i| i * 1000).collect();
        assert!(beacon(&fast).is_none());
    }

    #[test]
    fn dns() {
        assert!(dns_long_label("a8f3k2m9x7q1z5w4b6n0c3v8x1z7k2m9.d.exfil-example.net").is_some());
        assert!(dns_long_label("www.google.com").is_none());
        assert!(dns_long_label("a8f3k2m9x7q1z5w4b6n0c3v8x1z7k2m9.cloudfront.net").is_none());
        let p = view("svc.exe", r"C:\Users\a\AppData\Roaming\svc.exe", "unsigned");
        assert_eq!(dns_burst_finding(&p, "exfil-example.net", 45).unwrap().sev, 3);
    }

    #[test]
    fn upload_volume() {
        let signed = view("onedrive.exe", r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "signed");
        assert_eq!(upload_rule(&signed, 30 * MB, MB, 20 * MB, "x").unwrap().sev, 1);
        let odd = view("tool.exe", r"C:\Users\a\Desktop\tool.exe", "unsigned");
        assert_eq!(upload_rule(&odd, 30 * MB, MB, 20 * MB, "x").unwrap().sev, 3);
        assert!(upload_rule(&odd, 30 * MB, 20 * MB, 20 * MB, "x").is_none()); // video-call shaped
        assert!(upload_rule(&odd, 5 * MB, 0, 20 * MB, "x").is_none());
    }

    #[test]
    fn mail_and_ftp() {
        let c = VecDeque::new();
        let bad = view("stub.exe", r"C:\Users\a\AppData\Roaming\Stub\stub.exe", "unsigned");
        let r = flow_rules(&bad, &facts("203.0.113.8", 587, "smtp.mail-host.example", 40 * KB, &c));
        assert!(r.iter().any(|f| f.rule == "mail_out" && f.sev == 3), "{r:?}");
        let outlook = view("outlook.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "signed");
        assert!(flow_rules(&outlook, &facts("203.0.113.8", 587, "smtp.office365.com", 40 * KB, &c)).is_empty());
        let r = flow_rules(&bad, &facts("203.0.113.9", 21, "", 10 * KB, &c));
        assert!(r.iter().any(|f| f.rule == "ftp_out"));
        let fz = view("filezilla.exe", r"C:\Program Files\FileZilla FTP Client\filezilla.exe", "signed");
        assert!(flow_rules(&fz, &facts("203.0.113.9", 21, "ftp.example.com", 10 * KB, &c)).is_empty());
    }

    #[test]
    fn inbound() {
        let c = VecDeque::new();
        let rdp = view("svchost.exe", r"C:\Windows\System32\svchost.exe", "signed");
        let r = inbound_rules(&rdp, &facts("198.51.100.23", 3389, "", 2 * MB, &c));
        assert_eq!(r[0].rule, "inbound");
        assert_eq!(r[0].sev, 3);
        let lan = inbound_rules(&rdp, &facts("192.168.1.20", 3389, "", 0, &c));
        assert_eq!(lan[0].sev, 2);
        let sys = view("system", "", "signed");
        assert!(inbound_rules(&sys, &facts("192.168.1.20", 445, "", 5 * MB, &c)).is_empty());
        assert_eq!(inbound_rules(&sys, &facts("192.168.1.20", 445, "", 80 * MB, &c))[0].rule, "smb_copy");
        assert_eq!(inbound_rules(&sys, &facts("198.51.100.4", 445, "", 0, &c))[0].sev, 3);
        assert_eq!(remote_tool("anydesk.exe"), Some("AnyDesk"));
        assert_eq!(remote_tool("chrome.exe"), None);
    }

    /// A sample path of this kind from rules.json (tests keep such paths out of the binary too).
    pub fn sample(kind: &str) -> String {
        rules().samples.iter().find(|(k, _)| k == kind).map(|(_, p)| p.clone()).expect("sample in rules.json")
    }

    #[test]
    fn secret_files() {
        assert!(rules().secrets.len() >= 15, "rules.json loaded");
        for (kind, path) in &rules().samples {
            let got = secret_file(&path.to_lowercase()).map(|s| s.kind).unwrap_or("none");
            assert_eq!(got, kind, "{path}");
        }
        assert!(secret_owner("passwords", "chrome.exe", ""));
        assert!(!secret_owner("passwords", "updater.exe", ""));
        let tdir = &rules().owners["telegram"].dirs[0];
        assert!(secret_owner("telegram", "updater.exe", &format!(r"c:\users\a\appdata\roaming{tdir}updater.exe")));
        assert!(file_silent("msmpeng.exe", r"c:\programdata\microsoft\windows defender\platform\4.18\msmpeng.exe"));
        assert!(!file_silent("msmpeng.exe", r"c:\users\a\appdata\roaming\msmpeng.exe"));
        assert!(user_doc(r"c:\users\a\documents\taxes 2025.pdf"));
        assert!(!user_doc(r"c:\users\a\appdata\local\temp\x.png"));
        let p = view("stub.exe", r"C:\Users\a\AppData\Roaming\Stub\stub.exe", "unsigned");
        let s = secret_file(&sample("passwords").to_lowercase()).unwrap();
        assert_eq!(secret_read_finding(&p, &s, "x").sev, 3);
        let backup = view("backup.exe", r"C:\Program Files\Backup\backup.exe", "signed");
        assert_eq!(secret_read_finding(&backup, &s, "x").sev, 1);
        assert_eq!(secret_upload_finding(&p, s.label, "x", 200 * KB, "x").sev, 3);
    }
}
