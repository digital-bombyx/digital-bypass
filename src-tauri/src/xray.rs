//! Xray: `xray.exe` и базы geoip/geosite из официального релиза XTLS
//! (`scripts/sync-xray.mjs`), свои серверы и подписки, маршрутизация.
//!
//! Конфиг собирается заново при каждом запуске:
//! - вход `mixed` (SOCKS5 + HTTP) на 127.0.0.1:`port`, sniffing для правил по доменам;
//! - выбранный сервер (`proxy`) или «авто» — все серверы под балансировщиком
//!   `leastPing` с наблюдателем (observatory);
//! - правила: блок → свои «через сервер» → свои «напрямую» → частные сети →
//!   RU (geosite:category-ru, .ru/.su/.рф, geoip:ru) → остальное через сервер;
//! - DNS без утечек: российские домены — системным резолвером, остальные — DoH
//!   через сервер; `IPIfNonMatch` — чтобы geoip:ru срабатывал и для доменов.
//!   Системный DNS для остальных нельзя: провайдер отвечает заглушками из РФ,
//!   и заблокированный сайт ушёл бы «напрямую».
use crate::xraylinks::{Server, SubInfo};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// User-Agent подписок: панели (Marzban, 3x-ui, Remnawave) выбирают формат по нему.
pub const SUB_UA: &str = "v2rayN/7.0 digital-bypass";
/// «Сервер» `auto` — балансировщик по задержке.
pub const AUTO: &str = "auto";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sub {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub info: SubInfo,
    /// Unix-время последнего удачного обновления.
    #[serde(default)]
    pub updated: u64,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub id: String,
    /// Подписка (None — добавлен вручную).
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(flatten)]
    pub server: Server,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Routing {
    /// Российские сайты и адреса — напрямую.
    pub ru_direct: bool,
    /// Реклама (geosite:category-ads-all) — блок.
    pub ads_block: bool,
    /// Свои списки: домены, `geosite:…`, `geoip:…`, IP/CIDR.
    pub direct: Vec<String>,
    pub proxy: Vec<String>,
    pub block: Vec<String>,
}

impl Default for Routing {
    fn default() -> Self {
        Routing { ru_direct: true, ads_block: false, direct: Vec::new(), proxy: Vec::new(), block: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub port: u16,
    pub subs: Vec<Sub>,
    pub servers: Vec<Entry>,
    /// id сервера или `auto`.
    pub selected: String,
    pub routing: Routing,
    /// Нарезка ClientHello к серверу (finalmask fragment) — если сервер режут по SNI.
    pub fragment: bool,
    pub enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        // 10808/10809 обычно заняты v2rayN — берём свой порт.
        Config { port: 10820, subs: Vec::new(), servers: Vec::new(), selected: AUTO.into(), routing: Routing::default(), fragment: false, enabled: false }
    }
}

/// Короткий id по содержимому (sha256, 12 hex).
pub fn short_id(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes()).iter().take(6).map(|b| format!("{b:02x}")).collect()
}

pub fn entry(server: Server, sub: Option<String>) -> Entry {
    let id = short_id(&format!("{}{}", sub.as_deref().unwrap_or(""), server.outbound));
    Entry { id, sub, server }
}

// ---------- конфиг ----------

/// Свои правила: домены → `domain:`, IP/CIDR → ip, `geosite:/geoip:/regexp:/full:/keyword:/domain:` — как есть.
fn split_rules(list: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut dom, mut ip) = (Vec::new(), Vec::new());
    for x in list.iter().map(|x| x.trim()).filter(|x| !x.is_empty() && !x.starts_with('#')) {
        let low = x.to_ascii_lowercase();
        if low.starts_with("geoip:") || x.parse::<std::net::IpAddr>().is_ok() || (x.contains('/') && x.split('/').next().is_some_and(|a| a.parse::<std::net::IpAddr>().is_ok())) {
            ip.push(x.to_string());
        } else if ["geosite:", "regexp:", "full:", "keyword:", "domain:", "ext:"].iter().any(|p| low.starts_with(p)) {
            dom.push(x.to_string());
        } else {
            dom.push(format!("domain:{}", low.trim_start_matches("*.").trim_start_matches('.')));
        }
    }
    (dom, ip)
}

fn rule(out: &str, dom: Vec<String>, ip: Vec<String>, balancer: bool) -> Vec<Value> {
    let key = if balancer && out == "proxy" { "balancerTag" } else { "outboundTag" };
    let target = if balancer && out == "proxy" { AUTO } else { out };
    let mut v = Vec::new();
    if !dom.is_empty() {
        v.push(json!({ "type": "field", "domain": dom, key: target }));
    }
    if !ip.is_empty() {
        v.push(json!({ "type": "field", "ip": ip, key: target }));
    }
    v
}

/// Соединение с тегом; теги цепочки — с префиксом, ссылки dialerProxy переписаны.
fn tagged(e: &Entry, tag: &str, fragment: bool) -> Vec<Value> {
    let mut main = e.server.outbound.clone();
    main["tag"] = json!(tag);
    let mut out = Vec::new();
    let rename = |t: &str| format!("{tag}-{t}");
    if let Some(dp) = main["streamSettings"]["sockopt"]["dialerProxy"].as_str().map(String::from) {
        main["streamSettings"]["sockopt"]["dialerProxy"] = json!(rename(&dp));
    }
    for c in &e.server.chain {
        let mut c = c.clone();
        let t = c["tag"].as_str().unwrap_or("x").to_string();
        c["tag"] = json!(rename(&t));
        if let Some(dp) = c["streamSettings"]["sockopt"]["dialerProxy"].as_str().map(String::from) {
            c["streamSettings"]["sockopt"]["dialerProxy"] = json!(rename(&dp));
        }
        out.push(c);
    }
    // Нарезка первого пакета к серверу — только если у сервера своей нет и нет цепочки.
    let ss = &main["streamSettings"];
    let tls = matches!(ss["security"].as_str(), Some("tls" | "reality"));
    if fragment && tls && ss["finalmask"].is_null() && ss["sockopt"]["dialerProxy"].is_null() {
        main["streamSettings"]["finalmask"] = json!({ "tcp": [{ "type": "fragment", "settings": { "packets": "1-3", "length": "100-200", "delay": "5-15", "maxSplit": "2-4" } }] });
    }
    out.insert(0, main);
    out
}

/// Полный конфиг Xray. `selected` — один сервер или несколько (авто).
pub fn build(cfg: &Config, selected: &[&Entry], auto: bool) -> Value {
    let balancer = auto && selected.len() > 1;
    let mut outbounds: Vec<Value> = Vec::new();
    if balancer {
        for (i, e) in selected.iter().enumerate() {
            outbounds.extend(tagged(e, &format!("p{i}"), cfg.fragment));
        }
    } else if let Some(e) = selected.first() {
        outbounds.extend(tagged(e, "proxy", cfg.fragment));
    }
    outbounds.push(json!({ "tag": "direct", "protocol": "freedom" }));
    outbounds.push(json!({ "tag": "block", "protocol": "blackhole" }));

    let r = &cfg.routing;
    let mut rules: Vec<Value> = Vec::new();
    let (bd, bi) = split_rules(&r.block);
    rules.extend(rule("block", bd, bi, balancer));
    if r.ads_block {
        rules.extend(rule("block", vec!["geosite:category-ads-all".into()], vec![], balancer));
    }
    let (pd, pi) = split_rules(&r.proxy);
    rules.extend(rule("proxy", pd, pi, balancer));
    let (dd, di) = split_rules(&r.direct);
    rules.extend(rule("direct", dd, di, balancer));
    rules.extend(rule("direct", vec!["geosite:private".into()], vec!["geoip:private".into()], balancer));
    let ru_domains: Vec<String> = ["geosite:category-ru", "geosite:category-gov-ru", "domain:ru", "domain:su", "domain:xn--p1ai"].iter().map(|s| s.to_string()).collect();
    if r.ru_direct {
        rules.extend(rule("direct", ru_domains.clone(), vec!["geoip:ru".into()], balancer));
    }
    rules.push(if balancer { json!({ "type": "field", "network": "tcp,udp", "balancerTag": AUTO }) } else { json!({ "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }) });

    let mut routing = json!({ "domainStrategy": if r.ru_direct { "IPIfNonMatch" } else { "AsIs" }, "rules": rules });
    let mut cfgv = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "in", "listen": "127.0.0.1", "port": cfg.port, "protocol": "mixed",
            "settings": { "udp": true },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true }
        }],
        "outbounds": outbounds,
    });
    if r.ru_direct {
        // DoH к Cloudflare идёт через сервер (по правилам), российские домены — системным DNS.
        cfgv["dns"] = json!({
            "servers": [
                { "address": "localhost", "domains": ru_domains, "skipFallback": true },
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query"
            ],
            "queryStrategy": "UseIPv4"
        });
    }
    if balancer {
        routing["balancers"] = json!([{ "tag": AUTO, "selector": ["p"], "strategy": { "type": "leastPing" }, "fallbackTag": "p0" }]);
        cfgv["observatory"] = json!({ "subjectSelector": ["p"], "probeURL": "https://www.gstatic.com/generate_204", "probeInterval": "1m", "enableConcurrency": true });
    }
    cfgv["routing"] = routing;
    cfgv
}

/// Конфиг проверки задержки: по входу SOCKS на сервер, без своих правил.
pub fn build_test(entries: &[&Entry], ports: &[u16]) -> Value {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    for (i, (e, p)) in entries.iter().zip(ports).enumerate() {
        inbounds.push(json!({ "tag": format!("t{i}"), "listen": "127.0.0.1", "port": p, "protocol": "socks", "settings": { "udp": false } }));
        outbounds.extend(tagged(e, &format!("o{i}"), false));
        rules.push(json!({ "type": "field", "inboundTag": [format!("t{i}")], "outboundTag": format!("o{i}") }));
    }
    json!({ "log": { "loglevel": "warning" }, "inbounds": inbounds, "outbounds": outbounds, "routing": { "rules": rules } })
}

// ---------- процесс ----------

/// Порт готового xray (0 — не запущен). Читает прокси-обходчик.
static READY_PORT: AtomicU16 = AtomicU16::new(0);

pub fn ready_port() -> Option<u16> {
    match READY_PORT.load(Ordering::SeqCst) {
        0 => None,
        p => Some(p),
    }
}

pub fn find_dir(resource_dir: Option<&Path>) -> Option<PathBuf> {
    let mut c: Vec<PathBuf> = resource_dir.map(|r| vec![r.join("xray")]).unwrap_or_default();
    if cfg!(debug_assertions) {
        c.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("xray"));
    }
    c.into_iter().find(|d| d.join("xray.exe").is_file() && d.join("geoip.dat").is_file())
}

pub fn version(dir: &Path) -> Option<String> {
    let v: Value = serde_json::from_slice(&std::fs::read(dir.join("bundle.json")).ok()?).ok()?;
    v["version"].as_str().map(String::from)
}

fn xray_cmd(dir: &Path) -> std::process::Command {
    let mut c = crate::util::hidden(dir.join("xray.exe"));
    c.current_dir(dir).env("XRAY_LOCATION_ASSET", dir);
    c
}

/// Проверка конфига самим xray (`run -test`): понятная ошибка до запуска.
pub fn check_config(dir: &Path, path: &Path) -> Result<(), String> {
    let out = xray_cmd(dir).args(["run", "-test", "-c"]).arg(path).output().map_err(|e| format!("xray.exe: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let line = text.lines().rev().find(|l| l.contains("Failed") || l.contains("failed") || l.contains("error")).unwrap_or(text.trim()).trim().to_string();
    Err(crate::tr!("xray не принял конфиг: {line}", "xray rejected the config: {line}"))
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    pub running: bool,
    pub ready: bool,
    pub port: u16,
    /// Имя сервера или «авто (N)».
    pub server: String,
    pub error: Option<String>,
    pub uptime: u64,
}

pub struct Xray {
    child: Arc<Mutex<Option<Child>>>,
    log: Arc<Mutex<VecDeque<String>>>,
    error: Arc<Mutex<Option<String>>>,
    alive: Arc<AtomicBool>,
    port: u16,
    server: String,
    started: Instant,
}

const LOG_CAP: usize = 300;

impl Xray {
    pub fn start(cfg: &Config, dir: &Path, work: &Path) -> Result<Xray, String> {
        if cfg.port < 1024 {
            return Err(crate::tr!("порт должен быть от 1024 до 65535", "port must be 1024–65535"));
        }
        let port = cfg.port;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
            return Err(crate::tr!(
                "порт {port} занят (v2rayN или другая программа?) — смените порт",
                "port {port} is busy (v2rayN or another program?) — change the port"
            ));
        }
        let (sel, auto, label) = select(cfg)?;
        let conf = build(cfg, &sel, auto);
        std::fs::create_dir_all(work).map_err(|e| e.to_string())?;
        let path = work.join("xray.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&conf).unwrap_or_default()).map_err(|e| e.to_string())?;
        check_config(dir, &path)?;
        let mut child = xray_cmd(dir)
            .args(["run", "-c"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("xray.exe: {e}"))?;
        let log = Arc::new(Mutex::new(VecDeque::new()));
        let error = Arc::new(Mutex::new(None));
        for out in [child.stdout.take().map(|o| Box::new(o) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|o| Box::new(o) as Box<dyn std::io::Read + Send>)].into_iter().flatten() {
            let (log, error) = (log.clone(), error.clone());
            std::thread::spawn(move || {
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    let line = redact(&line);
                    if line.contains("[Error]") || line.contains("failed to") && !line.contains("[Info]") {
                        *error.lock().unwrap() = Some(line.split_once("] ").map_or(line.as_str(), |(_, m)| m).to_string());
                    }
                    let mut l = log.lock().unwrap();
                    if l.len() >= LOG_CAP {
                        l.pop_front();
                    }
                    l.push_back(line);
                }
            });
        }
        let child = Arc::new(Mutex::new(Some(child)));
        let alive = Arc::new(AtomicBool::new(true));
        // Готов — когда порт принимает соединения.
        let t0 = Instant::now();
        loop {
            if TcpStream::connect_timeout(&([127, 0, 0, 1], cfg.port).into(), Duration::from_millis(200)).is_ok() {
                break;
            }
            let exited = child.lock().unwrap().as_mut().map(|c| c.try_wait().ok().flatten().is_some()).unwrap_or(true);
            if exited || t0.elapsed() > Duration::from_secs(8) {
                if let Some(mut c) = child.lock().unwrap().take() {
                    let _ = c.kill();
                }
                std::thread::sleep(Duration::from_millis(150));
                let e = error.lock().unwrap().clone().unwrap_or_else(|| {
                    crate::tr!(
                        "xray.exe не запустился — проверьте, не блокирует ли его антивирус или брандмауэр (например, simplewall)",
                        "xray.exe did not start — check whether an antivirus or firewall (e.g. simplewall) blocks it"
                    )
                });
                return Err(e);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        READY_PORT.store(cfg.port, Ordering::SeqCst);
        // Следим за процессом: упал — порт закрыт для прокси-обходчика.
        let (c2, a2, e2) = (child.clone(), alive.clone(), error.clone());
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            let mut g = c2.lock().unwrap();
            match g.as_mut().map(|c| c.try_wait().ok().flatten()) {
                None => break,
                Some(Some(code)) => {
                    a2.store(false, Ordering::SeqCst);
                    READY_PORT.store(0, Ordering::SeqCst);
                    let mut e = e2.lock().unwrap();
                    if e.is_none() {
                        *e = Some(crate::tr!("xray завершился ({code})", "xray exited ({code})"));
                    }
                    *g = None;
                    break;
                }
                Some(None) => {}
            }
        });
        Ok(Xray { child, log, error, alive, port: cfg.port, server: label, started: Instant::now() })
    }

    pub fn status(&self) -> Status {
        let alive = self.alive.load(Ordering::SeqCst);
        Status { running: alive, ready: alive, port: self.port, server: self.server.clone(), error: self.error.lock().unwrap().clone(), uptime: self.started.elapsed().as_secs() }
    }

    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().iter().cloned().collect()
    }
}

impl Drop for Xray {
    fn drop(&mut self) {
        READY_PORT.store(0, Ordering::SeqCst);
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Серверы для запуска: выбранный или все (авто), и подпись.
fn select(cfg: &Config) -> Result<(Vec<&Entry>, bool, String), String> {
    if cfg.servers.is_empty() {
        return Err(crate::tr!("нет серверов — добавьте ссылку или подписку", "no servers — add a link or a subscription"));
    }
    if cfg.selected == AUTO {
        let all: Vec<&Entry> = cfg.servers.iter().collect();
        let n = all.len();
        let label = if n == 1 { all[0].server.name.clone() } else { crate::tr!("авто: лучший из {n}", "auto: best of {n}") };
        return Ok((all, true, label));
    }
    let e = cfg.servers.iter().find(|e| e.id == cfg.selected).ok_or_else(|| crate::tr!("выбранного сервера больше нет — выберите другой", "the selected server is gone — pick another"))?;
    Ok((vec![e], false, e.server.name.clone()))
}

/// Скрыть UUID в строках журнала xray.
pub fn redact(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if i + 36 <= b.len() && is_uuid(&s[i..i + 36]) {
            out.push_str("<uuid>");
            i += 36;
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36 && s.char_indices().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() })
}

// ---------- подписки ----------

/// Скачать подписку: серверы, сведения из заголовков, ошибки строк.
pub fn fetch_sub(url: &str, proxy: Option<u16>) -> Result<(Vec<Server>, SubInfo, Vec<String>), String> {
    let (body, headers) = crate::util::fetch_full(&crate::tr!("подписка", "subscription"), url, 25, proxy, Some(SUB_UA))?;
    let info = crate::xraylinks::parse_headers(&headers);
    let (servers, errors) = crate::xraylinks::parse_subscription(&body);
    if servers.is_empty() {
        let why = errors.first().cloned().unwrap_or_default();
        return Err(crate::tr!("в подписке нет подходящих серверов: {why}", "no usable servers in the subscription: {why}"));
    }
    Ok((servers, info, errors))
}

/// Заменить серверы подписки, сохранив выбор, если такой сервер остался.
pub fn apply_sub(cfg: &mut Config, sub_id: &str, servers: Vec<Server>) {
    cfg.servers.retain(|e| e.sub.as_deref() != Some(sub_id));
    for s in servers {
        let e = entry(s, Some(sub_id.to_string()));
        if !cfg.servers.iter().any(|x| x.id == e.id) {
            cfg.servers.push(e);
        }
    }
    if cfg.selected != AUTO && !cfg.servers.iter().any(|e| e.id == cfg.selected) {
        cfg.selected = AUTO.into();
    }
}

/// Пора ли обновить подписку (по Profile-Update-Interval, иначе раз в 12 ч).
pub fn sub_due(s: &Sub, now: u64) -> bool {
    let h = if s.info.update_hours > 0 { s.info.update_hours } else { 12 } as u64;
    now.saturating_sub(s.updated) >= h * 3600
}

// ---------- проверка задержки ----------

#[derive(Debug, Clone, Serialize)]
pub struct Ping {
    pub id: String,
    /// мс до ответа generate_204 через сервер; None — не ответил.
    pub ms: Option<u64>,
    pub error: Option<String>,
}

fn free_port() -> Option<u16> {
    std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?.local_addr().ok().map(|a| a.port())
}

/// Настоящая задержка: один xray с входом на каждый сервер, запрос через каждый.
pub fn test(dir: &Path, work: &Path, entries: &[&Entry], timeout: u32) -> Result<Vec<Ping>, String> {
    if entries.is_empty() {
        return Ok(vec![]);
    }
    let ports: Vec<u16> = entries.iter().map(|_| free_port()).collect::<Option<_>>().ok_or("no free port")?;
    let conf = build_test(entries, &ports);
    std::fs::create_dir_all(work).map_err(|e| e.to_string())?;
    let path = work.join("xray-test.json");
    std::fs::write(&path, serde_json::to_vec(&conf).unwrap_or_default()).map_err(|e| e.to_string())?;
    check_config(dir, &path)?;
    let mut child = xray_cmd(dir).args(["run", "-c"]).arg(&path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("xray.exe: {e}"))?;
    // Ждём, пока поднимется последний вход.
    let t0 = Instant::now();
    while TcpStream::connect_timeout(&([127, 0, 0, 1], *ports.last().unwrap()).into(), Duration::from_millis(200)).is_err() {
        if t0.elapsed() > Duration::from_secs(8) {
            let _ = child.kill();
            return Err(crate::tr!("xray для проверки не запустился", "xray for the test did not start"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let results: Mutex<HashMap<usize, Ping>> = Mutex::new(HashMap::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|sc| {
        for _ in 0..8.min(entries.len()) {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(e) = entries.get(i) else { break };
                let p = probe(ports[i], timeout);
                results.lock().unwrap().insert(i, Ping { id: e.id.clone(), ms: p.as_ref().ok().copied(), error: p.err() });
            });
        }
    });
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&path);
    let mut r = results.into_inner().unwrap();
    Ok((0..entries.len()).filter_map(|i| r.remove(&i)).collect())
}

/// Запрос generate_204 через SOCKS (имя разрешает сервер); время в мс.
fn probe(port: u16, timeout: u32) -> Result<u64, String> {
    let out = crate::util::hidden(crate::util::system32("curl.exe"))
        .args(["-s", "-o", "NUL", "-m", &timeout.to_string(), "-w", "%{http_code} %{time_total}", "-x", &format!("socks5h://127.0.0.1:{port}"), "https://www.gstatic.com/generate_204"])
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut it = text.split_whitespace();
    let code = it.next().unwrap_or("000");
    let secs: f64 = it.next().unwrap_or("0").replace(',', ".").parse().unwrap_or(0.0);
    if code == "204" || code == "200" {
        Ok((secs * 1000.0) as u64)
    } else if out.status.code() == Some(28) {
        Err(crate::tr!("нет ответа за {timeout} с", "no answer in {timeout} s"))
    } else {
        Err(crate::util::fetch_reason(out.status.code().unwrap_or(-1), code.parse().unwrap_or(0), timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xraylinks::parse_link;

    const U: &str = "11111111-2222-3333-4444-555555555555";

    fn cfg_with(links: &[&str]) -> Config {
        let mut c = Config::default();
        for l in links {
            c.servers.push(entry(parse_link(l).unwrap(), None));
        }
        c
    }

    #[test]
    fn config_single_and_rules() {
        let mut c = cfg_with(&[&format!("vless://{U}@a.ex:443?type=ws&security=tls&sni=a.ex#A")]);
        c.selected = c.servers[0].id.clone();
        c.routing.direct = vec!["example.org".into(), "10.0.0.0/8".into()];
        c.routing.block = vec!["geosite:category-ads".into()];
        c.fragment = true;
        let (sel, auto, label) = select(&c).unwrap();
        assert_eq!((auto, label.as_str()), (false, "A"));
        let v = build(&c, &sel, auto);
        assert_eq!(v["inbounds"][0]["port"], 10820);
        assert_eq!(v["inbounds"][0]["protocol"], "mixed");
        assert_eq!(v["outbounds"][0]["tag"], "proxy");
        assert_eq!(v["outbounds"][0]["streamSettings"]["finalmask"]["tcp"][0]["type"], "fragment");
        let rules = v["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "block");
        assert!(rules.iter().any(|r| r["domain"] == json!(["domain:example.org"]) && r["outboundTag"] == "direct"));
        assert!(rules.iter().any(|r| r["ip"] == json!(["10.0.0.0/8"])));
        assert!(rules.iter().any(|r| r["ip"] == json!(["geoip:ru"])));
        assert_eq!(rules.last().unwrap()["outboundTag"], "proxy");
        assert_eq!(v["routing"]["domainStrategy"], "IPIfNonMatch");
        assert!(v["dns"]["servers"][0]["domains"].as_array().unwrap().contains(&json!("geosite:category-ru")));
        // Без RU — без своего DNS и AsIs.
        let mut c2 = c.clone();
        c2.routing.ru_direct = false;
        let v = build(&c2, &sel, false);
        assert!(v.get("dns").is_none());
        assert_eq!(v["routing"]["domainStrategy"], "AsIs");
    }

    #[test]
    fn config_auto_and_chain() {
        let mut c = cfg_with(&[&format!("vless://{U}@a:1?security=none#A"), &format!("vless://{U}@b:2?type=grpc&serviceName=g&security=tls#B")]);
        let mut chained = parse_link(&format!("vless://{U}@c:3?security=tls#C")).unwrap();
        chained.outbound["streamSettings"]["sockopt"] = json!({ "dialerProxy": "frag" });
        chained.chain = vec![json!({ "tag": "frag", "protocol": "freedom" })];
        c.servers.push(entry(chained, None));
        let (sel, auto, label) = select(&c).unwrap();
        assert!(auto && label.contains('3'));
        let v = build(&c, &sel, auto);
        let tags: Vec<&str> = v["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, ["p0", "p1", "p2", "p2-frag", "direct", "block"]);
        assert_eq!(v["outbounds"][2]["streamSettings"]["sockopt"]["dialerProxy"], "p2-frag");
        assert_eq!(v["routing"]["balancers"][0]["strategy"]["type"], "leastPing");
        assert_eq!(v["routing"]["rules"].as_array().unwrap().last().unwrap()["balancerTag"], AUTO);
        assert!(v["observatory"]["subjectSelector"] == json!(["p"]));
    }

    #[test]
    fn subs_and_ids() {
        let mut c = Config::default();
        let s1 = parse_link(&format!("vless://{U}@a:1#A")).unwrap();
        let s2 = parse_link(&format!("vless://{U}@b:2#B")).unwrap();
        apply_sub(&mut c, "s", vec![s1.clone(), s2.clone()]);
        assert_eq!(c.servers.len(), 2);
        c.selected = c.servers[1].id.clone();
        apply_sub(&mut c, "s", vec![s2.clone()]);
        assert_eq!(c.servers.len(), 1);
        assert_ne!(c.selected, AUTO, "сервер остался — выбор сохранён");
        apply_sub(&mut c, "s", vec![s1]);
        assert_eq!(c.selected, AUTO);
        let s = Sub { id: "s".into(), name: "n".into(), url: "u".into(), info: SubInfo { update_hours: 12, ..Default::default() }, updated: 0, error: None };
        assert!(sub_due(&s, 13 * 3600));
        assert!(!sub_due(&Sub { updated: 3600, ..s }, 4 * 3600));
        assert_eq!(redact(&format!("x {U} y")), "x <uuid> y");
    }

    /// Живая проверка подписки: `XRAY_SUB=<url> cargo test live_xray -- --ignored --nocapture`.
    /// Ссылка — только из переменной окружения: в коде её быть не должно.
    #[test]
    #[ignore]
    fn live_xray() {
        let Ok(url) = std::env::var("XRAY_SUB") else { return };
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("xray");
        let (servers, info, errs) = fetch_sub(&url, None).unwrap();
        println!("servers {} info {info:?} errors {errs:?}", servers.len());
        let mut c = Config { port: 10899, ..Default::default() };
        apply_sub(&mut c, "s", servers);
        let work = std::env::temp_dir().join("digital-bypass-xray-test");
        let entries: Vec<&Entry> = c.servers.iter().collect();
        for p in test(&dir, &work, &entries, 10).unwrap() {
            let name = &c.servers.iter().find(|e| e.id == p.id).unwrap().server.name;
            println!("{:>6} {name} {}", p.ms.map(|m| format!("{m} ms")).unwrap_or("—".into()), p.error.unwrap_or_default());
        }
        let x = Xray::start(&c, &dir, &work).unwrap();
        println!("{:?}", x.status());
        for u in ["https://www.gstatic.com/generate_204", "https://ya.ru", "https://ifconfig.me/ip"] {
            let o = crate::util::hidden(crate::util::system32("curl.exe")).args(["-s", "-m", "20", "-o", "NUL", "-w", "%{http_code} %{time_total}", "-x", "socks5h://127.0.0.1:10899", u]).output().unwrap();
            println!("{u}: {}", String::from_utf8_lossy(&o.stdout));
        }
        let o = crate::util::hidden(crate::util::system32("curl.exe")).args(["-s", "-m", "20", "-x", "socks5h://127.0.0.1:10899", "https://ifconfig.me/ip"]).output().unwrap();
        println!("exit ip via xray: {}", String::from_utf8_lossy(&o.stdout));
        println!("log: {:?}", x.log().iter().rev().take(5).collect::<Vec<_>>());
    }
}
