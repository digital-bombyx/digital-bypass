//! Tor: `tor.exe` и `lyrebird.exe` (obfs4, webtunnel, snowflake, meek) из Tor
//! Expert Bundle, встроенного в установщик (`scripts/sync-tor.mjs`).
//!
//! Это обход блокировок, а не анонимность: браузер через наш прокси выдаёт свой
//! отпечаток. Для анонимности — Tor Browser.
//!
//! Устройство:
//! - tor слушает SOCKS5 на 127.0.0.1:`socks_port`, управление — `socks_port + 1`
//!   (cookie-аутентификация, нужно для «новой личности»).
//! - Папка данных постоянная: первая загрузка консенсуса через мост долгая, со
//!   второго раза tor берёт кэш и подключается за секунды.
//! - «Авто» перебирает ступени: свои и найденные мосты → встроенные obfs4 →
//!   snowflake → meek. Ступень меняется, если bootstrap не растёт `STALL`.
//! - `__OwningControllerProcess` — tor сам завершится, если приложение упало.
//! - Пути с пробелами (Program Files) в torrc не годятся для ClientTransportPlugin,
//!   поэтому tor запускается из своей папки, а lyrebird указан относительно неё.
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Способы подключения.
pub const TRANSPORTS: [&str; 7] = ["auto", "obfs4", "webtunnel", "snowflake", "meek", "custom", "direct"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub socks_port: u16,
    /// Один из `TRANSPORTS`.
    pub transport: String,
    /// Свои мосты (строки `Bridge`, слово `Bridge` можно не писать).
    pub bridges: Vec<String>,
    /// Найденные поиском мостов (лучшие).
    pub found: Vec<String>,
    /// Подключаться к мостам через прокси-обходчик (его нарезка ClientHello —
    /// для webtunnel, если провайдер глушит его TLS).
    pub via_proxy: bool,
    /// Включать при запуске приложения.
    pub enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { socks_port: 9055, transport: "auto".into(), bridges: Vec::new(), found: Vec::new(), via_proxy: false, enabled: false }
    }
}

impl Config {
    pub fn normalize(&mut self) {
        if !TRANSPORTS.contains(&self.transport.as_str()) {
            self.transport = "auto".into();
        }
        self.bridges = self.bridges.iter().filter_map(|l| clean_bridge(l)).collect();
        self.found = self.found.iter().filter_map(|l| clean_bridge(l)).collect();
    }
}

/// Порт SOCKS готового (bootstrap 100%) tor; 0 — не готов. Читает прокси-обходчик.
static READY_PORT: AtomicU16 = AtomicU16::new(0);

pub fn ready_port() -> Option<u16> {
    match READY_PORT.load(Ordering::SeqCst) {
        0 => None,
        p => Some(p),
    }
}

// ---------- мосты ----------

/// Транспорт строки моста: первое слово или `vanilla` для `ip:port fingerprint`.
pub fn bridge_transport(line: &str) -> &str {
    let w = line.split_whitespace().next().unwrap_or("");
    if w.contains(':') || w.parse::<std::net::IpAddr>().is_ok() {
        "vanilla"
    } else {
        w
    }
}

/// Строка моста без `Bridge`, проверенная: одна строка, печатные символы,
/// известный транспорт. Строки приходят из сети — в torrc их нельзя пускать как есть.
pub fn clean_bridge(line: &str) -> Option<String> {
    let l = line.trim();
    let l = l.strip_prefix("Bridge ").or_else(|| l.strip_prefix("bridge ")).unwrap_or(l).trim();
    if l.is_empty() || l.starts_with('#') || l.len() > 1500 || l.chars().any(|c| c.is_control()) {
        return None;
    }
    let t = bridge_transport(l);
    let ok = matches!(t, "vanilla" | "obfs4" | "webtunnel" | "snowflake" | "meek_lite" | "meek" | "conjure");
    // Адрес: второе слово (у vanilla — первое).
    let addr = if t == "vanilla" { l.split_whitespace().next() } else { l.split_whitespace().nth(1) };
    (ok && addr.is_some_and(|a| a.contains(':'))).then(|| l.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Встроенные мосты из `pt_config.json` бандла.
#[derive(Debug, Clone, Default)]
pub struct Builtin {
    pub obfs4: Vec<String>,
    pub snowflake: Vec<String>,
    pub meek: Vec<String>,
}

pub fn builtin(tor_dir: &Path) -> Builtin {
    let v: serde_json::Value = std::fs::read(tor_dir.join("pluggable_transports").join("pt_config.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let list = |k: &str| -> Vec<String> {
        v["bridges"][k].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).filter_map(clean_bridge).collect()).unwrap_or_default()
    };
    Builtin { obfs4: list("obfs4"), snowflake: list("snowflake"), meek: list("meek") }
}

/// Ступень подключения: название и мосты (пусто — напрямую).
#[derive(Debug, Clone, PartialEq)]
pub struct Tier {
    pub name: String,
    pub bridges: Vec<String>,
}

/// Ступени для выбранного способа. Свои и найденные мосты идут первыми.
pub fn plan(cfg: &Config, b: &Builtin) -> Result<Vec<Tier>, String> {
    let mine: Vec<String> = cfg.bridges.iter().chain(cfg.found.iter()).cloned().collect();
    let of = |t: &str| -> Vec<String> { mine.iter().filter(|l| bridge_transport(l) == t).cloned().collect() };
    let tier = |name: &str, bridges: Vec<String>| Tier { name: name.into(), bridges };
    let tiers = match cfg.transport.as_str() {
        "direct" => vec![tier("direct", vec![])],
        "custom" => {
            if cfg.bridges.is_empty() {
                return Err(crate::tr!("добавьте свои мосты", "add your bridges"));
            }
            vec![tier("custom", cfg.bridges.clone())]
        }
        "obfs4" => vec![tier("obfs4", of("obfs4").into_iter().chain(b.obfs4.iter().cloned()).collect())],
        "webtunnel" => {
            let w = of("webtunnel");
            if w.is_empty() {
                return Err(crate::tr!(
                    "нет мостов webtunnel — найдите их поиском или добавьте свои",
                    "no webtunnel bridges — find them or add your own"
                ));
            }
            vec![tier("webtunnel", w)]
        }
        "snowflake" => vec![tier("snowflake", b.snowflake.clone())],
        "meek" => vec![tier("meek", b.meek.clone())],
        _ => {
            let mut v = Vec::new();
            if !mine.is_empty() {
                v.push(tier("bridges", mine.clone()));
            }
            v.push(tier("obfs4", b.obfs4.clone()));
            v.push(tier("snowflake", b.snowflake.clone()));
            v.push(tier("meek", b.meek.clone()));
            v
        }
    };
    let tiers: Vec<Tier> = tiers.into_iter().filter(|t| t.name == "direct" || !t.bridges.is_empty()).collect();
    if tiers.is_empty() {
        return Err(crate::tr!("нет мостов для выбранного способа", "no bridges for this method"));
    }
    Ok(tiers)
}

/// torrc для ступени. Пути передаются в командной строке, не здесь.
pub fn torrc(cfg: &Config, tier: &Tier, proxy: Option<u16>) -> String {
    let mut s = format!(
        "SocksPort 127.0.0.1:{}\nControlPort 127.0.0.1:{}\nCookieAuthentication 1\nAvoidDiskWrites 1\nLog notice stdout\n\
         ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec pluggable_transports\\lyrebird.exe\n\
         ClientTransportPlugin snowflake exec pluggable_transports\\lyrebird.exe\n",
        cfg.socks_port,
        cfg.socks_port.wrapping_add(1)
    );
    if !tier.bridges.is_empty() {
        s.push_str("UseBridges 1\n");
        for b in &tier.bridges {
            s.push_str("Bridge ");
            s.push_str(b);
            s.push('\n');
        }
    }
    // snowflake (WebRTC) и meek через SOCKS-прокси не ходят.
    if let Some(p) = proxy.filter(|_| cfg.via_proxy && !matches!(tier.name.as_str(), "snowflake" | "meek" | "direct")) {
        s.push_str(&format!("Socks5Proxy 127.0.0.1:{p}\n"));
    }
    s
}

/// `Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors` → (45, «Asking…»).
pub fn parse_bootstrap(line: &str) -> Option<(u8, String)> {
    let i = line.find("Bootstrapped ")? + "Bootstrapped ".len();
    let rest = &line[i..];
    let pct: u8 = rest[..rest.find('%')?].trim().parse().ok()?;
    let summary = rest.split_once("): ").map(|(_, s)| s.trim().to_string()).unwrap_or_default();
    Some((pct.min(100), summary))
}

// ---------- процесс ----------

/// Bootstrap не растёт столько — в «авто» переходим к следующей ступени.
const STALL: Duration = Duration::from_secs(90);
const LOG_CAP: usize = 300;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    pub running: bool,
    pub ready: bool,
    pub percent: u8,
    pub phase: String,
    /// Текущая ступень (obfs4, snowflake…).
    pub tier: String,
    pub tiers: Vec<String>,
    pub socks_port: u16,
    pub error: Option<String>,
    /// Секунд с запуска текущей ступени.
    pub elapsed: u64,
}

#[derive(Default)]
struct Shared {
    stop: AtomicBool,
    alive: AtomicBool,
    percent: AtomicU8,
    phase: Mutex<String>,
    tier: Mutex<String>,
    error: Mutex<Option<String>>,
    log: Mutex<VecDeque<String>>,
    child: Mutex<Option<Child>>,
    started: Mutex<Option<Instant>>,
}

impl Shared {
    fn push_log(&self, l: String) {
        let mut g = self.log.lock().unwrap();
        if g.len() >= LOG_CAP {
            g.pop_front();
        }
        g.push_back(l);
    }
    fn kill(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

pub struct Tor {
    shared: Arc<Shared>,
    tiers: Vec<String>,
    port: u16,
    data_dir: PathBuf,
    sup: Option<std::thread::JoinHandle<()>>,
}

/// Где лежат tor.exe и lyrebird: ресурсы установщика, в отладке — src-tauri/tor.
pub fn find_dir(resource_dir: Option<&Path>) -> Option<PathBuf> {
    let mut c: Vec<PathBuf> = resource_dir.map(|r| vec![r.join("tor")]).unwrap_or_default();
    if cfg!(debug_assertions) {
        c.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tor"));
    }
    c.into_iter().find(|d| d.join("tor.exe").is_file() && d.join("pluggable_transports").join("lyrebird.exe").is_file())
}

pub fn version(tor_dir: &Path) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(tor_dir.join("bundle.json")).ok()?).ok()?;
    v["version"].as_str().map(String::from)
}

impl Tor {
    /// `work_dir` — папка данных приложения (torrc и tor-data внутри).
    pub fn start(cfg: &Config, tor_dir: &Path, work_dir: &Path, proxy: Option<u16>) -> Result<Tor, String> {
        if cfg.socks_port < 1024 || cfg.socks_port == u16::MAX {
            return Err(crate::tr!("порт должен быть от 1024 до 65534", "port must be 1024–65534"));
        }
        if cfg.via_proxy && proxy.is_none() {
            return Err(crate::tr!(
                "включите прокси-обходчик: мосты настроены идти через него",
                "turn on the bypass proxy: bridges are set to go through it"
            ));
        }
        for p in [cfg.socks_port, cfg.socks_port + 1] {
            if std::net::TcpListener::bind(("127.0.0.1", p)).is_err() {
                return Err(crate::tr!("порт {p} занят (Tor Browser или другой tor?)", "port {p} is busy (Tor Browser or another tor?)"));
            }
        }
        // Snowflake: свежие настройки из API Tor, если есть (встроенные фронты
        // бандла могут быть уже заблокированы). Устаревшие — обновляем в фоне;
        // ступень snowflake перечитает их, когда до неё дойдёт очередь.
        let mut b = builtin(tor_dir);
        let cached = crate::bridges::cached_snowflake(work_dir);
        if cached.as_ref().is_none_or(|(_, age)| *age >= crate::bridges::SNOWFLAKE_TTL) {
            let wd = work_dir.to_path_buf();
            std::thread::spawn(move || {
                let _ = crate::bridges::refresh_snowflake(&wd, proxy);
            });
        }
        if let Some((sf, _)) = cached {
            b.snowflake = sf;
        }
        let tiers = plan(cfg, &b)?;
        let data_dir = work_dir.join("tor-data");
        std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
        let shared = Arc::new(Shared::default());
        shared.alive.store(true, Ordering::SeqCst);
        let (sh, cfg2, dir, wd, dd, tl) = (shared.clone(), cfg.clone(), tor_dir.to_path_buf(), work_dir.to_path_buf(), data_dir.clone(), tiers.clone());
        let sup = std::thread::spawn(move || {
            supervise(&sh, &cfg2, &dir, &wd, &dd, &tl, proxy);
            sh.alive.store(false, Ordering::SeqCst);
        });
        Ok(Tor { shared, tiers: tiers.into_iter().map(|t| t.name).collect(), port: cfg.socks_port, data_dir, sup: Some(sup) })
    }

    pub fn status(&self) -> Status {
        let s = &self.shared;
        let pct = s.percent.load(Ordering::SeqCst);
        Status {
            running: s.alive.load(Ordering::SeqCst),
            ready: pct == 100 && s.alive.load(Ordering::SeqCst),
            percent: pct,
            phase: s.phase.lock().unwrap().clone(),
            tier: s.tier.lock().unwrap().clone(),
            tiers: self.tiers.clone(),
            socks_port: self.port,
            error: s.error.lock().unwrap().clone(),
            elapsed: s.started.lock().unwrap().map(|t| t.elapsed().as_secs()).unwrap_or(0),
        }
    }

    pub fn log(&self) -> Vec<String> {
        self.shared.log.lock().unwrap().iter().cloned().collect()
    }

    /// Новая личность: новые цепочки для новых соединений (SIGNAL NEWNYM).
    pub fn new_identity(&self) -> Result<(), String> {
        let cookie = std::fs::read(self.data_dir.join("control_auth_cookie")).map_err(|e| e.to_string())?;
        let hex: String = cookie.iter().map(|b| format!("{b:02x}")).collect();
        let mut s = TcpStream::connect_timeout(&([127, 0, 0, 1], self.port + 1).into(), Duration::from_secs(3)).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        s.write_all(format!("AUTHENTICATE {hex}\r\nSIGNAL NEWNYM\r\nQUIT\r\n").as_bytes()).map_err(|e| e.to_string())?;
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        let replies: Vec<&str> = out.lines().collect();
        if replies.len() >= 2 && replies[0].starts_with("250") && replies[1].starts_with("250") {
            Ok(())
        } else {
            Err(format!("tor: {}", out.trim()))
        }
    }
}

impl Drop for Tor {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.kill();
        READY_PORT.store(0, Ordering::SeqCst);
        if let Some(h) = self.sup.take() {
            let _ = h.join();
        }
    }
}

fn supervise(sh: &Arc<Shared>, cfg: &Config, tor_dir: &Path, work_dir: &Path, data_dir: &Path, tiers: &[Tier], proxy: Option<u16>) {
    let auto = cfg.transport == "auto";
    for (i, tier) in tiers.iter().enumerate() {
        if sh.stop.load(Ordering::SeqCst) {
            return;
        }
        // Настройки Snowflake могли обновиться в фоне, пока шли прежние ступени.
        let fresh;
        let tier = match crate::bridges::cached_snowflake(work_dir) {
            Some((sf, _)) if tier.name == "snowflake" && sf != tier.bridges => {
                fresh = Tier { name: tier.name.clone(), bridges: sf };
                &fresh
            }
            _ => tier,
        };
        *sh.tier.lock().unwrap() = tier.name.clone();
        sh.percent.store(0, Ordering::SeqCst);
        *sh.phase.lock().unwrap() = String::new();
        *sh.started.lock().unwrap() = Some(Instant::now());
        sh.push_log(format!("--- {} ({} bridges) ---", tier.name, tier.bridges.len()));
        let torrc_path = work_dir.join("torrc");
        if let Err(e) = std::fs::write(&torrc_path, torrc(cfg, tier, proxy)) {
            *sh.error.lock().unwrap() = Some(e.to_string());
            return;
        }
        let child = crate::util::hidden(tor_dir.join("tor.exe"))
            .current_dir(tor_dir)
            .arg("-f")
            .arg(&torrc_path)
            .arg("--DataDirectory")
            .arg(data_dir)
            .args(["--GeoIPFile", "", "--GeoIPv6File", "", "__OwningControllerProcess"])
            .arg(std::process::id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                *sh.error.lock().unwrap() = Some(format!("tor.exe: {e}"));
                return;
            }
        };
        let out = child.stdout.take();
        *sh.child.lock().unwrap() = Some(child);
        if let Some(out) = out {
            let sh2 = sh.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    if let Some((p, ph)) = parse_bootstrap(&line) {
                        sh2.percent.fetch_max(p, Ordering::SeqCst);
                        *sh2.phase.lock().unwrap() = ph;
                    }
                    // После подключения предупреждения о других мостах — шум; ошибки — нет.
                    let ready = sh2.percent.load(Ordering::SeqCst) == 100;
                    if line.contains("[err]") || (!ready && line.contains("[warn]") && !line.contains("GeoIP")) {
                        let msg = line.split_once("] ").map_or(line.as_str(), |(_, m)| m).to_string();
                        *sh2.error.lock().unwrap() = Some(msg);
                    }
                    sh2.push_log(line);
                }
            });
        }
        let (mut best, mut since) = (0u8, Instant::now());
        loop {
            std::thread::sleep(Duration::from_millis(300));
            if sh.stop.load(Ordering::SeqCst) {
                return;
            }
            let p = sh.percent.load(Ordering::SeqCst);
            // Подключились: порт открыт для прокси-обходчика, прошлые ошибки сняты.
            if p == 100 && READY_PORT.swap(cfg.socks_port, Ordering::SeqCst) == 0 {
                *sh.error.lock().unwrap() = None;
            }
            if p > best {
                (best, since) = (p, Instant::now());
            }
            let exited = sh.child.lock().unwrap().as_mut().map(|c| c.try_wait().ok().flatten().is_some()).unwrap_or(true);
            if exited {
                READY_PORT.store(0, Ordering::SeqCst);
                let quick = sh.started.lock().unwrap().is_some_and(|t| t.elapsed() < Duration::from_secs(10));
                let mut err = sh.error.lock().unwrap();
                if err.is_none() || quick {
                    let detail = err.take().map(|e| format!(": {e}")).unwrap_or_default();
                    *err = Some(if quick {
                        crate::tr!(
                            "tor.exe завершился сразу после запуска{detail} — проверьте, не блокирует ли его антивирус или брандмауэр (например, simplewall)",
                            "tor.exe exited right after start{detail} — check whether an antivirus or firewall (e.g. simplewall) blocks it"
                        )
                    } else {
                        crate::tr!("tor завершился{detail}", "tor exited{detail}")
                    });
                }
                break;
            }
            if auto && p < 100 && since.elapsed() >= STALL && i + 1 < tiers.len() {
                sh.push_log(format!("--- {}: no progress for {} s, next ---", tier.name, STALL.as_secs()));
                break;
            }
        }
        sh.kill();
        READY_PORT.store(0, Ordering::SeqCst);
        if !auto {
            return;
        }
    }
    if !sh.stop.load(Ordering::SeqCst) {
        let last = sh.error.lock().unwrap().take().map(|e| format!(" ({e})")).unwrap_or_default();
        *sh.error.lock().unwrap() = Some(crate::tr!(
            "не удалось подключиться ни одним способом{last} — найдите свежие мосты (поиск мостов ниже); если lyrebird.exe блокирует брандмауэр, мосты не ответят вовсе",
            "could not connect by any method{last} — find fresh bridges (bridge search below); if a firewall blocks lyrebird.exe, no bridge will answer"
        ));
    }
}

// ---------- SOCKS5-клиент для прокси-обходчика ----------

/// Соединение с `host:port` через SOCKS5 tor (имя разрешает tor).
pub fn socks_connect(tor_port: u16, host: &str, port: u16, timeout: Duration) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect_timeout(&([127, 0, 0, 1], tor_port).into(), Duration::from_secs(3))?;
    s.set_read_timeout(Some(timeout))?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [5, 0] {
        return Err(std::io::Error::other("tor socks: auth"));
    }
    let mut req = vec![5, 1, 0];
    match host.trim_matches(|c| c == '[' || c == ']').parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Ok(std::net::IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
        Err(_) => {
            let h = host.as_bytes();
            if h.len() > 255 {
                return Err(std::io::Error::other("host too long"));
            }
            req.push(3);
            req.push(h.len() as u8);
            req.extend_from_slice(h);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0 {
        return Err(std::io::Error::other(format!("tor: {}", socks_error(head[1]))));
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n)?;
            n[0] as usize
        }
        _ => return Err(std::io::Error::other("tor socks: bad reply")),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest)?;
    s.set_read_timeout(None)?;
    Ok(s)
}

fn socks_error(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "not allowed",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridges_clean() {
        let o = "obfs4 1.2.3.4:443 ABCDEF cert=xx iat-mode=0";
        assert_eq!(clean_bridge(&format!("Bridge {o}")).as_deref(), Some(o));
        assert_eq!(clean_bridge("  webtunnel [2001:db8::1]:443 FF url=https://a/b ver=0.0.1 ").unwrap().split(' ').count(), 5);
        assert_eq!(bridge_transport("1.2.3.4:9001 ABCD"), "vanilla");
        assert!(clean_bridge("1.2.3.4:9001 ABCD").is_some());
        // Перевод строки — попытка вписать в torrc свою опцию.
        assert!(clean_bridge("obfs4 1.2.3.4:443 A\nSocksPort 0.0.0.0:1").is_none());
        assert!(clean_bridge("ExitNodes {ru}").is_none());
        assert!(clean_bridge("# comment").is_none());
        assert!(clean_bridge("obfs4 nohostport").is_none());
    }

    #[test]
    fn bootstrap_line() {
        let l = "Nov 24 02:28:37.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors";
        assert_eq!(parse_bootstrap(l), Some((45, "Asking for relay descriptors".into())));
        assert_eq!(parse_bootstrap("Bootstrapped 100% (done): Done").unwrap().0, 100);
        assert!(parse_bootstrap("[notice] Opening Socks listener").is_none());
    }

    #[test]
    fn plans() {
        let b = Builtin { obfs4: vec!["obfs4 9.9.9.9:1 B cert=c iat-mode=0".into()], snowflake: vec!["snowflake 192.0.2.3:80 F".into()], meek: vec!["meek_lite 192.0.2.20:80 url=x".into()] };
        let mut c = Config::default();
        let names = |c: &Config| plan(c, &b).unwrap().into_iter().map(|t| t.name).collect::<Vec<_>>();
        assert_eq!(names(&c), ["obfs4", "snowflake", "meek"]);
        c.found = vec!["webtunnel [2001:db8::1]:443 F url=https://a/b".into(), "obfs4 1.1.1.1:2 A cert=c iat-mode=0".into()];
        assert_eq!(names(&c), ["bridges", "obfs4", "snowflake", "meek"]);
        c.transport = "obfs4".into();
        let t = plan(&c, &b).unwrap();
        assert_eq!(t[0].bridges.len(), 2);
        assert!(t[0].bridges[0].starts_with("obfs4 1.1.1.1"));
        c.transport = "webtunnel".into();
        assert_eq!(plan(&c, &b).unwrap()[0].bridges.len(), 1);
        c.transport = "custom".into();
        assert!(plan(&c, &b).is_err());
        c.transport = "direct".into();
        assert!(plan(&c, &b).unwrap()[0].bridges.is_empty());
    }

    #[test]
    fn torrc_text() {
        let c = Config { via_proxy: true, ..Default::default() };
        let t = Tier { name: "bridges".into(), bridges: vec!["obfs4 1.1.1.1:2 A cert=c iat-mode=0".into()] };
        let s = torrc(&c, &t, Some(8881));
        assert!(s.contains("SocksPort 127.0.0.1:9055\nControlPort 127.0.0.1:9056\n"));
        assert!(s.contains("UseBridges 1\nBridge obfs4 1.1.1.1:2"));
        assert!(s.contains("Socks5Proxy 127.0.0.1:8881"));
        let sf = Tier { name: "snowflake".into(), bridges: vec!["snowflake 192.0.2.3:80 F".into()] };
        assert!(!torrc(&c, &sf, Some(8881)).contains("Socks5Proxy"));
        assert!(!torrc(&Config::default(), &t, Some(8881)).contains("Socks5Proxy"));
    }

    #[test]
    fn bundled_builtin() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tor");
        if !dir.join("tor.exe").is_file() {
            return; // бандл не скачан (npm run sync-tor)
        }
        let b = builtin(&dir);
        assert!(b.obfs4.len() >= 3 && !b.snowflake.is_empty() && !b.meek.is_empty());
        assert_eq!(version(&dir).as_deref(), Some("16.0.1"));
    }

    /// Живой запуск: `cargo test live_tor -- --ignored --nocapture` (сеть, ~1–3 мин).
    #[test]
    #[ignore]
    fn live_tor() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tor");
        let wd = std::env::temp_dir().join("digital-bypass-tor-test");
        let mut cfg = Config { socks_port: 19150, transport: std::env::var("TOR_TRANSPORT").unwrap_or("auto".into()), ..Default::default() };
        // Как в приложении: сначала поиск мостов, найденные идут первыми.
        if cfg.transport == "auto" {
            let r = crate::bridges::find(&dir, &wd, &["obfs4", "webtunnel"], 6, None, false, &AtomicBool::new(false), |_| {}).unwrap();
            cfg.found = r.found.into_iter().map(|f| f.line).collect();
            println!("found {}", cfg.found.len());
        }
        let t = Tor::start(&cfg, &dir, &wd, None).unwrap();
        for _ in 0..600 {
            std::thread::sleep(Duration::from_millis(500));
            let s = t.status();
            if s.ready || !s.running {
                break;
            }
        }
        let s = t.status();
        println!("{s:?}");
        assert!(s.ready, "{:?}", t.log());
        // Наш SOCKS-клиент (как в прокси-обходчике) и HTTPS-проверка через curl.
        let mut c = socks_connect(19150, "check.torproject.org", 80, Duration::from_secs(30)).unwrap();
        c.write_all(b"HEAD / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n").unwrap();
        let mut head = String::new();
        let _ = c.read_to_string(&mut head);
        assert!(head.starts_with("HTTP/1."), "{head}");
        let o = crate::util::hidden(crate::util::system32("curl.exe"))
            .args(["-sS", "-m", "40", "--socks5-hostname", "127.0.0.1:19150", "https://check.torproject.org/api/ip"])
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&o.stdout);
        println!("{out}");
        assert!(out.contains("\"IsTor\":true"));
        t.new_identity().unwrap();
        if std::env::var("TOR_RU").is_err() {
            return;
        }
        // Прокси-обходчик в режиме Tor «весь трафик»: российские сайты — напрямую.
        crate::geo::set_dir(Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("xray")));
        assert!(crate::geo::get().is_some());
        let mut pc = crate::proxy::Config { port: 18898, log: true, ..Default::default() };
        pc.rules.tor_scope = "all".into();
        let p = crate::proxy::Proxy::start(pc, &[]).unwrap();
        for u in ["https://ya.ru", "https://www.gosuslugi.ru", "https://check.torproject.org/api/ip"] {
            let o = crate::util::hidden(crate::util::system32("curl.exe"))
                .args(["-s", "-m", "40", "-o", "NUL", "-w", "%{http_code}", "-x", "http://127.0.0.1:18898", u])
                .output()
                .unwrap();
            println!("{u}: {}", String::from_utf8_lossy(&o.stdout));
        }
        for e in p.log() {
            println!("{} → {}", e.host, e.action);
        }
        let log = p.log();
        assert!(log.iter().any(|e| e.host == "ya.ru" && e.action != "tor"));
        assert!(log.iter().any(|e| e.host == "check.torproject.org" && e.action == "tor"));
    }
}
