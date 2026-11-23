//! Поиск рабочих мостов Tor (идея — TorBridgeMaster, тот же автор).
//!
//! 1. Списки проверенных мостов scriptzteam/Tor-Bridges-Collector-v2 (обновляются
//!    каждые 5 минут из BridgeDB): obfs4 и webtunnel.
//! 2. obfs4 — TCP-connect параллельно, по задержке: мёртвые порты отсеиваются сразу.
//! 3. Настоящая проверка — через один `lyrebird` в режиме managed PT: SOCKS5 к нему
//!    с параметрами моста в логине и пароле (pt-spec), затем TLS ClientHello —
//!    реле Tor отвечает записью Handshake (0x16). Так видно, что проходит и
//!    рукопожатие obfs4/webtunnel, и связь с самим реле, — за доли секунды вместо
//!    полного bootstrap tor на каждый мост.
//! 4. Останавливаемся, когда найдено `want` мостов: кандидаты идут по задержке.
//!
//! Параллельно не больше 8: часть провайдеров ограничивает число соединений.
use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SOURCES: [(&str, &str); 2] = [
    ("obfs4", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/obfs4_tested.txt"),
    ("webtunnel", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel_tested.txt"),
];

const PARALLEL: usize = 8;
/// Голый TCP-connect лимиту TLS-соединений не подпадает.
const TCP_PARALLEL: usize = 32;
const TCP_TIMEOUT: Duration = Duration::from_secs(4);
const CHECK_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Serialize)]
pub struct Found {
    pub line: String,
    pub transport: String,
    /// Время до ответа реле, мс.
    pub ms: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub found: Vec<Found>,
    pub checked: usize,
    pub candidates: usize,
    /// Скачано по транспортам.
    pub downloaded: Vec<(String, usize)>,
    pub errors: Vec<String>,
    pub cancelled: bool,
    pub secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub stage: &'static str,
    pub done: usize,
    pub total: usize,
    pub found: usize,
}

/// Скачать список (curl.exe; при неудаче — через прокси-обходчик, если он запущен).
fn download(url: &str, proxy: Option<u16>) -> Result<String, String> {
    let curl = crate::util::system32("curl.exe");
    let mut tries: Vec<Vec<String>> = vec![vec![]];
    if let Some(p) = proxy {
        tries.push(vec!["-x".into(), format!("http://127.0.0.1:{p}")]);
    }
    let mut last = String::new();
    for extra in tries {
        let mut args: Vec<String> = vec!["-sSfL".into(), "-m".into(), "25".into()];
        args.extend(extra);
        args.push(url.into());
        match crate::util::hidden(&curl).args(&args).output() {
            Ok(o) if o.status.success() => return Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
            Ok(o) => last = String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

/// Разобрать список: только нужные транспорты, без повторов по отпечатку.
pub fn parse_list(text: &str, kinds: &[&str]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    text.lines()
        .filter_map(crate::tor::clean_bridge)
        .filter(|l| kinds.contains(&crate::tor::bridge_transport(l)))
        .filter(|l| seen.insert(l.split_whitespace().nth(2).unwrap_or(l).to_ascii_uppercase()))
        .collect()
}

/// Адрес моста (`1.2.3.4:443`, `[2001:db8::1]:443`).
fn bridge_addr(line: &str) -> Option<SocketAddr> {
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Параметры моста для SOCKS5-логина lyrebird: `k=v;k=v` (без адреса и отпечатка).
pub fn pt_args(line: &str) -> String {
    line.split_whitespace().skip(3).filter(|w| w.contains('=')).map(|w| w.replace('\\', "\\\\").replace(';', "\\;")).collect::<Vec<_>>().join(";")
}

/// Хост из `url=` моста webtunnel.
fn webtunnel_host(line: &str) -> Option<String> {
    let url = line.split_whitespace().find_map(|w| w.strip_prefix("url="))?;
    let rest = url.split_once("://")?.1;
    Some(rest.split(['/', '?']).next()?.to_string())
}

/// Минимальный TLS 1.2 ClientHello без SNI — реле Tor отвечает на любой.
pub fn probe_hello() -> Vec<u8> {
    let mut random = [0u8; 32];
    let _ = getrandom::getrandom(&mut random);
    let suites: &[u8] = &[0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35];
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]); // группы: x25519
    ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]); // форматы точек
    ext.extend_from_slice(&[0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x01, 0x05, 0x01, 0x08, 0x04]); // подписи
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&random);
    body.push(0);
    body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    body.extend_from_slice(suites);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// lyrebird в режиме клиента: порты SOCKS по транспортам.
struct Lyrebird {
    child: std::process::Child,
    ports: std::collections::HashMap<String, u16>,
    _state: tempdir::Dir,
}

mod tempdir {
    /// Временная папка, удаляется при Drop.
    pub struct Dir(pub std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

impl Lyrebird {
    fn start(tor_dir: &Path, proxy: Option<u16>) -> Result<Lyrebird, String> {
        let state = std::env::temp_dir().join(format!("digital-bypass-pt-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&state);
        let mut cmd = crate::util::hidden(tor_dir.join("pluggable_transports").join("lyrebird.exe"));
        cmd.env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
            .env("TOR_PT_CLIENT_TRANSPORTS", "obfs4,webtunnel")
            .env("TOR_PT_STATE_LOCATION", &state)
            .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(p) = proxy {
            cmd.env("TOR_PT_PROXY", format!("socks5://127.0.0.1:{p}"));
        }
        let mut child = cmd.spawn().map_err(|e| format!("lyrebird: {e}"))?;
        let out = child.stdout.take().ok_or("lyrebird: no stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut ports = std::collections::HashMap::new();
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                let w: Vec<&str> = l.split_whitespace().collect();
                if w.len() >= 4 && w[0] == "CMETHOD" && w[2] == "socks5" {
                    if let Some(p) = w[3].rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) {
                        ports.insert(w[1].to_string(), p);
                    }
                } else if w.first() == Some(&"CMETHODS") || w.first().is_some_and(|x| x.ends_with("-ERROR")) {
                    let _ = tx.send((ports.clone(), l.clone()));
                    break;
                }
            }
        });
        // Процесс завернём сразу: при ошибке Drop его завершит и уберёт папку.
        let mut lb = Lyrebird { child, ports: Default::default(), _state: tempdir::Dir(state) };
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok((ports, _)) if !ports.is_empty() => {
                lb.ports = ports;
                Ok(lb)
            }
            Ok((_, line)) => Err(format!("lyrebird: {line}")),
            Err(_) => Err(crate::tr!(
                "lyrebird не запустился (брандмауэр вроде simplewall?)",
                "lyrebird did not start (a firewall such as simplewall?)"
            )),
        }
    }
}

impl Drop for Lyrebird {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Проверить мост через lyrebird: SOCKS5 + ClientHello → ответ реле. Время в мс.
fn check_one(pt_port: u16, line: &str) -> Result<u64, String> {
    let t0 = Instant::now();
    let target = bridge_addr(line).ok_or("bad address")?;
    let mut s = TcpStream::connect_timeout(&([127, 0, 0, 1], pt_port).into(), Duration::from_secs(3)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(CHECK_TIMEOUT)).ok();
    s.set_nodelay(true).ok();
    let io = |e: std::io::Error| e.to_string();
    s.write_all(&[5, 1, 2]).map_err(io)?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).map_err(io)?;
    if r != [5, 2] {
        return Err("pt: method".into());
    }
    // pt-spec: аргументы в логине (до 255 байт) и пароле (остаток или NUL).
    let args = pt_args(line).into_bytes();
    let (u, p) = args.split_at(args.len().min(255));
    let u: &[u8] = if u.is_empty() { &[0] } else { u };
    let p: &[u8] = if p.is_empty() { &[0] } else { p };
    let mut auth = vec![1, u.len() as u8];
    auth.extend_from_slice(u);
    auth.push(p.len().min(255) as u8);
    auth.extend_from_slice(&p[..p.len().min(255)]);
    s.write_all(&auth).map_err(io)?;
    s.read_exact(&mut r).map_err(io)?;
    if r[1] != 0 {
        return Err("pt: args rejected".into());
    }
    let mut req = vec![5, 1, 0];
    match target {
        SocketAddr::V4(a) => {
            req.push(1);
            req.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            req.push(4);
            req.extend_from_slice(&a.ip().octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).map_err(io)?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep[..4]).map_err(io)?;
    if rep[1] != 0 {
        return Err(format!("pt: socks {}", rep[1]));
    }
    let rest = if rep[3] == 4 { 18 } else { 6 };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).map_err(io)?;
    s.write_all(&probe_hello()).map_err(io)?;
    let mut b = [0u8; 1];
    s.read_exact(&mut b).map_err(io)?;
    if b[0] == 0x16 {
        Ok(t0.elapsed().as_millis() as u64)
    } else {
        Err(format!("relay answered 0x{:02x}", b[0]))
    }
}

/// TCP-задержка до адреса (для webtunnel — до хоста из url).
fn tcp_ms(line: &str) -> Option<u64> {
    let addr = if crate::tor::bridge_transport(line) == "webtunnel" {
        let h = webtunnel_host(line)?;
        (h.as_str(), 443).to_socket_addrs().ok()?.find(|a| a.is_ipv4())?
    } else {
        bridge_addr(line)?
    };
    let t = Instant::now();
    TcpStream::connect_timeout(&addr, TCP_TIMEOUT).ok()?;
    Some(t.elapsed().as_millis() as u64)
}

/// Выполнить `f` над элементами в `PARALLEL` потоков; `stop` прерывает раздачу.
fn par_each<T: Send + Sync, R: Send>(n: usize, items: &[T], stop: &(dyn Fn() -> bool + Sync), f: &(dyn Fn(&T) -> R + Sync), on: &(dyn Fn(usize, R) + Sync)) {
    let next = AtomicUsize::new(0);
    std::thread::scope(|sc| {
        for _ in 0..n.min(items.len()) {
            sc.spawn(|| loop {
                if stop() {
                    break;
                }
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(it) = items.get(i) else { break };
                let r = f(it);
                on(i, r);
            });
        }
    });
}

/// Найти до `want` рабочих мостов среди `kinds` (obfs4, webtunnel).
/// `proxy` — порт работающего прокси-обходчика (запасной путь для скачивания);
/// `via_proxy` — и сами проверки вести через него.
pub fn find(tor_dir: &Path, kinds: &[&str], want: usize, proxy: Option<u16>, via_proxy: bool, cancel: &AtomicBool, progress: impl Fn(Progress) + Sync) -> Result<Report, String> {
    let t0 = Instant::now();
    let mut rep = Report::default();
    let mut lists: Vec<Vec<String>> = Vec::new();
    for (kind, url) in SOURCES.iter().filter(|(k, _)| kinds.contains(k)) {
        progress(Progress { stage: "download", done: 0, total: 0, found: 0 });
        match download(url, proxy) {
            Ok(t) => {
                let v = parse_list(&t, &[kind]);
                rep.downloaded.push((kind.to_string(), v.len()));
                lists.push(v);
            }
            Err(e) => rep.errors.push(format!("{kind}: {e}")),
        }
    }
    // Чередуем транспорты, чтобы оба получили шанс до остановки по `want`.
    let mut all = Vec::new();
    let longest = lists.iter().map(Vec::len).max().unwrap_or(0);
    for i in 0..longest {
        for l in &lists {
            if let Some(x) = l.get(i) {
                all.push(x.clone());
            }
        }
    }
    if all.is_empty() {
        return Err(if rep.errors.is_empty() { crate::tr!("списки мостов пусты", "bridge lists are empty") } else { rep.errors.join("; ") });
    }

    // 1. TCP: живые адреса, по задержке.
    let done = AtomicUsize::new(0);
    let alive: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());
    let total = all.len();
    par_each(
        TCP_PARALLEL,
        &all,
        &|| cancel.load(Ordering::SeqCst),
        &|l: &String| tcp_ms(l),
        &|i, r| {
            if let Some(ms) = r {
                alive.lock().unwrap().push((ms, all[i].clone()));
            }
            let d = done.fetch_add(1, Ordering::SeqCst) + 1;
            progress(Progress { stage: "tcp", done: d, total, found: 0 });
        },
    );
    if cancel.load(Ordering::SeqCst) {
        rep.cancelled = true;
        rep.secs = t0.elapsed().as_secs();
        return Ok(rep);
    }
    let mut alive = alive.into_inner().unwrap();
    alive.sort_by_key(|(ms, _)| *ms);
    let cands: Vec<String> = alive.into_iter().map(|(_, l)| l).collect();
    rep.candidates = cands.len();

    // 2. Через lyrebird до ответа реле.
    let lb = Lyrebird::start(tor_dir, proxy.filter(|_| via_proxy))?;
    let found: Mutex<Vec<Found>> = Mutex::new(Vec::new());
    let checked = AtomicUsize::new(0);
    let enough = Arc::new(AtomicBool::new(false));
    let ctotal = cands.len();
    par_each(
        PARALLEL,
        &cands,
        &|| cancel.load(Ordering::SeqCst) || enough.load(Ordering::SeqCst),
        &|l: &String| {
            let t = crate::tor::bridge_transport(l);
            lb.ports.get(t).map(|p| check_one(*p, l))
        },
        &|i, r| {
            if let Some(Ok(ms)) = r {
                let mut f = found.lock().unwrap();
                f.push(Found { line: cands[i].clone(), transport: crate::tor::bridge_transport(&cands[i]).to_string(), ms });
                if f.len() >= want {
                    enough.store(true, Ordering::SeqCst);
                }
            }
            let d = checked.fetch_add(1, Ordering::SeqCst) + 1;
            let n = found.lock().unwrap().len();
            progress(Progress { stage: "check", done: d, total: ctotal, found: n });
        },
    );
    drop(lb);
    let mut found = found.into_inner().unwrap();
    found.sort_by_key(|f| f.ms);
    found.truncate(want.max(1));
    rep.found = found;
    rep.checked = checked.into_inner();
    rep.cancelled = cancel.load(Ordering::SeqCst);
    rep.secs = t0.elapsed().as_secs();
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_and_args() {
        let text = "obfs4 1.2.3.4:443 AAAA cert=x/y+z iat-mode=0\nobfs4 1.2.3.5:443 aaaa cert=q iat-mode=1\n\
                    webtunnel [2001:db8::1]:443 BBBB url=https://w.example/p ver=0.0.1\njunk\n";
        assert_eq!(parse_list(text, &["obfs4"]).len(), 1, "повтор отпечатка отброшен");
        let w = parse_list(text, &["webtunnel"]);
        assert_eq!(w.len(), 1);
        assert_eq!(pt_args("obfs4 1.2.3.4:443 AAAA cert=x/y+z iat-mode=0"), "cert=x/y+z;iat-mode=0");
        assert_eq!(pt_args(&w[0]), "url=https://w.example/p;ver=0.0.1");
        assert_eq!(pt_args("obfs4 1.2.3.4:1 A k=a;b"), "k=a\\;b");
        assert_eq!(webtunnel_host(&w[0]).as_deref(), Some("w.example"));
        assert_eq!(bridge_addr(&w[0]), Some("[2001:db8::1]:443".parse().unwrap()));
    }

    #[test]
    fn hello_shape() {
        let h = probe_hello();
        assert_eq!(&h[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
        assert_eq!(h[5], 1);
    }

    /// `cargo test live_bridges -- --ignored --nocapture` — сеть, ~30–90 с.
    #[test]
    #[ignore]
    fn live_bridges() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tor");
        let r = find(&dir, &["obfs4", "webtunnel"], 8, None, false, &AtomicBool::new(false), |p| eprintln!("{p:?}")).unwrap();
        for f in &r.found {
            println!("{} ms  {}", f.ms, &f.line[..f.line.len().min(70)]);
        }
        println!("checked {} of {}, {:?}, {} s", r.checked, r.candidates, r.downloaded, r.secs);
        assert!(!r.found.is_empty());
    }
}
