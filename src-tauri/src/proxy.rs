//! Обход DPI без прав администратора и без драйвера: локальный HTTP-прокси.
//!
//! Браузер (или вся система через настройки прокси Windows) открывает через
//! него туннели CONNECT. Первый пакет туннеля — TLS ClientHello — режется на
//! несколько TLS-записей так, что имя сайта (SNI) оказывается разорвано между
//! ними. Простые DPI собирают только первую запись и имя не видят.
//!
//! Способы отправки:
//! - `split` — записи уходят отдельными TCP-сегментами;
//! - `disorder` — первая запись уходит с TTL=1 и теряется по дороге, ядро
//!   пересылает её позже: DPI видит поток не по порядку.
//!
//! Адреса сайтов можно разрешать через DoH — тогда не мешает и подмена DNS.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const FIRST_DATA_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub port: u16,
    /// split | disorder
    pub method: String,
    /// Разрешать адреса через DoH (Cloudflare → Google), иначе системным DNS.
    pub doh: bool,
    /// Прописать прокси в настройки Windows (HKCU).
    pub system: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { port: 8881, method: "disorder".into(), doh: true, system: true }
    }
}

// ---------- разбор и нарезка ClientHello ----------

/// Смещение и длина имени сервера (SNI) внутри TLS-записи с ClientHello.
pub fn find_sni(rec: &[u8]) -> Option<(usize, usize)> {
    if rec.len() < 5 || rec[0] != 0x16 || rec[1] != 0x03 {
        return None;
    }
    let end = (5 + u16::from_be_bytes([rec[3], rec[4]]) as usize).min(rec.len());
    let get = |i: usize| rec.get(i).copied().filter(|_| i < end);
    let u16_at = |i: usize| Some(u16::from_be_bytes([get(i)?, get(i + 1)?]) as usize);
    let mut i = 5;
    if get(i)? != 0x01 {
        return None; // не ClientHello
    }
    i += 4 + 2 + 32; // тип+длина, версия, random
    i += 1 + get(i)? as usize; // session id
    i += 2 + u16_at(i)?; // cipher suites
    i += 1 + get(i)? as usize; // compression
    let ext_end = (i + 2 + u16_at(i)?).min(end);
    i += 2;
    while i + 4 <= ext_end {
        let ty = u16_at(i)?;
        let len = u16_at(i + 2)?;
        if ty == 0 {
            // server_name: list_len(2) type(1) name_len(2) name
            let name_len = u16_at(i + 4 + 3)?;
            let start = i + 4 + 5;
            if start + name_len <= end {
                return Some((start, name_len));
            }
            return None;
        }
        i += 4 + len;
    }
    None
}

/// Разрезать первую TLS-запись на несколько: до имени, середина имени, остаток.
/// Неподходящие данные возвращаются одним куском.
pub fn split_client_hello(data: &[u8]) -> Vec<Vec<u8>> {
    let Some((sni, sni_len)) = find_sni(data) else { return vec![data.to_vec()] };
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + rec_len > data.len() {
        return vec![data.to_vec()];
    }
    let payload = &data[5..5 + rec_len];
    let tail = &data[5 + rec_len..];
    // Точки разреза в координатах payload.
    let a = sni - 5;
    let b = a + (sni_len / 2).max(1);
    let mut cuts = vec![0, a, b, payload.len()];
    cuts.dedup();
    let mut out: Vec<Vec<u8>> = cuts
        .windows(2)
        .filter(|w| w[1] > w[0])
        .map(|w| {
            let part = &payload[w[0]..w[1]];
            let mut r = vec![0x16, data[1], data[2]];
            r.extend_from_slice(&(part.len() as u16).to_be_bytes());
            r.extend_from_slice(part);
            r
        })
        .collect();
    if !tail.is_empty() {
        out.last_mut().unwrap().extend_from_slice(tail);
    }
    out
}

fn send_parts(up: &mut TcpStream, parts: &[Vec<u8>], method: &str) -> std::io::Result<()> {
    up.set_nodelay(true)?;
    for (i, p) in parts.iter().enumerate() {
        if i == 0 && method == "disorder" && parts.len() > 1 {
            // TTL работает только для IPv4-сокета; для IPv6 — обычная нарезка.
            if let Ok(ttl) = up.ttl() {
                if up.set_ttl(1).is_ok() {
                    up.write_all(p)?;
                    std::thread::sleep(Duration::from_millis(10));
                    up.set_ttl(ttl)?;
                    continue;
                }
            }
        }
        up.write_all(p)?;
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

// ---------- HTTP-запрос клиента ----------

#[derive(Debug, PartialEq)]
pub enum Request {
    Connect { host: String, port: u16 },
    /// Обычный HTTP: адрес и заголовок, переписанный в origin-form.
    Http { host: String, port: u16, head: Vec<u8> },
}

pub fn parse_request(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let first = text.lines().next()?;
    let mut it = first.split_whitespace();
    let method = it.next()?;
    let target = it.next()?;
    let version = it.next()?;
    let split_hp = |hp: &str, def: u16| -> Option<(String, u16)> {
        if let Some(rest) = hp.strip_prefix('[') {
            let (h, p) = rest.split_once(']')?;
            let port = p.strip_prefix(':').map(|p| p.parse().ok()).unwrap_or(Some(def))?;
            return Some((h.to_string(), port));
        }
        match hp.rsplit_once(':') {
            Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
            None => Some((hp.to_string(), def)),
        }
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_hp(target, 443)?;
        return Some(Request::Connect { host, port });
    }
    let rest = target.strip_prefix("http://")?;
    let (hp, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_hp(hp, 80)?;
    let mut new_head = format!("{method} {path} {version}\r\n").into_bytes();
    let after_first = &head[first.len()..];
    let after_first = after_first.strip_prefix(b"\r\n").unwrap_or(after_first);
    new_head.extend_from_slice(after_first);
    Some(Request::Http { host, port, head: new_head })
}

fn read_head(s: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(p + 4);
            return Ok((buf, rest));
        }
        if buf.len() > 32 * 1024 {
            return Err(std::io::Error::other("header too large"));
        }
        let n = s.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

// ---------- сервер ----------

#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub running: bool,
    pub port: u16,
    pub active: u64,
    pub total: u64,
    pub failed: u64,
    pub system: bool,
    pub last_error: Option<String>,
}

struct Shared {
    cfg: Config,
    stop: AtomicBool,
    active: AtomicU64,
    total: AtomicU64,
    failed: AtomicU64,
    last_error: Mutex<Option<String>>,
    doh: Vec<crate::doh::DohClient>,
}

impl Shared {
    fn resolve(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![SocketAddr::new(ip, port)];
        }
        if self.cfg.doh {
            for c in &self.doh {
                if let Ok(ips) = c.resolve(host) {
                    let mut v: Vec<SocketAddr> = ips.iter().filter(|i| i.is_ipv4()).map(|i| SocketAddr::new(*i, port)).collect();
                    v.extend(ips.iter().filter(|i| i.is_ipv6()).map(|i| SocketAddr::new(*i, port)));
                    if !v.is_empty() {
                        return v;
                    }
                }
            }
        }
        (host, port).to_socket_addrs().map(|i| i.collect()).unwrap_or_default()
    }

    fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let addrs = self.resolve(host, port);
        let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, format!("{host}: no address"));
        for a in addrs.iter().take(4) {
            match TcpStream::connect_timeout(a, CONNECT_TIMEOUT) {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn handle(&self, mut client: TcpStream) -> std::io::Result<()> {
        client.set_read_timeout(Some(FIRST_DATA_TIMEOUT))?;
        let (head, early) = read_head(&mut client)?;
        let req = parse_request(&head).ok_or_else(|| std::io::Error::other("bad request"))?;
        match req {
            Request::Connect { host, port } => {
                let mut up = match self.connect(&host, port) {
                    Ok(u) => u,
                    Err(e) => {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                        return Err(e);
                    }
                };
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                // Первый пакет туннеля — обычно ClientHello.
                let mut first = early;
                if first.is_empty() {
                    let mut tmp = [0u8; 16 * 1024];
                    let n = client.read(&mut tmp)?;
                    if n == 0 {
                        return Ok(());
                    }
                    first.extend_from_slice(&tmp[..n]);
                }
                send_parts(&mut up, &split_client_hello(&first), &self.cfg.method)?;
                relay(client, up)
            }
            Request::Http { host, port, head } => {
                let mut up = self.connect(&host, port)?;
                up.write_all(&head)?;
                up.write_all(&early)?;
                relay(client, up)
            }
        }
    }
}

/// Двунаправленная пересылка до закрытия любой стороны.
fn relay(client: TcpStream, up: TcpStream) -> std::io::Result<()> {
    client.set_read_timeout(None)?;
    up.set_read_timeout(None)?;
    let (mut c2, mut u2) = (client.try_clone()?, up.try_clone()?);
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut u2, &mut c2);
        let _ = c2.shutdown(Shutdown::Write);
    });
    let (mut c, mut u) = (client, up);
    let _ = std::io::copy(&mut c, &mut u);
    let _ = u.shutdown(Shutdown::Write);
    let _ = t.join();
    Ok(())
}

pub struct Proxy {
    shared: Arc<Shared>,
}

impl Proxy {
    pub fn start(cfg: Config) -> Result<Proxy, String> {
        if cfg.method != "split" && cfg.method != "disorder" {
            let m = &cfg.method;
            return Err(crate::tr!("неизвестный способ: {m}", "unknown method: {m}"));
        }
        let port = cfg.port;
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| crate::tr!("порт {port} занят: {e}", "port {port} is busy: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let doh = if cfg.doh {
            [
                ("https://cloudflare-dns.com/dns-query", ["1.1.1.1", "1.0.0.1"]),
                ("https://dns.google/dns-query", ["8.8.8.8", "8.8.4.4"]),
            ]
            .iter()
            .filter_map(|(t, ips)| {
                let boot: Vec<IpAddr> = ips.iter().filter_map(|s| s.parse().ok()).collect();
                crate::doh::DohClient::new(t, &boot).ok()
            })
            .collect()
        } else {
            Vec::new()
        };
        let shared = Arc::new(Shared {
            cfg,
            stop: AtomicBool::new(false),
            active: AtomicU64::new(0),
            total: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            last_error: Mutex::new(None),
            doh,
        });
        let sh = shared.clone();
        std::thread::spawn(move || {
            while !sh.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, _)) => {
                        let sh = sh.clone();
                        std::thread::spawn(move || {
                            let _ = s.set_nonblocking(false);
                            sh.total.fetch_add(1, Ordering::Relaxed);
                            sh.active.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = sh.handle(s) {
                                if !matches!(e.kind(), std::io::ErrorKind::UnexpectedEof) {
                                    sh.failed.fetch_add(1, Ordering::Relaxed);
                                    *sh.last_error.lock().unwrap() = Some(e.to_string());
                                }
                            }
                            sh.active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(Proxy { shared })
    }

    pub fn stats(&self) -> Stats {
        Stats {
            running: true,
            port: self.shared.cfg.port,
            active: self.shared.active.load(Ordering::Relaxed),
            total: self.shared.total.load(Ordering::Relaxed),
            failed: self.shared.failed.load(Ordering::Relaxed),
            system: self.shared.cfg.system,
            last_error: self.shared.last_error.lock().unwrap().clone(),
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

// ---------- системный прокси Windows (HKCU, без прав администратора) ----------

/// Значения до включения — чтобы вернуть как было.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SystemProxy {
    pub enable: u32,
    pub server: Option<String>,
    pub r#override: Option<String>,
}

const INET: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

mod reg {
    use windows_sys::Win32::System::Registry::{
        RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD,
        RRF_RT_REG_SZ,
    };

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn get_dword(path: &str, name: &str) -> Option<u32> {
        let (p, n) = (w(path), w(name));
        let mut v = 0u32;
        let mut size = 4u32;
        let r = unsafe {
            RegGetValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), &mut v as *mut u32 as *mut _, &mut size)
        };
        (r == 0).then_some(v)
    }

    pub fn get_sz(path: &str, name: &str) -> Option<String> {
        let (p, n) = (w(path), w(name));
        let mut buf = vec![0u16; 4096];
        let mut size = (buf.len() * 2) as u32;
        let r = unsafe {
            RegGetValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut size)
        };
        if r != 0 {
            return None;
        }
        buf.truncate((size as usize / 2).saturating_sub(1));
        Some(String::from_utf16_lossy(&buf))
    }

    pub fn set_dword(path: &str, name: &str, v: u32) -> Result<(), String> {
        let (p, n) = (w(path), w(name));
        let r = unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr(), REG_DWORD, &v as *const u32 as *const _, 4) };
        if r == 0 {
            Ok(())
        } else {
            Err(format!("registry {name}: {r}"))
        }
    }

    pub fn set_sz(path: &str, name: &str, v: Option<&str>) -> Result<(), String> {
        let (p, n) = (w(path), w(name));
        let r = match v {
            Some(v) => {
                let data = w(v);
                unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr(), REG_SZ, data.as_ptr() as *const _, (data.len() * 2) as u32) }
            }
            None => unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr()) },
        };
        if r == 0 || (v.is_none() && r == 2) {
            Ok(())
        } else {
            Err(format!("registry {name}: {r}"))
        }
    }
}

/// Сообщить WinINet (браузеры, система), что настройки прокси изменились.
fn notify_wininet() {
    use windows_sys::Win32::Networking::WinInet::{InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED};
    unsafe {
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

pub fn system_current() -> SystemProxy {
    SystemProxy {
        enable: reg::get_dword(INET, "ProxyEnable").unwrap_or(0),
        server: reg::get_sz(INET, "ProxyServer"),
        r#override: reg::get_sz(INET, "ProxyOverride"),
    }
}

pub fn our_server(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Включить наш прокси в системе; вернуть прежние настройки.
pub fn system_set(port: u16) -> Result<SystemProxy, String> {
    let prev = system_current();
    reg::set_sz(INET, "ProxyServer", Some(&our_server(port)))?;
    reg::set_sz(INET, "ProxyOverride", Some("localhost;127.*;10.*;172.16.*;192.168.*;<local>"))?;
    reg::set_dword(INET, "ProxyEnable", 1)?;
    notify_wininet();
    Ok(prev)
}

/// Вернуть прежние настройки (если в системе всё ещё наш прокси).
pub fn system_restore(prev: &SystemProxy, port: u16) -> Result<(), String> {
    let cur = system_current();
    if cur.server.as_deref() != Some(our_server(port).as_str()) {
        return Ok(()); // пользователь уже поменял сам — не трогаем
    }
    reg::set_sz(INET, "ProxyServer", prev.server.as_deref())?;
    reg::set_sz(INET, "ProxyOverride", prev.r#override.as_deref())?;
    reg::set_dword(INET, "ProxyEnable", prev.enable)?;
    notify_wininet();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Минимальный ClientHello с SNI.
    fn hello(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        // Ещё одно расширение после SNI.
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_sni() {
        let h = hello("www.youtube.com");
        let (i, n) = find_sni(&h).unwrap();
        assert_eq!(&h[i..i + n], b"www.youtube.com");
        assert!(find_sni(b"GET / HTTP/1.1\r\n").is_none());
        assert!(find_sni(&h[..40]).is_none());
    }

    #[test]
    fn split_keeps_payload_and_cuts_sni() {
        let h = hello("discord.com");
        let parts = split_client_hello(&h);
        assert_eq!(parts.len(), 3);
        // Склейка payload всех записей = исходный payload.
        let mut payload = Vec::new();
        for p in &parts {
            assert_eq!(&p[..3], &[0x16, 0x03, 0x01]);
            let len = u16::from_be_bytes([p[3], p[4]]) as usize;
            assert_eq!(p.len(), 5 + len);
            payload.extend_from_slice(&p[5..]);
        }
        assert_eq!(payload, h[5..]);
        // Имя целиком не встречается ни в одной записи.
        for p in &parts {
            assert!(!p.windows(11).any(|w| w == b"discord.com"));
        }
        // Хвост после записи прикрепляется к последней части.
        let mut with_tail = h.clone();
        with_tail.extend_from_slice(b"TAIL");
        assert!(split_client_hello(&with_tail).last().unwrap().ends_with(b"TAIL"));
        assert_eq!(split_client_hello(b"plain"), vec![b"plain".to_vec()]);
    }

    #[test]
    fn parses_requests() {
        assert_eq!(
            parse_request(b"CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(Request::Connect { host: "www.youtube.com".into(), port: 443 })
        );
        assert_eq!(
            parse_request(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n"),
            Some(Request::Connect { host: "2001:db8::1".into(), port: 8443 })
        );
        match parse_request(b"GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap() {
            Request::Http { host, port, head } => {
                assert_eq!((host.as_str(), port), ("example.com", 80));
                assert_eq!(head, b"GET /a?b HTTP/1.1\r\nHost: example.com\r\n\r\n");
            }
            _ => panic!(),
        }
        assert!(parse_request(b"GET /relative HTTP/1.1\r\n\r\n").is_none());
    }

    /// Сеть: curl через прокси до PROXY_URL (по умолчанию YouTube) обоими способами.
    /// Системный прокси не трогается.
    #[test]
    #[ignore]
    fn live_proxy() {
        let url = std::env::var("PROXY_URL").unwrap_or_else(|_| "https://www.youtube.com/".into());
        for method in ["split", "disorder"] {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let _p = Proxy::start(Config { port, method: method.into(), doh: true, system: false }).unwrap();
            let out = std::process::Command::new(crate::util::system32("curl.exe"))
                .args(["-s", "-o", "NUL", "-w", "%{http_code} %{time_total}", "--max-time", "12"])
                .args(["-x", &format!("http://127.0.0.1:{port}"), &url])
                .output()
                .unwrap();
            println!("{method}: {} (exit {:?})", String::from_utf8_lossy(&out.stdout), out.status.code());
        }
    }

    /// Сквозной тест на loopback: «сервер» получает три TLS-записи, склейка
    /// их payload равна исходному ClientHello.
    #[test]
    fn end_to_end_loopback() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let sport = server.local_addr().unwrap().port();
        let h = hello("example.com");
        let expect = h[5..].to_vec();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = server.accept().unwrap();
            let mut payload = Vec::new();
            let mut records = 0;
            while payload.len() < expect.len() {
                let mut hdr = [0u8; 5];
                s.read_exact(&mut hdr).unwrap();
                assert_eq!(hdr[0], 0x16);
                let mut part = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
                s.read_exact(&mut part).unwrap();
                payload.extend_from_slice(&part);
                records += 1;
            }
            assert_eq!(payload, expect);
            assert_eq!(records, 3);
            s.write_all(b"pong").unwrap();
        });
        // Свободный порт для прокси.
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let pport = probe.local_addr().unwrap().port();
        drop(probe);
        let _proxy = Proxy::start(Config { port: pport, method: "split".into(), doh: false, system: false }).unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", pport)).unwrap();
        write!(c, "CONNECT 127.0.0.1:{sport} HTTP/1.1\r\n\r\n").unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200"));
        c.write_all(&h).unwrap();
        let mut pong = [0u8; 4];
        c.read_exact(&mut pong).unwrap();
        assert_eq!(&pong, b"pong");
        srv.join().unwrap();
    }
}
