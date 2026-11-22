//! DNS-over-HTTPS без сторонних HTTP-библиотек: rustls + минимальный HTTP/1.1.
//!
//! - `DohClient` — запросы RFC 8484 (POST application/dns-message) по
//!   keep-alive соединению. Адрес сервера берётся из bootstrap-IP, поэтому
//!   системный DNS не нужен (и не может зациклиться на наш же резолвер).
//! - `Stub` — локальный резолвер на 127.0.0.1:53 (и [::1]:53, если свободен),
//!   UDP и TCP, с кэшем. Даёт шифрованный DNS на Windows 10, где нет
//!   встроенного DoH, и на любом адаптере.
//! - `resolve` — A/AAAA через DoH для диагностики и прокси.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const TIMEOUT: Duration = Duration::from_secs(5);

// ---------- DNS-сообщения ----------

/// Запрос с одним вопросом и флагом RD.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut m = Vec::with_capacity(32 + name.len());
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(crate::tr!("некорректное имя: {name}", "invalid name: {name}"));
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    Ok(m)
}

fn skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *m.get(i)? as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + len;
    }
}

fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]))
}

/// Адреса A/AAAA из ответа и минимальный TTL записей.
pub fn parse_answers(m: &[u8]) -> Option<(Vec<IpAddr>, u32)> {
    let qd = u16_at(m, 4)? as usize;
    let an = u16_at(m, 6)? as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(m, i)? + 4;
    }
    let mut out = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..an {
        i = skip_name(m, i)?;
        let ty = u16_at(m, i)?;
        let ttl = u32::from_be_bytes([*m.get(i + 4)?, *m.get(i + 5)?, *m.get(i + 6)?, *m.get(i + 7)?]);
        let len = u16_at(m, i + 8)? as usize;
        let data = m.get(i + 10..i + 10 + len)?;
        min_ttl = min_ttl.min(ttl);
        match (ty, len) {
            (TYPE_A, 4) => out.push(IpAddr::from([data[0], data[1], data[2], data[3]])),
            (TYPE_AAAA, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(data);
                out.push(IpAddr::from(b));
            }
            _ => {}
        }
        i += 10 + len;
    }
    Some((out, if min_ttl == u32::MAX { 0 } else { min_ttl }))
}

/// Ответ SERVFAIL на запрос — чтобы клиент не ждал таймаута.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let mut r = query.to_vec();
    if r.len() >= 4 {
        r[2] |= 0x80; // QR
        r[3] = (r[3] & 0xF0) | 2;
    }
    r
}

// ---------- TLS ----------

/// Общая конфигурация rustls с корнями из хранилища Windows.
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

pub type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// TCP + TLS-рукопожатие с проверкой сертификата.
pub fn tls_connect(addr: SocketAddr, host: &str, timeout: Duration) -> std::io::Result<Tls> {
    let tcp = TcpStream::connect_timeout(&addr, timeout)?;
    tls_handshake(tcp, host, timeout)
}

pub fn tls_handshake(tcp: TcpStream, host: &str, timeout: Duration) -> std::io::Result<Tls> {
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    tcp.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    let conn = rustls::ClientConnection::new(tls_config(), name).map_err(std::io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(tls)
}

// ---------- DoH-клиент ----------

#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// `https://host[:port]/path[{?dns}]`.
pub fn parse_template(t: &str) -> Result<Template, String> {
    let bad = || crate::tr!("некорректный шаблон DoH: {t}", "invalid DoH template: {t}");
    let rest = t.trim().strip_prefix("https://").ok_or_else(bad)?;
    let rest = rest.replace("{?dns}", "");
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest.as_str(), "/dns-query".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().map_err(|_| bad())?),
        _ => (hostport.to_string(), 443),
    };
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err(bad());
    }
    Ok(Template { host, port, path })
}

pub struct DohClient {
    pub template: String,
    tpl: Template,
    addrs: Vec<SocketAddr>,
    conn: Mutex<Option<Tls>>,
}

impl DohClient {
    /// `bootstrap` — IP сервера; пусто — один раз через системный DNS.
    pub fn new(template: &str, bootstrap: &[IpAddr]) -> Result<Self, String> {
        let tpl = parse_template(template)?;
        let addrs: Vec<SocketAddr> = if bootstrap.is_empty() {
            use std::net::ToSocketAddrs;
            (tpl.host.as_str(), tpl.port)
                .to_socket_addrs()
                .map_err(|e| { let h = &tpl.host; crate::tr!("не удалось найти {h}: {e}", "cannot resolve {h}: {e}") })?
                .collect()
        } else {
            bootstrap.iter().map(|ip| SocketAddr::new(*ip, tpl.port)).collect()
        };
        if addrs.is_empty() {
            return Err(crate::tr!("нет адреса DoH-сервера", "no DoH server address"));
        }
        Ok(DohClient { template: template.to_string(), tpl, addrs, conn: Mutex::new(None) })
    }

    pub fn bootstrap(&self) -> Vec<IpAddr> {
        self.addrs.iter().map(|a| a.ip()).collect()
    }

    fn connect(&self) -> std::io::Result<Tls> {
        let mut last = std::io::Error::other("no address");
        for a in &self.addrs {
            match tls_connect(*a, &self.tpl.host, TIMEOUT) {
                Ok(t) => return Ok(t),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn post(tls: &mut Tls, tpl: &Template, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            tpl.path,
            tpl.host,
            query.len()
        );
        tls.write_all(head.as_bytes())?;
        tls.write_all(query)?;
        tls.flush()?;
        read_http_body(tls)
    }

    /// Обмен «сырым» DNS-сообщением. Одна повторная попытка на новом соединении.
    pub fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut guard = self.conn.lock().unwrap();
        for attempt in 0..2 {
            if guard.is_none() {
                *guard = Some(self.connect().map_err(|e| format!("DoH {}: {e}", self.tpl.host))?);
            }
            match Self::post(guard.as_mut().unwrap(), &self.tpl, query) {
                Ok(b) => return Ok(b),
                Err(e) => {
                    *guard = None;
                    if attempt == 1 {
                        return Err(format!("DoH {}: {e}", self.tpl.host));
                    }
                }
            }
        }
        unreachable!()
    }

    /// A и AAAA.
    pub fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        let mut out = Vec::new();
        for (i, qt) in [TYPE_A, TYPE_AAAA].into_iter().enumerate() {
            let q = build_query(0x4d00 + i as u16, name, qt)?;
            let r = self.exchange(&q)?;
            if let Some((ips, _)) = parse_answers(&r) {
                out.extend(ips);
            }
        }
        Ok(out)
    }
}

fn read_http_body(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::other("HTTP header too large"));
        }
        let n = r.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "connection closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(std::io::Error::other(format!("HTTP {status}")));
    }
    let mut body = buf[head_end..].to_vec();
    let header = |name: &str| {
        head.lines().find_map(|l| l.strip_prefix(name).map(|v| v.trim_start_matches(':').trim().to_string()))
    };
    if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        while body.len() < len {
            let n = r.read(&mut tmp)?;
            if n == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short body"));
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(len);
        return Ok(body);
    }
    if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        return read_chunked(body, r);
    }
    Err(std::io::Error::other("HTTP response without length"))
}

fn read_chunked(mut raw: Vec<u8>, r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut more = |raw: &mut Vec<u8>| -> std::io::Result<()> {
        let n = r.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "chunked eof"));
        }
        raw.extend_from_slice(&tmp[..n]);
        Ok(())
    };
    loop {
        let line_end = loop {
            if let Some(p) = raw.windows(2).position(|w| w == b"\r\n") {
                break p;
            }
            more(&mut raw)?;
        };
        let size_str = String::from_utf8_lossy(&raw[..line_end]).to_string();
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| std::io::Error::other("bad chunk size"))?;
        raw.drain(..line_end + 2);
        if size == 0 {
            return Ok(out);
        }
        while raw.len() < size + 2 {
            more(&mut raw)?;
        }
        out.extend_from_slice(&raw[..size]);
        raw.drain(..size + 2);
    }
}

// ---------- локальный резолвер ----------

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StubStats {
    pub queries: u64,
    pub cached: u64,
    pub errors: u64,
    pub last_error: Option<String>,
    pub ipv6: bool,
    /// Адрес петли, на котором слушает резолвер.
    pub addr: String,
    pub template: String,
}

struct Shared {
    client: DohClient,
    cache: Mutex<HashMap<Vec<u8>, (Vec<u8>, Instant)>>,
    queries: AtomicU64,
    cached: AtomicU64,
    errors: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl Shared {
    fn answer(&self, query: &[u8]) -> Vec<u8> {
        self.queries.fetch_add(1, Ordering::Relaxed);
        if query.len() < 12 {
            return Vec::new();
        }
        let key = query[2..].to_vec();
        if let Some((resp, exp)) = self.cache.lock().unwrap().get(&key) {
            if *exp > Instant::now() {
                self.cached.fetch_add(1, Ordering::Relaxed);
                let mut r = resp.clone();
                r[..2].copy_from_slice(&query[..2]);
                return r;
            }
        }
        match self.client.exchange(query) {
            Ok(mut r) if r.len() >= 12 => {
                r[..2].copy_from_slice(&query[..2]);
                let ttl = parse_answers(&r).map(|(_, t)| t).unwrap_or(0).clamp(10, 300);
                let mut c = self.cache.lock().unwrap();
                if c.len() > 4096 {
                    c.clear();
                }
                c.insert(key, (r.clone(), Instant::now() + Duration::from_secs(ttl as u64)));
                r
            }
            Ok(_) => servfail(query),
            Err(e) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                *self.last_error.lock().unwrap() = Some(e);
                servfail(query)
            }
        }
    }
}

pub struct Stub {
    stop: Arc<AtomicBool>,
    shared: Arc<Shared>,
    ipv6: bool,
    addr: std::net::Ipv4Addr,
}

/// Адреса петли по порядку: 127.0.0.1:53 часто занят (Hyper-V/ICS, другие DNS-прокси).
pub const LOOPBACKS: [[u8; 4]; 4] = [[127, 0, 0, 1], [127, 0, 0, 53], [127, 53, 53, 53], [127, 0, 53, 1]];

impl Stub {
    /// Занять порт 53 на первом свободном адресе петли (UDP и TCP) и на [::1], если получится.
    pub fn start(client: DohClient) -> Result<Stub, String> {
        let mut bound = None;
        let mut last = String::new();
        for o in LOOPBACKS {
            let a = SocketAddr::from((o, 53));
            match (UdpSocket::bind(a), TcpListener::bind(a)) {
                (Ok(u), Ok(t)) => {
                    bound = Some((std::net::Ipv4Addr::from(o), u, t));
                    break;
                }
                (Err(e), _) | (_, Err(e)) => last = e.to_string(),
            }
        }
        let Some((addr, u4, t4)) = bound else {
            return Err(crate::tr!(
                "порт 53 занят на всех адресах 127.x ({last}) — закройте другой DNS-сервер",
                "port 53 is busy on every 127.x address ({last}) — close the other DNS server"
            ));
        };
        let u6 = UdpSocket::bind("[::1]:53").ok();
        let t6 = TcpListener::bind("[::1]:53").ok();
        let ipv6 = u6.is_some() && t6.is_some();
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            client,
            cache: Mutex::new(HashMap::new()),
            queries: AtomicU64::new(0),
            cached: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_error: Mutex::new(None),
        });
        for u in std::iter::once(u4).chain(u6.filter(|_| ipv6)) {
            let (stop, shared) = (stop.clone(), shared.clone());
            std::thread::spawn(move || udp_loop(u, stop, shared));
        }
        for t in std::iter::once(t4).chain(t6.filter(|_| ipv6)) {
            let (stop, shared) = (stop.clone(), shared.clone());
            std::thread::spawn(move || tcp_loop(t, stop, shared));
        }
        Ok(Stub { stop, shared, ipv6, addr })
    }

    pub fn addr(&self) -> std::net::Ipv4Addr {
        self.addr
    }

    pub fn ipv6(&self) -> bool {
        self.ipv6
    }

    pub fn stats(&self) -> StubStats {
        StubStats {
            queries: self.shared.queries.load(Ordering::Relaxed),
            cached: self.shared.cached.load(Ordering::Relaxed),
            errors: self.shared.errors.load(Ordering::Relaxed),
            last_error: self.shared.last_error.lock().unwrap().clone(),
            ipv6: self.ipv6,
            addr: self.addr.to_string(),
            template: self.shared.client.template.clone(),
        }
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn udp_loop(sock: UdpSocket, stop: Arc<AtomicBool>, shared: Arc<Shared>) {
    let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
    let sock = Arc::new(sock);
    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::SeqCst) {
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let q = buf[..n].to_vec();
        let (sock, shared) = (sock.clone(), shared.clone());
        std::thread::spawn(move || {
            let mut r = shared.answer(&q);
            if r.is_empty() {
                return;
            }
            // Без EDNS клиент ждёт не больше 512 байт: обрезаем и ставим TC — он повторит по TCP.
            if r.len() > 512 && !has_opt(&q) {
                r = servfail(&q);
                r[2] |= 0x02;
                r[3] &= 0xF0;
            }
            let _ = sock.send_to(&r, from);
        });
    }
}

/// Есть ли в запросе OPT-запись (EDNS) — тогда UDP-ответ может быть больше 512 байт.
fn has_opt(q: &[u8]) -> bool {
    u16_at(q, 10).is_some_and(|ar| ar > 0)
}

fn tcp_loop(l: TcpListener, stop: Arc<AtomicBool>, shared: Arc<Shared>) {
    let _ = l.set_nonblocking(true);
    while !stop.load(Ordering::SeqCst) {
        match l.accept() {
            Ok((mut s, _)) => {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    loop {
                        let mut len = [0u8; 2];
                        if s.read_exact(&mut len).is_err() {
                            return;
                        }
                        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                        if s.read_exact(&mut q).is_err() {
                            return;
                        }
                        let r = shared.answer(&q);
                        let mut out = (r.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&r);
                        if s.write_all(&out).is_err() {
                            return;
                        }
                    }
                });
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let q = build_query(0x1234, "dns.google", TYPE_A).unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&q[12..], b"\x03dns\x06google\x00\x00\x01\x00\x01");
        assert!(build_query(1, "a..b", TYPE_A).is_err());
    }

    #[test]
    fn parse_compressed_answers() {
        // Ответ на example.com A/AAAA: имя в ответах — указатель на вопрос (0xC00C).
        let mut m = build_query(7, "example.com", TYPE_A).unwrap();
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 2; // ancount
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        m.extend_from_slice(&[0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
        m.extend_from_slice(&[0x26, 0x06, 0x28, 0, 0x02, 0x20, 0, 1, 0x2, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46]);
        let (ips, ttl) = parse_answers(&m).unwrap();
        assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap(), "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()]);
        assert_eq!(ttl, 30);
        assert!(parse_answers(&m[..20]).is_none());
    }

    #[test]
    fn servfail_keeps_id() {
        let q = build_query(0xBEEF, "a.b", TYPE_A).unwrap();
        let r = servfail(&q);
        assert_eq!(&r[..2], &[0xBE, 0xEF]);
        assert_eq!(r[2] & 0x80, 0x80);
        assert_eq!(r[3] & 0x0F, 2);
    }

    #[test]
    fn templates() {
        assert_eq!(
            parse_template("https://dns.google/dns-query").unwrap(),
            Template { host: "dns.google".into(), port: 443, path: "/dns-query".into() }
        );
        assert_eq!(parse_template("https://h:8443/q{?dns}").unwrap().port, 8443);
        assert_eq!(parse_template("https://h").unwrap().path, "/dns-query");
        assert!(parse_template("http://h/q").is_err());
    }

    #[test]
    fn http_bodies() {
        let mut r: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA";
        assert_eq!(read_http_body(&mut r).unwrap(), b"abc");
        let mut r: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(read_http_body(&mut r).unwrap(), b"abcde");
        let mut r: &[u8] = b"HTTP/1.1 400 Bad\r\nContent-Length: 0\r\n\r\n";
        assert!(read_http_body(&mut r).is_err());
    }

    /// Сеть: настоящий DoH-запрос к Cloudflare. Ничего в системе не меняет.
    #[test]
    #[ignore]
    fn live_resolve() {
        let c = DohClient::new("https://cloudflare-dns.com/dns-query", &["1.1.1.1".parse().unwrap()]).unwrap();
        let ips = c.resolve("example.com").unwrap();
        println!("{ips:?}");
        assert!(!ips.is_empty());
    }

    /// Сеть: резолвер на 127.0.0.1:53 отвечает по UDP и TCP. Адаптеры не трогает.
    #[test]
    #[ignore]
    fn live_stub() {
        let c = DohClient::new("https://dns.google/dns-query", &["8.8.8.8".parse().unwrap()]).unwrap();
        let stub = Stub::start(c).unwrap();
        let q = build_query(0x5151, "youtube.com", TYPE_A).unwrap();
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        let at = SocketAddr::from((stub.addr(), 53));
        println!("stub at {at}");
        u.send_to(&q, at).unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = u.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..2], &[0x51, 0x51]);
        println!("udp: {:?}", parse_answers(&buf[..n]));
        // Повтор — из кэша.
        u.send_to(&q, at).unwrap();
        u.recv_from(&mut buf).unwrap();
        let mut t = TcpStream::connect(at).unwrap();
        t.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        let mut m = (q.len() as u16).to_be_bytes().to_vec();
        m.extend_from_slice(&q);
        t.write_all(&m).unwrap();
        let mut len = [0u8; 2];
        t.read_exact(&mut len).unwrap();
        let mut r = vec![0u8; u16::from_be_bytes(len) as usize];
        t.read_exact(&mut r).unwrap();
        println!("tcp: {:?}", parse_answers(&r));
        let st = stub.stats();
        println!("{st:?}");
        assert_eq!((st.queries, st.cached, st.errors), (3, 2, 0));
    }
}
