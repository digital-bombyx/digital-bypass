//! «Почему не открывается сайт»: сравнить системный DNS с DoH, проверить
//! TCP:443 и TLS-рукопожатие с SNI по каждому адресу и подсказать модуль.
//!
//! - TCP не подключается ни к одному адресу — блокировка по IP (нужен VPN);
//! - TCP есть, а TLS сбрасывается/висит — DPI по SNI (zapret2 или прокси);
//! - системный DNS отдаёт заглушку или «чужой» сертификат, а адреса из DoH
//!   работают — подмена DNS (модуль DNS / hosts).

use serde::Serialize;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PER_SOURCE: usize = 3;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    Ok,
    /// TCP не подключился.
    TcpFail,
    /// TLS: соединение сброшено.
    TlsReset,
    /// TLS: ответа нет (таймаут).
    TlsTimeout,
    /// TLS: сертификат не подходит к домену — подмена/заглушка.
    TlsCert,
    /// TLS: другая ошибка.
    TlsError,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub ip: String,
    /// system | doh | both
    pub source: &'static str,
    pub result: Probe,
    pub ms: Option<u64>,
    pub detail: Option<String>,
    /// Для сброса/таймаута TLS: на каком шаге (пришло ли что-то от сервера).
    pub stage: Option<Stage>,
    /// Повторы проверки дали разный результат (балансировка, несколько DPI).
    pub unstable: bool,
}

/// На чём срабатывает DPI.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Ответа сервера не было: режут наш ClientHello (имя сайта) — нарезка помогает.
    Request,
    /// Сервер ответил, потом сброс/тишина: режут по ответу (сертификат) —
    /// нарезка запроса не поможет.
    Response,
}

/// Дополнительные проверки, если сайт режет DPI: что именно блокируется.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Extra {
    /// Адрес, на котором проверяли.
    pub ip: String,
    /// С нарезкой ClientHello (как в прокси) открывается.
    pub split_ok: Option<bool>,
    /// С маленьким буфером приёма (сервер шлёт ответ мелкими кусками) открывается.
    pub small_buf_ok: Option<bool>,
    /// Тот же адрес с другим именем сайта отвечает (адрес сам по себе не фильтруется).
    pub ip_clean: Option<bool>,
    /// Имя сайта режется и на постороннем адресе (1.1.1.1) — DPI по имени везде.
    pub name_anywhere: Option<bool>,
    /// Для ограничения по сети назначения: имена (обычно из белых списков),
    /// с которыми этот адрес всё же отвечает. Пусто — не проходит ни одно.
    pub sni_pass: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Открывается.
    Ok,
    /// Подмена DNS: модуль DNS / hosts.
    Dns,
    /// DPI по SNI: zapret2 или прокси.
    Dpi,
    /// Блокировка по IP: только VPN.
    Ip,
    /// Ограничение по сети назначения (с 2025 года — зарубежные хостинги по AS):
    /// TLS к адресу обрывается при любом имени сайта, или передача замирает
    /// после нескольких пакетов. Нарезка не помогает.
    DestNet,
    /// Имя не разрешается нигде.
    NoDomain,
    /// Не удалось определить.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub domain: String,
    pub system: Vec<String>,
    pub system_error: Option<String>,
    pub doh: Vec<String>,
    pub doh_error: Option<String>,
    /// Системный DNS вернул заглушку (0.0.0.0, 127.x, частные сети).
    pub system_bogus: bool,
    pub checks: Vec<Check>,
    pub verdict: Verdict,
    /// Для вердикта «DPI»: на чём режут (по первому заблокированному адресу).
    pub stage: Option<Stage>,
    pub extra: Option<Extra>,
    /// Проверка «замирания»: маленький запрос и 64 КБ (если TLS прошёл).
    pub freeze: Option<FreezeProbe>,
    /// Тот же сайт через наш прокси-обходчик (если он включён).
    pub via_proxy: Option<ProxyCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyCheck {
    pub port: u16,
    pub result: Probe,
    pub ms: Option<u64>,
    pub detail: Option<String>,
}

/// TLS к сайту через HTTP CONNECT нашего прокси.
pub fn probe_via_proxy(port: u16, host: &str) -> ProxyCheck {
    use std::io::{Read, Write};
    let t0 = Instant::now();
    let fail = |result, d: String| ProxyCheck { port, result, ms: None, detail: Some(d) };
    let mut tcp = match TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), TIMEOUT) {
        Ok(s) => s,
        Err(e) => return fail(Probe::TcpFail, format!("proxy: {e}")),
    };
    let _ = tcp.set_read_timeout(Some(TIMEOUT * 2));
    if let Err(e) = write!(tcp, "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n") {
        return fail(Probe::TcpFail, e.to_string());
    }
    // Ответ прокси до пустой строки.
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 4096 {
        match tcp.read(&mut b) {
            Ok(1) => head.push(b[0]),
            Ok(_) => return fail(Probe::TcpFail, "proxy closed".into()),
            Err(e) => return fail(Probe::TcpFail, e.to_string()),
        }
    }
    let status = String::from_utf8_lossy(&head);
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return fail(Probe::TcpFail, status.lines().next().unwrap_or("").to_string());
    }
    match crate::doh::tls_handshake(tcp, host, TIMEOUT * 2) {
        Ok(_) => ProxyCheck { port, result: Probe::Ok, ms: Some(t0.elapsed().as_millis() as u64), detail: None },
        Err(e) => {
            let (p, d) = classify(&e);
            fail(p, d)
        }
    }
}

/// Замирание соединения после N пакетов (с 2025 года — к Hetzner, OVH,
/// DigitalOcean и др. по сети назначения: передача встаёт без сброса).
#[derive(Debug, Clone, Serialize)]
pub struct FreezeProbe {
    pub ip: String,
    /// Ответ на маленький запрос получен.
    pub small_ok: bool,
    /// Ответ после отправки 64 КБ получен.
    pub big_ok: bool,
    pub detail: Option<String>,
}

const FREEZE_BYTES: usize = 64 * 1024;

/// Режут адрес, а не имя: нарезка не помогает, с другим именем адрес тоже
/// режется, а это имя на постороннем адресе проходит.
pub fn dest_net(x: &Extra) -> bool {
    x.split_ok != Some(true) && x.ip_clean == Some(false) && x.name_anywhere == Some(false)
}

/// TLS к `ip` и HTTP-запрос с телом `body` байт; Ok(true) — пришёл хоть байт ответа,
/// Ok(false) — тишина до таймаута (замирание), Err — сброс или другая ошибка.
fn exchange(ip: IpAddr, host: &str, body: usize) -> std::io::Result<bool> {
    use std::io::{Read, Write};
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(ip, 443), TIMEOUT)?;
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tcp.set_write_timeout(Some(TIMEOUT))?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(std::io::Error::other)?;
    let conn = rustls::ClientConnection::new(crate::doh::tls_config(), name).map_err(std::io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let head = if body == 0 {
        format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
    } else {
        format!("POST / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/octet-stream\r\nContent-Length: {body}\r\nConnection: close\r\n\r\n")
    };
    tls.write_all(head.as_bytes())?;
    let chunk = vec![b'x'; 4096];
    let mut left = body;
    while left > 0 {
        let n = left.min(chunk.len());
        match tls.write_all(&chunk[..n]) {
            Ok(()) => left -= n,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    tls.flush()?;
    let mut b = [0u8; 1];
    match tls.read(&mut b) {
        Ok(n) => Ok(n > 0),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Маленький запрос отвечается, а после 64 КБ — тишина: замирание.
pub fn freeze_probe(ip: IpAddr, host: &str) -> FreezeProbe {
    let small = exchange(ip, host, 0);
    let big = if matches!(small, Ok(true)) { exchange(ip, host, FREEZE_BYTES) } else { Ok(false) };
    let detail = [small.as_ref().err(), big.as_ref().err()].into_iter().flatten().next().map(|e| e.to_string());
    FreezeProbe { ip: ip.to_string(), small_ok: matches!(small, Ok(true)), big_ok: matches!(big, Ok(true)), detail }
}

impl FreezeProbe {
    /// Замирание — только если маленький ответ пришёл, а большой утонул в тишине (не сброс).
    pub fn frozen(&self) -> bool {
        self.small_ok && !self.big_ok && self.detail.is_none()
    }
}

/// Домен из того, что вставил пользователь: схема, путь, порт, `*.` отбрасываются.
pub fn normalize(input: &str) -> Result<String, String> {
    let mut s = input.trim().to_lowercase();
    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_string();
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s.truncate(i);
    }
    if let Some(i) = s.rfind('@') {
        s = s[i + 1..].to_string();
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) {
            s = h.to_string();
        }
    }
    let s = s.trim_start_matches("*.").trim_end_matches('.').to_string();
    let ok = s.contains('.')
        && s.len() <= 253
        && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    if !ok {
        return Err(crate::tr!("введите домен, например youtube.com", "enter a domain, e.g. youtube.com"));
    }
    Ok(s)
}

/// Адрес, который не может быть настоящим сайтом в интернете.
pub fn is_bogus(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_unspecified() || a.is_loopback() || a.is_private() || a.is_link_local() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_unspecified() || a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn classify(e: &std::io::Error) -> (Probe, String) {
    use std::io::ErrorKind::*;
    if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        let p = match inner {
            rustls::Error::InvalidCertificate(_) => Probe::TlsCert,
            _ => Probe::TlsError,
        };
        return (p, inner.to_string());
    }
    let p = match e.kind() {
        TimedOut | WouldBlock => Probe::TlsTimeout,
        ConnectionReset | ConnectionAborted | UnexpectedEof | BrokenPipe => Probe::TlsReset,
        _ => Probe::TlsError,
    };
    (p, e.to_string())
}

pub fn probe(ip: IpAddr, host: &str) -> (Probe, Option<u64>, Option<String>) {
    let r = handshake(ip, host, false, 0);
    (r.probe, r.ms, r.detail)
}

/// Результат TLS-рукопожатия; `got` — сколько байт успел прислать сервер.
pub struct Outcome {
    pub probe: Probe,
    pub ms: Option<u64>,
    pub detail: Option<String>,
    pub got: usize,
}

impl Outcome {
    /// Для сброса/таймаута: режут запрос или ответ.
    pub fn stage(&self) -> Option<Stage> {
        matches!(self.probe, Probe::TlsReset | Probe::TlsTimeout).then_some(if self.got > 0 { Stage::Response } else { Stage::Request })
    }
}

/// TLS-рукопожатие с `host` на `ip:443`. `split` — нарезать ClientHello как
/// прокси; `rcvbuf` — маленький буфер приёма (0 — системный).
/// Сертификат проверяется полностью (несовпадение имени → `TlsCert`).
pub fn handshake(ip: IpAddr, host: &str, split: bool, rcvbuf: usize) -> Outcome {
    let fail = |probe, detail: String, got| Outcome { probe, ms: None, detail: Some(detail), got };
    let t0 = Instant::now();
    let tcp = match crate::proxy::connect_one(SocketAddr::new(ip, 443), TIMEOUT, rcvbuf) {
        Ok(s) => s,
        Err(e) => return fail(Probe::TcpFail, e.to_string(), 0),
    };
    let _ = tcp.set_nodelay(true);
    let _ = tcp.set_read_timeout(Some(TIMEOUT));
    let _ = tcp.set_write_timeout(Some(TIMEOUT));
    let name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => return fail(Probe::TlsError, e.to_string(), 0),
    };
    let conn = match rustls::ClientConnection::new(crate::doh::tls_config(), name) {
        Ok(c) => c,
        Err(e) => return fail(Probe::TlsError, e.to_string(), 0),
    };
    let mut tls = rustls::StreamOwned::new(conn, Fragmenting { inner: tcp, first: split, got: 0 });
    while tls.conn.is_handshaking() {
        if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
            let (p, d) = classify(&e);
            return fail(p, d, tls.sock.got);
        }
    }
    Outcome { probe: Probe::Ok, ms: Some(t0.elapsed().as_millis() as u64), detail: None, got: tls.sock.got }
}

/// TCP-поток, у которого первая запись (ClientHello) уходит нарезанной —
/// как в прокси: куски по TLS-записям с disorder. Нужен, чтобы проверить
/// сертификат сайта, имя которого режет DPI.
pub(crate) struct Fragmenting {
    pub(crate) inner: TcpStream,
    /// Первая запись ещё не ушла (и её надо нарезать).
    pub(crate) first: bool,
    /// Сколько байт пришло от сервера.
    pub(crate) got: usize,
}

impl std::io::Read for Fragmenting {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(b)?;
        self.got += n;
        Ok(n)
    }
}

impl std::io::Write for Fragmenting {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.first {
            self.first = false;
            let o = crate::proxy::SplitOpts { split: "chunk".into(), records: true, chunk: 4, ..Default::default() };
            crate::proxy::send_parts(&mut self.inner, &crate::proxy::split_with(b, &o), true, false)?;
            return Ok(b.len());
        }
        self.inner.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Как `probe`, но ClientHello нарезается — для сайтов, которые режет DPI.
pub fn probe_fragmented(ip: IpAddr, host: &str) -> (Probe, Option<u64>, Option<String>) {
    let r = handshake(ip, host, true, 0);
    (r.probe, r.ms, r.detail)
}

/// Маленький буфер приёма для проверки «режут по ответу».
pub const SMALL_RCVBUF: usize = 2048;
/// Имя для проверки «адрес фильтруется сам по себе»: заведомо не блокируется.
const NEUTRAL_SNI: &str = "example.com";
/// Адрес для проверки «имя режется везде».
const NEUTRAL_IP: &str = "1.1.1.1";

/// Сброс/таймаут — признак вмешательства; ответ с любой ошибкой TLS — сервер отвечает.
fn cut(p: Probe) -> bool {
    matches!(p, Probe::TlsReset | Probe::TlsTimeout)
}

/// Две попытки параллельно: результат засчитывается, только если совпал.
/// При расхождении берётся неудачный (как REPEATS в blockcheck).
fn probe_twice(ip: IpAddr, host: &str) -> (Outcome, bool) {
    let h = host.to_string();
    let t = std::thread::spawn(move || handshake(ip, &h, false, 0));
    let a = handshake(ip, host, false, 0);
    let b = t.join().unwrap_or(Outcome { probe: Probe::TlsError, ms: None, detail: None, got: 0 });
    let unstable = a.probe != b.probe;
    let pick = if a.probe == Probe::Ok { b } else { a };
    (pick, unstable)
}

/// Что именно режут на адресе `ip` (запускается для вердикта «DPI»).
pub fn extra(ip: IpAddr, host: &str, stage: Option<Stage>) -> Extra {
    let h = host.to_string();
    let split = std::thread::spawn(move || handshake(ip, &h, true, 0).probe);
    let h = host.to_string();
    let small = (stage == Some(Stage::Response)).then(|| std::thread::spawn(move || handshake(ip, &h, false, SMALL_RCVBUF).probe));
    let other = std::thread::spawn(move || handshake(ip, NEUTRAL_SNI, false, 0).probe);
    let h = host.to_string();
    let anywhere = std::thread::spawn(move || handshake(NEUTRAL_IP.parse().unwrap(), &h, false, 0).probe);
    let join = |t: std::thread::JoinHandle<Probe>| t.join().ok();
    Extra {
        ip: ip.to_string(),
        split_ok: join(split).map(|p| p == Probe::Ok),
        small_buf_ok: small.and_then(join).map(|p| p == Probe::Ok),
        ip_clean: join(other).filter(|p| *p != Probe::TcpFail).map(|p| !cut(p)),
        name_anywhere: join(anywhere).filter(|p| *p != Probe::TcpFail).map(cut),
        sni_pass: None,
    }
}

/// Вердикт по результатам (чистая функция — покрыта тестами).
pub fn verdict(system: &[IpAddr], doh: &[IpAddr], bogus: bool, checks: &[Check]) -> Verdict {
    if system.is_empty() && doh.is_empty() {
        return Verdict::NoDomain;
    }
    let sys_ok = checks.iter().any(|c| c.source != "doh" && c.result == Probe::Ok);
    let doh_ok = checks.iter().any(|c| c.source != "system" && c.result == Probe::Ok);
    if sys_ok && !bogus {
        return Verdict::Ok;
    }
    let sys_spoofed = bogus
        || (system.is_empty() && !doh.is_empty())
        || checks.iter().any(|c| c.source == "system" && c.result == Probe::TlsCert);
    if doh_ok && (sys_spoofed || !sys_ok) {
        return Verdict::Dns;
    }
    let real: Vec<&Check> = checks.iter().filter(|c| c.source != "system" || !bogus).collect();
    if real.is_empty() {
        return if bogus { Verdict::Dns } else { Verdict::Unknown };
    }
    if real.iter().all(|c| c.result == Probe::TcpFail) {
        return Verdict::Ip;
    }
    if real.iter().any(|c| matches!(c.result, Probe::TlsReset | Probe::TlsTimeout)) {
        return Verdict::Dpi;
    }
    if sys_spoofed {
        return Verdict::Dns;
    }
    Verdict::Unknown
}

/// Проверка домена. DoH — Cloudflare, при ошибке Google (по IP, без системного DNS).
#[cfg(test)]
pub fn run(input: &str) -> Result<Report, String> {
    run_with(input, None)
}

/// `proxy_port` — порт включённого прокси-обходчика: сайт проверяется и через него.
pub fn run_with(input: &str, proxy_port: Option<u16>) -> Result<Report, String> {
    let domain = normalize(input)?;
    let (system, system_error) = match (domain.as_str(), 443).to_socket_addrs() {
        Ok(it) => {
            let mut v: Vec<IpAddr> = Vec::new();
            for a in it {
                if !v.contains(&a.ip()) {
                    v.push(a.ip());
                }
            }
            (v, None)
        }
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let mut doh_error = None;
    let mut doh: Vec<IpAddr> = Vec::new();
    for (tpl, ips) in [
        ("https://cloudflare-dns.com/dns-query", ["1.1.1.1", "1.0.0.1"]),
        ("https://dns.google/dns-query", ["8.8.8.8", "8.8.4.4"]),
    ] {
        let boot: Vec<IpAddr> = ips.iter().map(|s| s.parse().unwrap()).collect();
        match crate::doh::DohClient::new(tpl, &boot).and_then(|c| c.resolve(&domain)) {
            Ok(v) => {
                doh = v;
                doh_error = None;
                break;
            }
            Err(e) => doh_error = Some(e),
        }
    }
    let bogus = !system.is_empty() && system.iter().all(is_bogus);

    // Что проверять: до 3 адресов из каждого источника; IPv6 — только если IPv4 нет
    // (без IPv6-связности он всегда «не подключается» и путает вердикт).
    let pick = |v: &[IpAddr]| -> Vec<IpAddr> {
        let v4: Vec<IpAddr> = v.iter().filter(|i| i.is_ipv4()).copied().collect();
        let mut s = if v4.is_empty() { v.to_vec() } else { v4 };
        s.truncate(MAX_PER_SOURCE);
        s
    };
    let mut targets: Vec<(IpAddr, &'static str)> = Vec::new();
    for ip in pick(&system) {
        targets.push((ip, if doh.contains(&ip) { "both" } else { "system" }));
    }
    for ip in pick(&doh) {
        if !targets.iter().any(|(t, _)| *t == ip) {
            targets.push((ip, "doh"));
        }
    }
    let host = domain.clone();
    let handles: Vec<_> = targets
        .into_iter()
        .map(|(ip, source)| {
            let host = host.clone();
            std::thread::spawn(move || {
                // Заглушки вроде 127.0.0.1 не трогаем: там может быть что угодно локальное.
                if is_bogus(&ip) {
                    return Check { ip: ip.to_string(), source, result: Probe::TcpFail, ms: None, detail: Some("bogus".into()), stage: None, unstable: false };
                }
                let (o, unstable) = probe_twice(ip, &host);
                Check { ip: ip.to_string(), source, result: o.probe, ms: o.ms, detail: o.detail.clone(), stage: o.stage(), unstable }
            })
        })
        .collect();
    let checks: Vec<Check> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
    let mut v = verdict(&system, &doh, bogus, &checks);
    // TLS прошёл — проверить, не замирает ли передача после нескольких пакетов.
    let freeze = if v == Verdict::Ok {
        checks.iter().find(|c| c.result == Probe::Ok).and_then(|c| c.ip.parse().ok()).map(|ip| freeze_probe(ip, &domain))
    } else {
        None
    };
    if freeze.as_ref().is_some_and(|f| f.frozen()) {
        v = Verdict::DestNet;
    }
    let cutc = checks.iter().find(|c| cut(c.result) && !(bogus && c.source == "system"));
    let stage = if v == Verdict::Dpi { cutc.and_then(|c| c.stage) } else { None };
    let extra = match (v, cutc) {
        (Verdict::Dpi, Some(c)) => c.ip.parse().ok().map(|ip| self::extra(ip, &domain, stage)),
        _ => None,
    };
    let mut extra = extra;
    if let Some(x) = extra.as_mut().filter(|x| dest_net(x)) {
        v = Verdict::DestNet;
        // Какие имена этот адрес пропускает: если есть из белых списков —
        // VLESS+Reality с таким SNI на этом хостинге может работать.
        let snis: Vec<String> = crate::sniscan::DEFAULT_SNIS.iter().map(|s| s.to_string()).collect();
        x.sni_pass = crate::sniscan::run(&format!("{}:443", x.ip), &snis, 4).ok().map(|r| {
            r.items.into_iter().filter(|i| i.outcome == crate::sniscan::Outcome::Pass).map(|i| i.sni).take(8).collect()
        });
    }
    let via_proxy = proxy_port.map(|p| probe_via_proxy(p, &domain));
    Ok(Report {
        domain,
        system: system.iter().map(|i| i.to_string()).collect(),
        system_error,
        doh: doh.iter().map(|i| i.to_string()).collect(),
        doh_error,
        system_bogus: bogus,
        checks,
        verdict: v,
        stage,
        extra,
        freeze,
        via_proxy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn c(ip: &str, source: &'static str, result: Probe) -> Check {
        Check { ip: ip.into(), source, result, ms: None, detail: None, stage: None, unstable: false }
    }

    #[test]
    fn dest_net_rule() {
        let x = |split_ok, ip_clean, name_anywhere| Extra { split_ok, ip_clean, name_anywhere, ..Default::default() };
        // Структура с новым полем по умолчанию — без SNI.
        assert!(x(None, None, None).sni_pass.is_none());
        assert!(dest_net(&x(Some(false), Some(false), Some(false))));
        assert!(!dest_net(&x(Some(true), Some(false), Some(false))));
        assert!(!dest_net(&x(Some(false), Some(true), Some(false))));
        assert!(!dest_net(&x(Some(false), Some(false), Some(true))));
        assert!(!dest_net(&x(Some(false), None, Some(false))));
    }

    #[test]
    fn freeze_flag() {
        let f = |small_ok, big_ok, detail: Option<&str>| FreezeProbe { ip: String::new(), small_ok, big_ok, detail: detail.map(String::from) };
        assert!(f(true, false, None).frozen());
        assert!(!f(true, true, None).frozen());
        assert!(!f(false, false, None).frozen());
        assert!(!f(true, false, Some("reset")).frozen());
    }

    #[test]
    fn stages() {
        let o = |probe, got| Outcome { probe, ms: None, detail: None, got };
        assert_eq!(o(Probe::TlsReset, 0).stage(), Some(Stage::Request));
        assert_eq!(o(Probe::TlsTimeout, 3000).stage(), Some(Stage::Response));
        assert_eq!(o(Probe::TlsCert, 3000).stage(), None);
        assert_eq!(o(Probe::Ok, 3000).stage(), None);
    }

    #[test]
    fn normalize_inputs() {
        assert_eq!(normalize("https://www.YouTube.com/watch?v=1").unwrap(), "www.youtube.com");
        assert_eq!(normalize("discord.com:443").unwrap(), "discord.com");
        assert_eq!(normalize("*.example.org.").unwrap(), "example.org");
        assert!(normalize("localhost").is_err());
        assert!(normalize("bad domain.com").is_err());
    }

    #[test]
    fn bogus_addresses() {
        assert!(is_bogus(&ip("0.0.0.0")));
        assert!(is_bogus(&ip("127.0.0.1")));
        assert!(is_bogus(&ip("10.10.34.35")));
        assert!(is_bogus(&ip("::1")));
        assert!(!is_bogus(&ip("142.250.74.14")));
    }

    #[test]
    fn verdicts() {
        let s = [ip("1.2.3.4")];
        let d = [ip("1.2.3.4")];
        assert_eq!(verdict(&s, &d, false, &[c("1.2.3.4", "both", Probe::Ok)]), Verdict::Ok);
        assert_eq!(verdict(&s, &d, false, &[c("1.2.3.4", "both", Probe::TlsReset)]), Verdict::Dpi);
        assert_eq!(verdict(&s, &d, false, &[c("1.2.3.4", "both", Probe::TlsTimeout)]), Verdict::Dpi);
        assert_eq!(verdict(&s, &d, false, &[c("1.2.3.4", "both", Probe::TcpFail)]), Verdict::Ip);
        // Системный DNS — заглушка, DoH-адрес работает.
        let sb = [ip("127.0.0.1")];
        let d2 = [ip("5.6.7.8")];
        assert_eq!(verdict(&sb, &d2, true, &[c("127.0.0.1", "system", Probe::TcpFail), c("5.6.7.8", "doh", Probe::Ok)]), Verdict::Dns);
        // Заглушка и DPI на настоящем адресе — сначала DPI не скрываем: работающего пути нет.
        assert_eq!(verdict(&sb, &d2, true, &[c("127.0.0.1", "system", Probe::TcpFail), c("5.6.7.8", "doh", Probe::TlsReset)]), Verdict::Dpi);
        // Подменённый сертификат на системном адресе, DoH-адрес работает.
        let s3 = [ip("9.9.9.1")];
        assert_eq!(verdict(&s3, &d2, false, &[c("9.9.9.1", "system", Probe::TlsCert), c("5.6.7.8", "doh", Probe::Ok)]), Verdict::Dns);
        assert_eq!(verdict(&[], &[], false, &[]), Verdict::NoDomain);
        // Системный DNS ничего не вернул, DoH — вернул и работает.
        assert_eq!(verdict(&[], &d2, false, &[c("5.6.7.8", "doh", Probe::Ok)]), Verdict::Dns);
    }

    /// Сеть: проверка через временный прокси-обходчик (DIAG_DOMAIN, по умолчанию x.com).
    #[test]
    #[ignore]
    fn live_via_proxy() {
        let d = std::env::var("DIAG_DOMAIN").unwrap_or_else(|_| "x.com".into());
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let cfg = crate::proxy::Config { port, system: false, ..Default::default() };
        let _p = crate::proxy::Proxy::start(cfg, &[]).unwrap();
        let r = run_with(&d, Some(port)).unwrap();
        println!("verdict {:?}, via proxy {:?}", r.verdict, r.via_proxy);
    }

    /// Сеть: проверка домена (DIAG_DOMAIN, по умолчанию example.com). Только чтение.
    #[test]
    #[ignore]
    fn live_diag() {
        let d = std::env::var("DIAG_DOMAIN").unwrap_or_else(|_| "example.com".into());
        let r = run(&d).unwrap();
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
    }
}
