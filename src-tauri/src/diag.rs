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
    let t0 = Instant::now();
    let tcp = match TcpStream::connect_timeout(&SocketAddr::new(ip, 443), TIMEOUT) {
        Ok(s) => s,
        Err(e) => return (Probe::TcpFail, None, Some(e.to_string())),
    };
    match crate::doh::tls_handshake(tcp, host, TIMEOUT) {
        Ok(_) => (Probe::Ok, Some(t0.elapsed().as_millis() as u64), None),
        Err(e) => {
            let (p, d) = classify(&e);
            (p, None, Some(d))
        }
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
pub fn run(input: &str) -> Result<Report, String> {
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
                    return Check { ip: ip.to_string(), source, result: Probe::TcpFail, ms: None, detail: Some("bogus".into()) };
                }
                let (result, ms, detail) = probe(ip, &host);
                Check { ip: ip.to_string(), source, result, ms, detail }
            })
        })
        .collect();
    let checks: Vec<Check> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
    let v = verdict(&system, &doh, bogus, &checks);
    Ok(Report {
        domain,
        system: system.iter().map(|i| i.to_string()).collect(),
        system_error,
        doh: doh.iter().map(|i| i.to_string()).collect(),
        doh_error,
        system_bogus: bogus,
        checks,
        verdict: v,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn c(ip: &str, source: &'static str, result: Probe) -> Check {
        Check { ip: ip.into(), source, result, ms: None, detail: None }
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

    /// Сеть: проверка домена (DIAG_DOMAIN, по умолчанию example.com). Только чтение.
    #[test]
    #[ignore]
    fn live_diag() {
        let d = std::env::var("DIAG_DOMAIN").unwrap_or_else(|_| "example.com".into());
        let r = run(&d).unwrap();
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
    }
}
