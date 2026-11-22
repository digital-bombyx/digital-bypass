//! Проверка DNS на подмену провайдером.
//!
//! 1. **Перехват**: провайдер перехватывает запросы на порт 53 к чужим серверам
//!    и отвечает сам — смена DNS в настройках тогда не помогает.
//!    - запрос к адресу, где DNS-сервера нет (документационные сети) — любой
//!      ответ пришёл от перехватчика;
//!    - `whoami.akamai.net` возвращает адрес, с которого резолвер ходит к
//!      авторитетным серверам. У Google, Cloudflare и Quad9 он свой; если у
//!      двух совпал или совпал с резолвером провайдера — отвечает один и тот
//!      же сервер, то есть провайдерский.
//! 2. **Заглушки**: на заблокированные домены резолвер отдаёт заглушку
//!    (127.0.0.1, частные адреса) или адреса, которых нет в эталонном ответе.
//!    Эталон — DoT к Cloudflare: зашифрованный запрос провайдер не подменит.

use crate::doh::{build_query, parse_answers, DohClient, TYPE_A};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const UDP_TIMEOUT: Duration = Duration::from_millis(2500);
const WHOAMI: &str = "whoami.akamai.net";

/// Публичные резолверы, к которым шлём обычные (незашифрованные) запросы.
pub const PUBLIC: &[(&str, &str)] = &[("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1"), ("Quad9", "9.9.9.9")];
/// Адреса, где DNS-сервера заведомо нет (RFC 5737).
pub const NOWHERE: &[&str] = &["192.0.2.53", "198.51.100.53"];
/// Домены, которые в России блокируют чаще всего.
pub const DEFAULT_DOMAINS: &[&str] =
    &["rutracker.org", "www.linkedin.com", "www.instagram.com", "www.facebook.com", "x.com", "nnmclub.to", "www.youtube.com", "discord.com"];

#[derive(Debug, Clone, Serialize)]
pub struct ResolverProbe {
    pub name: String,
    pub server: String,
    /// Ответ получен.
    pub answered: bool,
    /// Адрес, с которого резолвер ходит в интернет (whoami.akamai.net).
    pub egress: Option<String>,
    pub ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainVerdict {
    /// Совпадает с эталоном (или пересекается).
    Ok,
    /// Резолвер провайдера отдал заглушку.
    StubSystem,
    /// Запрос к публичному резолверу вернул заглушку — перехват на пути.
    StubIntercepted,
    /// Адреса не пересекаются с эталоном, проверить сертификатом не удалось.
    Differs,
    /// Другой адрес, но с настоящим сертификатом сайта — просто другой узел CDN.
    Cdn,
    /// Отличающийся адрес предъявил чужой сертификат — подмена адреса.
    Spoofed,
    /// Нет ответа ни от кого.
    NoAnswer,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainCheck {
    pub domain: String,
    pub system: Vec<String>,
    pub public: Vec<String>,
    pub trusted: Vec<String>,
    pub verdict: DomainVerdict,
    /// Какой адрес проверялся сертификатом и что вышло.
    pub cert_check: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Ответ пришёл с адреса, где DNS-сервера нет.
    pub nowhere_answered: bool,
    pub resolvers: Vec<ResolverProbe>,
    /// Адрес резолвера провайдера (через системный DNS).
    pub system_egress: Option<String>,
    /// Эталон (DoT к Cloudflare) доступен.
    pub trusted_ok: bool,
    pub trusted_error: Option<String>,
    pub intercepted: bool,
    /// Чем подтверждён перехват — для пояснения в интерфейсе.
    pub intercept_reasons: Vec<String>,
    pub domains: Vec<DomainCheck>,
    pub stubs: usize,
}

/// Обычный DNS-запрос по UDP, только A-записи.
fn udp_query(server: IpAddr, name: &str) -> Option<(Vec<IpAddr>, u64)> {
    let t0 = Instant::now();
    let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    sock.set_read_timeout(Some(UDP_TIMEOUT)).ok()?;
    let id = (t0.elapsed().as_nanos() as u16) ^ 0x5a5a;
    let q = build_query(id, name, TYPE_A).ok()?;
    sock.send_to(&q, SocketAddr::new(server, 53)).ok()?;
    let mut buf = [0u8; 2048];
    loop {
        let (n, _) = sock.recv_from(&mut buf).ok()?;
        // Чужие ответы (не тот id) пропускаем.
        if n >= 12 && buf[..2] == id.to_be_bytes() {
            let ips = parse_answers(&buf[..n]).map(|(v, _)| v).unwrap_or_default();
            return Some((ips.into_iter().filter(|i| i.is_ipv4()).collect(), t0.elapsed().as_millis() as u64));
        }
    }
}

fn system_resolve(name: &str) -> Vec<IpAddr> {
    (name, 443).to_socket_addrs().map(|it| it.map(|a| a.ip()).filter(|i| i.is_ipv4()).collect()).unwrap_or_default()
}

/// Вердикт для домена (чистая функция — покрыта тестами).
pub fn domain_verdict(system: &[IpAddr], public: &[IpAddr], trusted: &[IpAddr]) -> DomainVerdict {
    let bogus = |v: &[IpAddr]| !v.is_empty() && v.iter().all(crate::diag::is_bogus);
    if bogus(public) {
        return DomainVerdict::StubIntercepted;
    }
    if bogus(system) {
        return DomainVerdict::StubSystem;
    }
    if system.is_empty() && public.is_empty() && trusted.is_empty() {
        return DomainVerdict::NoAnswer;
    }
    let overlaps = |a: &[IpAddr], b: &[IpAddr]| a.is_empty() || b.is_empty() || a.iter().any(|x| b.contains(x));
    if trusted.is_empty() || (overlaps(system, trusted) && overlaps(public, trusted)) {
        DomainVerdict::Ok
    } else {
        DomainVerdict::Differs
    }
}

/// Признаки перехвата (чистая функция — покрыта тестами).
pub fn intercept_reasons(nowhere: bool, resolvers: &[ResolverProbe], system_egress: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if nowhere {
        out.push("nowhere".to_string());
    }
    let eg: Vec<(&str, &str)> = resolvers.iter().filter_map(|r| r.egress.as_deref().map(|e| (r.name.as_str(), e))).collect();
    for (i, (a, ea)) in eg.iter().enumerate() {
        for (b, eb) in eg.iter().skip(i + 1) {
            if ea == eb {
                out.push(format!("same:{a}:{b}"));
            }
        }
        if system_egress == Some(*ea) {
            out.push(format!("isp:{a}"));
        }
    }
    out
}

pub fn run(domains: &[String]) -> Report {
    // Эталон: DoT к Cloudflare, при недоступности — DoT к Google.
    let trusted: Option<DohClient> = [("tls://cloudflare-dns.com", "1.1.1.1"), ("tls://dns.google", "8.8.8.8")]
        .iter()
        .filter_map(|(t, ip)| DohClient::new(t, &[ip.parse().unwrap()]).ok())
        .find(|c| c.query("example.com", TYPE_A).is_ok());
    let trusted_error = trusted.is_none().then(|| crate::tr!("DoT недоступен — сравнивать не с чем", "DoT is unreachable — nothing to compare with"));

    let nowhere_answered = NOWHERE.iter().any(|ip| udp_query(ip.parse().unwrap(), "example.com").is_some());
    let resolvers: Vec<ResolverProbe> = PUBLIC
        .iter()
        .map(|(name, ip)| {
            let r = udp_query(ip.parse().unwrap(), WHOAMI);
            ResolverProbe {
                name: name.to_string(),
                server: ip.to_string(),
                answered: r.is_some(),
                egress: r.as_ref().and_then(|(v, _)| v.first()).map(|i| i.to_string()),
                ms: r.map(|(_, ms)| ms),
            }
        })
        .collect();
    let system_egress = system_resolve(WHOAMI).first().map(|i| i.to_string());
    let reasons = intercept_reasons(nowhere_answered, &resolvers, system_egress.as_deref());

    let mut checks = Vec::new();
    for d in domains {
        let system = system_resolve(d);
        let public = udp_query("8.8.8.8".parse().unwrap(), d).map(|(v, _)| v).unwrap_or_default();
        let trusted_ips: Vec<IpAddr> = trusted.as_ref().and_then(|c| c.query(d, TYPE_A).ok()).map(|(v, _)| v).unwrap_or_default();
        let mut verdict = domain_verdict(&system, &public, &trusted_ips);
        let mut cert_check = None;
        if verdict == DomainVerdict::Differs {
            // Адреса, которых нет в эталоне: по одному из системного и публичного ответа.
            let mut cands: Vec<IpAddr> = Vec::new();
            for v in [&system, &public] {
                if let Some(ip) = v.iter().find(|i| !trusted_ips.contains(i)) {
                    if !cands.contains(ip) {
                        cands.push(*ip);
                    }
                }
            }
            let results: Vec<(IpAddr, crate::diag::Probe)> = cands
                .into_iter()
                .map(|ip| {
                    let d = d.clone();
                    std::thread::spawn(move || {
                        use crate::diag::Probe;
                        // Сначала напрямую; если DPI режет имя — с нарезкой, как в прокси.
                        let p = crate::diag::probe(ip, &d).0;
                        let p = if matches!(p, Probe::TlsTimeout | Probe::TlsReset) { crate::diag::probe_fragmented(ip, &d).0 } else { p };
                        (ip, p)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .filter_map(|h| h.join().ok())
                .collect();
            use crate::diag::Probe;
            if let Some((ip, _)) = results.iter().find(|(_, p)| *p == Probe::TlsCert) {
                verdict = DomainVerdict::Spoofed;
                cert_check = Some(format!("{ip}: cert"));
            } else if !results.is_empty() && results.iter().all(|(_, p)| *p == Probe::Ok) {
                verdict = DomainVerdict::Cdn;
                cert_check = Some(results.iter().map(|(ip, _)| format!("{ip}: ok")).collect::<Vec<_>>().join(", "));
            } else {
                cert_check = Some(results.iter().map(|(ip, p)| format!("{ip}: {p:?}")).collect::<Vec<_>>().join(", "));
            }
        }
        let s = |v: &[IpAddr]| v.iter().map(|i| i.to_string()).collect::<Vec<_>>();
        checks.push(DomainCheck { domain: d.clone(), system: s(&system), public: s(&public), trusted: s(&trusted_ips), verdict, cert_check });
    }
    let stubs = checks
        .iter()
        .filter(|c| matches!(c.verdict, DomainVerdict::StubSystem | DomainVerdict::StubIntercepted | DomainVerdict::Spoofed))
        .count();
    let intercepted = !reasons.is_empty() || checks.iter().any(|c| c.verdict == DomainVerdict::StubIntercepted);
    Report {
        nowhere_answered,
        resolvers,
        system_egress,
        trusted_ok: trusted.is_some(),
        trusted_error,
        intercepted,
        intercept_reasons: reasons,
        domains: checks,
        stubs,
    }
}

/// Домены из ввода; пусто — список по умолчанию.
pub fn parse_domains(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if let Ok(d) = crate::diag::normalize(raw) {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out.truncate(20);
    if out.is_empty() {
        out = DEFAULT_DOMAINS.iter().map(|s| s.to_string()).collect();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn probe(name: &str, egress: Option<&str>) -> ResolverProbe {
        ResolverProbe { name: name.into(), server: String::new(), answered: egress.is_some(), egress: egress.map(String::from), ms: None }
    }

    #[test]
    fn domain_verdicts() {
        let real = [ip("104.16.1.1")];
        assert_eq!(domain_verdict(&real, &real, &real), DomainVerdict::Ok);
        assert_eq!(domain_verdict(&[ip("127.0.0.1")], &real, &real), DomainVerdict::StubSystem);
        assert_eq!(domain_verdict(&real, &[ip("10.0.0.1")], &real), DomainVerdict::StubIntercepted);
        assert_eq!(domain_verdict(&[ip("95.1.1.1")], &real, &real), DomainVerdict::Differs);
        assert_eq!(domain_verdict(&[], &[], &[]), DomainVerdict::NoAnswer);
        // Эталона нет — судить не по чему, кроме заглушек.
        assert_eq!(domain_verdict(&[ip("95.1.1.1")], &real, &[]), DomainVerdict::Ok);
    }

    #[test]
    fn intercept_detection() {
        let ok = [probe("Google", Some("74.125.1.1")), probe("Cloudflare", Some("172.71.1.1")), probe("Quad9", Some("74.63.1.1"))];
        assert!(intercept_reasons(false, &ok, Some("95.2.2.2")).is_empty());
        assert_eq!(intercept_reasons(true, &ok, None), vec!["nowhere"]);
        let same = [probe("Google", Some("95.2.2.2")), probe("Cloudflare", Some("95.2.2.2")), probe("Quad9", None)];
        let r = intercept_reasons(false, &same, Some("95.2.2.2"));
        assert!(r.contains(&"same:Google:Cloudflare".to_string()) && r.contains(&"isp:Google".to_string()));
    }

    #[test]
    fn domain_input() {
        assert_eq!(parse_domains("https://rutracker.org/forum, x.com x.com"), vec!["rutracker.org", "x.com"]);
        assert_eq!(parse_domains("").len(), DEFAULT_DOMAINS.len());
    }

    /// Сеть: проверка этой машины. Только запросы, ничего не меняет.
    #[test]
    #[ignore]
    fn live_dnscheck() {
        let r = run(&parse_domains(""));
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
    }
}
