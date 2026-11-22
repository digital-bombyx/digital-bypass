//! Сканер SNI: к одному и тому же IP отправляются TLS ClientHello с разными
//! именами сайтов. Если сервер ответил чем угодно на уровне TLS (рукопожатие,
//! чужой сертификат, alert) — DPI это имя пропустил. Если соединение сброшено
//! или ответа нет — имя режется.
//!
//! Зачем: понять, включён ли режим белых списков и какие имена в нём проходят;
//! подобрать serverName для VLESS Reality или поддельный SNI для fake-стратегий.
//! Идея — из sni-spoofing-rust (MIT, therealaleph); код свой.

use serde::Serialize;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_TARGET: &str = "104.16.132.229:443";
const PARALLEL: usize = 12;

/// Кандидаты по умолчанию: российские сервисы (обычно в белых списках) и
/// крупные зарубежные. Пользователь может дописать свои.
pub const DEFAULT_SNIS: &[&str] = &[
    // Россия
    "ya.ru", "yandex.ru", "dzen.ru", "vk.com", "vk.ru", "mail.ru", "ok.ru", "gosuslugi.ru", "nalog.gov.ru",
    "sberbank.ru", "online.sberbank.ru", "tbank.ru", "vtb.ru", "alfabank.ru", "ozon.ru", "wildberries.ru",
    "avito.ru", "rutube.ru", "kinopoisk.ru", "2gis.ru", "hh.ru", "rzd.ru", "mos.ru", "max.ru",
    // Зарубежные
    "www.google.com", "www.youtube.com", "www.microsoft.com", "update.microsoft.com", "www.apple.com",
    "www.icloud.com", "github.com", "www.cloudflare.com", "speed.cloudflare.com", "www.amazon.com",
    "www.samsung.com", "www.nvidia.com", "steamcommunity.com", "discord.com", "telegram.org", "www.instagram.com",
    "x.com", "www.wikipedia.org", "www.speedtest.net", "dl.google.com",
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Сервер ответил (TLS дошёл) — имя проходит.
    Pass,
    /// Соединение сброшено после ClientHello.
    Reset,
    /// Ответа нет.
    Timeout,
    /// TCP не подключился — проблема с адресом, а не с именем.
    NoTcp,
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub sni: String,
    pub outcome: Outcome,
    pub ms: Option<u64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: String,
    pub items: Vec<Item>,
    pub passed: usize,
    pub blocked: usize,
    /// Проходят почти только российские имена — похоже на белые списки.
    pub whitelist_suspected: bool,
}

/// `ip`, `ip:port`, `host`, `host:port` → адрес (порт по умолчанию 443).
pub fn parse_target(t: &str) -> Result<SocketAddr, String> {
    let t = t.trim();
    let bad = || crate::tr!("некорректный адрес: {t}", "invalid address: {t}");
    if t.is_empty() {
        return Err(bad());
    }
    if let Ok(a) = t.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = t.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 443));
    }
    let with_port = if t.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) { t.to_string() } else { format!("{t}:443") };
    with_port.to_socket_addrs().map_err(|_| bad())?.next().ok_or_else(bad)
}

/// Нормализовать список имён: по одному в строке/через пробел, без дублей.
pub fn parse_snis(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let s = raw.trim().trim_end_matches('.').to_lowercase();
        if s.is_empty() || s.starts_with('#') || !s.contains('.') || s.len() > 253 {
            continue;
        }
        if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') && !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// Классификация ошибки рукопожатия: любой ответ TLS-уровня — «прошло».
pub fn classify(e: &std::io::Error) -> Outcome {
    use std::io::ErrorKind::*;
    if e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()).is_some() {
        return Outcome::Pass;
    }
    match e.kind() {
        TimedOut | WouldBlock => Outcome::Timeout,
        _ => Outcome::Reset,
    }
}

fn probe(target: SocketAddr, sni: &str, timeout: Duration) -> Item {
    let t0 = Instant::now();
    let tcp = match TcpStream::connect_timeout(&target, timeout) {
        Ok(s) => s,
        Err(e) => return Item { sni: sni.into(), outcome: Outcome::NoTcp, ms: None, detail: Some(e.to_string()) },
    };
    match crate::doh::tls_handshake(tcp, sni, timeout) {
        Ok(_) => Item { sni: sni.into(), outcome: Outcome::Pass, ms: Some(t0.elapsed().as_millis() as u64), detail: None },
        Err(e) => {
            let outcome = classify(&e);
            let ms = (outcome == Outcome::Pass).then(|| t0.elapsed().as_millis() as u64);
            Item { sni: sni.into(), outcome, ms, detail: Some(e.to_string()) }
        }
    }
}

pub fn summarize(target: String, items: Vec<Item>) -> Report {
    let passed = items.iter().filter(|i| i.outcome == Outcome::Pass).count();
    let blocked = items.iter().filter(|i| matches!(i.outcome, Outcome::Reset | Outcome::Timeout)).count();
    let ru = |s: &str| s.ends_with(".ru") || s.ends_with(".рф") || s == "vk.com";
    let pass_ru = items.iter().filter(|i| i.outcome == Outcome::Pass && ru(&i.sni)).count();
    let pass_foreign = passed - pass_ru;
    let tried_foreign = items.iter().filter(|i| !ru(&i.sni) && i.outcome != Outcome::NoTcp).count();
    // Российские проходят, а из зарубежных — почти ничего.
    let whitelist_suspected = pass_ru >= 3 && tried_foreign >= 5 && pass_foreign * 5 <= tried_foreign;
    Report { target, items, passed, blocked, whitelist_suspected }
}

pub fn run(target: &str, snis: &[String], timeout_secs: u64) -> Result<Report, String> {
    let addr = parse_target(target)?;
    if snis.is_empty() {
        return Err(crate::tr!("список имён пуст", "the name list is empty"));
    }
    let timeout = Duration::from_secs(timeout_secs.clamp(2, 15));
    let list: Arc<Vec<String>> = Arc::new(snis.iter().take(500).cloned().collect());
    let next = Arc::new(AtomicUsize::new(0));
    let out = Arc::new(Mutex::new(vec![None; list.len()]));
    let workers: Vec<_> = (0..PARALLEL.min(list.len()))
        .map(|_| {
            let (list, next, out) = (list.clone(), next.clone(), out.clone());
            std::thread::spawn(move || loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(sni) = list.get(i) else { break };
                let item = probe(addr, sni, timeout);
                out.lock().unwrap()[i] = Some(item);
            })
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
    let items: Vec<Item> = Arc::try_unwrap(out).map(|m| m.into_inner().unwrap()).unwrap_or_default().into_iter().flatten().collect();
    if !items.is_empty() && items.iter().all(|i| i.outcome == Outcome::NoTcp) {
        return Err(crate::tr!("к {addr} не подключиться по TCP — выберите другой адрес", "cannot connect to {addr} over TCP — pick another address"));
    }
    Ok(summarize(addr.to_string(), items))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn it(sni: &str, outcome: Outcome) -> Item {
        Item { sni: sni.into(), outcome, ms: None, detail: None }
    }

    #[test]
    fn targets() {
        assert_eq!(parse_target("1.2.3.4").unwrap(), "1.2.3.4:443".parse().unwrap());
        assert_eq!(parse_target("1.2.3.4:8443").unwrap(), "1.2.3.4:8443".parse().unwrap());
        assert_eq!(parse_target("[2001:db8::1]:443").unwrap(), "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(parse_target("2001:db8::1").unwrap(), "[2001:db8::1]:443".parse().unwrap());
        assert!(parse_target("").is_err());
    }

    #[test]
    fn sni_lists() {
        assert_eq!(parse_snis("Ya.ru, vk.com\n# comment\nvk.com  bad\nx.com.\nbad_name.com"), vec!["ya.ru", "vk.com", "x.com"]);
        for s in DEFAULT_SNIS {
            assert_eq!(parse_snis(s), vec![s.to_string()], "{s}");
        }
    }

    #[test]
    fn classify_errors() {
        let tls = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure));
        assert_eq!(classify(&tls), Outcome::Pass);
        assert_eq!(classify(&std::io::Error::from(std::io::ErrorKind::TimedOut)), Outcome::Timeout);
        assert_eq!(classify(&std::io::Error::from(std::io::ErrorKind::ConnectionReset)), Outcome::Reset);
    }

    #[test]
    fn whitelist_detection() {
        let mut v: Vec<Item> = ["ya.ru", "vk.com", "ozon.ru", "mail.ru"].iter().map(|s| it(s, Outcome::Pass)).collect();
        v.extend(["github.com", "x.com", "www.google.com", "www.apple.com", "discord.com"].iter().map(|s| it(s, Outcome::Reset)));
        let r = summarize("t".into(), v.clone());
        assert!(r.whitelist_suspected);
        assert_eq!((r.passed, r.blocked), (4, 5));
        // Зарубежные тоже проходят — обычный режим.
        for i in v.iter_mut().skip(4) {
            i.outcome = Outcome::Pass;
        }
        assert!(!summarize("t".into(), v).whitelist_suspected);
    }

    /// Сеть: сканирование SNI_TARGET (по умолчанию Cloudflare). Только чтение.
    #[test]
    #[ignore]
    fn live_scan() {
        let t = std::env::var("SNI_TARGET").unwrap_or_else(|_| DEFAULT_TARGET.into());
        let snis: Vec<String> = DEFAULT_SNIS.iter().map(|s| s.to_string()).collect();
        let r = run(&t, &snis, 5).unwrap();
        for i in &r.items {
            println!("{:<26} {:?} {:?}", i.sni, i.outcome, i.ms);
        }
        println!("passed {} blocked {} whitelist {}", r.passed, r.blocked, r.whitelist_suspected);
    }
}
