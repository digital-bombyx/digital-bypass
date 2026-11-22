//! Подбор способа нарезки для прокси-обходчика — аналог тестов стратегий zapret2.
//!
//! Для каждого варианта (где резать × чем резать × disorder) поднимается
//! временный прокси на свободном порту 127.0.0.1, через него curl открывает
//! выбранные сайты. Системный прокси и рабочий прокси не трогаются. Лучший
//! вариант — больше всего открытых сайтов, при равенстве — быстрее.

use crate::proxy::{Config, Proxy};
use serde::Serialize;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Сайты по умолчанию: заблокированные по DPI у большинства провайдеров.
pub const DEFAULT_TARGETS: &[&str] = &["www.youtube.com", "x.com", "discord.com", "www.instagram.com"];
const PARALLEL_VARIANTS: usize = 4;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Variant {
    pub split: String,
    pub unit: String,
    pub disorder: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetResult {
    pub host: String,
    pub ok: bool,
    /// HTTP-код ответа (любой ответ = TLS прошёл).
    pub code: Option<u16>,
    pub ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariantResult {
    pub variant: Variant,
    pub ok: usize,
    pub total: usize,
    /// Среднее время успешных запросов.
    pub avg_ms: Option<u64>,
    pub targets: Vec<TargetResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub done: usize,
    pub total: usize,
    pub result: VariantResult,
}

/// Все варианты: сначала «без нарезки» для сравнения.
pub fn variants() -> Vec<Variant> {
    let mut v = vec![Variant { split: "none".into(), unit: "records".into(), disorder: false }];
    for split in ["sni", "first-byte", "chunk", "random"] {
        for unit in ["records", "tcp"] {
            for disorder in [true, false] {
                v.push(Variant { split: split.into(), unit: unit.into(), disorder });
            }
        }
    }
    v
}

/// Домены из ввода пользователя (через пробел, запятую или с новой строки).
pub fn parse_targets(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let mut s = raw.trim().to_ascii_lowercase();
        if let Some(i) = s.find("://") {
            s = s[i + 3..].to_string();
        }
        if let Some(i) = s.find('/') {
            s.truncate(i);
        }
        if let Some(d) = crate::proxy::normalize_domain(&s) {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out.truncate(12);
    out
}

/// Лучший: больше открытых сайтов, при равенстве — быстрее; «без нарезки» —
/// только если остальные не лучше.
pub fn best(results: &[VariantResult]) -> Option<&VariantResult> {
    results.iter().filter(|r| r.ok > 0).max_by(|a, b| {
        a.ok.cmp(&b.ok)
            .then((a.variant.split == "none").cmp(&(b.variant.split == "none")).reverse())
            .then(b.avg_ms.unwrap_or(u64::MAX).cmp(&a.avg_ms.unwrap_or(u64::MAX)))
    })
}

fn free_port() -> Option<u16> {
    TcpListener::bind("127.0.0.1:0").ok()?.local_addr().ok().map(|a| a.port())
}

/// Ответ curl `код время` → (код, мс).
pub fn parse_curl(out: &str) -> Option<(u16, u64)> {
    let mut it = out.split_whitespace();
    let code: u16 = it.next()?.parse().ok()?;
    let secs: f64 = it.next()?.replace(',', ".").parse().ok()?;
    Some((code, (secs * 1000.0) as u64))
}

fn curl_through(port: u16, host: &str, timeout: u64) -> TargetResult {
    let t0 = Instant::now();
    let out = crate::util::hidden(crate::util::system32("curl.exe"))
        .args(["-s", "-o", "NUL", "-w", "%{http_code} %{time_total}", "--max-time", &timeout.to_string()])
        .args(["-x", &format!("http://127.0.0.1:{port}"), &format!("https://{host}/")])
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let parsed = parse_curl(&text);
            let ok = o.status.success() && parsed.is_some_and(|(c, _)| c > 0);
            let error = (!ok).then(|| match o.status.code() {
                Some(28) => "timeout".to_string(),
                Some(35) => "tls reset".to_string(),
                Some(7) => "connect failed".to_string(),
                Some(c) => format!("curl {c}"),
                None => "curl".to_string(),
            });
            TargetResult {
                host: host.into(),
                ok,
                code: parsed.map(|(c, _)| c).filter(|c| *c > 0),
                ms: if ok { parsed.map(|(_, ms)| ms) } else { None },
                error,
            }
        }
        Err(e) => TargetResult { host: host.into(), ok: false, code: None, ms: Some(t0.elapsed().as_millis() as u64), error: Some(e.to_string()) },
    }
}

fn run_variant(base: &Config, v: &Variant, targets: &[String], timeout: u64) -> VariantResult {
    let mut cfg = base.clone();
    cfg.split = v.split.clone();
    cfg.unit = v.unit.clone();
    cfg.disorder = v.disorder;
    cfg.system = false;
    cfg.lan = false;
    cfg.user.clear();
    cfg.pass.clear();
    cfg.rules = Default::default();
    let started = free_port().and_then(|p| {
        cfg.port = p;
        Proxy::start(cfg.clone(), &[]).ok().map(|proxy| (p, proxy))
    });
    let results: Vec<TargetResult> = match started {
        Some((port, _proxy)) => {
            let handles: Vec<_> = targets
                .iter()
                .map(|h| {
                    let h = h.clone();
                    std::thread::spawn(move || curl_through(port, &h, timeout))
                })
                .collect();
            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        }
        None => targets
            .iter()
            .map(|h| TargetResult { host: h.clone(), ok: false, code: None, ms: None, error: Some("proxy failed to start".into()) })
            .collect(),
    };
    let ok_ms: Vec<u64> = results.iter().filter(|r| r.ok).filter_map(|r| r.ms).collect();
    VariantResult {
        variant: v.clone(),
        ok: results.iter().filter(|r| r.ok).count(),
        total: results.len(),
        avg_ms: (!ok_ms.is_empty()).then(|| ok_ms.iter().sum::<u64>() / ok_ms.len() as u64),
        targets: results,
    }
}

/// Прогнать все варианты (по 4 одновременно). `on_progress` — после каждого.
pub fn run(base: &Config, targets: &[String], timeout: u64, cancel: &AtomicBool, on_progress: impl Fn(Progress) + Send + Sync) -> Vec<VariantResult> {
    let list = variants();
    let total = list.len();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let out: Mutex<Vec<(usize, VariantResult)>> = Mutex::new(Vec::new());
    let on_progress = Arc::new(on_progress);
    std::thread::scope(|s| {
        for _ in 0..PARALLEL_VARIANTS {
            s.spawn(|| loop {
                if cancel.load(Ordering::SeqCst) {
                    break;
                }
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(v) = list.get(i) else { break };
                let r = run_variant(base, v, targets, timeout);
                let d = done.fetch_add(1, Ordering::SeqCst) + 1;
                on_progress(Progress { done: d, total, result: r.clone() });
                out.lock().unwrap().push((i, r));
            });
        }
    });
    let mut v = out.into_inner().unwrap();
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, r)| r).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vr(split: &str, ok: usize, ms: Option<u64>) -> VariantResult {
        VariantResult { variant: Variant { split: split.into(), unit: "records".into(), disorder: true }, ok, total: 4, avg_ms: ms, targets: vec![] }
    }

    #[test]
    fn variant_list() {
        let v = variants();
        assert_eq!(v.len(), 17);
        assert_eq!(v[0].split, "none");
        assert_eq!(v.iter().filter(|x| x.disorder).count(), 8);
    }

    #[test]
    fn targets_parsing() {
        assert_eq!(parse_targets("https://www.YouTube.com/watch, x.com\nx.com localhost"), vec!["www.youtube.com", "x.com"]);
    }

    #[test]
    fn curl_output() {
        assert_eq!(parse_curl("200 1.249371"), Some((200, 1249)));
        assert_eq!(parse_curl("000 12,0"), Some((0, 12000)));
        assert_eq!(parse_curl(""), None);
    }

    #[test]
    fn best_choice() {
        let r = vec![vr("none", 1, Some(100)), vr("sni", 3, Some(900)), vr("chunk", 3, Some(400)), vr("random", 0, None)];
        assert_eq!(best(&r).unwrap().variant.split, "chunk");
        // При равенстве «без нарезки» не выбирается, даже если быстрее.
        let r = vec![vr("none", 2, Some(100)), vr("sni", 2, Some(900))];
        assert_eq!(best(&r).unwrap().variant.split, "sni");
        assert!(best(&[vr("sni", 0, None)]).is_none());
    }

    /// Сеть: полный подбор на сайтах по умолчанию. Только чтение, системный прокси не трогает.
    #[test]
    #[ignore]
    fn live_proxy_test() {
        let targets: Vec<String> = DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect();
        let cancel = AtomicBool::new(false);
        let res = run(&Config::default(), &targets, 8, &cancel, |p| {
            let r = &p.result;
            println!("{:>2}/{} {}/{}{} ok {}/{} avg {:?}", p.done, p.total, r.variant.split, r.variant.unit, if r.variant.disorder { "+disorder" } else { "" }, r.ok, r.total, r.avg_ms);
        });
        println!("best: {:?}", best(&res).map(|b| &b.variant));
    }
}
