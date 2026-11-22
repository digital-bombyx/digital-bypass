//! Тестирование стратегий: порт utils\test zapret.ps1.
//! standard — curl HTTP/TLS1.2/TLS1.3 по utils\targets.txt + ICMP-пинг;
//! dpi — проверка «заморозки» TCP 16-20 КБ по набору hyperion-cs/dpi-checkers.
//! Используется системный curl.exe (schannel) ради тех же отпечатков, что у ps1.

use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const DPI_SUITE_URL: &str = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json";
const DPI_RANGE_BYTES: usize = 65536;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Params {
    pub timeout: u32,
    pub parallel: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetResult {
    pub key: String,
    /// url | ping | dpi
    pub kind: String,
    /// Метки проверок: HTTP / TLS1.2 / TLS1.3 → статус.
    pub checks: Vec<(String, String)>,
    pub ping_ms: Option<u32>,
    pub ping_tried: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StrategyResult {
    pub file: String,
    pub started: bool,
    pub error: Option<String>,
    pub targets: Vec<TargetResult>,
    pub ok: u32,
    pub fail: u32,
    pub unsup: u32,
    pub blocked: u32,
    pub ping_ok: u32,
    pub ping_fail: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TestRun {
    pub id: u64,
    /// standard | dpi
    pub kind: String,
    pub total: usize,
    pub index: usize,
    pub current: Option<String>,
    pub results: Vec<StrategyResult>,
    pub best: Option<String>,
    pub finished: bool,
    pub cancelled: bool,
    pub message: Option<String>,
}

#[derive(Clone)]
struct Target {
    key: String,
    url: Option<String>,
    ping_host: Option<String>,
    dpi_host: Option<String>,
}

/// utils\targets.txt: `Key = "https://..."` или `Key = "PING:1.2.3.4"`.
pub fn load_targets(dir: &Path) -> Vec<(String, String)> {
    let text = crate::util::read_text(&dir.join("utils").join("targets.txt")).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            let k = k.trim();
            let v = v.trim().trim_matches('"').trim();
            (!k.is_empty() && k.chars().all(|c| c.is_alphanumeric() || c == '_') && !v.is_empty())
                .then(|| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn standard_targets(dir: &Path) -> Vec<Target> {
    load_targets(dir)
        .into_iter()
        .map(|(key, v)| {
            if let Some(ip) = v.strip_prefix("PING:") {
                Target { key, url: None, ping_host: Some(ip.trim().to_string()), dpi_host: None }
            } else {
                let host = v
                    .split("://")
                    .nth(1)
                    .unwrap_or(&v)
                    .split(['/', ':', '?'])
                    .next()
                    .unwrap_or("")
                    .to_string();
                Target { key, url: Some(v), ping_host: Some(host), dpi_host: None }
            }
        })
        .collect()
}

fn dpi_targets(timeout: u32) -> Result<Vec<Target>, String> {
    let out = crate::util::hidden(crate::util::system32("curl.exe"))
        .args(["-s", "-L", "-m", &timeout.max(5).to_string(), DPI_SUITE_URL])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|_| crate::tr!("не удалось получить набор DPI-проверок", "failed to fetch the DPI check suite"))?;
    let arr = v.as_array().ok_or_else(|| crate::tr!("неожиданный формат набора DPI-проверок", "unexpected DPI suite format"))?;
    let s = |e: &serde_json::Value, k: &str| e.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let list: Vec<Target> = arr
        .iter()
        .filter(|e| !s(e, "host").is_empty())
        .map(|e| Target {
            key: format!("{} {} · {}", s(e, "country"), s(e, "provider"), s(e, "id")).trim().to_string(),
            url: None,
            ping_host: None,
            dpi_host: Some(s(e, "host")),
        })
        .collect();
    if list.is_empty() {
        return Err(crate::tr!("набор DPI-проверок пуст", "DPI check suite is empty"));
    }
    Ok(list)
}

const TLS_TESTS: [(&str, &[&str]); 3] = [
    ("HTTP", &["--http1.1"]),
    ("TLS1.2", &["--tlsv1.2", "--tls-max", "1.2"]),
    ("TLS1.3", &["--tlsv1.3", "--tls-max", "1.3"]),
];

fn is_unsupported(exit: i32, text: &str) -> bool {
    exit == 35
        || [
            "does not support",
            "not supported",
            "unsupported protocol",
            "unrecognized option",
            "unknown option",
            "unsupported option",
            "unsupported feature",
            "schannel",
        ]
        .iter()
        .any(|p| text.contains(p))
}

fn check_standard(t: &Target, timeout: u32) -> TargetResult {
    let mut r = TargetResult { key: t.key.clone(), kind: "url".into(), ..Default::default() };
    if let Some(url) = &t.url {
        let curl = crate::util::system32("curl.exe");
        for (label, extra) in TLS_TESTS {
            let out = crate::util::hidden(&curl)
                .args(["-I", "-s", "-m", &timeout.to_string()])
                .args(["--connect-timeout", &timeout.min(2).to_string()])
                .args(["-o", "NUL", "-w", "%{http_code}", "--show-error"])
                .args(extra)
                .arg(url)
                .output();
            let status = match out {
                Err(_) => "ERROR",
                Ok(o) => {
                    let exit = o.status.code().unwrap_or(-1);
                    let err = String::from_utf8_lossy(&o.stderr).to_lowercase();
                    let ssl = [
                        "could not resolve host",
                        "certificate",
                        "ssl certificate problem",
                        "self-signed",
                        "self signed",
                        "certificate verify failed",
                        "unable to get local issuer certificate",
                    ]
                    .iter()
                    .any(|p| err.contains(p));
                    if ssl {
                        "SSL"
                    } else if is_unsupported(exit, &err) {
                        "UNSUP"
                    } else if exit == 0 {
                        "OK"
                    } else {
                        "ERROR"
                    }
                }
            };
            r.checks.push((label.into(), status.into()));
        }
    } else {
        r.kind = "ping".into();
    }
    if let Some(host) = &t.ping_host {
        r.ping_tried = true;
        let addr = (host.as_str(), 443).to_socket_addrs().ok().and_then(|mut it| {
            it.find_map(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
        });
        r.ping_ms = addr.and_then(|a| crate::winapi::ping(a, 1000));
    }
    r
}

fn check_dpi(t: &Target, timeout: u32, payload: &Path) -> TargetResult {
    let mut r = TargetResult { key: t.key.clone(), kind: "dpi".into(), ..Default::default() };
    let host = t.dpi_host.clone().unwrap_or_default();
    let curl = crate::util::system32("curl.exe");
    let mut details = Vec::new();
    for (label, extra) in TLS_TESTS {
        let out = crate::util::hidden(&curl)
            .args(["--range", &format!("0-{}", DPI_RANGE_BYTES - 1), "-m", &timeout.to_string()])
            .args(["--connect-timeout", &timeout.min(3).to_string()])
            .args(["-w", "%{http_code} %{size_upload} %{size_download} %{time_total}", "-o", "NUL", "-X", "POST"])
            .arg("--data-binary")
            .arg(format!("@{}", payload.display()))
            .arg("-s")
            .args(extra)
            .arg(format!("https://{host}"))
            .output();
        let (exit, text) = match out {
            Ok(o) => {
                let mut t = String::from_utf8_lossy(&o.stdout).trim().to_string();
                let e = String::from_utf8_lossy(&o.stderr).trim().to_string();
                if !e.is_empty() {
                    t.push(' ');
                    t.push_str(&e);
                }
                (o.status.code().unwrap_or(-1), t)
            }
            Err(e) => (-1, e.to_string()),
        };
        let parts: Vec<&str> = text.split_whitespace().collect();
        let parsed = (parts.len() == 4 && parts[0].len() == 3 && parts[0].bytes().all(|b| b.is_ascii_digit()))
            .then(|| {
                Some((
                    parts[1].parse::<u64>().ok()?,
                    parts[2].parse::<u64>().ok()?,
                    parts[3].replace(',', ".").parse::<f64>().ok()?,
                ))
            })
            .flatten();
        let (up, down, time) = parsed.unwrap_or((0, 0, -1.0));
        let unsup = parsed.is_none() && (is_unsupported(exit, &text.to_lowercase()) || text.contains("SSL"));
        let mut status = if unsup {
            "UNSUP"
        } else if exit != 0 || parsed.is_none() {
            "FAIL"
        } else {
            "OK"
        };
        if up > 0 && down == 0 && time >= timeout as f64 && exit != 0 {
            status = "BLOCKED";
        }
        details.push(format!("{label}: ↑{:.1}K ↓{:.1}K {time:.2}s", up as f64 / 1024.0, down as f64 / 1024.0));
        r.checks.push((label.into(), status.into()));
    }
    r.detail = Some(details.join(" · "));
    r
}

fn tally(s: &mut StrategyResult) {
    for t in &s.targets {
        for (_, st) in &t.checks {
            match st.as_str() {
                "OK" => s.ok += 1,
                "UNSUP" => s.unsup += 1,
                "BLOCKED" => s.blocked += 1,
                _ => s.fail += 1,
            }
        }
        if t.ping_tried {
            if t.ping_ms.is_some() {
                s.ping_ok += 1;
            } else {
                s.ping_fail += 1;
            }
        }
    }
}

/// Лучшая стратегия: больше всего OK, при равенстве — больше удачных пингов.
fn best(results: &[StrategyResult]) -> Option<String> {
    let mut best: Option<&StrategyResult> = None;
    for r in results.iter().filter(|r| r.started && r.ok > 0) {
        best = match best {
            None => Some(r),
            Some(b) if (r.ok, r.ping_ok) > (b.ok, b.ping_ok) => Some(r),
            b => b,
        };
    }
    best.map(|b| b.file.clone())
}

fn write_payload() -> Result<PathBuf, String> {
    let mut x: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        ^ ((std::process::id() as u64) << 32)
        | 1;
    let mut buf = vec![0u8; DPI_RANGE_BYTES];
    for chunk in buf.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
    }
    let p = std::env::temp_dir().join("digital-bypass-dpi-payload.bin");
    std::fs::write(&p, buf).map_err(|e| e.to_string())?;
    Ok(p)
}

/// Параллельная проверка целей пулом потоков; on_done вызывается после каждой цели.
fn run_targets(
    targets: &[Target],
    parallel: usize,
    cancel: &AtomicBool,
    check: impl Fn(&Target) -> TargetResult + Sync,
    on_done: impl Fn(Vec<TargetResult>) + Sync,
) -> Vec<TargetResult> {
    let results: Mutex<Vec<Option<TargetResult>>> = Mutex::new(vec![None; targets.len()]);
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..parallel.clamp(1, 32).min(targets.len().max(1)) {
            s.spawn(|| loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= targets.len() {
                    break;
                }
                let r = check(&targets[i]);
                let snapshot = {
                    let mut g = results.lock().unwrap();
                    g[i] = Some(r);
                    g.iter().flatten().cloned().collect()
                };
                on_done(snapshot);
            });
        }
    });
    results.into_inner().unwrap().into_iter().flatten().collect()
}

pub struct Ctx<'a> {
    pub dir: &'a Path,
    pub runner: &'a crate::runner::Runner,
    pub cancel: &'a AtomicBool,
    pub game_vars: (String, String),
}

/// Прогон тестов. emit получает снимок состояния после каждого шага.
pub fn run(ctx: Ctx, kind: &str, files: Vec<String>, params: Params, emit: impl Fn(&TestRun) + Sync) -> TestRun {
    let run = Arc::new(Mutex::new(TestRun {
        id: crate::util::now_secs(),
        kind: kind.into(),
        total: files.len(),
        ..Default::default()
    }));
    let push = |f: &dyn Fn(&mut TestRun)| {
        let mut g = run.lock().unwrap();
        f(&mut g);
        emit(&g);
    };
    let finish = |msg: Option<String>| -> TestRun {
        let mut g = run.lock().unwrap();
        g.finished = true;
        g.current = None;
        g.cancelled = ctx.cancel.load(Ordering::Relaxed);
        if msg.is_some() {
            g.message = msg;
        }
        g.best = best(&g.results);
        emit(&g);
        g.clone()
    };

    if crate::service::state(crate::service::NAME).1 {
        return finish(Some(crate::tr!("Работает служба zapret — остановите её перед тестом", "The zapret service is running — stop it before testing")));
    }
    let prior = {
        let st = ctx.runner.status();
        (st.mode == "process").then_some(st.strategy).flatten()
    };

    let targets = if kind == "dpi" {
        match dpi_targets(params.timeout) {
            Ok(t) => t,
            Err(e) => return finish(Some(e)),
        }
    } else {
        standard_targets(ctx.dir)
    };
    if targets.is_empty() {
        return finish(Some(crate::tr!("нет целей для проверки (utils\\targets.txt)", "no targets to check (utils\\targets.txt)")));
    }
    let payload = if kind == "dpi" {
        match write_payload() {
            Ok(p) => Some(p),
            Err(e) => return finish(Some(e)),
        }
    } else {
        None
    };
    let ipset_switched = kind == "dpi" && crate::ipset::status(ctx.dir) != "any";
    if ipset_switched {
        if let Err(e) = crate::ipset::test_switch_any(ctx.dir) {
            return finish(Some(format!("ipset: {e}")));
        }
    }

    let vars = crate::strategy::Vars::new(ctx.dir, &ctx.game_vars.0, &ctx.game_vars.1);
    for (i, file) in files.iter().enumerate() {
        if ctx.cancel.load(Ordering::Relaxed) {
            break;
        }
        push(&|g| {
            g.index = i + 1;
            g.current = Some(file.clone());
            g.results.push(StrategyResult { file: file.clone(), ..Default::default() });
        });
        let started = crate::strategy::build_args(ctx.dir, file, &vars)
            .and_then(|args| ctx.runner.start(ctx.dir, file, &args));
        if let Err(e) = started {
            push(&|g| {
                if let Some(last) = g.results.last_mut() {
                    last.error = Some(e.clone());
                }
            });
            continue;
        }
        push(&|g| {
            if let Some(last) = g.results.last_mut() {
                last.started = true;
            }
        });
        let on_done = |partial: Vec<TargetResult>| {
            push(&|g| {
                if let Some(last) = g.results.last_mut() {
                    last.targets = partial.clone();
                }
            })
        };
        let results = match &payload {
            Some(p) => run_targets(&targets, params.parallel, ctx.cancel, |t| check_dpi(t, params.timeout, p), on_done),
            None => run_targets(&targets, params.parallel, ctx.cancel, |t| check_standard(t, params.timeout), on_done),
        };
        push(&|g| {
            if let Some(last) = g.results.last_mut() {
                last.targets = results.clone();
                tally(last);
            }
        });
    }

    ctx.runner.stop_processes();
    if ipset_switched {
        crate::ipset::test_restore(ctx.dir);
    }
    if let Some(p) = payload {
        let _ = std::fs::remove_file(p);
    }
    // Вернуть то, что работало до теста.
    if let Some(file) = prior {
        if let Ok(args) = crate::strategy::build_args(ctx.dir, &file, &vars) {
            let _ = ctx.runner.start(ctx.dir, &file, &args);
        }
    }
    ctx.runner.notify_changed();
    finish(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_prefers_ok_then_ping() {
        let mk = |f: &str, ok, ping_ok| StrategyResult { file: f.into(), started: true, ok, ping_ok, ..Default::default() };
        let r = vec![mk("a", 5, 1), mk("b", 7, 0), mk("c", 7, 3)];
        assert_eq!(best(&r).as_deref(), Some("c"));
        assert_eq!(best(&[mk("z", 0, 5)]), None);
    }

    #[test]
    fn real_targets() {
        let dir = Path::new(r"D:\zapret-discord-youtube");
        if !dir.exists() {
            return;
        }
        let t = standard_targets(dir);
        assert!(t.iter().any(|x| x.key == "DiscordMain" && x.ping_host.as_deref() == Some("discord.com")));
        assert!(t.iter().any(|x| x.url.is_none() && x.ping_host.as_deref() == Some("1.1.1.1")));
    }
}
