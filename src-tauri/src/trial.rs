//! Пробные изменения от ИИ (MCP) с автооткатом.
//!
//! Если ассистент через MCP сменит стратегию, настройки прокси или маршруты
//! и этим сломает сеть, он теряет связь со своим облаком и уже не может это
//! исправить. Поэтому перед первым изменением снимается снимок, а после
//! каждого запускается таймер: если ассистент не вызвал `confirm_changes`
//! (проверив, что сайты открываются), приложение само возвращает снимок.
//! Пользователь видит отсчёт в окне и может оставить или откатить сам.

use crate::{AppState, R};
use serde::Serialize;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

/// Сколько ждать подтверждения после последнего изменения.
pub const TRIAL: Duration = Duration::from_secs(120);

/// Что возвращает откат: какие модули были включены и с какими настройками.
pub struct Snapshot {
    zapret_running: bool,
    strategy: Option<String>,
    proxy_running: bool,
    proxy: crate::proxy::Config,
    tor_running: bool,
    tor_transport: String,
    xray_running: bool,
    xray_selected: String,
    /// Свои списки zapret2 (general, exclude) — текст файлов.
    lists: Vec<(String, String)>,
}

pub struct Trial {
    snap: Snapshot,
    /// Нет — изменение ещё выполняется (долгий подбор стратегии).
    deadline: Option<Instant>,
    tools: Vec<String>,
}

/// Для окна и `get_status`.
#[derive(Serialize, Clone)]
pub struct TrialView {
    pub seconds_left: Option<u64>,
    pub tools: Vec<String>,
}

const LISTS: [&str; 2] = ["general", "exclude"];

fn snapshot(st: &AppState) -> Snapshot {
    let s = st.settings.lock().unwrap().clone();
    let z = st.runner.status();
    let lists = st
        .dir()
        .map(|d| LISTS.iter().filter_map(|k| crate::lists::read(&d, k).ok().map(|t| (k.to_string(), t))).collect())
        .unwrap_or_default();
    Snapshot {
        zapret_running: z.running,
        strategy: if z.running { z.strategy.or(s.strategy) } else { s.strategy },
        proxy_running: st.proxy.lock().unwrap().is_some(),
        proxy: s.proxy,
        tor_running: st.tor.lock().unwrap().is_some(),
        tor_transport: s.tor.transport,
        xray_running: st.xray.lock().unwrap().is_some(),
        xray_selected: s.xray.selected,
        lists,
    }
}

pub fn enabled(st: &AppState) -> bool {
    let m = st.settings.lock().unwrap().mcp.clone();
    m.allow_changes && m.rollback
}

/// Перед изменением: снять снимок, если пробы ещё нет; таймер — на паузе.
pub fn begin(app: &AppHandle) {
    let st = app.state::<AppState>();
    if !enabled(&st) {
        return;
    }
    let mut g = st.mcp_trial.lock().unwrap();
    match g.as_mut() {
        Some(t) => t.deadline = None,
        None => *g = Some(Trial { snap: snapshot(&st), deadline: None, tools: Vec::new() }),
    }
}

/// После изменения: запустить (продлить) отсчёт.
pub fn after(app: &AppHandle, tool: &str) {
    let st = app.state::<AppState>();
    let mut g = st.mcp_trial.lock().unwrap();
    if let Some(t) = g.as_mut() {
        t.deadline = Some(Instant::now() + TRIAL);
        if !t.tools.iter().any(|x| x == tool) {
            t.tools.push(tool.to_string());
        }
    }
    drop(g);
    let _ = app.emit("mcp-trial", ());
}

pub fn view(st: &AppState) -> Option<TrialView> {
    st.mcp_trial.lock().unwrap().as_ref().map(|t| TrialView {
        seconds_left: t.deadline.map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
        tools: t.tools.clone(),
    })
}

/// Оставить изменения.
pub fn confirm(app: &AppHandle) -> bool {
    let had = app.state::<AppState>().mcp_trial.lock().unwrap().take().is_some();
    let _ = app.emit("mcp-trial", ());
    had
}

/// Вернуть снимок. Ошибки отдельных шагов собираются, остальное всё равно откатывается.
pub fn rollback(app: &AppHandle) -> R<Vec<String>> {
    let st = app.state::<AppState>();
    let Some(t) = st.mcp_trial.lock().unwrap().take() else {
        return Err("no pending changes to roll back".into());
    };
    let s = t.snap;
    let mut done = Vec::new();
    let mut errs = Vec::new();
    let mut step = |what: &str, r: R<()>| match r {
        Ok(()) => done.push(what.to_string()),
        Err(e) => errs.push(format!("{what}: {e}")),
    };

    // Списки zapret2 — до перезапуска zapret, чтобы он взял старые.
    if let Ok(dir) = st.dir() {
        for (kind, text) in &s.lists {
            if crate::lists::read(&dir, kind).ok().as_deref() != Some(text.as_str()) {
                step(&format!("list {kind}"), crate::list_write(app.state(), kind.clone(), text.clone()).map(|_| ()));
            }
        }
    }

    // zapret2: стратегия и включён ли.
    let z = st.runner.status();
    let cur_strategy = st.settings.lock().unwrap().strategy.clone();
    if cur_strategy != s.strategy {
        st.update(|x| x.strategy = s.strategy.clone());
    }
    if s.zapret_running {
        if !z.running || z.strategy != s.strategy {
            step("zapret2", st.apply());
        }
    } else if z.running {
        step("zapret2 off", st.disable());
    }

    // Прокси: настройки и включён ли (выключение возвращает и системный прокси Windows).
    let same_cfg = serde_json::to_value(&st.settings.lock().unwrap().proxy).ok() == serde_json::to_value(&s.proxy).ok();
    let running = st.proxy.lock().unwrap().is_some();
    if s.proxy_running {
        if !running || !same_cfg {
            step("proxy", st.proxy_start(s.proxy.clone()));
        }
    } else {
        if running {
            st.proxy_stop_inner();
            step("proxy off", Ok(()));
        }
        if !same_cfg {
            st.update(|x| x.proxy = s.proxy.clone());
        }
    }

    // Tor.
    if st.settings.lock().unwrap().tor.transport != s.tor_transport {
        st.update(|x| x.tor.transport = s.tor_transport.clone());
    }
    let tor_now = st.tor.lock().unwrap().is_some();
    if s.tor_running && !tor_now {
        let cfg = st.settings.lock().unwrap().tor.clone();
        step("tor", st.tor_start(cfg));
    } else if !s.tor_running && tor_now {
        st.tor_stop();
        step("tor off", Ok(()));
    }

    // Xray: выбранный сервер и включён ли.
    let xc = st.settings.lock().unwrap().xray.clone();
    if xc.selected != s.xray_selected {
        step("xray server", crate::xray_set(app.state(), xc.port, s.xray_selected.clone(), xc.routing.clone(), xc.fragment).map(|_| ()));
    }
    let xray_now = st.xray.lock().unwrap().is_some();
    if s.xray_running && !xray_now {
        let cfg = st.settings.lock().unwrap().xray.clone();
        step("xray", st.xray_start(cfg));
    } else if !s.xray_running && xray_now {
        st.xray_stop();
        step("xray off", Ok(()));
    }

    let _ = app.emit("mcp-trial", ());
    let _ = app.emit("proxy-changed", ());
    let _ = app.emit("tor-changed", ());
    let _ = app.emit("xray-changed", ());
    let _ = app.emit("status", &st.runner.status());
    crate::refresh_tray(app);
    if errs.is_empty() {
        Ok(done)
    } else {
        Err(errs.join("; "))
    }
}

/// Следит за сроком; по истечении — откат и сообщение в окно.
pub fn watch(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let due = {
            let st = app.state::<AppState>();
            let g = st.mcp_trial.lock().unwrap();
            g.as_ref().and_then(|t| t.deadline).is_some_and(|d| Instant::now() >= d)
        };
        if due {
            let msg = match rollback(&app) {
                Ok(_) => crate::tr!(
                    "Изменения от ИИ откачены: он не подтвердил, что всё работает",
                    "Changes by the AI were rolled back: it did not confirm that everything works"
                ),
                Err(e) => crate::tr!("Откат изменений от ИИ: {e}", "Rolling back the AI's changes: {e}"),
            };
            let _ = app.emit("error", msg);
        }
    });
}
