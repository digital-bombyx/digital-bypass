mod autostart;
mod bundled;
mod diag;
mod dns;
mod doh;
mod game_filter;
mod hosts;
mod i18n;
mod ipset;
mod lists;
mod proxy;
mod runner;
mod service;
mod settings;
mod sniscan;
mod strategy;
mod tester;
mod util;
mod winapi;
mod zapret_dir;

use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};

type R<T> = Result<T, String>;

pub struct AppState {
    config_dir: PathBuf,
    settings: Mutex<settings::Settings>,
    runner: runner::Runner,
    testing: AtomicBool,
    cancel: AtomicBool,
    last_test: Mutex<Option<tester::TestRun>>,
    /// Развёрнутая встроенная сборка (если она есть в установщике).
    bundled_dir: Option<PathBuf>,
    bundle_error: Mutex<Option<String>>,
    proxy: Mutex<Option<proxy::Proxy>>,
    stub: Mutex<Option<doh::Stub>>,
}

impl AppState {
    fn dir(&self) -> R<PathBuf> {
        let configured = self.settings.lock().unwrap().zapret_dir.clone();
        zapret_dir::detect(configured.as_deref(), self.bundled_dir.as_deref())
            .ok_or_else(|| tr!("Папка zapret-discord-youtube не найдена — укажите её в настройках", "zapret-discord-youtube folder not found — set it in Settings"))
    }
    fn update(&self, f: impl FnOnce(&mut settings::Settings)) {
        let mut s = self.settings.lock().unwrap();
        f(&mut s);
        settings::save(&self.config_dir, &s);
    }
    fn history_path(&self) -> PathBuf {
        self.config_dir.join("test-history.json")
    }
    fn hosts_cache(&self) -> PathBuf {
        self.config_dir.join("hosts-upstream.txt")
    }
    fn require_admin(&self) -> R<()> {
        if winapi::is_admin() {
            Ok(())
        } else {
            Err(tr!("Нужны права администратора: запустите приложение от имени администратора", "Administrator rights required: run the app as administrator"))
        }
    }
    fn require_idle(&self) -> R<()> {
        if self.testing.load(Ordering::SeqCst) {
            Err(tr!("Идёт тестирование стратегий — дождитесь окончания или отмените его", "Strategy test in progress — wait for it to finish or cancel it"))
        } else {
            Ok(())
        }
    }

    /// Аргументы выбранной стратегии с учётом Game Filter.
    fn selected_args(&self, dir: &std::path::Path) -> R<(String, Vec<String>)> {
        let file = self
            .settings
            .lock()
            .unwrap()
            .strategy
            .clone()
            .or_else(|| strategy::list(dir).first().map(|s| s.file.clone()))
            .ok_or_else(|| tr!("В папке нет стратегий general*.bat", "No general*.bat strategies in the folder"))?;
        let gf = game_filter::load(dir);
        let (tcp, udp) = game_filter::vars(&gf);
        let args = strategy::build_args(dir, &file, &strategy::Vars::new(dir, &tcp, &udp))?;
        Ok((file, args))
    }

    /// Включить обход выбранной стратегией в выбранном режиме.
    fn apply(&self) -> R<()> {
        self.require_admin()?;
        self.require_idle()?;
        let dir = self.dir()?;
        let (file, args) = self.selected_args(&dir)?;
        let mode = self.settings.lock().unwrap().mode.clone();
        if mode == "service" {
            self.runner.stop_processes();
            lists::ensure(&dir);
            service::install(&dir, file.trim_end_matches(".bat"), &args)?;
            self.runner.clear_error();
            self.runner.notify_changed();
        } else {
            if service::state(service::NAME).0 {
                service::stop_and_delete(service::NAME)?;
            }
            self.runner.start(&dir, &file, &args)?;
        }
        self.update(|s| {
            s.last_enabled = true;
            s.strategy = Some(file);
        });
        Ok(())
    }

    fn disable(&self) -> R<()> {
        self.require_admin()?;
        self.require_idle()?;
        if service::state(service::NAME).0 {
            service::remove_all()?;
        }
        self.runner.stop();
        self.update(|s| s.last_enabled = false);
        Ok(())
    }

    /// Запустить прокси по настройкам и, если нужно, прописать его в Windows.
    fn proxy_start(&self, mut cfg: proxy::Config) -> R<()> {
        self.proxy_stop_inner();
        cfg.normalize();
        // Домены списков zapret2 для правила «только списки» (если папка есть).
        let lists = if cfg.rules.zapret_lists { self.dir().map(|d| lists::bypass_domains(&d)).unwrap_or_default() } else { Vec::new() };
        let p = proxy::Proxy::start(cfg.clone(), &lists)?;
        *self.proxy.lock().unwrap() = Some(p);
        // Раздача в LAN: правило брандмауэра (только с правами администратора).
        if cfg.lan && winapi::is_admin() {
            if let Err(e) = proxy::firewall_allow(cfg.port) {
                *self.proxy.lock().unwrap() = None;
                return Err(e);
            }
        }
        if cfg.system {
            let prev = proxy::system_set(cfg.port)?;
            self.update(|s| s.proxy_prev = Some(prev));
        }
        self.update(|s| {
            s.proxy = cfg;
            s.proxy_enabled = true;
        });
        Ok(())
    }

    /// Остановить прокси и вернуть системные настройки; флаг «включён» не трогает.
    fn proxy_stop_inner(&self) {
        let was_lan = self.proxy.lock().unwrap().take().is_some_and(|p| p.stats().lan);
        if was_lan && winapi::is_admin() {
            proxy::firewall_remove();
        }
        let (prev, port) = {
            let s = self.settings.lock().unwrap();
            (s.proxy_prev.clone(), s.proxy.port)
        };
        if let Some(prev) = prev {
            if proxy::system_restore(&prev, port).is_ok() {
                self.update(|s| s.proxy_prev = None);
            }
        }
    }

    fn stub_start(&self, cfg: &dns::StubConfig) -> R<()> {
        let boot: Vec<std::net::IpAddr> = cfg.bootstrap.iter().filter_map(|b| b.parse().ok()).collect();
        let client = doh::DohClient::new(&cfg.template, &boot)?;
        let stub = doh::Stub::start(client)?;
        // После перезапуска свободным может оказаться другой адрес — тогда адаптер
        // указывает в пустоту; прописываем заново (нужны права администратора).
        if stub.addr().to_string() != cfg.addr && winapi::is_admin() {
            if let Some(a) = dns::info().adapters.into_iter().find(|a| a.guid.eq_ignore_ascii_case(&cfg.guid)) {
                let boot: Vec<std::net::IpAddr> = cfg.bootstrap.iter().filter_map(|b| b.parse().ok()).collect();
                let fb = cfg.fallback.as_deref().and_then(|f| f.parse().ok());
                let mut fresh = dns::stub_point(a.index, stub.addr(), stub.ipv6(), &cfg.template, &boot, fb)?;
                fresh.prev_v4 = cfg.prev_v4.clone();
                fresh.prev_v6 = cfg.prev_v6.clone();
                self.update(|s| s.dns_stub = Some(fresh));
            }
        }
        *self.stub.lock().unwrap() = Some(stub);
        Ok(())
    }

    /// Вернуть DNS адаптера и остановить резолвер.
    fn stub_disable(&self) -> R<()> {
        let cfg = self.settings.lock().unwrap().dns_stub.clone();
        if let Some(cfg) = cfg {
            dns::stub_restore(&cfg)?;
            self.update(|s| s.dns_stub = None);
        }
        self.stub.lock().unwrap().take();
        dns::flush();
        Ok(())
    }

    /// После изменения настроек перезапустить, если обход работает под нашим управлением.
    fn restart_if_running(&self) -> R<()> {
        let st = self.runner.status();
        if st.running && (st.mode == "process" || st.mode == "service") {
            self.apply()?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct Overview {
    admin: bool,
    dir: Option<String>,
    version: Option<String>,
    strategies: Vec<strategy::StrategyInfo>,
    selected: Option<String>,
    status: runner::Status,
    game_filter: game_filter::GameFilter,
    ipset: String,
    ipset_has_backup: bool,
    mode: String,
    autostart: bool,
    close_to_tray: bool,
    test_timeout: u32,
    test_parallel: usize,
    testing: bool,
    language: String,
    /// bundled — встроенная сборка; custom — своя папка из настроек; found — найдена на диске.
    dir_source: &'static str,
    bundled_version: Option<String>,
    bundle_error: Option<String>,
}

fn overview_of(state: &AppState) -> Overview {
    let dir = state.dir().ok();
    let s = state.settings.lock().unwrap().clone();
    let strategies = dir.as_deref().map(strategy::list).unwrap_or_default();
    let selected = s
        .strategy
        .clone()
        .filter(|f| strategies.iter().any(|x| &x.file == f))
        .or_else(|| strategies.first().map(|x| x.file.clone()));
    Overview {
        admin: winapi::is_admin(),
        version: dir.as_deref().and_then(zapret_dir::version),
        game_filter: dir.as_deref().map(game_filter::load).unwrap_or_default(),
        ipset: dir.as_deref().map(ipset::status).unwrap_or("none").into(),
        ipset_has_backup: dir.as_deref().is_some_and(ipset::has_backup),
        dir: dir.map(|d| d.to_string_lossy().into_owned()),
        strategies,
        selected,
        status: state.runner.status(),
        mode: s.mode,
        autostart: autostart::is_enabled(),
        close_to_tray: s.close_to_tray,
        test_timeout: s.test_timeout,
        test_parallel: s.test_parallel,
        testing: state.testing.load(Ordering::SeqCst),
        dir_source: match (&state.dir().ok(), &state.bundled_dir, &s.zapret_dir) {
            (Some(d), _, Some(c)) if !c.trim().is_empty() && d == &PathBuf::from(c) => "custom",
            (Some(d), Some(b), _) if d == b => "bundled",
            _ => "found",
        },
        bundled_version: state.bundled_dir.as_deref().and_then(bundled::version),
        bundle_error: state.bundle_error.lock().unwrap().clone(),
        language: state.settings.lock().unwrap().language.clone(),
    }
}

// ---------- команды ----------

#[tauri::command(async)]
fn overview(state: State<AppState>) -> Overview {
    overview_of(&state)
}

#[tauri::command(async)]
fn status(state: State<AppState>) -> runner::Status {
    state.runner.status()
}

#[tauri::command(async)]
fn log_tail(state: State<AppState>) -> Vec<String> {
    state.runner.log_tail(200)
}

#[tauri::command(async)]
fn set_zapret_dir(state: State<AppState>, path: String) -> R<Overview> {
    // Пустой путь — вернуться к встроенной сборке.
    if path.trim().is_empty() {
        state.update(|s| s.zapret_dir = None);
        return Ok(overview_of(&state));
    }
    let p = PathBuf::from(path.trim());
    if !zapret_dir::is_valid(&p) {
        return Err(tr!("В папке нет bin\\winws2.exe, lua\\ или lists\\", "Folder has no bin\\winws2.exe, lua\\ or lists\\"));
    }
    state.update(|s| s.zapret_dir = Some(p.to_string_lossy().into_owned()));
    Ok(overview_of(&state))
}

#[tauri::command(async)]
fn select_strategy(app: AppHandle, state: State<AppState>, file: String) -> R<()> {
    state.update(|s| s.strategy = Some(file));
    let r = state.restart_if_running();
    refresh_tray(&app);
    r
}

#[tauri::command(async)]
fn enable(state: State<AppState>) -> R<()> {
    state.apply()
}

#[tauri::command(async)]
fn disable(state: State<AppState>) -> R<()> {
    state.disable()
}

#[tauri::command(async)]
fn set_mode(state: State<AppState>, mode: String) -> R<()> {
    if mode != "process" && mode != "service" {
        return Err(tr!("некорректный режим", "invalid mode"));
    }
    let was_running = state.runner.status();
    state.update(|s| s.mode = mode);
    if was_running.running && was_running.mode != "external" {
        state.apply()?;
    }
    Ok(())
}

#[tauri::command(async)]
fn set_game_filter(state: State<AppState>, gf: game_filter::GameFilter) -> R<()> {
    state.require_idle()?;
    game_filter::save(&state.dir()?, &gf)?;
    state.restart_if_running()
}

#[tauri::command(async)]
fn set_ipset(state: State<AppState>, mode: String) -> R<()> {
    state.require_idle()?;
    ipset::set(&state.dir()?, &mode)?;
    state.restart_if_running()
}

#[tauri::command(async)]
fn strategy_command(state: State<AppState>, file: String) -> R<Vec<String>> {
    let dir = state.dir()?;
    let (tcp, udp) = game_filter::vars(&game_filter::load(&dir));
    strategy::build_args(&dir, &file, &strategy::Vars::new(&dir, &tcp, &udp))
}

#[tauri::command(async)]
fn list_read(state: State<AppState>, kind: String) -> R<String> {
    lists::read(&state.dir()?, &kind)
}

#[tauri::command(async)]
fn list_write(state: State<AppState>, kind: String, content: String) -> R<lists::SaveResult> {
    state.require_idle()?;
    let r = lists::write(&state.dir()?, &kind, &content)?;
    state.restart_if_running()?;
    Ok(r)
}

#[tauri::command(async)]
fn test_targets(state: State<AppState>) -> R<Vec<(String, String)>> {
    Ok(tester::load_targets(&state.dir()?))
}

#[tauri::command(async)]
fn test_start(app: AppHandle, state: State<AppState>, kind: String, files: Vec<String>) -> R<()> {
    state.require_admin()?;
    let dir = state.dir()?;
    if files.is_empty() {
        return Err(tr!("Не выбрано ни одной стратегии", "No strategies selected"));
    }
    if state.testing.swap(true, Ordering::SeqCst) {
        return Err(tr!("Тест уже идёт", "A test is already running"));
    }
    state.cancel.store(false, Ordering::SeqCst);
    let params = {
        let s = state.settings.lock().unwrap();
        tester::Params { timeout: s.test_timeout.clamp(2, 30), parallel: s.test_parallel.clamp(1, 32) }
    };
    std::thread::spawn(move || {
        let st = app.state::<AppState>();
        let gf = game_filter::load(&dir);
        let ctx = tester::Ctx { dir: &dir, runner: &st.runner, cancel: &st.cancel, game_vars: game_filter::vars(&gf) };
        let emit_app = app.clone();
        let run = tester::run(ctx, &kind, files, params, move |r| {
            let _ = emit_app.emit("test-progress", r);
        });
        *st.last_test.lock().unwrap() = Some(run.clone());
        // История: последние 10 прогонов.
        let mut hist: Vec<tester::TestRun> = std::fs::read(st.history_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if !run.results.is_empty() {
            hist.insert(0, run);
            hist.truncate(10);
            if let Ok(j) = serde_json::to_vec(&hist) {
                let _ = std::fs::write(st.history_path(), j);
            }
        }
        st.testing.store(false, Ordering::SeqCst);
        let _ = app.emit("test-finished", ());
        refresh_tray(&app);
    });
    Ok(())
}

#[tauri::command]
fn test_cancel(state: State<AppState>) {
    state.cancel.store(true, Ordering::SeqCst);
}

#[tauri::command(async)]
fn test_last(state: State<AppState>) -> Option<tester::TestRun> {
    state.last_test.lock().unwrap().clone()
}

#[tauri::command(async)]
fn test_history(state: State<AppState>) -> Vec<tester::TestRun> {
    std::fs::read(state.history_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

#[tauri::command(async)]
fn set_test_params(state: State<AppState>, timeout: u32, parallel: usize) {
    state.update(|s| {
        s.test_timeout = timeout.clamp(2, 30);
        s.test_parallel = parallel.clamp(1, 32);
    });
}

#[tauri::command(async)]
fn hosts_status(state: State<AppState>) -> R<hosts::Status> {
    let dir = state.dir()?;
    let custom = state.settings.lock().unwrap().hosts_custom.clone();
    Ok(hosts::status(&dir, &state.hosts_cache(), &custom))
}

#[tauri::command(async)]
fn hosts_apply(state: State<AppState>, entries: Vec<hosts::Entry>, custom: Vec<hosts::Entry>) -> R<()> {
    state.require_admin()?;
    for e in entries.iter().chain(custom.iter()) {
        if e.ip.parse::<std::net::IpAddr>().is_err() || e.host.is_empty() || e.host.contains(char::is_whitespace) {
            let (ip, host) = (&e.ip, &e.host);
            return Err(tr!("некорректная запись: {ip} {host}", "invalid entry: {ip} {host}"));
        }
    }
    state.update(|s| s.hosts_custom = custom.clone());
    let all: Vec<hosts::Entry> = entries.into_iter().chain(custom).collect();
    hosts::apply(&all)
}

#[tauri::command(async)]
fn hosts_remove(state: State<AppState>) -> R<()> {
    state.require_admin()?;
    hosts::apply(&[])
}

#[tauri::command(async)]
fn hosts_update(state: State<AppState>) -> R<usize> {
    hosts::update_upstream(&state.hosts_cache())
}

#[tauri::command(async)]
fn dns_info() -> dns::Info {
    dns::info()
}

#[tauri::command(async)]
fn dns_presets() -> &'static [dns::Preset] {
    dns::PRESETS
}

#[tauri::command(async)]
fn dns_apply(state: State<AppState>, req: dns::ApplyReq) -> R<dns::Info> {
    state.require_admin()?;
    dns::apply(&req)?;
    Ok(dns::info())
}

#[tauri::command(async)]
fn dns_reset(state: State<AppState>, index: u32, v4: bool, v6: bool) -> R<dns::Info> {
    state.require_admin()?;
    dns::reset(index, v4, v6)?;
    Ok(dns::info())
}

#[tauri::command(async)]
fn dns_flush() -> R<()> {
    if dns::flush() {
        Ok(())
    } else {
        Err(tr!("не удалось сбросить кэш DNS", "failed to flush the DNS cache"))
    }
}

#[derive(Serialize)]
struct StubStatus {
    running: bool,
    config: Option<dns::StubConfig>,
    stats: Option<doh::StubStats>,
}

fn stub_status_of(state: &AppState) -> StubStatus {
    let stats = state.stub.lock().unwrap().as_ref().map(|s| s.stats());
    StubStatus { running: stats.is_some(), config: state.settings.lock().unwrap().dns_stub.clone(), stats }
}

#[tauri::command(async)]
fn dns_stub_status(state: State<AppState>) -> StubStatus {
    stub_status_of(&state)
}

#[tauri::command(async)]
fn dns_stub_enable(state: State<AppState>, index: u32, template: String, bootstrap: Vec<String>, fallback: bool) -> R<StubStatus> {
    state.require_admin()?;
    let template = dns::validate_template(&template)?;
    if state.settings.lock().unwrap().dns_stub.is_some() {
        state.stub_disable()?;
    }
    let boot: Vec<std::net::IpAddr> = bootstrap.iter().filter_map(|b| b.trim().parse().ok()).collect();
    // Пустой bootstrap: адрес сервера один раз узнаём системным DNS, пока он ещё не наш.
    let client = doh::DohClient::new(&template, &boot)?;
    let boot = client.bootstrap();
    // Проверка до переключения адаптера: если DoH не отвечает, ничего не меняем.
    client
        .resolve("example.com")
        .map_err(|e| tr!("DoH-сервер не ответил, DNS не изменён: {e}", "DoH server did not answer, DNS unchanged: {e}"))?;
    let stub = doh::Stub::start(client)?;
    let fb = if fallback { boot.iter().find(|i| i.is_ipv4()).copied() } else { None };
    let cfg = dns::stub_point(index, stub.addr(), stub.ipv6(), &template, &boot, fb)?;
    *state.stub.lock().unwrap() = Some(stub);
    state.update(|s| s.dns_stub = Some(cfg));
    dns::flush();
    Ok(stub_status_of(&state))
}

#[tauri::command(async)]
fn dns_stub_disable(state: State<AppState>) -> R<StubStatus> {
    state.require_admin()?;
    state.stub_disable()?;
    Ok(stub_status_of(&state))
}

#[derive(Serialize)]
struct ProxyStatus {
    config: proxy::Config,
    enabled: bool,
    stats: proxy::Stats,
}

fn proxy_status_of(state: &AppState) -> ProxyStatus {
    let s = state.settings.lock().unwrap().clone();
    let stats = state.proxy.lock().unwrap().as_ref().map(|p| p.stats()).unwrap_or_default();
    ProxyStatus { config: s.proxy, enabled: s.proxy_enabled, stats }
}

#[tauri::command(async)]
fn proxy_status(state: State<AppState>) -> ProxyStatus {
    proxy_status_of(&state)
}

#[tauri::command(async)]
fn proxy_start(app: AppHandle, state: State<AppState>, config: proxy::Config) -> R<ProxyStatus> {
    if config.port < 1024 {
        return Err(tr!("порт должен быть от 1024 до 65535", "port must be 1024–65535"));
    }
    config.validate_auth()?;
    let r = state.proxy_start(config);
    refresh_tray(&app);
    r?;
    Ok(proxy_status_of(&state))
}

/// Сохранить настройки прокси; работающий перезапустить с ними.
#[tauri::command(async)]
fn proxy_set_config(app: AppHandle, state: State<AppState>, config: proxy::Config) -> R<ProxyStatus> {
    if config.port < 1024 {
        return Err(tr!("порт должен быть от 1024 до 65535", "port must be 1024–65535"));
    }
    config.validate_auth()?;
    let mut config = config;
    config.normalize();
    if state.proxy.lock().unwrap().is_some() {
        let r = state.proxy_start(config);
        refresh_tray(&app);
        r?;
    } else {
        state.update(|s| s.proxy = config);
    }
    Ok(proxy_status_of(&state))
}

#[tauri::command(async)]
fn proxy_stop(app: AppHandle, state: State<AppState>) -> ProxyStatus {
    state.proxy_stop_inner();
    state.update(|s| s.proxy_enabled = false);
    refresh_tray(&app);
    proxy_status_of(&state)
}

#[derive(Serialize)]
struct SniDefaults {
    target: &'static str,
    snis: &'static [&'static str],
}

#[tauri::command(async)]
fn sni_defaults() -> SniDefaults {
    SniDefaults { target: sniscan::DEFAULT_TARGET, snis: sniscan::DEFAULT_SNIS }
}

#[tauri::command(async)]
fn sni_scan(target: String, snis: String, timeout: u64) -> R<sniscan::Report> {
    sniscan::run(&target, &sniscan::parse_snis(&snis), timeout)
}

/// IPv4-адреса ПК в локальной сети — их указывают на телефоне при раздаче.
#[tauri::command(async)]
fn lan_addresses() -> Vec<String> {
    dns::info()
        .adapters
        .into_iter()
        .filter(|a| a.up && a.gateway)
        .flat_map(|a| a.addresses)
        .filter(|s| s.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_private()))
        .collect()
}

#[tauri::command(async)]
fn diag_run(domain: String) -> R<diag::Report> {
    diag::run(&domain)
}

#[tauri::command(async)]
fn list_presets(state: State<AppState>) -> Vec<lists::PresetView> {
    state.dir().map(|d| lists::presets_for(&d)).unwrap_or_default()
}

#[tauri::command(async)]
fn list_add_presets(state: State<AppState>, ids: Vec<String>) -> R<usize> {
    state.require_idle()?;
    let n = lists::add_presets(&state.dir()?, &ids)?;
    if n > 0 {
        state.restart_if_running()?;
    }
    Ok(n)
}

#[tauri::command(async)]
fn set_autostart(enabled: bool) -> R<bool> {
    autostart::set(enabled)?;
    Ok(autostart::is_enabled())
}

#[tauri::command(async)]
fn set_language(app: AppHandle, state: State<AppState>, lang: String) {
    let lang = if lang == "en" { "en" } else { "ru" }.to_string();
    i18n::set_lang(&lang);
    state.update(|s| s.language = lang);
    refresh_tray(&app);
}

#[tauri::command(async)]
fn set_close_to_tray(state: State<AppState>, enabled: bool) {
    state.update(|s| s.close_to_tray = enabled);
}

#[tauri::command(async)]
fn open_path(path: String) -> R<()> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err(tr!("путь не найден", "path not found"));
    }
    std::process::Command::new("explorer.exe").arg(p).spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

// ---------- трей ----------

fn tray_icon(on: bool) -> tauri::image::Image<'static> {
    const S: usize = 32;
    let (r, g, b) = if on { (0x58, 0xa6, 0xff) } else { (0x73, 0x7d, 0x8a) };
    let mut px = vec![0u8; S * S * 4];
    let c = (S as f32 - 1.0) / 2.0;
    for y in 0..S {
        for x in 0..S {
            let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
            let i = (y * S + x) * 4;
            // Кольцо + точка: индикатор состояния zapret2.
            let ring = (d - 12.5).abs();
            let a_ring = (1.6 - ring).clamp(0.0, 1.0);
            let a_dot = (6.5 - d).clamp(0.0, 1.0);
            let a = a_ring.max(if on { a_dot } else { a_dot * 0.55 });
            px[i] = r;
            px[i + 1] = g;
            px[i + 2] = b;
            px[i + 3] = (a * 255.0) as u8;
        }
    }
    tauri::image::Image::new_owned(px, S as u32, S as u32)
}

fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let state = app.state::<AppState>();
    let st = state.runner.status();
    let selected = state.settings.lock().unwrap().strategy.clone();
    let dir = state.dir().ok();
    let strategies = dir.as_deref().map(strategy::list).unwrap_or_default();
    let toggle = CheckMenuItem::with_id(app, "toggle", "zapret2", dir.is_some(), st.running, None::<&str>)?;
    let sub = Submenu::with_id(app, "strategies", tr!("Стратегия zapret2", "zapret2 strategy"), dir.is_some())?;
    for s in &strategies {
        let checked = selected.as_deref() == Some(s.file.as_str());
        sub.append(&CheckMenuItem::with_id(app, format!("s:{}", s.file), &s.name, true, checked, None::<&str>)?)?;
    }
    let proxy_on = state.proxy.lock().unwrap().is_some();
    let port = state.settings.lock().unwrap().proxy.port;
    let proxy = CheckMenuItem::with_id(app, "proxy", tr!("Прокси-обходчик (:{port})", "Bypass proxy (:{port})"), true, proxy_on, None::<&str>)?;
    // DoH-резолвер меняет DNS адаптера (нужны права) — в трее только состояние.
    let stub_label = match state.stub.lock().unwrap().as_ref() {
        Some(s) => {
            let a = s.addr();
            tr!("DoH-резолвер: работает ({a})", "DoH resolver: running ({a})")
        }
        None if state.settings.lock().unwrap().dns_stub.is_some() => tr!("DoH-резолвер: не запущен", "DoH resolver: not running"),
        None => tr!("DoH-резолвер: выключен", "DoH resolver: off"),
    };
    let stub = MenuItem::with_id(app, "stub", stub_label, false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", tr!("Открыть", "Open"), true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", tr!("Выход", "Quit"), true, None::<&str>)?;
    let sep = || PredefinedMenuItem::separator(app);
    Menu::with_items(app, &[&toggle, &sub, &sep()?, &proxy, &stub, &sep()?, &open, &quit])
}

fn refresh_tray(app: &AppHandle) {
    let Some(tray) = app.tray_by_id("main") else { return };
    let state = app.state::<AppState>();
    let st = state.runner.status();
    let proxy_on = state.proxy.lock().unwrap().is_some();
    let stub_on = state.stub.lock().unwrap().is_some();
    // Значок «включён», если работает хоть один обход.
    let _ = tray.set_icon(Some(tray_icon(st.running || proxy_on)));
    let mut tip = vec!["digital-bypass".to_string()];
    tip.push(match (&st.running, &st.strategy) {
        (true, Some(s)) => {
            let s = s.trim_end_matches(".bat");
            tr!("zapret2: {s}", "zapret2: {s}")
        }
        (true, None) => tr!("zapret2: включён", "zapret2: on"),
        _ => tr!("zapret2: выключен", "zapret2: off"),
    });
    if proxy_on {
        tip.push(tr!("прокси: включён", "proxy: on"));
    }
    if stub_on {
        tip.push(tr!("DoH-резолвер: включён", "DoH resolver: on"));
    }
    let _ = tray.set_tooltip(Some(tip.join("\n")));
    if let Ok(menu) = build_tray_menu(app) {
        let _ = tray.set_menu(Some(menu));
    }
}

/// Вернуть окну сохранённые размер и положение (если монитор на месте).
fn restore_geometry(app: &AppHandle, w: &tauri::WebviewWindow) {
    let Some(g) = app.state::<AppState>().settings.lock().unwrap().window else { return };
    let monitors: Vec<(i32, i32, u32, u32)> = w
        .available_monitors()
        .unwrap_or_default()
        .iter()
        .map(|m| (m.position().x, m.position().y, m.size().width, m.size().height))
        .collect();
    if !g.visible_on(&monitors) {
        let _ = w.set_size(tauri::PhysicalSize::new(g.width.max(460), g.height.max(520)));
        let _ = w.center();
    } else {
        let _ = w.set_size(tauri::PhysicalSize::new(g.width, g.height));
        let _ = w.set_position(tauri::PhysicalPosition::new(g.x, g.y));
    }
    if g.maximized {
        let _ = w.maximize();
    }
}

/// Запомнить размер и положение (в памяти; на диск — при закрытии окна и выходе).
fn remember_geometry(window: &tauri::Window) {
    if window.is_minimized().unwrap_or(true) || !window.is_visible().unwrap_or(false) {
        return;
    }
    let st = window.app_handle().state::<AppState>();
    let mut s = st.settings.lock().unwrap();
    if window.is_maximized().unwrap_or(false) {
        // Размер «до разворачивания» оставляем прежним.
        if let Some(g) = s.window.as_mut() {
            g.maximized = true;
        }
        return;
    }
    let (Ok(pos), Ok(size)) = (window.outer_position(), window.inner_size()) else { return };
    s.window = Some(settings::WindowGeom { x: pos.x, y: pos.y, width: size.width, height: size.height, maximized: false });
}

fn save_settings(app: &AppHandle) {
    let st = app.state::<AppState>();
    let s = st.settings.lock().unwrap().clone();
    settings::save(&st.config_dir, &s);
}

/// Показать окно. Если оно было закрыто в трей (уничтожено вместе с WebView2),
/// создать заново из конфигурации. Создание — в отдельном потоке: на Windows
/// построение окна из обработчика событий главного потока может зависнуть.
fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        // Первый показ окна, созданного из конфигурации при старте.
        if !w.is_visible().unwrap_or(true) {
            restore_geometry(app, &w);
        }
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || {
        let Some(cfg) = app.config().app.windows.iter().find(|w| w.label == "main").cloned() else { return };
        if let Ok(w) = tauri::WebviewWindowBuilder::from_config(&app, &cfg).and_then(|b| b.build()) {
            restore_geometry(&app, &w);
            let _ = w.show();
            let _ = w.set_focus();
        }
    });
}

/// Свёрнутое окно: спрятать и приостановить WebView2, попросить его отдать память.
/// Развёрнутое: вернуть как было.
#[cfg(windows)]
fn webview_low_memory(app: &AppHandle, low: bool) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2_19, ICoreWebView2_3, COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW,
        COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL,
    };
    use windows_core::Interface;
    let Some(w) = app.get_webview_window("main") else { return };
    let _ = w.with_webview(move |pw| unsafe {
        let ctrl = pw.controller();
        let Ok(core) = ctrl.CoreWebView2() else { return };
        if low {
            let _ = ctrl.SetIsVisible(false.into());
        }
        if let Ok(c19) = core.cast::<ICoreWebView2_19>() {
            let level = if low {
                COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW
            } else {
                COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL
            };
            let _ = c19.SetMemoryUsageTargetLevel(level);
        }
        if let Ok(c3) = core.cast::<ICoreWebView2_3>() {
            if low {
                let handler = webview2_com::TrySuspendCompletedHandler::create(Box::new(|_, _| Ok(())));
                let _ = c3.TrySuspend(&handler);
            } else {
                let _ = c3.Resume();
            }
        }
        if !low {
            let _ = ctrl.SetIsVisible(true.into());
        }
    });
}

fn on_tray_menu(app: &AppHandle, id: &str) {
    match id {
        "open" => show_main(app),
        "proxy" => {
            let app = app.clone();
            std::thread::spawn(move || {
                let st = app.state::<AppState>();
                if st.proxy.lock().unwrap().is_some() {
                    st.proxy_stop_inner();
                    st.update(|s| s.proxy_enabled = false);
                } else {
                    let cfg = st.settings.lock().unwrap().proxy.clone();
                    if let Err(e) = st.proxy_start(cfg) {
                        let _ = app.emit("error", e);
                        show_main(&app);
                    }
                }
                let _ = app.emit("proxy-changed", ());
                refresh_tray(&app);
            });
        }
        "quit" => app.exit(0),
        "toggle" => {
            let app = app.clone();
            std::thread::spawn(move || {
                let st = app.state::<AppState>();
                let r = if st.runner.status().running { st.disable() } else { st.apply() };
                if let Err(e) = r {
                    let _ = app.emit("error", e);
                    show_main(&app);
                }
                refresh_tray(&app);
            });
        }
        other => {
            if let Some(file) = other.strip_prefix("s:") {
                let app = app.clone();
                let file = file.to_string();
                std::thread::spawn(move || {
                    let st = app.state::<AppState>();
                    st.update(|s| s.strategy = Some(file));
                    if let Err(e) = st.restart_if_running() {
                        let _ = app.emit("error", e);
                    }
                    let _ = app.emit("overview-changed", ());
                    refresh_tray(&app);
                });
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let start_in_tray = std::env::args().any(|a| a == "--tray");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .setup(move |app| {
            let config_dir = app.path().app_config_dir().unwrap_or_else(|_| std::env::temp_dir().join("digital-bypass"));
            let settings = settings::load(&config_dir);
            i18n::set_lang(&settings.language);

            // Встроенный zapret: развернуть/обновить из ресурсов в папку данных.
            let mut bundle_error = None;
            let bundled_dir = match (app.path().resource_dir(), app.path().app_local_data_dir()) {
                (Ok(res), Ok(local)) => {
                    let dst = bundled::target_root(&local);
                    if let Err(e) = bundled::ensure(&bundled::resource_root(&res), &dst) {
                        bundle_error = Some(e);
                    }
                    zapret_dir::is_valid(&dst).then_some(dst)
                }
                _ => None,
            };

            app.manage(AppState {
                bundled_dir,
                bundle_error: Mutex::new(bundle_error),
                config_dir,
                settings: Mutex::new(settings),
                runner: runner::Runner::new(),
                testing: AtomicBool::new(false),
                cancel: AtomicBool::new(false),
                last_test: Mutex::new(None),
                proxy: Mutex::new(None),
                stub: Mutex::new(None),
            });

            let handle = app.handle().clone();
            app.state::<AppState>().runner.set_notify(move || {
                let st = handle.state::<AppState>().runner.status();
                let _ = handle.emit("status", &st);
                refresh_tray(&handle);
            });

            TrayIconBuilder::with_id("main")
                .icon(tray_icon(false))
                .tooltip("digital-bypass")
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| on_tray_menu(app, e.id().as_ref()))
                .on_tray_icon_event(|tray, e| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;

            // Прокси и DoH-резолвер не зависят от папки zapret.
            {
                let st = app.state::<AppState>();
                let (enabled, cfg, prev, stub) = {
                    let s = st.settings.lock().unwrap();
                    (s.proxy_enabled, s.proxy.clone(), s.proxy_prev.clone(), s.dns_stub.clone())
                };
                // Прошлый запуск мог упасть с прописанным прокси — сначала вернуть как было.
                if let Some(prev) = prev {
                    if proxy::system_restore(&prev, cfg.port).is_ok() {
                        st.update(|s| s.proxy_prev = None);
                    }
                }
                if enabled {
                    if let Err(e) = st.proxy_start(cfg) {
                        let _ = app.handle().emit("error", e);
                    }
                }
                if let Some(c) = stub {
                    if let Err(e) = st.stub_start(&c) {
                        let _ = app.handle().emit("error", tr!("DoH-резолвер не запустился: {e}", "DoH resolver failed to start: {e}"));
                    }
                }
            }

            // Фоновые шаги при старте: восстановить ipset после прерванного теста,
            // включить обход, если он был включён при выходе.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let st = handle.state::<AppState>();
                if let Ok(dir) = st.dir() {
                    ipset::test_restore(&dir);
                    let (last, mode) = {
                        let s = st.settings.lock().unwrap();
                        (s.last_enabled, s.mode.clone())
                    };
                    if last && mode == "process" && winapi::is_admin() && !st.runner.status().running {
                        if let Err(e) = st.apply() {
                            let _ = handle.emit("error", e);
                        }
                    }
                }
                refresh_tray(&handle);
            });

            if start_in_tray {
                // В трее окно не нужно: не держим WebView2 в памяти до первого открытия.
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.destroy();
                }
            } else {
                show_main(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            match event {
                WindowEvent::Resized(_) | WindowEvent::Moved(_) => remember_geometry(window),
                // Закрытие в трей уничтожает окно — сохраняем, пока оно ещё есть.
                WindowEvent::CloseRequested { .. } => {
                    remember_geometry(window);
                    save_settings(window.app_handle());
                }
                _ => {}
            }
            // Закрытие в трей = окно уничтожается вместе с WebView2 (основная часть RAM);
            // само приложение остаётся жить — см. ExitRequested ниже.
            #[cfg(windows)]
            if let WindowEvent::Resized(_) = event {
                let minimized = window.is_minimized().unwrap_or(false);
                let app = window.app_handle().clone();
                // Состояние «свёрнуто» меняется редко, но Resized сыплется при перетаскивании
                // границ — реагируем только на смену состояния.
                static WAS_MIN: AtomicBool = AtomicBool::new(false);
                if WAS_MIN.swap(minimized, Ordering::SeqCst) != minimized {
                    webview_low_memory(&app, minimized);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            overview,
            status,
            log_tail,
            set_zapret_dir,
            select_strategy,
            enable,
            disable,
            set_mode,
            set_game_filter,
            set_ipset,
            strategy_command,
            list_read,
            list_write,
            test_targets,
            test_start,
            test_cancel,
            test_last,
            test_history,
            set_test_params,
            hosts_status,
            hosts_apply,
            hosts_remove,
            hosts_update,
            dns_info,
            dns_presets,
            dns_apply,
            dns_reset,
            dns_flush,
            dns_stub_status,
            dns_stub_enable,
            dns_stub_disable,
            proxy_status,
            proxy_start,
            proxy_stop,
            proxy_set_config,
            diag_run,
            lan_addresses,
            sni_defaults,
            sni_scan,
            list_presets,
            list_add_presets,
            set_autostart,
            set_close_to_tray,
            set_language,
            open_path,
            quit_app,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // Последнее окно закрыто крестиком (code = None) при «сворачивать в трей» —
            // приложение продолжает работать в трее без окна. Выход из меню трея — app.exit(0).
            if let tauri::RunEvent::ExitRequested { code: None, api, .. } = &event {
                if app.state::<AppState>().settings.lock().unwrap().close_to_tray {
                    api.prevent_exit();
                }
            }
            // Процесс winws2, запущенный нами, при выходе гасим; служба продолжает работать.
            if let tauri::RunEvent::Exit = event {
                save_settings(app);
                let st = app.state::<AppState>();
                st.cancel.store(true, Ordering::SeqCst);
                st.runner.stop_own();
                // Системный прокси и DNS адаптера возвращаем: без приложения они не работают.
                st.proxy_stop_inner();
                if st.settings.lock().unwrap().dns_stub.is_some() && winapi::is_admin() {
                    let _ = st.stub_disable();
                }
            }
        });
}
