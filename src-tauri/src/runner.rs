//! Запуск winws2.exe процессом: без cmd и без консольного окна.
//! За процессом следит поток с WaitForSingleObject — без поллинга.

use serde::Serialize;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const LOG_CAP: usize = 300;

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub running: bool,
    /// off | process | service | external
    pub mode: String,
    pub strategy: Option<String>,
    pub service_installed: bool,
    pub last_error: Option<String>,
}

struct Inner {
    child: Option<Child>,
    strategy: Option<String>,
    last_error: Option<String>,
    generation: u64,
}

pub struct Runner {
    inner: Arc<Mutex<Inner>>,
    log: Arc<Mutex<VecDeque<String>>>,
    notify: Arc<OnceLock<Box<dyn Fn() + Send + Sync>>>,
}

impl Runner {
    pub fn new() -> Self {
        Runner {
            inner: Arc::new(Mutex::new(Inner { child: None, strategy: None, last_error: None, generation: 0 })),
            log: Arc::new(Mutex::new(VecDeque::new())),
            notify: Arc::new(OnceLock::new()),
        }
    }

    /// Колбэк на изменение состояния (событие в UI + обновление трея).
    pub fn set_notify(&self, f: impl Fn() + Send + Sync + 'static) {
        let _ = self.notify.set(Box::new(f));
    }

    fn fire(notify: &OnceLock<Box<dyn Fn() + Send + Sync>>) {
        if let Some(f) = notify.get() {
            f();
        }
    }

    pub fn log_tail(&self, n: usize) -> Vec<String> {
        let log = self.log.lock().unwrap();
        log.iter().skip(log.len().saturating_sub(n)).cloned().collect()
    }

    pub fn status(&self) -> Status {
        let (installed, svc_running) = crate::service::state(crate::service::NAME);
        let mut inner = self.inner.lock().unwrap();
        let own_alive = match inner.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        };
        let (running, mode, strategy) = if svc_running {
            // service.bat пишет в реестр имя без расширения.
            let s = crate::service::installed_strategy().map(|n| if n.to_ascii_lowercase().ends_with(".bat") { n } else { format!("{n}.bat") });
            (true, "service", s)
        } else if own_alive {
            (true, "process", inner.strategy.clone())
        } else if !crate::winapi::find_processes(&["winws2.exe", "winws.exe"]).is_empty() {
            (true, "external", None)
        } else {
            (false, "off", None)
        };
        Status {
            running,
            mode: mode.into(),
            strategy,
            service_installed: installed,
            last_error: inner.last_error.clone(),
        }
    }

    /// Запустить стратегию. Предыдущие winws/winws2 завершаются.
    pub fn start(&self, dir: &Path, strategy_file: &str, args: &[String]) -> Result<(), String> {
        crate::lists::ensure(dir);
        crate::addons::ensure_files(dir)?;
        self.stop_processes();
        tcp_timestamps_enable();

        let bin = dir.join("bin");
        let mut cmd = crate::util::hidden(bin.join("winws2.exe"));
        cmd.args(args).current_dir(&bin).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| crate::tr!("не удалось запустить winws2.exe: {e}", "failed to start winws2.exe: {e}"))?;

        self.log.lock().unwrap().clear();
        if let Some(out) = child.stdout.take() {
            pipe_to_log(out, self.log.clone());
        }
        if let Some(err) = child.stderr.take() {
            pipe_to_log(err, self.log.clone());
        }

        let pid = child.id();
        let generation = {
            let mut inner = self.inner.lock().unwrap();
            inner.generation += 1;
            inner.child = Some(child);
            inner.strategy = Some(strategy_file.to_string());
            inner.last_error = None;
            inner.generation
        };

        // Наблюдатель: процесс завершился сам — сохраняем ошибку и сообщаем UI.
        if let Some(waiter) = crate::winapi::ProcWait::open(pid) {
            let inner = self.inner.clone();
            let log = self.log.clone();
            let notify = self.notify.clone();
            std::thread::spawn(move || {
                waiter.wait();
                // Дать потокам дочитать вывод.
                std::thread::sleep(Duration::from_millis(150));
                {
                    let mut g = inner.lock().unwrap();
                    if g.generation == generation {
                        let code = g.child.as_mut().and_then(|c| c.try_wait().ok().flatten()).and_then(|s| s.code());
                        let tail: Vec<String> = {
                            let l = log.lock().unwrap();
                            l.iter().skip(l.len().saturating_sub(8)).cloned().collect()
                        };
                        let code = code.map(|c| crate::tr!(" (код {c})", " (code {c})")).unwrap_or_default();
                        let tail = tail.join("\n");
                        g.last_error = Some(crate::tr!("winws2 завершился{code}\n{tail}", "winws2 exited{code}\n{tail}").trim().to_string());
                        g.child = None;
                    }
                }
                Runner::fire(&notify);
            });
        }

        // Ранняя ошибка: неверные аргументы, занятый драйвер и т.п.
        std::thread::sleep(Duration::from_millis(700));
        let early = {
            let mut g = self.inner.lock().unwrap();
            match g.child.as_mut().map(|c| c.try_wait()) {
                Some(Ok(Some(_))) | None => Some(g.last_error.clone().unwrap_or_else(|| crate::tr!("winws2 сразу завершился", "winws2 exited immediately"))),
                _ => None,
            }
        };
        Runner::fire(&self.notify);
        match early {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Завершить свой процесс и любые winws/winws2 (как Stop-Zapret).
    pub fn stop_processes(&self) {
        {
            let mut g = self.inner.lock().unwrap();
            g.generation += 1;
            if let Some(mut c) = g.child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
            g.strategy = None;
        }
        crate::winapi::kill_by_name(&["winws2.exe", "winws.exe"]);
    }

    /// Завершить только свой процесс (при выходе из приложения).
    pub fn stop_own(&self) {
        let mut g = self.inner.lock().unwrap();
        g.generation += 1;
        if let Some(mut c) = g.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn stop(&self) {
        self.stop_processes();
        self.inner.lock().unwrap().last_error = None;
        Runner::fire(&self.notify);
    }

    pub fn clear_error(&self) {
        self.inner.lock().unwrap().last_error = None;
    }

    pub fn notify_changed(&self) {
        Runner::fire(&self.notify);
    }
}

fn pipe_to_log(stream: impl Read + Send + 'static, log: Arc<Mutex<VecDeque<String>>>) {
    std::thread::spawn(move || {
        let mut r = BufReader::new(stream);
        let mut buf = Vec::new();
        while r.read_until(b'\n', &mut buf).map(|n| n > 0).unwrap_or(false) {
            let line = String::from_utf8_lossy(&buf).trim_end().to_string();
            buf.clear();
            if line.is_empty() {
                continue;
            }
            let mut l = log.lock().unwrap();
            if l.len() >= LOG_CAP {
                l.pop_front();
            }
            l.push_back(line);
        }
    });
}

/// Как :tcp_enable в service.bat: zapret требует включённых TCP timestamps.
fn tcp_timestamps_enable() {
    let netsh = crate::util::system32("netsh.exe");
    let _ = crate::util::run_hidden(&netsh, &["interface", "tcp", "set", "global", "timestamps=enabled"]);
}
