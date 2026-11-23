use std::path::Path;
use std::process::{Command, Output};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// CREATE_NO_WINDOW: дочерние консольные процессы без мигающих окон.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Команда без консольного окна.
pub fn hidden(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Запустить скрытую команду и вернуть вывод.
pub fn run_hidden(program: &str, args: &[&str]) -> std::io::Result<Output> {
    hidden(program).args(args).output()
}

/// Путь к системному exe (System32), чтобы не зависеть от PATH.
pub fn system32(exe: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let p = Path::new(&root).join("System32").join(exe);
    if p.is_file() {
        p.to_string_lossy().into_owned()
    } else {
        exe.to_string()
    }
}

/// Прочитать текстовый файл, терпимо к BOM и не-UTF8.
pub fn read_text(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// Запись с CRLF, как пишут bat-скрипты.
pub fn write_crlf(path: &Path, lines: &[String]) -> std::io::Result<()> {
    let mut s = String::new();
    for l in lines {
        s.push_str(l);
        s.push_str("\r\n");
    }
    std::fs::write(path, s)
}

/// Почему не скачался внешний источник — по коду выхода curl и HTTP-статусу.
pub fn fetch_reason(curl_code: i32, http: u16, timeout: u32) -> String {
    match (curl_code, http) {
        (_, 404 | 410) => crate::tr!(
            "файла больше нет (HTTP {http}) — источник переехал или удалён, нужна новая версия приложения",
            "the file is gone (HTTP {http}) — the source moved or was deleted, a newer app version is needed"
        ),
        (_, 429) => crate::tr!("слишком много запросов (HTTP 429) — попробуйте позже", "too many requests (HTTP 429) — try later"),
        (_, h) if h >= 400 => crate::tr!("сервер ответил HTTP {h}", "the server answered HTTP {h}"),
        (6, _) => crate::tr!("имя сервера не найдено (DNS) — нет интернета или DNS подменён", "server name not found (DNS) — no internet or DNS is spoofed"),
        (7, _) => crate::tr!("сервер не принимает соединение — адрес заблокирован или недоступен", "the server refuses the connection — the address is blocked or down"),
        (28, _) => crate::tr!("нет ответа за {timeout} с — источник, похоже, заблокирован", "no answer in {timeout} s — the source seems blocked"),
        (35 | 52 | 56, _) => crate::tr!("соединение оборвано — похоже на блокировку по DPI", "the connection was cut — looks like DPI blocking"),
        (60, _) => crate::tr!("чужой сертификат — ответ подменён (провайдер или антивирус)", "a foreign certificate — the answer is spoofed (ISP or antivirus)"),
        (c, _) => format!("curl {c}"),
    }
}

/// Скачать внешний источник (curl.exe). Не вышло напрямую и задан `proxy` —
/// повтор через прокси-обходчик. Ошибка называет источник, адрес и причину.
pub fn fetch(name: &str, url: &str, timeout: u32, proxy: Option<u16>) -> Result<String, String> {
    let host = url.split("://").nth(1).and_then(|r| r.split(['/', '?']).next()).unwrap_or(url).to_string();
    let mut reasons = Vec::new();
    let routes: Vec<Option<u16>> = std::iter::once(None).chain(proxy.map(Some)).collect();
    for via in routes {
        let mut cmd = hidden(system32("curl.exe"));
        cmd.args(["-sSL", "-m", &timeout.to_string(), "-w", "\n%{http_code}"]);
        if let Some(p) = via {
            cmd.args(["-x", &format!("http://127.0.0.1:{p}")]);
        }
        let out = cmd.arg(url).output().map_err(|e| format!("curl.exe: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (body, code) = text.rsplit_once('\n').unwrap_or(("", text.as_str()));
        let http: u16 = code.trim().parse().unwrap_or(0);
        if out.status.success() && (200..300).contains(&http) {
            return Ok(body.to_string());
        }
        let reason = fetch_reason(out.status.code().unwrap_or(-1), http, timeout);
        reasons.push(if via.is_some() { crate::tr!("через прокси-обходчик: {reason}", "through the bypass proxy: {reason}") } else { reason });
    }
    let why = reasons.join("; ");
    Err(crate::tr!("источник недоступен: {name} ({host}) — {why}", "source unavailable: {name} ({host}) — {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_reasons() {
        assert!(fetch_reason(22, 404, 15).contains("404"));
        assert!(fetch_reason(28, 0, 15).contains("15"));
        assert!(fetch_reason(6, 0, 15).contains("DNS"));
        assert!(fetch_reason(35, 0, 15).contains("DPI"));
        assert_eq!(fetch_reason(99, 0, 15), "curl 99");
    }

    /// `cargo test live_fetch -- --ignored --nocapture` — сеть.
    #[test]
    #[ignore]
    fn live_fetch() {
        let e = fetch("test", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_tested.txt", 15, None).unwrap_err();
        println!("{e}");
        assert!(e.contains("404") && e.contains("raw.githubusercontent.com"));
        // Причина зависит от сети: часть роутеров отвечает адресом даже на несуществующие имена.
        let e = fetch("test", "https://nonexistent.invalid/x", 5, None).unwrap_err();
        println!("{e}");
        assert!(e.contains("nonexistent.invalid") && !e.ends_with("— "));
        assert!(fetch("test", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/README.md", 15, None).unwrap().contains("Tor"));
    }
}

/// Секунды Unix-времени.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
