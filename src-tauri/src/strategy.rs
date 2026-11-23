//! Разбор стратегий `general*.bat`: порт логики `service_install` из service.bat.
//! Bat-файлы не меняем, а вытаскиваем из них аргументы winws2.exe.

use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct StrategyInfo {
    /// Имя файла, например `general (ALT2).bat` — это идентификатор.
    pub file: String,
    /// Имя без расширения.
    pub name: String,
    /// Имена блоков `--name=...` (Discord Voice, Youtube…).
    pub blocks: Vec<String>,
    /// Техники из `--lua-desync=<техника>:...` по порядку, без повторов
    /// (fake, multisplit, fakedsplit…) — именно ими стратегии отличаются.
    pub methods: Vec<String>,
}

/// Значения переменных, которые bat подставляет в командную строку.
pub struct Vars {
    pub bin: String,
    pub lists: String,
    pub lua: String,
    pub game_tcp: String,
    pub game_udp: String,
}

impl Vars {
    pub fn new(dir: &Path, game_tcp: &str, game_udp: &str) -> Self {
        let with_sep = |p: PathBuf| {
            let mut s = p.to_string_lossy().into_owned();
            if !s.ends_with('\\') {
                s.push('\\');
            }
            s
        };
        Vars {
            bin: with_sep(dir.join("bin")),
            lists: with_sep(dir.join("lists")),
            lua: with_sep(dir.join("lua")),
            game_tcp: game_tcp.to_string(),
            game_udp: game_udp.to_string(),
        }
    }

    fn lookup(&self, name: &str) -> Option<&str> {
        match name.to_ascii_uppercase().as_str() {
            "BIN" => Some(&self.bin),
            "LISTS" => Some(&self.lists),
            "LUA" => Some(&self.lua),
            "GAMEFILTERTCP" => Some(&self.game_tcp),
            "GAMEFILTERUDP" => Some(&self.game_udp),
            // %GameFilter% в старых стратегиях = TCP-диапазон или 12.
            "GAMEFILTER" => Some(&self.game_tcp),
            _ => None,
        }
    }
}

/// Натуральная сортировка как в service.bat: числа дополняются нулями до 8 знаков.
fn natural_key(name: &str) -> String {
    let mut out = String::new();
    let mut digits = String::new();
    for c in name.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            if !digits.is_empty() {
                out.push_str(&format!("{:0>8}", digits));
                digits.clear();
            }
            out.push(c.to_ascii_lowercase());
        }
    }
    if !digits.is_empty() {
        out.push_str(&format!("{:0>8}", digits));
    }
    out
}

/// Список стратегий: все *.bat в корне, кроме service*.
pub fn list(dir: &Path) -> Vec<StrategyInfo> {
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| {
                    let l = n.to_ascii_lowercase();
                    l.ends_with(".bat") && !l.starts_with("service")
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort_by_key(|a| natural_key(a));
    files
        .into_iter()
        .filter_map(|file| {
            let text = crate::util::read_text(&dir.join(&file)).ok()?;
            let raw = extract_command(&text)?;
            let tokens = tokenize(&raw);
            let blocks = tokens.iter().filter_map(|t| t.strip_prefix("--name=").map(str::to_string)).collect();
            let mut methods: Vec<String> = Vec::new();
            for t in &tokens {
                if let Some(m) = t.strip_prefix("--lua-desync=").map(|v| v.split(':').next().unwrap_or(v)) {
                    if !m.is_empty() && !methods.iter().any(|x| x == m) {
                        methods.push(m.to_string());
                    }
                }
            }
            let name = file.trim_end_matches(".bat").trim_end_matches(".BAT").to_string();
            Some(StrategyInfo { file, name, blocks, methods })
        })
        .collect()
}

/// Хвост команды после `winws2.exe"` со склеенными `^`-продолжениями.
/// Возвращает None, если в файле нет запуска winws2.exe.
pub fn extract_command(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut capturing = false;
    for raw_line in text.lines() {
        // for /f "tokens=*" обрезает ведущие пробелы и пропускает пустые строки.
        let line = raw_line.trim_start().trim_end_matches(['\r', ' ', '\t']);
        if line.is_empty() {
            continue;
        }
        if !capturing {
            if line.starts_with("::") || line.to_ascii_lowercase().starts_with("rem ") {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(pos) = lower.find("winws2.exe") {
                capturing = true;
                let mut rest = &line[pos + "winws2.exe".len()..];
                rest = rest.strip_prefix('"').unwrap_or(rest);
                let (body, cont) = strip_caret(rest);
                out.push_str(body);
                out.push(' ');
                if !cont {
                    break;
                }
            }
            continue;
        }
        let (body, cont) = strip_caret(line);
        out.push_str(body);
        out.push(' ');
        if !cont {
            break;
        }
    }
    if capturing {
        Some(out.trim().to_string())
    } else {
        None
    }
}

fn strip_caret(line: &str) -> (&str, bool) {
    match line.strip_suffix('^') {
        Some(b) => (b.trim_end(), true),
        None => (line, false),
    }
}

/// Подстановка %VAR%. Неизвестные переменные возвращаются как ошибка.
pub fn expand(raw: &str, vars: &Vars) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len() * 2);
    let mut rest = raw;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(stripped) = after.strip_prefix('%') {
            out.push('%');
            rest = stripped;
            continue;
        }
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match vars.lookup(name) {
                    Some(v) => out.push_str(v),
                    None => return Err(crate::tr!("неизвестная переменная %{name}%", "unknown variable %{name}%")),
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// Разбиение командной строки на argv: пробелы вне кавычек, кавычки убираются.
pub fn tokenize(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    args.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(cur);
    }
    args
}

/// Готовые аргументы winws2.exe для стратегии.
pub fn build_args(dir: &Path, file: &str, vars: &Vars) -> Result<Vec<String>, String> {
    if file.contains(['/', '\\']) || !file.to_ascii_lowercase().ends_with(".bat") {
        return Err(crate::tr!("некорректное имя стратегии", "invalid strategy name"));
    }
    let path = dir.join(file);
    let text = crate::util::read_text(&path).map_err(|e| format!("{file}: {e}"))?;
    args_from_text(file, &text, vars)
}

/// Аргументы winws2.exe из текста bat-файла (`file` — для сообщений об ошибках).
pub fn args_from_text(file: &str, text: &str, vars: &Vars) -> Result<Vec<String>, String> {
    let raw = extract_command(text).ok_or_else(|| crate::tr!("{file}: не найден запуск winws2.exe", "{file}: winws2.exe launch not found"))?;
    let expanded = expand(&raw, vars).map_err(|e| format!("{file}: {e}"))?;
    let args = tokenize(&expanded);
    if args.is_empty() {
        return Err(crate::tr!("{file}: пустая командная строка", "{file}: empty command line"));
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "@echo off\r\nset \"BIN=%~dp0bin\\\"\r\nstart \"zapret: %~n0\" /min \"%BIN%winws2.exe\" --debug=0 --wf-tcp-out=80,443,%GameFilterTCP% ^\r\n\r\n--lua-init=@\"%LUA%blobs.lua\" ^\r\n--name=\"Discord Voice\" ^\r\n--hostlist=\"%LISTS%list general.txt\" --new ^\r\n--filter-udp=%GameFilterUDP%\r\necho after\r\n";

    fn vars() -> Vars {
        Vars {
            bin: r"C:\z\bin\".into(),
            lists: r"C:\z\lists\".into(),
            lua: r"C:\z\lua\".into(),
            game_tcp: "12".into(),
            game_udp: "1024-65535".into(),
        }
    }

    #[test]
    fn parses_sample() {
        let raw = extract_command(SAMPLE).unwrap();
        let args = tokenize(&expand(&raw, &vars()).unwrap());
        assert_eq!(
            args,
            vec![
                "--debug=0",
                "--wf-tcp-out=80,443,12",
                r"--lua-init=@C:\z\lua\blobs.lua",
                "--name=Discord Voice",
                r"--hostlist=C:\z\lists\list general.txt",
                "--new",
                "--filter-udp=1024-65535",
            ]
        );
    }

    #[test]
    fn natural_sort() {
        let mut v = vec!["general (ALT10).bat", "general (ALT2).bat", "general (ALT).bat", "general.bat"];
        v.sort_by_key(|a| natural_key(a));
        assert_eq!(v, vec!["general (ALT).bat", "general (ALT2).bat", "general (ALT10).bat", "general.bat"]);
    }

    #[test]
    fn unknown_var_is_error() {
        assert!(expand("--x=%FOO%", &vars()).is_err());
    }

    /// Сухой прогон: `cargo test dump_general -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_general() {
        let dir = Path::new(r"D:\zapret-discord-youtube");
        let args = build_args(dir, "general.bat", &Vars::new(dir, "12", "12")).unwrap();
        for a in args {
            println!("{a}");
        }
    }

    /// Прогон по реальной сборке, если она есть на диске.
    #[test]
    fn real_strategies() {
        let dir = Path::new(r"D:\zapret-discord-youtube");
        if !crate::zapret_dir::is_valid(dir) {
            eprintln!("skip: нет {dir:?}");
            return;
        }
        let list = list(dir);
        assert!(list.len() >= 10, "стратегий найдено: {}", list.len());
        let v = Vars::new(dir, "12", "12");
        for s in &list {
            let args = build_args(dir, &s.file, &v).unwrap();
            assert!(args[0].starts_with("--"), "{}: {:?}", s.file, &args[..2]);
            assert!(args.iter().any(|a| a.starts_with("--wf-")), "{}", s.file);
            assert!(!s.blocks.is_empty(), "{}: нет --name", s.file);
            assert!(!s.methods.is_empty(), "{}: нет --lua-desync", s.file);
            for a in &args {
                assert!(!a.contains('%') && !a.contains('^') && !a.contains('"'), "{}: {a}", s.file);
                if let Some(p) = a.strip_prefix("--lua-init=@") {
                    assert!(Path::new(p).is_file(), "{}: {p}", s.file);
                }
                for key in ["--hostlist=", "--ipset=", "--hostlist-exclude=", "--ipset-exclude="] {
                    if let Some(p) = a.strip_prefix(key) {
                        assert!(p.contains(r"\lists\"), "{}: {a}", s.file);
                    }
                }
            }
        }
    }
}
