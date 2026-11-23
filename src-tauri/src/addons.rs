//! Дополнения к стратегиям zapret2 из официальной сборки bol-van
//! (zapret-win-bundle): автопереключение стратегии (`circular` из
//! zapret-auto.lua), разблокировка WireGuard, экономный перехват UDP
//! фильтрами WinDivert в ядре и скрытие WinDivert от античитов.
//!
//! Файлы встроены в exe: `npm run sync-zapret` пересоздаёт папку сборки,
//! поэтому они пишутся в папку zapret при запуске (`ensure_files`).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const AUTO_LUA: &str = include_str!("../addons/zapret-auto.lua");
const F_QUIC: &str = include_str!("../addons/windivert_part.quic_initial_ietf.txt");
const F_STUN: &str = include_str!("../addons/windivert_part.stun.txt");
const F_DISCORD: &str = include_str!("../addons/windivert_part.discord_media.txt");
const F_WG: &str = include_str!("../addons/windivert_part.wireguard.txt");
/// Входящие RST — для детектора сбоев `circular` (без перехвата всего входящего потока).
const F_RST_IN: &str = "inbound and tcp and tcp.Rst and (tcp.SrcPort == 443 or tcp.SrcPort == 80)";
/// Копия WinDivert64.sys под именем службы «Monkey» и пропатченная WinDivert.dll.
const MONKEY_SYS: &[u8] = include_bytes!("../addons/Monkey64.sys");
const MONKEY_DLL: &[u8] = include_bytes!("../addons/WinDivert-monkey.dll");
/// Фейки коллекции kinlay0, которых нет в сборке Flowseal.
const BLOBS_EXTRA: &str = include_str!("../addons/blobs-extra.lua");
const BLOB_FIRPO: &[u8] = include_bytes!("../addons/tls_clienthello_firpo_ru.bin");
const BLOB_RETEXT: &[u8] = include_bytes!("../addons/tls_clienthello_retext_ai.bin");

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Addons {
    /// Фейк перед рукопожатием WireGuard (на любых портах).
    pub wireguard: bool,
    /// QUIC, STUN и Discord перехватываются фильтрами ядра, а не целыми портами.
    pub lean_udp: bool,
    /// WinDivert под другим именем службы и файла (для античитов).
    pub hide_windivert: bool,
}

fn write_if_changed(p: &Path, data: &[u8]) -> std::io::Result<()> {
    if std::fs::read(p).ok().as_deref() == Some(data) {
        return Ok(());
    }
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(p, data)
}

fn filters(dir: &Path) -> PathBuf {
    dir.join("windivert.filter")
}

/// Положить файлы дополнений в папку сборки zapret.
pub fn ensure_files(dir: &Path) -> Result<(), String> {
    let f = filters(dir);
    for (name, body) in [
        ("windivert_part.quic_initial_ietf.txt", F_QUIC),
        ("windivert_part.stun.txt", F_STUN),
        ("windivert_part.discord_media.txt", F_DISCORD),
        ("windivert_part.wireguard.txt", F_WG),
        ("windivert_part.rst_in.txt", F_RST_IN),
    ] {
        write_if_changed(&f.join(name), body.as_bytes()).map_err(|e| format!("{name}: {e}"))?;
    }
    write_if_changed(&dir.join("lua").join("zapret-auto.lua"), AUTO_LUA.as_bytes()).map_err(|e| format!("zapret-auto.lua: {e}"))?;
    write_if_changed(&dir.join("lua").join("blobs-extra.lua"), BLOBS_EXTRA.as_bytes()).map_err(|e| format!("blobs-extra.lua: {e}"))?;
    write_if_changed(&dir.join("bin").join("tls_clienthello_firpo_ru.bin"), BLOB_FIRPO).map_err(|e| e.to_string())?;
    write_if_changed(&dir.join("bin").join("tls_clienthello_retext_ai.bin"), BLOB_RETEXT).map_err(|e| e.to_string())?;
    // Коллекция стратегий kinlay0 — рядом со стратегиями сборки.
    for (name, text) in crate::addons_strats::STRATS {
        write_if_changed(&dir.join(name), text.as_bytes()).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

fn raw_part(dir: &Path, name: &str) -> String {
    format!("--wf-raw-part=@{}", filters(dir).join(format!("windivert_part.{name}.txt")).display())
}

/// Индекс первого профиля (дальше идут только опции профилей).
fn first_profile(args: &[String]) -> usize {
    args.iter()
        .position(|a| a.starts_with("--name=") || a.starts_with("--filter-") || a.starts_with("--hostlist") || a.starts_with("--ipset") || a.starts_with("--payload=") || a.starts_with("--lua-desync="))
        .unwrap_or(args.len())
}

/// Добавить глобальную опцию перед первым профилем.
fn insert_global(args: &mut Vec<String>, opt: String) {
    let i = first_profile(args);
    args.insert(i, opt);
}

/// Применить дополнения к аргументам winws2.
pub fn apply(args: &mut Vec<String>, dir: &Path, a: &Addons) {
    if a.lean_udp {
        // QUIC (443) и голос Discord — только пакеты, которые нужны профилям:
        // QUIC Initial, STUN, обнаружение адреса Discord. Остальной поток
        // (видео по QUIC, сам голос) в winws2 больше не перенаправляется.
        if let Some(i) = args.iter().position(|t| t.starts_with("--wf-udp-out=")) {
            let ports: Vec<String> = args[i]["--wf-udp-out=".len()..]
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty() && !["443", "19294-19344", "50000-50100", "50000-50099"].contains(&p.as_str()))
                .collect();
            if ports.is_empty() {
                args.remove(i);
            } else {
                args[i] = format!("--wf-udp-out={}", ports.join(","));
            }
            for name in ["quic_initial_ietf", "stun", "discord_media"] {
                insert_global(args, raw_part(dir, name));
            }
        }
    }
    if a.wireguard {
        insert_global(args, raw_part(dir, "wireguard"));
        // Свой профиль первым: профили проверяются по порядку.
        let i = first_profile(args);
        let profile = [
            "--name=WireGuard",
            "--filter-l7=wireguard",
            "--payload=wireguard_initiation,wireguard_cookie",
            "--lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=2",
            "--new",
        ];
        for (k, t) in profile.iter().enumerate() {
            args.insert(i + k, t.to_string());
        }
    }
}

// ---------- скрытие WinDivert ----------

fn sc(args: &[&str]) {
    let _ = crate::util::run_hidden(&crate::util::system32("sc.exe"), args);
}

/// Включено ли скрытие (в bin лежит пропатченная DLL).
pub fn hidden(dir: &Path) -> bool {
    std::fs::read(dir.join("bin").join("WinDivert.dll")).ok().as_deref() == Some(MONKEY_DLL)
}

/// Поставить драйвер «Monkey» вместо службы «WinDivert». winws2 должен быть остановлен.
pub fn hide_on(dir: &Path) -> Result<(), String> {
    let bin = dir.join("bin");
    sc(&["stop", "windivert"]);
    sc(&["delete", "windivert"]);
    let dll = bin.join("WinDivert.dll");
    let orig = bin.join("WinDivert.dll.orig");
    if !hidden(dir) && !orig.exists() {
        std::fs::copy(&dll, &orig).map_err(|e| format!("WinDivert.dll: {e}"))?;
    }
    write_if_changed(&bin.join("Monkey64.sys"), MONKEY_SYS).map_err(|e| format!("Monkey64.sys: {e}"))?;
    write_if_changed(&dll, MONKEY_DLL).map_err(|e| tr_busy(&e))
}

/// Вернуть обычный WinDivert. winws2 должен быть остановлен.
pub fn hide_off(dir: &Path) -> Result<(), String> {
    let bin = dir.join("bin");
    sc(&["stop", "monkey"]);
    sc(&["delete", "monkey"]);
    let orig = bin.join("WinDivert.dll.orig");
    if orig.exists() {
        std::fs::copy(&orig, bin.join("WinDivert.dll")).map_err(|e| tr_busy(&e))?;
        let _ = std::fs::remove_file(&orig);
    }
    let _ = std::fs::remove_file(bin.join("Monkey64.sys"));
    Ok(())
}

fn tr_busy(e: &std::io::Error) -> String {
    crate::tr!("WinDivert.dll занята ({e}) — выключите обход и службу zapret", "WinDivert.dll is in use ({e}) — turn the bypass and the zapret service off")
}

// ---------- авто-стратегия (circular) ----------

/// Файл собранной авто-стратегии.
pub const ROTATE_FILE: &str = "general (AUTO ROTATE).bat";

/// Профиль bat-файла: имя (`--name=`) и строки от него до следующего профиля.
struct Profile {
    name: String,
    start: usize,
    end: usize,
}

fn profiles(lines: &[&str]) -> Vec<Profile> {
    let mut out: Vec<Profile> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if let Some(rest) = l.trim().strip_prefix("--name=") {
            let name = rest.trim_end_matches('^').trim().trim_matches('"').to_string();
            if let Some(last) = out.last_mut() {
                last.end = i;
            }
            out.push(Profile { name, start: i, end: lines.len() });
        }
    }
    out
}

/// Секции профиля: `--payload=X` и действия после неё (до следующего `--payload`).
/// Действия до первого `--payload` — в секции с пустым именем.
fn sections(lines: &[&str], p: &Profile) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = vec![(String::new(), Vec::new())];
    for t in lines[p.start..p.end].iter().flat_map(|l| l.split_whitespace()) {
        if let Some(v) = t.strip_prefix("--payload=") {
            out.push((v.to_string(), Vec::new()));
        } else if let Some(d) = t.strip_prefix("--lua-desync=") {
            out.last_mut().unwrap().1.push(d.to_string());
        }
    }
    out.retain(|(n, d)| !n.is_empty() || !d.is_empty());
    out
}

/// Профиль по TCP: есть `--filter-tcp=` и нет `--filter-udp=`.
fn tcp_profile(lines: &[&str], p: &Profile) -> bool {
    let body = lines[p.start..p.end].join(" ");
    body.contains("--filter-tcp=") && !body.contains("--filter-udp=") && !body.contains("--filter-l7=discord")
}

/// Действия секции ClientHello (её и переключаем).
fn tls_chain(secs: &[(String, Vec<String>)]) -> Option<Vec<String>> {
    secs.iter().find(|(n, d)| n.split(',').any(|x| x == "tls_client_hello") && !d.is_empty()).map(|(_, d)| d.clone())
}

/// Собрать авто-стратегию: основа — первая из `texts` (лучшая), а в каждом её
/// TCP-профиле действия для ClientHello других стратегий с тем же `--name`
/// становятся запасными вариантами `circular`: winws2 сам переходит к
/// следующему для сайта, на котором текущий даёт сбои (RST от DPI,
/// ретрансмиссии). Остальные секции профиля (например, `http_req`) и
/// остальные профили остаются как в основе. Возвращает текст bat-файла или
/// None, если объединять нечего.
pub fn build_rotate(texts: &[(String, String)]) -> Option<String> {
    let (base_name, base) = texts.first()?;
    let lines: Vec<&str> = base.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let others: Vec<(Vec<&str>, Vec<Profile>)> = texts[1..]
        .iter()
        .map(|(_, t)| {
            let ls: Vec<&str> = t.split('\n').map(|l| l.trim_end_matches('\r')).collect();
            let ps = profiles(&ls);
            (ls, ps)
        })
        .collect();
    let mut out: Vec<String> = Vec::new();
    let mut merged = 0;
    let mut cursor = 0;
    for p in profiles(&lines) {
        // Только профили, которые заканчиваются --new: в последнем строка без «^».
        let ends_new = lines[p.start..p.end].iter().any(|l| l.split_whitespace().any(|t| t == "--new"));
        if !tcp_profile(&lines, &p) || !ends_new {
            continue;
        }
        let secs = sections(&lines, &p);
        let Some(own) = tls_chain(&secs) else { continue };
        let mut chains: Vec<Vec<String>> = vec![own];
        for (ls, ps) in &others {
            if let Some(q) = ps.iter().find(|q| q.name == p.name) {
                if let Some(c) = tls_chain(&sections(ls, q)) {
                    if !chains.contains(&c) {
                        chains.push(c);
                    }
                }
            }
        }
        if chains.len() < 2 {
            continue;
        }
        merged += 1;
        out.extend(lines[cursor..p.start].iter().map(|s| s.to_string()));
        // Заголовок профиля: всё, кроме действий, секций и --new.
        for l in &lines[p.start..p.end] {
            let kept: Vec<&str> =
                l.split_whitespace().filter(|t| !t.starts_with("--lua-desync=") && !t.starts_with("--payload=") && *t != "--new").collect();
            if kept.iter().all(|t| *t == "^") {
                continue;
            }
            let mut line = kept.join(" ");
            if !line.ends_with('^') {
                line.push_str(" ^");
            }
            out.push(line);
        }
        // Секция ClientHello с переключением, затем остальные секции основы.
        let tls_name = secs.iter().find(|(n, _)| n.split(',').any(|x| x == "tls_client_hello")).map(|(n, _)| n.clone()).unwrap_or_default();
        out.push(format!("--payload={tls_name} ^"));
        out.push("--in-range=-s34228 ^".into());
        out.push("--lua-desync=circular:fails=2:time=60 ^".into());
        for (k, c) in chains.iter().enumerate() {
            for d in c {
                out.push(format!("--lua-desync={d}:strategy={} ^", k + 1));
            }
        }
        for (n, ds) in secs.iter().filter(|(n, _)| *n != tls_name) {
            if !n.is_empty() {
                out.push(format!("--payload={n} ^"));
            }
            for d in ds {
                out.push(format!("--lua-desync={d} ^"));
            }
        }
        out.push("--new ^".into());
        out.push(String::new());
        cursor = p.end;
    }
    if merged == 0 {
        return None;
    }
    out.extend(lines[cursor..].iter().map(|s| s.to_string()));
    let mut text = out.join("\r\n");
    // zapret-auto.lua (circular) и перехват входящих RST.
    text = text.replacen(
        "--lua-init=@\"%LUA%zapret-antidpi.lua\" ^",
        "--lua-init=@\"%LUA%zapret-antidpi.lua\" ^\r\n--lua-init=@\"%LUA%zapret-auto.lua\" ^\r\n--wf-raw-part=@\"%BIN%..\\windivert.filter\\windivert_part.rst_in.txt\" ^",
        1,
    );
    let sources: Vec<&str> = texts.iter().map(|(n, _)| n.as_str()).collect();
    let note = format!(":: digital-bypass auto-rotate: base \"{base_name}\", alternatives from {}\r\n", sources[1..].join(", "));
    Some(match text.find('\n') {
        Some(i) => format!("{}{note}{}", &text[..=i], &text[i + 1..]),
        None => format!("{note}{text}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bat(tls: &str) -> String {
        format!(
            "@echo off\r\nset \"LUA=%~dp0lua\\\"\r\nstart \"z\" /min \"%BIN%winws2.exe\" --wf-tcp-out=80,443 --wf-udp-out=443,19294-19344,50000-50100,12 ^\r\n--lua-init=@\"%LUA%zapret-lib.lua\" ^\r\n--lua-init=@\"%LUA%zapret-antidpi.lua\" ^\r\n\r\n--name=\"Quic\" ^\r\n--filter-udp=443 ^\r\n--lua-desync=fake:blob=quic_google:repeats=6 ^\r\n--new ^\r\n\r\n--name=\"General\" ^\r\n--filter-tcp=443 ^\r\n--hostlist=\"%LISTS%list general.txt\" ^\r\n--payload=tls_client_hello ^\r\n{tls} ^\r\n--new ^\r\n\r\n--name=\"Last\" ^\r\n--filter-tcp=80 ^\r\n--lua-desync=multisplit:pos=2\r\n"
        )
    }

    #[test]
    fn rotate_merges_same_profiles() {
        let a = bat("--lua-desync=fake:blob=tls_google:repeats=6 --lua-desync=multisplit:pos=1");
        let b = bat("--lua-desync=multidisorder:pos=midsld");
        let c = bat("--lua-desync=fake:blob=tls_google:repeats=6 --lua-desync=multisplit:pos=1");
        let t = build_rotate(&[("a.bat".into(), a), ("b.bat".into(), b), ("c.bat".into(), c)]).unwrap();
        let vars = crate::strategy::Vars { bin: r"C:\z\bin\".into(), lists: r"C:\z\lists\".into(), lua: r"C:\z\lua\".into(), game_tcp: "12".into(), game_udp: "12".into() };
        let args = crate::strategy::args_from_text("r.bat", &t, &vars).unwrap();
        let s = args.join(" ");
        assert!(s.contains("--lua-init=@C:\\z\\lua\\zapret-auto.lua"), "{s}");
        assert!(s.contains("--lua-desync=circular:fails=2:time=60"));
        assert!(s.contains("--lua-desync=fake:blob=tls_google:repeats=6:strategy=1 --lua-desync=multisplit:pos=1:strategy=1 --lua-desync=multidisorder:pos=midsld:strategy=2"), "{s}");
        // Повтор (c) не добавился, QUIC не тронут, последний профиль без --new тоже не тронут (у всех одинаковый).
        assert!(!s.contains("strategy=3"));
        assert!(s.contains("--lua-desync=fake:blob=quic_google:repeats=6 --new"));
        assert!(s.contains("--hostlist=%LISTS%list general.txt") || s.contains("list general.txt"));
        assert_eq!(args.iter().filter(|a| *a == "--new").count(), 2);
    }

    /// Коллекция kinlay0: каждая стратегия разбирается, а все фейки известны
    /// (из blobs.lua сборки или blobs-extra.lua).
    #[test]
    fn kinlay_strategies_parse() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("zapret");
        let known = {
            let mut s = crate::util::read_text(&dir.join("lua").join("blobs.lua")).unwrap_or_default();
            s.push_str(BLOBS_EXTRA);
            s
        };
        let vars = crate::strategy::Vars::new(&dir, "12", "12");
        assert!(crate::addons_strats::STRATS.len() >= 30);
        for (name, text) in crate::addons_strats::STRATS {
            let args = crate::strategy::args_from_text(name, text, &vars).unwrap();
            for a in args.iter().filter(|a| a.starts_with("--lua-desync=")) {
                for p in a.split(':') {
                    if let Some(b) = p.strip_prefix("blob=").or_else(|| p.strip_prefix("seqovl_pattern=")) {
                        if b.starts_with("0x") || b == "ch_clone" {
                            continue;
                        }
                        assert!(known.contains(&format!("{b} ")) || known.contains(&format!("{b}\t")) || known.contains(&format!("{b}=")), "{name}: blob {b}");
                    }
                }
            }
        }
    }

    /// Реальная сборка: авто-стратегия из лучших разбирается; печать результата.
    #[test]
    fn real_bundle_rotate() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("zapret");
        let files = ["general (ALT4).bat", "general (EXP).bat", "general (ALT).bat", "general (ALT10).bat"];
        let texts: Vec<(String, String)> = files.iter().filter_map(|f| crate::util::read_text(&dir.join(f)).ok().map(|t| (f.to_string(), t))).collect();
        if texts.len() < 2 {
            return;
        }
        let t = build_rotate(&texts).expect("something to merge");
        let vars = crate::strategy::Vars::new(&dir, "12", "12");
        let args = crate::strategy::args_from_text("r.bat", &t, &vars).unwrap();
        let n = args.iter().filter(|a| a.starts_with("--lua-desync=circular")).count();
        assert!(n >= 1);
        if std::env::var("SHOW").is_ok() {
            println!("{t}");
        }
    }

    #[test]
    fn rotate_needs_alternatives() {
        let a = bat("--lua-desync=multisplit:pos=1");
        assert!(build_rotate(&[("a.bat".into(), a.clone()), ("b.bat".into(), a)]).is_none());
    }

    #[test]
    fn addons_edit_args() {
        let dir = Path::new(r"C:\z");
        let base: Vec<String> = ["--wf-tcp-out=80,443", "--wf-udp-out=443,19294-19344,50000-50100,12", "--lua-init=@x", "--name=Q", "--filter-udp=443", "--lua-desync=fake", "--new", "--name=T", "--filter-tcp=443"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut a = base.clone();
        apply(&mut a, dir, &Addons { lean_udp: true, ..Default::default() });
        assert!(a.contains(&"--wf-udp-out=12".to_string()));
        assert_eq!(a.iter().filter(|t| t.starts_with("--wf-raw-part=")).count(), 3);
        assert!(a.iter().position(|t| t.starts_with("--wf-raw-part=")).unwrap() < a.iter().position(|t| t == "--name=Q").unwrap());
        let mut w = base.clone();
        apply(&mut w, dir, &Addons { wireguard: true, ..Default::default() });
        let i = w.iter().position(|t| t == "--name=WireGuard").unwrap();
        assert!(i < w.iter().position(|t| t == "--name=Q").unwrap());
        assert_eq!(w[i + 4], "--new");
        let mut n = base.clone();
        apply(&mut n, dir, &Addons::default());
        assert_eq!(n, base);
    }
}
