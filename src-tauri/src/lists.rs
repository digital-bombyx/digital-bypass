//! Пользовательские списки: list-general-user, list-exclude-user, ipset-exclude-user.
//! Значения по умолчанию — как в :load_user_lists (файлы нельзя оставлять пустыми).

use serde::Serialize;
use std::path::{Path, PathBuf};

pub const KINDS: [&str; 3] = ["general", "exclude", "ipset-exclude"];

fn path(dir: &Path, kind: &str) -> Result<PathBuf, String> {
    let name = match kind {
        "general" => "list-general-user.txt",
        "exclude" => "list-exclude-user.txt",
        "ipset-exclude" => "ipset-exclude-user.txt",
        _ => return Err(crate::tr!("неизвестный список", "unknown list")),
    };
    Ok(dir.join("lists").join(name))
}

fn default_lines(kind: &str) -> Vec<String> {
    match kind {
        "general" => vec!["# Never leave this file empty".into(), "domain.example.abc".into()],
        "exclude" => vec!["domain.example.abc".into()],
        _ => vec![crate::ipset::PLACEHOLDER.into()],
    }
}

/// Создать отсутствующие пользовательские списки (иначе winws2 не стартует).
pub fn ensure(dir: &Path) {
    for kind in KINDS {
        if let Ok(p) = path(dir, kind) {
            if !p.exists() {
                let _ = crate::util::write_crlf(&p, &default_lines(kind));
            }
        }
    }
}

pub fn read(dir: &Path, kind: &str) -> Result<String, String> {
    let p = path(dir, kind)?;
    if !p.exists() {
        return Ok(default_lines(kind).join("\n"));
    }
    crate::util::read_text(&p).map(|t| t.replace("\r\n", "\n")).map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct SaveResult {
    /// Строки, которые не похожи на домен / IP / CIDR (сохраняются всё равно).
    pub warnings: Vec<String>,
}

pub fn write(dir: &Path, kind: &str, content: &str) -> Result<SaveResult, String> {
    let p = path(dir, kind)?;
    let mut lines: Vec<String> = content.lines().map(|l| l.trim().to_string()).collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let meaningful = lines.iter().any(|l| !l.is_empty() && !l.starts_with('#'));
    if !meaningful {
        lines.extend(default_lines(kind).into_iter().filter(|l| !l.starts_with('#')));
    }
    let warnings = lines
        .iter()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| if kind == "ipset-exclude" { !is_ip_or_cidr(l) } else { !is_domain(l) })
        .cloned()
        .collect();
    crate::util::write_crlf(&p, &lines).map_err(|e| e.to_string())?;
    Ok(SaveResult { warnings })
}

/// Тематические наборы доменов для list-general-user.txt.
/// В hostlist zapret домен покрывает и все поддомены. YouTube (list-google.txt)
/// и Discord (list-general.txt) уже есть во встроенных списках — их тут нет.
#[derive(Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub domains: &'static [&'static str],
}

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "telegram",
        name: "Telegram",
        domains: &["telegram.org", "t.me", "telegram.me", "telegram.dog", "telegra.ph", "telesco.pe", "tdesktop.com", "cdn-telegram.org"],
    },
    Preset {
        id: "meta",
        name: "Instagram / Facebook / WhatsApp",
        domains: &[
            "instagram.com", "cdninstagram.com", "facebook.com", "fb.com", "fbcdn.net", "facebook.net",
            "messenger.com", "whatsapp.com", "whatsapp.net", "threads.net",
        ],
    },
    Preset {
        id: "twitter",
        name: "X / Twitter",
        domains: &["x.com", "twitter.com", "twimg.com", "t.co"],
    },
    Preset {
        id: "roblox",
        name: "Roblox",
        domains: &["roblox.com", "rbxcdn.com", "rbx.com"],
    },
    Preset {
        id: "soundcloud",
        name: "SoundCloud",
        domains: &["soundcloud.com", "soundcloud.cloud", "sndcdn.com"],
    },
];

/// Встроенные списки сборки, которые стратегии подключают и так.
const BUILTIN: [&str; 2] = ["list-general.txt", "list-google.txt"];

fn domains_in(text: &str) -> impl Iterator<Item = String> + '_ {
    text.lines().map(|l| l.trim().to_lowercase()).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// Домены встроенных списков.
pub fn builtin_domains(dir: &Path) -> std::collections::HashSet<String> {
    BUILTIN
        .iter()
        .filter_map(|f| crate::util::read_text(&dir.join("lists").join(f)).ok())
        .flat_map(|t| domains_in(&t).collect::<Vec<_>>())
        .collect()
}

/// Все домены, которые zapret2 обходит по спискам: встроенные + list-general-user.
pub fn bypass_domains(dir: &Path) -> Vec<String> {
    let mut all = builtin_domains(dir);
    if let Ok(t) = read(dir, "general") {
        all.extend(domains_in(&t).filter(|d| d != "domain.example.abc"));
    }
    all.into_iter().collect()
}

/// Набор для интерфейса: только домены, которых ещё нет во встроенных списках.
#[derive(Serialize)]
pub struct PresetView {
    pub id: &'static str,
    pub name: &'static str,
    pub domains: Vec<&'static str>,
    /// Сколько доменов набора уже есть во встроенных списках.
    pub builtin: usize,
}

pub fn presets_for(dir: &Path) -> Vec<PresetView> {
    let b = builtin_domains(dir);
    PRESETS
        .iter()
        .map(|p| {
            let domains: Vec<&'static str> = p.domains.iter().copied().filter(|d| !b.contains(*d)).collect();
            PresetView { id: p.id, name: p.name, builtin: p.domains.len() - domains.len(), domains }
        })
        .filter(|p| !p.domains.is_empty())
        .collect()
}

/// Добавить наборы в list-general-user.txt без дублей (и без доменов встроенных
/// списков). Возвращает число новых доменов.
pub fn add_presets(dir: &Path, ids: &[String]) -> Result<usize, String> {
    let current = read(dir, "general")?;
    let mut existing: std::collections::HashSet<String> = domains_in(&current).collect();
    existing.extend(builtin_domains(dir));
    let mut add = Vec::new();
    for id in ids {
        let p = PRESETS.iter().find(|p| p.id == id).ok_or_else(|| crate::tr!("неизвестный набор: {id}", "unknown set: {id}"))?;
        let mut header = false;
        for d in p.domains {
            if existing.insert(d.to_string()) {
                if !header {
                    add.push(format!("# {}", p.name));
                    header = true;
                }
                add.push(d.to_string());
            }
        }
    }
    let added = add.iter().filter(|l| !l.starts_with('#')).count();
    if added == 0 {
        return Ok(0);
    }
    // Заглушку по умолчанию убираем — теперь в списке есть настоящие домены.
    let mut lines: Vec<String> = current.lines().map(|l| l.trim_end().to_string()).filter(|l| l.trim() != "domain.example.abc").collect();
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    lines.extend(add);
    write(dir, "general", &lines.join("\n"))?;
    Ok(added)
}

fn is_domain(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    s.contains('.')
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        })
}

fn is_ip_or_cidr(s: &str) -> bool {
    let (ip, mask) = s.split_once('/').unwrap_or((s, ""));
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    if mask.is_empty() {
        return true;
    }
    let max = if addr.is_ipv4() { 32 } else { 128 };
    mask.parse::<u8>().is_ok_and(|m| m <= max)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validators() {
        assert!(is_domain("discord.com"));
        assert!(is_domain("xn--80ak6aa92e.xn--p1ai"));
        assert!(!is_domain("localhost"));
        assert!(!is_domain("bad domain.com"));
        assert!(is_ip_or_cidr("1.2.3.0/24"));
        assert!(is_ip_or_cidr("2606:4700::/32"));
        assert!(!is_ip_or_cidr("1.2.3.0/33"));
        assert!(!is_ip_or_cidr("example.com"));
    }

    #[test]
    fn presets_valid_and_merge() {
        for p in PRESETS {
            for d in p.domains {
                assert!(is_domain(d), "{d}");
            }
        }
        let dir = std::env::temp_dir().join(format!("digital-bypass-lists-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("lists")).unwrap();
        ensure(&dir);
        // Встроенный список уже содержит t.me — его набор Telegram не добавит.
        std::fs::write(dir.join("lists").join("list-general.txt"), "t.me\r\n").unwrap();
        let tg = PRESETS.iter().find(|p| p.id == "telegram").unwrap();
        let tw = PRESETS.iter().find(|p| p.id == "twitter").unwrap();
        let view = presets_for(&dir);
        let v = view.iter().find(|p| p.id == "telegram").unwrap();
        assert_eq!((v.builtin, v.domains.len()), (1, tg.domains.len() - 1));
        let n = add_presets(&dir, &["telegram".into(), "twitter".into()]).unwrap();
        assert_eq!(n, tg.domains.len() - 1 + tw.domains.len());
        assert_eq!(add_presets(&dir, &["telegram".into()]).unwrap(), 0);
        let t = read(&dir, "general").unwrap();
        assert!(t.contains("# Telegram") && t.contains("x.com") && !t.contains("domain.example.abc"));
        assert!(!t.lines().any(|l| l == "t.me"));
        // Набор, целиком покрытый встроенными списками, не показывается.
        let all_x: String = tw.domains.iter().map(|d| format!("{d}\n")).collect();
        std::fs::write(dir.join("lists").join("list-google.txt"), all_x).unwrap();
        assert!(!presets_for(&dir).iter().any(|p| p.id == "twitter"));
        assert!(add_presets(&dir, &["nope".into()]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
