//! Управление hosts. В апстриме .service\hosts лежит для ручного копирования
//! (service.bat → Update Hosts File открывает его в блокноте). Здесь записи
//! пишутся в системный hosts отдельным помеченным блоком, который можно снять.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const BEGIN: &str = "# >>> digital-bypass (managed block, do not edit)";
const END: &str = "# <<< digital-bypass";
pub const UPSTREAM_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub ip: String,
    pub host: String,
}

#[derive(Serialize)]
pub struct Group {
    pub name: String,
    pub entries: Vec<EntryState>,
}

#[derive(Serialize)]
pub struct EntryState {
    pub ip: String,
    pub host: String,
    /// Есть в нашем блоке.
    pub in_block: bool,
    /// Такая строка уже есть в hosts вне блока (скопирована вручную).
    pub manual: bool,
}

#[derive(Serialize)]
pub struct Status {
    pub source: String,
    pub groups: Vec<Group>,
    pub custom: Vec<EntryState>,
    pub block_present: bool,
    /// В блоке есть записи, которых нет в актуальном источнике, или наоборот.
    pub outdated: bool,
    pub hosts_path: String,
}

pub fn system_hosts() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Path::new(&root).join(r"System32\drivers\etc\hosts")
}

pub fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            let mut it = l.split_whitespace();
            let ip = it.next()?;
            let host = it.next()?;
            ip.parse::<std::net::IpAddr>().ok()?;
            Some(Entry { ip: ip.into(), host: host.to_ascii_lowercase() })
        })
        .collect()
}

/// Источник: кэш, скачанный с GitHub, иначе файл из сборки.
fn upstream(dir: &Path, cache: &Path) -> (String, Vec<Entry>) {
    if let Ok(t) = crate::util::read_text(cache) {
        let e = parse(&t);
        if !e.is_empty() {
            return (crate::tr!("GitHub (обновлено)", "GitHub (updated)"), e);
        }
    }
    let p = dir.join(".service").join("hosts");
    (crate::tr!("сборка (.service\\hosts)", "build (.service\\hosts)"), crate::util::read_text(&p).map(|t| parse(&t)).unwrap_or_default())
}

/// Разделить системный hosts на «наш блок» и всё остальное.
fn split(text: &str) -> (Vec<String>, Vec<Entry>, bool) {
    let mut outside = Vec::new();
    let mut block = Vec::new();
    let mut inside = false;
    let mut present = false;
    for line in text.lines() {
        let t = line.trim();
        if t == BEGIN {
            inside = true;
            present = true;
            continue;
        }
        if inside && t == END {
            inside = false;
            continue;
        }
        if inside {
            block.extend(parse(t));
        } else {
            outside.push(line.to_string());
        }
    }
    (outside, block, present)
}

fn group_name(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

pub fn status(dir: &Path, cache: &Path, custom: &[Entry]) -> Status {
    let (source, up) = upstream(dir, cache);
    let hosts = system_hosts();
    let text = crate::util::read_text(&hosts).unwrap_or_default();
    let (outside, block, present) = split(&text);
    let manual: Vec<Entry> = parse(&outside.join("\n"));
    let state = |e: &Entry| EntryState {
        ip: e.ip.clone(),
        host: e.host.clone(),
        in_block: block.contains(e),
        manual: manual.contains(e),
    };
    let mut groups: BTreeMap<String, Vec<EntryState>> = BTreeMap::new();
    for e in &up {
        groups.entry(group_name(&e.host)).or_default().push(state(e));
    }
    // Устарело: в блоке есть upstream-хосты с другим IP, или запись, которой больше нет.
    let outdated = present
        && block.iter().any(|b| !up.contains(b) && !custom.contains(b))
        || up.iter().any(|e| block.iter().any(|b| b.host == e.host && b.ip != e.ip));
    Status {
        source,
        groups: groups.into_iter().map(|(name, entries)| Group { name, entries }).collect(),
        custom: custom.iter().map(state).collect(),
        block_present: present,
        outdated,
        hosts_path: hosts.to_string_lossy().into_owned(),
    }
}

/// Записать блок (пустой список — удалить блок). Перед записью — бэкап.
pub fn apply(entries: &[Entry]) -> Result<(), String> {
    let hosts = system_hosts();
    let text = crate::util::read_text(&hosts).unwrap_or_default();
    let backup = hosts.with_file_name("hosts.digital-bypass.bak");
    std::fs::write(&backup, text.as_bytes()).map_err(|e| crate::tr!("бэкап hosts: {e}", "hosts backup: {e}"))?;
    let (mut outside, _, _) = split(&text);
    while outside.last().is_some_and(|l| l.trim().is_empty()) {
        outside.pop();
    }
    if !entries.is_empty() {
        let mut uniq: Vec<&Entry> = Vec::new();
        for e in entries {
            if !uniq.contains(&e) {
                uniq.push(e);
            }
        }
        outside.push(String::new());
        outside.push(BEGIN.into());
        outside.extend(uniq.iter().map(|e| format!("{} {}", e.ip, e.host)));
        outside.push(END.into());
    }
    crate::util::write_crlf(&hosts, &outside).map_err(|e| crate::tr!("запись hosts: {e} (нужны права администратора; файл мог заблокировать антивирус)", "writing hosts: {e} (admin rights required; the file may be locked by antivirus)"))?;
    let _ = crate::util::run_hidden(&crate::util::system32("ipconfig.exe"), &["/flushdns"]);
    Ok(())
}

/// Скачать актуальный файл с GitHub в кэш приложения (`proxy` — запасной путь).
pub fn update_upstream(cache: &Path, proxy: Option<u16>) -> Result<usize, String> {
    let url = format!("{UPSTREAM_URL}?t={}", crate::util::now_secs());
    let text = crate::util::fetch("hosts Flowseal", &url, 15, proxy)?;
    let n = parse(&text).len();
    if n == 0 {
        return Err(crate::tr!("скачанный файл пуст или некорректен", "downloaded file is empty or invalid"));
    }
    if let Some(p) = cache.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    std::fs::write(cache, text).map_err(|e| e.to_string())?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_and_parse() {
        let text = format!("127.0.0.1 localhost\n\n{BEGIN}\n1.2.3.4 a.example.com\n{END}\n# c\n");
        let (outside, block, present) = split(&text);
        assert!(present);
        assert_eq!(block, vec![Entry { ip: "1.2.3.4".into(), host: "a.example.com".into() }]);
        assert_eq!(outside, vec!["127.0.0.1 localhost", "", "# c"]);
        assert_eq!(group_name("cdn.discordapp.com"), "discordapp.com");
        assert_eq!(parse("2606:50c0:8000::154 objects.githubusercontent.com").len(), 1);
        assert!(parse("garbage line").is_empty());
    }
}
