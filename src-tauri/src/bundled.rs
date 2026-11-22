//! Встроенная сборка zapret-discord-youtube. Установщик кладёт её в ресурсы
//! (src-tauri/zapret, см. scripts/sync-zapret.mjs). При старте она разворачивается
//! в папку данных приложения: туда можно писать (списки, game filter, ipset).
//!
//! При обновлении GUI обновляются bin, lua, стратегии и базовые списки. Остаются
//! нетронутыми пользовательские файлы (*-user.txt, utils\game_filter.enabled)
//! и текущий режим ipset (lists\ipset-all.txt).

use std::path::{Path, PathBuf};

const STAMP: &str = "bundle.json";

pub fn resource_root(resource_dir: &Path) -> PathBuf {
    resource_dir.join("zapret")
}

pub fn target_root(local_data: &Path) -> PathBuf {
    local_data.join("zapret")
}

/// Версия встроенной сборки из bundle.json.
pub fn version(dir: &Path) -> Option<String> {
    let text = std::fs::read(dir.join(STAMP)).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&text).ok()?;
    let ver = v.get("version")?.as_str()?;
    let commit = v.get("commit").and_then(|c| c.as_str()).unwrap_or("");
    Some(if commit.is_empty() { ver.to_string() } else { format!("{ver} @ {commit}") })
}

/// Развернуть или обновить сборку. Ok(true) — файлы обновлены.
pub fn ensure(src: &Path, dst: &Path) -> Result<bool, String> {
    let src_stamp = match std::fs::read(src.join(STAMP)) {
        Ok(b) => b,
        // В ресурсах нет сборки (например, dev без sync-zapret) — ничего не делаем.
        Err(_) => return Ok(false),
    };
    if std::fs::read(dst.join(STAMP)).ok().as_deref() == Some(src_stamp.as_slice()) && crate::zapret_dir::is_valid(dst) {
        return Ok(false);
    }
    let first_install = !crate::zapret_dir::is_valid(dst);
    let mut failed = Vec::new();
    copy_tree(src, dst, src, first_install, &mut failed);
    if !failed.is_empty() {
        let list = failed.join(", ");
        return Err(crate::tr!(
            "Встроенный zapret обновлён не полностью, файлы заняты: {list}. Выключите обход (и службу), затем перезапустите приложение.",
            "Bundled zapret was only partially updated, files are in use: {list}. Turn the bypass (and the service) off, then restart the app."
        ));
    }
    // Метку пишем последней: при сбое обновление повторится при следующем запуске.
    std::fs::write(dst.join(STAMP), src_stamp).map_err(|e| e.to_string())?;
    Ok(true)
}

fn copy_tree(dir: &Path, dst_root: &Path, src_root: &Path, first_install: bool, failed: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let path = e.path();
        let rel = path.strip_prefix(src_root).unwrap_or(&path).to_path_buf();
        let rel_s = rel.to_string_lossy().replace('/', "\\");
        if rel_s == STAMP {
            continue;
        }
        if path.is_dir() {
            if rel_s != "_service" {
                let _ = std::fs::create_dir_all(dst_root.join(&rel));
            }
            copy_tree(&path, dst_root, src_root, first_install, failed);
            continue;
        }
        // _service → .service (папки с точкой в ресурсах не держим).
        let mapped = match rel_s.strip_prefix("_service\\") {
            Some(rest) => PathBuf::from(".service").join(rest),
            None => rel.clone(),
        };
        // Текущий режим ipset пользователя не трогаем; свежий список идёт в .backup.
        if !first_install && rel_s.eq_ignore_ascii_case(r"lists\ipset-all.txt") {
            continue;
        }
        let target = dst_root.join(&mapped);
        if let Some(p) = target.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let Ok(new) = std::fs::read(&path) else {
            failed.push(rel_s);
            continue;
        };
        if std::fs::read(&target).ok().as_deref() == Some(new.as_slice()) {
            continue;
        }
        if std::fs::write(&target, &new).is_err() {
            failed.push(mapped.to_string_lossy().into_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("digital-bypass-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn mk(src: &Path, ver: &str, list: &str) {
        for d in ["bin", "lua", "lists", "_service"] {
            std::fs::create_dir_all(src.join(d)).unwrap();
        }
        std::fs::write(src.join("bin/winws2.exe"), ver).unwrap();
        std::fs::write(src.join("lua/blobs.lua"), "--").unwrap();
        std::fs::write(src.join("lists/ipset-all.txt"), list).unwrap();
        std::fs::write(src.join("lists/ipset-all.txt.backup"), format!("backup {ver}")).unwrap();
        std::fs::write(src.join("_service/version.txt"), ver).unwrap();
        std::fs::write(src.join(STAMP), format!(r#"{{"version":"{ver}","commit":"abc"}}"#)).unwrap();
    }

    /// Реальный бандл из sync-zapret: разворачивается и даёт рабочие стратегии.
    #[test]
    fn real_bundle() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("zapret");
        if !src.join(STAMP).exists() {
            return;
        }
        let dst = tmp("real");
        assert_eq!(ensure(&src, &dst), Ok(true));
        assert!(crate::zapret_dir::is_valid(&dst));
        assert!(dst.join(".service").join("hosts").is_file());
        assert!(crate::zapret_dir::version(&dst).is_some());
        let list = crate::strategy::list(&dst);
        assert!(list.len() >= 10);
        let v = crate::strategy::Vars::new(&dst, "12", "12");
        for s in &list {
            crate::strategy::build_args(&dst, &s.file, &v).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[test]
    fn install_then_update_keeps_user_state() {
        let (src, dst) = (tmp("src"), tmp("dst"));
        mk(&src, "1", "203.0.113.113/32");
        assert_eq!(ensure(&src, &dst), Ok(true));
        assert!(crate::zapret_dir::is_valid(&dst));
        assert_eq!(std::fs::read_to_string(dst.join(".service/version.txt")).unwrap(), "1");
        assert_eq!(version(&dst).as_deref(), Some("1 @ abc"));
        // Повторный запуск без изменений — ничего не делает.
        assert_eq!(ensure(&src, &dst), Ok(false));

        // Пользователь переключил ipset и завёл свой список.
        std::fs::write(dst.join("lists/ipset-all.txt"), "").unwrap();
        std::fs::write(dst.join("lists/list-general-user.txt"), "my.example.com").unwrap();

        mk(&src, "2", "203.0.113.113/32");
        assert_eq!(ensure(&src, &dst), Ok(true));
        assert_eq!(std::fs::read_to_string(dst.join("bin/winws2.exe")).unwrap(), "2");
        assert_eq!(std::fs::read_to_string(dst.join("lists/ipset-all.txt")).unwrap(), "");
        assert_eq!(std::fs::read_to_string(dst.join("lists/ipset-all.txt.backup")).unwrap(), "backup 2");
        assert_eq!(std::fs::read_to_string(dst.join("lists/list-general-user.txt")).unwrap(), "my.example.com");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }
}
