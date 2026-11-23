use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub zapret_dir: Option<String>,
    /// Выбранная стратегия (имя bat-файла).
    pub strategy: Option<String>,
    /// Обход был включён при выходе — включить снова при старте.
    pub last_enabled: bool,
    /// process | service
    pub mode: String,
    pub close_to_tray: bool,
    pub test_timeout: u32,
    pub test_parallel: usize,
    pub hosts_custom: Vec<crate::hosts::Entry>,
    /// ru | en
    pub language: String,
    /// Локальный прокси-обходчик.
    pub proxy: crate::proxy::Config,
    /// Прокси был включён при выходе — включить при старте.
    pub proxy_enabled: bool,
    /// Системный прокси до нашего — пока наш прописан в Windows.
    pub proxy_prev: Option<crate::proxy::SystemProxy>,
    /// Активный локальный DoH-резолвер (пока он прописан на адаптере).
    pub dns_stub: Option<crate::dns::StubConfig>,
    /// Размер и положение окна (физические пиксели) — восстанавливаются при запуске.
    pub window: Option<WindowGeom>,
    /// Telegram-прокси (MTProto → WebSocket).
    pub tg: crate::telegram::Config,
    /// Включение по сети.
    pub net: crate::netrules::NetRules,
    /// MCP-сервер для ИИ-ассистентов.
    pub mcp: crate::mcp::Settings,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct WindowGeom {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub maximized: bool,
}

impl WindowGeom {
    /// Окно видно хотя бы на одном мониторе (заголовок в пределах экрана).
    /// Мониторы — (x, y, ширина, высота) в физических пикселях.
    pub fn visible_on(&self, monitors: &[(i32, i32, u32, u32)]) -> bool {
        let (px, py) = (self.x + 60, self.y + 12);
        self.width >= 200
            && self.height >= 150
            && monitors.iter().any(|&(mx, my, mw, mh)| px >= mx && py >= my && px < mx + mw as i32 && py < my + mh as i32)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            zapret_dir: None,
            strategy: None,
            last_enabled: false,
            mode: "process".into(),
            close_to_tray: true,
            test_timeout: 4,
            test_parallel: 16,
            hosts_custom: vec![],
            language: "ru".into(),
            proxy: Default::default(),
            proxy_enabled: false,
            proxy_prev: None,
            dns_stub: None,
            window: None,
            tg: Default::default(),
            net: Default::default(),
            mcp: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_on_screen() {
        let mons = [(0, 0, 1920, 1080), (1920, 0, 2560, 1440)];
        let g = |x, y| WindowGeom { x, y, width: 1040, height: 680, maximized: false };
        assert!(g(100, 100).visible_on(&mons));
        assert!(g(3000, 200).visible_on(&mons));
        // Монитор отключили — окно осталось за пределами.
        assert!(!g(5000, 100).visible_on(&mons));
        assert!(!g(-1500, 100).visible_on(&mons));
        assert!(!WindowGeom { width: 10, ..g(100, 100) }.visible_on(&mons));
    }
}

pub fn path(config_dir: &Path) -> PathBuf {
    config_dir.join("settings.json")
}

pub fn load(config_dir: &Path) -> Settings {
    let mut s: Settings = std::fs::read(path(config_dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    s.proxy.normalize();
    if s.mcp.token.is_empty() {
        s.mcp.token = crate::mcp::new_token();
        save(config_dir, &s);
    }
    // Секрет Telegram-прокси создаётся один раз и дальше не меняется сам.
    if crate::telegram::parse_secret(&s.tg.secret).is_err() {
        s.tg.secret = crate::telegram::new_secret();
        save(config_dir, &s);
    }
    s
}

pub fn save(config_dir: &Path, s: &Settings) {
    let _ = std::fs::create_dir_all(config_dir);
    if let Ok(json) = serde_json::to_vec_pretty(s) {
        let tmp = path(config_dir).with_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, path(config_dir));
        }
    }
}
