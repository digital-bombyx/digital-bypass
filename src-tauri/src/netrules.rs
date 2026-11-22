//! Включение по сети (как `--ssid-filter` / `--nlm-filter` в winws): прокси
//! и zapret2 работают только в выбранных сетях или везде, кроме них.
//!
//! Сеть узнаётся по имени профиля Windows (для Wi-Fi это имя сети, SSID) —
//! без прав на геолокацию, которые в Windows 11 нужны `netsh wlan`. Имена
//! перечитываются только при смене подключений (адреса адаптеров с шлюзом).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NetRules {
    pub enabled: bool,
    /// only — работать только в этих сетях; except — везде, кроме них.
    pub mode: String,
    pub networks: Vec<String>,
    /// К чему применять.
    pub zapret: bool,
    pub proxy: bool,
}

impl Default for NetRules {
    fn default() -> Self {
        NetRules { enabled: false, mode: "except".into(), networks: Vec::new(), zapret: true, proxy: true }
    }
}

impl NetRules {
    /// Можно ли работать при текущих сетях `current`.
    pub fn allowed(&self, current: &[String]) -> bool {
        let list: Vec<&str> = self.networks.iter().map(|n| n.trim()).filter(|n| !n.is_empty()).collect();
        if !self.enabled || list.is_empty() {
            return true;
        }
        let hit = current.iter().any(|c| list.iter().any(|n| n.eq_ignore_ascii_case(c.trim())));
        if self.mode == "only" {
            hit
        } else {
            !hit
        }
    }

    pub fn normalize(&mut self) {
        if self.mode != "only" {
            self.mode = "except".into();
        }
        self.networks = self.networks.iter().map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).collect();
        self.networks.dedup();
    }
}

/// Имена подключённых сетей (профили Windows).
pub fn current() -> Vec<String> {
    let ps = crate::util::system32(r"WindowsPowerShell\v1.0\powershell.exe");
    let cmd = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-NetConnectionProfile | ForEach-Object { $_.Name }";
    match crate::util::run_hidden(&ps, &["-NoProfile", "-NonInteractive", "-Command", cmd]) {
        Ok(o) => parse(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

fn parse(out: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for l in out.lines().map(|l| l.trim().trim_start_matches('\u{feff}')).filter(|l| !l.is_empty()) {
        if !v.iter().any(|x| x == l) {
            v.push(l.to_string());
        }
    }
    v
}

/// Отпечаток подключений: меняется при смене сети.
pub fn fingerprint() -> String {
    let mut v: Vec<String> =
        crate::dns::info().adapters.into_iter().filter(|a| a.up && a.gateway).map(|a| format!("{}={}", a.guid, a.addresses.join(","))).collect();
    v.sort();
    v.join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(mode: &str, nets: &[&str]) -> NetRules {
        NetRules { enabled: true, mode: mode.into(), networks: nets.iter().map(|s| s.to_string()).collect(), zapret: true, proxy: true }
    }

    #[test]
    fn allowed_modes() {
        let cur = vec!["HomeWiFi".to_string()];
        assert!(!r("except", &["homewifi"]).allowed(&cur));
        assert!(r("except", &["Office"]).allowed(&cur));
        assert!(r("only", &["HomeWiFi "]).allowed(&cur));
        assert!(!r("only", &["Office"]).allowed(&cur));
        // Нет сети — «только в этих» не работает, «кроме этих» работает.
        assert!(!r("only", &["Office"]).allowed(&[]));
        assert!(r("except", &["Office"]).allowed(&[]));
        // Выключено или пустой список — без ограничений.
        let mut off = r("only", &["Office"]);
        off.enabled = false;
        assert!(off.allowed(&cur));
        assert!(r("only", &[" "]).allowed(&cur));
    }

    #[test]
    fn parse_names() {
        assert_eq!(parse("\u{feff}Сеть 2\r\nHomeWiFi\r\n\r\nHomeWiFi\r\n"), vec!["Сеть 2", "HomeWiFi"]);
    }

    /// Система: текущие сети. Только чтение.
    #[test]
    #[ignore]
    fn live_current() {
        println!("{:?}", current());
        println!("{}", fingerprint());
    }
}
