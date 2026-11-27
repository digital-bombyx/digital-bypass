//! Что на этом компьютере может мешать обходу: другие обходчики DPI
//! (второй WinDivert перехватывает те же пакеты), VPN-клиенты (весь трафик
//! уходит в туннель мимо zapret2) и сторонние антивирусы (удаляют или
//! блокируют WinDivert64.sys). Для `get_status` в MCP — частая причина
//! «включил, а не работает».

use serde::Serialize;

#[derive(Debug, Serialize, PartialEq)]
pub struct Conflict {
    /// dpi | vpn | antivirus
    pub kind: &'static str,
    pub name: String,
    pub note: &'static str,
}

/// (процесс в нижнем регистре, название, вид)
const PROCS: &[(&str, &str, &str)] = &[
    ("goodbyedpi.exe", "GoodbyeDPI", "dpi"),
    ("winws.exe", "zapret (winws)", "dpi"),
    ("ciadpi.exe", "ByeDPI", "dpi"),
    ("spoofdpi.exe", "SpoofDPI", "dpi"),
    ("v2rayn.exe", "v2rayN", "vpn"),
    ("hiddify.exe", "Hiddify", "vpn"),
    ("amneziavpn.exe", "AmneziaVPN", "vpn"),
    ("nekoray.exe", "NekoRay", "vpn"),
    ("throne.exe", "Throne", "vpn"),
    ("clash-verge.exe", "Clash Verge", "vpn"),
    ("mihomo.exe", "mihomo (Clash)", "vpn"),
    ("sing-box.exe", "sing-box", "vpn"),
    ("wireguard.exe", "WireGuard", "vpn"),
    ("openvpn.exe", "OpenVPN", "vpn"),
    ("openvpn-gui.exe", "OpenVPN", "vpn"),
    ("outline.exe", "Outline", "vpn"),
];

fn note(kind: &str) -> &'static str {
    match kind {
        "dpi" => "another DPI bypass tool: two WinDivert users fight over the same packets — stop it before using zapret2",
        "vpn" => "a VPN client: in TUN/system mode all traffic goes into the tunnel and zapret2/the proxy have nothing to do; its own server connection can still be helped by zapret2",
        _ => "a third-party antivirus may delete or block WinDivert64.sys — add the zapret folder to its exclusions",
    }
}

/// Процессы из `tasklist /fo csv /nh`.
pub fn from_tasklist(csv: &str) -> Vec<Conflict> {
    let mut out: Vec<Conflict> = Vec::new();
    for line in csv.lines() {
        let exe = line.trim().trim_start_matches('"').split('"').next().unwrap_or("").to_ascii_lowercase();
        if let Some((_, name, kind)) = PROCS.iter().find(|(p, _, _)| *p == exe) {
            if !out.iter().any(|c| c.name == *name) {
                out.push(Conflict { kind, name: name.to_string(), note: note(kind) });
            }
        }
    }
    out
}

/// Антивирусы из Центра безопасности, кроме Защитника Windows.
pub fn antivirus_from(names: &str) -> Vec<Conflict> {
    names
        .lines()
        .map(str::trim)
        .filter(|n| !n.is_empty() && !n.to_ascii_lowercase().contains("defender"))
        .map(|n| Conflict { kind: "antivirus", name: n.to_string(), note: note("antivirus") })
        .collect()
}

pub fn detect() -> Vec<Conflict> {
    let mut v = crate::util::hidden(crate::util::system32("tasklist.exe"))
        .args(["/fo", "csv", "/nh"])
        .output()
        .map(|o| from_tasklist(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();
    let av = crate::util::hidden(crate::util::system32("WindowsPowerShell\\v1.0\\powershell.exe"))
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { $_.displayName }",
        ])
        .output()
        .map(|o| antivirus_from(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();
    v.extend(av);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let t = "\"svchost.exe\",\"1\",\"Services\",\"0\",\"1 K\"\r\n\"v2rayN.exe\",\"2\",\"Console\",\"1\",\"9 K\"\r\n\"goodbyedpi.exe\",\"3\",\"Services\",\"0\",\"2 K\"\r\n\"v2rayN.exe\",\"4\",\"Console\",\"1\",\"9 K\"";
        let c = from_tasklist(t);
        assert_eq!(c.iter().map(|x| (x.kind, x.name.as_str())).collect::<Vec<_>>(), [("vpn", "v2rayN"), ("dpi", "GoodbyeDPI")]);
        let a = antivirus_from("Windows Defender\r\nKaspersky Anti-Virus\r\n");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].name, "Kaspersky Anti-Virus");
    }

    /// `cargo test live_conflicts -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_conflicts() {
        println!("{:#?}", detect());
    }
}
