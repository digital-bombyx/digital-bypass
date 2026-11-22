//! Смена DNS сетевых адаптеров Windows.
//!
//! - Адаптеры и текущие DNS читаются через `GetAdaptersAddresses`, признак
//!   «вручную / DHCP» — по значению `NameServer` в реестре Tcpip(6).
//! - Запись идёт через `netsh interface ipv4|ipv6 set/add dnsservers` по индексу
//!   интерфейса: так не мешают локализованные имена адаптеров.
//! - DoH (Windows 11): шаблон сервера регистрируется `netsh dns add|set encryption`,
//!   а для адаптера ставится `DohFlags = 1` в
//!   `Dnscache\InterfaceSpecificParameters\{GUID}\DohInterfaceSettings\Doh(6)\<ip>`
//!   — то же, что пишет «Параметры → Сеть → DNS → Шифрование».

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ---------- пресеты ----------

#[derive(Debug, Clone, Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    /// Короткое описание: фильтрация, особенности.
    pub note_ru: &'static str,
    pub note_en: &'static str,
    pub v4: &'static [&'static str],
    pub v6: &'static [&'static str],
    pub doh: Option<&'static str>,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "cloudflare",
        name: "Cloudflare",
        note_ru: "без фильтрации, быстрый",
        note_en: "no filtering, fast",
        v4: &["1.1.1.1", "1.0.0.1"],
        v6: &["2606:4700:4700::1111", "2606:4700:4700::1001"],
        doh: Some("https://cloudflare-dns.com/dns-query"),
    },
    Preset {
        id: "cloudflare-security",
        name: "Cloudflare Security",
        note_ru: "блокирует вредоносные домены",
        note_en: "blocks malware domains",
        v4: &["1.1.1.2", "1.0.0.2"],
        v6: &["2606:4700:4700::1112", "2606:4700:4700::1002"],
        doh: Some("https://security.cloudflare-dns.com/dns-query"),
    },
    Preset {
        id: "google",
        name: "Google",
        note_ru: "без фильтрации",
        note_en: "no filtering",
        v4: &["8.8.8.8", "8.8.4.4"],
        v6: &["2001:4860:4860::8888", "2001:4860:4860::8844"],
        doh: Some("https://dns.google/dns-query"),
    },
    Preset {
        id: "quad9",
        name: "Quad9",
        note_ru: "блокирует вредоносные домены, DNSSEC",
        note_en: "blocks malware domains, DNSSEC",
        v4: &["9.9.9.9", "149.112.112.112"],
        v6: &["2620:fe::fe", "2620:fe::9"],
        doh: Some("https://dns.quad9.net/dns-query"),
    },
    Preset {
        id: "adguard",
        name: "AdGuard",
        note_ru: "режет рекламу и трекеры",
        note_en: "blocks ads and trackers",
        v4: &["94.140.14.14", "94.140.15.15"],
        v6: &["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        doh: Some("https://dns.adguard-dns.com/dns-query"),
    },
    Preset {
        id: "adguard-unfiltered",
        name: "AdGuard Unfiltered",
        note_ru: "без фильтрации",
        note_en: "no filtering",
        v4: &["94.140.14.140", "94.140.14.141"],
        v6: &["2a10:50c0::1:ff", "2a10:50c0::2:ff"],
        doh: Some("https://unfiltered.adguard-dns.com/dns-query"),
    },
    Preset {
        id: "yandex",
        name: "Яндекс",
        note_ru: "базовый, доступен при белых списках",
        note_en: "basic, reachable under whitelists",
        v4: &["77.88.8.8", "77.88.8.1"],
        v6: &["2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"],
        doh: Some("https://common.dot.dns.yandex.net/dns-query"),
    },
    Preset {
        id: "yandex-safe",
        name: "Яндекс Безопасный",
        note_ru: "блокирует мошеннические сайты",
        note_en: "blocks fraudulent sites",
        v4: &["77.88.8.88", "77.88.8.2"],
        v6: &["2a02:6b8::feed:bad", "2a02:6b8:0:1::feed:bad"],
        doh: Some("https://safe.dot.dns.yandex.net/dns-query"),
    },
    Preset {
        id: "opendns",
        name: "OpenDNS",
        note_ru: "Cisco, без фильтрации",
        note_en: "Cisco, no filtering",
        v4: &["208.67.222.222", "208.67.220.220"],
        v6: &["2620:119:35::35", "2620:119:53::53"],
        doh: Some("https://doh.opendns.com/dns-query"),
    },
    Preset {
        id: "mullvad",
        name: "Mullvad",
        note_ru: "без логов и фильтрации",
        note_en: "no logs, no filtering",
        v4: &["194.242.2.2"],
        v6: &["2a07:e340::2"],
        doh: Some("https://dns.mullvad.net/dns-query"),
    },
];

// ---------- валидация ----------

pub const MAX_SERVERS: usize = 4;

/// Разобрать и проверить адреса одного семейства. Пустые строки пропускаются.
pub fn parse_servers(v6: bool, list: &[String]) -> Result<Vec<IpAddr>, String> {
    let mut out: Vec<IpAddr> = Vec::new();
    for raw in list {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }
        let ip: IpAddr = s.parse().map_err(|_| crate::tr!("некорректный адрес DNS: {s}", "invalid DNS address: {s}"))?;
        let ok = match ip {
            IpAddr::V4(a) => !v6 && !a.is_unspecified() && !a.is_multicast() && !a.is_broadcast(),
            IpAddr::V6(a) => v6 && !a.is_unspecified() && !a.is_multicast(),
        };
        if !ok {
            let fam = if v6 { "IPv6" } else { "IPv4" };
            return Err(crate::tr!("адрес {s} не подходит для {fam}", "address {s} is not valid for {fam}"));
        }
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    if out.len() > MAX_SERVERS {
        return Err(crate::tr!("не больше {MAX_SERVERS} серверов на семейство", "at most {MAX_SERVERS} servers per family"));
    }
    Ok(out)
}

/// Шаблон DoH: только https, без пробелов и кавычек (уходит в аргумент netsh).
pub fn validate_template(t: &str) -> Result<String, String> {
    let t = t.trim();
    let bad = !t.starts_with("https://")
        || t.len() <= "https://".len()
        || t.len() > 512
        || t.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '`' | '^' | '&' | '|' | '<' | '>'));
    if bad {
        return Err(crate::tr!("некорректный шаблон DoH: нужен https://…", "invalid DoH template: https://… expected"));
    }
    Ok(t.to_string())
}

// ---------- аргументы netsh (чистые функции, покрыты тестами) ----------

fn fam(v6: bool) -> &'static str {
    if v6 {
        "ipv6"
    } else {
        "ipv4"
    }
}

/// Команды netsh, задающие список DNS интерфейса.
pub fn netsh_set_args(v6: bool, if_index: u32, servers: &[IpAddr]) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    for (i, ip) in servers.iter().enumerate() {
        let mut a: Vec<String> = vec!["interface".into(), fam(v6).into()];
        if i == 0 {
            a.extend([
                "set".into(),
                "dnsservers".into(),
                format!("name={if_index}"),
                "source=static".into(),
                format!("address={ip}"),
                "register=primary".into(),
                "validate=no".into(),
            ]);
        } else {
            a.extend([
                "add".into(),
                "dnsservers".into(),
                format!("name={if_index}"),
                format!("address={ip}"),
                format!("index={}", i + 1),
                "validate=no".into(),
            ]);
        }
        cmds.push(a);
    }
    cmds
}

/// Вернуть получение DNS по DHCP.
pub fn netsh_dhcp_args(v6: bool, if_index: u32) -> Vec<String> {
    vec![
        "interface".into(),
        fam(v6).into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={if_index}"),
        "source=dhcp".into(),
    ]
}

/// `netsh dns add|set encryption …`.
pub fn netsh_encryption_args(verb: &str, server: &IpAddr, template: &str, fallback: bool) -> Vec<String> {
    vec![
        "dns".into(),
        verb.into(),
        "encryption".into(),
        format!("server={server}"),
        format!("dohtemplate={template}"),
        "autoupgrade=yes".into(),
        format!("udpfallback={}", if fallback { "yes" } else { "no" }),
    ]
}

// ---------- шаблоны DoH, известные системе ----------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DohTemplate {
    pub server: String,
    pub template: String,
    pub autoupgrade: bool,
    pub fallback: bool,
}

fn yes(v: &str) -> bool {
    matches!(v.trim().to_lowercase().as_str(), "yes" | "да" | "true" | "1")
}

/// Разбор `netsh dns show encryption`. Не зависит от языка: блок начинается со
/// строки, последнее слово которой — IP; первая пара «ключ : значение» с https —
/// шаблон, следующие две — автообновление и откат на UDP.
pub fn parse_encryption(text: &str) -> Vec<DohTemplate> {
    let mut out: Vec<DohTemplate> = Vec::new();
    let mut cur: Option<(DohTemplate, usize)> = None;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.chars().all(|c| c == '-') {
            continue;
        }
        // «Ключ   : значение» — двоеточие, окружённое пробелами (в IPv6 их нет).
        if let Some(pos) = l.find(" : ").or_else(|| l.find(" :")) {
            let value = l[pos..].trim_start_matches([' ', ':']).trim();
            if let Some((t, n)) = cur.as_mut() {
                if *n == 0 {
                    if value.starts_with("https://") {
                        t.template = value.to_string();
                        *n = 1;
                    }
                } else if *n == 1 {
                    t.autoupgrade = yes(value);
                    *n = 2;
                } else if *n == 2 {
                    t.fallback = yes(value);
                    *n = 3;
                }
            }
            continue;
        }
        if let Some(last) = l.split_whitespace().last() {
            if last.parse::<IpAddr>().is_ok() {
                if let Some((t, _)) = cur.take() {
                    if !t.template.is_empty() {
                        out.push(t);
                    }
                }
                cur = Some((
                    DohTemplate { server: last.to_string(), template: String::new(), autoupgrade: false, fallback: false },
                    0,
                ));
            }
        }
    }
    if let Some((t, _)) = cur {
        if !t.template.is_empty() {
            out.push(t);
        }
    }
    out
}

// ---------- адаптеры ----------

#[derive(Debug, Clone, Serialize)]
pub struct Adapter {
    pub index: u32,
    pub ipv6_index: u32,
    pub guid: String,
    pub name: String,
    pub description: String,
    pub up: bool,
    /// Есть шлюз по умолчанию — через этот адаптер идёт интернет.
    pub gateway: bool,
    /// Через этот адаптер система ходит в интернет (GetBestInterface до 1.1.1.1).
    pub internet: bool,
    /// Метрика IPv4 интерфейса: меньше — приоритетнее.
    pub metric: u32,
    /// ethernet | wifi | other
    pub kind: &'static str,
    pub addresses: Vec<String>,
    pub dns_v4: Vec<String>,
    pub dns_v6: Vec<String>,
    /// DNS задан вручную (иначе — DHCP/автоматически).
    pub static_v4: bool,
    pub static_v6: bool,
    /// Серверы, для которых на адаптере включён DoH.
    pub doh: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Info {
    pub adapters: Vec<Adapter>,
    pub doh_supported: bool,
    pub templates: Vec<DohTemplate>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApplyReq {
    pub index: u32,
    /// None — семейство не трогать.
    pub v4: Option<Vec<String>>,
    pub v6: Option<Vec<String>>,
    /// Шаблон DoH для всех заданных адресов; None — без шифрования.
    pub doh_template: Option<String>,
    #[serde(default)]
    pub doh_fallback: bool,
}

/// Служебные адреса fec0:0:0:ffff::1..3 Windows подставляет, когда IPv6 DNS нет.
fn is_placeholder_v6(a: &Ipv6Addr) -> bool {
    let s = a.segments();
    s[0] == 0xfec0 && s[1] == 0 && s[2] == 0 && s[3] == 0xffff && s[4..7] == [0, 0, 0] && (1..=3).contains(&s[7])
}

#[cfg(windows)]
mod sys {
    use super::*;
    use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_OEMCP};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GetBestInterface, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKET_ADDRESS};
    use windows_sys::Win32::System::Registry::{
        RegDeleteTreeW, RegGetValueW, RegSetKeyValueW, HKEY_LOCAL_MACHINE, REG_QWORD, RRF_RT_REG_QWORD, RRF_RT_REG_SZ,
    };

    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_TYPE_ETHERNET: u32 = 6;
    const IF_TYPE_IEEE80211: u32 = 71;
    /// Teredo, 6to4, ISATAP: DNS на них не настраивают.
    const IF_TYPE_TUNNEL: u32 = 131;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn pwstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    unsafe fn sockaddr_ip(a: &SOCKET_ADDRESS) -> Option<IpAddr> {
        let p = a.lpSockaddr as *const SOCKADDR;
        if p.is_null() {
            return None;
        }
        let b = p as *const u8;
        match (*p).sa_family {
            AF_INET if a.iSockaddrLength >= 8 => {
                let o = std::slice::from_raw_parts(b.add(4), 4);
                Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
            }
            AF_INET6 if a.iSockaddrLength >= 24 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(std::slice::from_raw_parts(b.add(8), 16));
                Some(IpAddr::V6(Ipv6Addr::from(o)))
            }
            _ => None,
        }
    }

    pub fn reg_sz(path: &str, name: &str) -> Option<String> {
        let (wp, wn) = (wide(path), wide(name));
        let mut buf = vec![0u16; 1024];
        let mut size = (buf.len() * 2) as u32;
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                wp.as_ptr(),
                wn.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut _,
                &mut size,
            )
        };
        if r != 0 {
            return None;
        }
        buf.truncate((size as usize / 2).saturating_sub(1));
        Some(String::from_utf16_lossy(&buf))
    }

    pub fn reg_qword(path: &str, name: &str) -> Option<u64> {
        let (wp, wn) = (wide(path), wide(name));
        let mut v: u64 = 0;
        let mut size = 8u32;
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                wp.as_ptr(),
                wn.as_ptr(),
                RRF_RT_REG_QWORD,
                std::ptr::null_mut(),
                &mut v as *mut u64 as *mut _,
                &mut size,
            )
        };
        (r == 0).then_some(v)
    }

    pub fn set_reg_qword(path: &str, name: &str, v: u64) -> Result<(), String> {
        let (wp, wn) = (wide(path), wide(name));
        let r = unsafe { RegSetKeyValueW(HKEY_LOCAL_MACHINE, wp.as_ptr(), wn.as_ptr(), REG_QWORD, &v as *const u64 as *const _, 8) };
        if r == 0 {
            Ok(())
        } else {
            Err(crate::tr!("запись в реестр ({path}): код {r}", "registry write ({path}): code {r}"))
        }
    }

    pub fn delete_tree(path: &str) {
        let wp = wide(path);
        unsafe {
            RegDeleteTreeW(HKEY_LOCAL_MACHINE, wp.as_ptr());
        }
    }

    /// Вывод консольных утилит (netsh) — в OEM-кодировке (cp866 у русской Windows).
    pub fn decode_oem(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        unsafe {
            let n = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, std::ptr::null_mut(), 0);
            if n <= 0 {
                return String::from_utf8_lossy(bytes).into_owned();
            }
            let mut w = vec![0u16; n as usize];
            MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, w.as_mut_ptr(), n);
            String::from_utf16_lossy(&w)
        }
    }

    pub fn adapters() -> Vec<Adapter> {
        let mut size: u32 = 32 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
        let mut ok = false;
        for _ in 0..4 {
            buf = vec![0u64; (size as usize).div_ceil(8)];
            let r = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                )
            };
            if r == 0 {
                ok = true;
                break;
            }
            if r != ERROR_BUFFER_OVERFLOW {
                break;
            }
        }
        let mut out = Vec::new();
        if !ok {
            return out;
        }
        let mut best: u32 = 0;
        // Адрес — в сетевом порядке байт, как в in_addr.
        let best_ok = unsafe { GetBestInterface(u32::from_ne_bytes([1, 1, 1, 1]), &mut best) } == 0;
        unsafe {
            let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !p.is_null() {
                let a = &*p;
                p = a.Next;
                if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == IF_TYPE_TUNNEL {
                    continue;
                }
                let guid = std::ffi::CStr::from_ptr(a.AdapterName as *const _).to_string_lossy().into_owned();
                let mut addresses = Vec::new();
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    if let Some(ip) = sockaddr_ip(&(*u).Address) {
                        // Локальные fe80:: не показываем — они есть у всех.
                        let link_local = matches!(ip, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80);
                        if !link_local {
                            addresses.push(ip.to_string());
                        }
                    }
                    u = (*u).Next;
                }
                let (mut dns_v4, mut dns_v6) = (Vec::new(), Vec::new());
                let mut d = a.FirstDnsServerAddress;
                while !d.is_null() {
                    let list = match sockaddr_ip(&(*d).Address) {
                        Some(IpAddr::V4(v)) => Some((&mut dns_v4, v.to_string())),
                        Some(IpAddr::V6(v)) if !is_placeholder_v6(&v) => Some((&mut dns_v6, v.to_string())),
                        _ => None,
                    };
                    if let Some((l, s)) = list {
                        if !l.contains(&s) {
                            l.push(s);
                        }
                    }
                    d = (*d).Next;
                }
                let ns = |tcpip: &str| {
                    reg_sz(&format!(r"SYSTEM\CurrentControlSet\Services\{tcpip}\Parameters\Interfaces\{guid}"), "NameServer")
                        .is_some_and(|s| !s.trim().is_empty())
                };
                let doh_base = doh_key(&guid);
                let doh = dns_v4
                    .iter()
                    .map(|s| (s, "Doh"))
                    .chain(dns_v6.iter().map(|s| (s, "Doh6")))
                    .filter(|(s, sub)| reg_qword(&format!(r"{doh_base}\{sub}\{s}"), "DohFlags").is_some_and(|f| f != 0))
                    .map(|(s, _)| s.clone())
                    .collect();
                out.push(Adapter {
                    index: a.Anonymous1.Anonymous.IfIndex,
                    ipv6_index: a.Ipv6IfIndex,
                    name: pwstr(a.FriendlyName),
                    description: pwstr(a.Description),
                    up: a.OperStatus == 1,
                    gateway: !a.FirstGatewayAddress.is_null(),
                    metric: a.Ipv4Metric,
                    internet: best_ok && a.Anonymous1.Anonymous.IfIndex == best,
                    kind: match a.IfType {
                        IF_TYPE_ETHERNET => "ethernet",
                        IF_TYPE_IEEE80211 => "wifi",
                        _ => "other",
                    },
                    addresses,
                    dns_v4,
                    dns_v6,
                    static_v4: ns("Tcpip"),
                    static_v6: ns("Tcpip6"),
                    doh,
                    guid,
                });
            }
        }
        // Сначала интернет-адаптер, потом подключённые со шлюзом, затем подключённые; внутри — по метрике и имени.
        out.sort_by(|a, b| {
            b.internet.cmp(&a.internet).then((b.up && b.gateway).cmp(&(a.up && a.gateway)).then(b.up.cmp(&a.up)).then(a.metric.cmp(&b.metric)).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())))
        });
        out
    }
}

/// Ключ реестра с настройками DoH конкретного адаптера.
pub fn doh_key(guid: &str) -> String {
    format!(r"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\{guid}\DohInterfaceSettings")
}

fn netsh(args: &[String]) -> Result<String, String> {
    let out = crate::util::hidden(crate::util::system32("netsh.exe"))
        .args(args)
        .output()
        .map_err(|e| format!("netsh: {e}"))?;
    let text = sys::decode_oem(&out.stdout);
    if out.status.success() {
        Ok(text)
    } else {
        let err = sys::decode_oem(&out.stderr);
        let msg = if err.trim().is_empty() { text.trim().to_string() } else { err.trim().to_string() };
        Err(format!("netsh {}: {msg}", args.join(" ")))
    }
}

pub fn info() -> Info {
    let enc = netsh(&["dns".into(), "show".into(), "encryption".into()]);
    Info {
        adapters: sys::adapters(),
        doh_supported: enc.is_ok(),
        templates: enc.map(|t| parse_encryption(&t)).unwrap_or_default(),
    }
}

fn find(index: u32) -> Result<Adapter, String> {
    sys::adapters()
        .into_iter()
        .find(|a| a.index == index)
        .ok_or_else(|| crate::tr!("адаптер с индексом {index} не найден", "adapter with index {index} not found"))
}

fn v6_index(a: &Adapter) -> u32 {
    if a.ipv6_index != 0 {
        a.ipv6_index
    } else {
        a.index
    }
}

pub fn apply(req: &ApplyReq) -> Result<(), String> {
    let a = find(req.index)?;
    let v4 = req.v4.as_deref().map(|l| parse_servers(false, l)).transpose()?;
    let v6 = req.v6.as_deref().map(|l| parse_servers(true, l)).transpose()?;
    if v4.is_none() && v6.is_none() {
        return Err(crate::tr!("не выбрано ни IPv4, ни IPv6", "neither IPv4 nor IPv6 selected"));
    }
    if v4.as_ref().is_some_and(|l| l.is_empty()) || v6.as_ref().is_some_and(|l| l.is_empty()) {
        return Err(crate::tr!("укажите хотя бы один адрес", "enter at least one address"));
    }
    let template = req.doh_template.as_deref().map(validate_template).transpose()?;

    // Сначала регистрируем шаблоны DoH: если система их не поддерживает, адаптер не трогаем.
    let all: Vec<IpAddr> = v4.iter().flatten().chain(v6.iter().flatten()).copied().collect();
    if let Some(t) = &template {
        for ip in &all {
            if netsh(&netsh_encryption_args("add", ip, t, req.doh_fallback)).is_err() {
                netsh(&netsh_encryption_args("set", ip, t, req.doh_fallback)).map_err(|e| {
                    crate::tr!("DoH-шаблон не применился (нужна Windows 11): {e}", "DoH template failed (Windows 11 required): {e}")
                })?;
            }
        }
    }

    let base = doh_key(&a.guid);
    for (v6, list) in [(false, &v4), (true, &v6)] {
        let Some(list) = list else { continue };
        let idx = if v6 { v6_index(&a) } else { a.index };
        for cmd in netsh_set_args(v6, idx, list) {
            netsh(&cmd)?;
        }
        let sub = if v6 { "Doh6" } else { "Doh" };
        sys::delete_tree(&format!(r"{base}\{sub}"));
        if template.is_some() {
            for ip in list {
                sys::set_reg_qword(&format!(r"{base}\{sub}\{ip}"), "DohFlags", 1)?;
            }
        }
    }
    flush();
    Ok(())
}

/// Вернуть DNS по DHCP для выбранных семейств и снять флаги DoH адаптера.
pub fn reset(index: u32, v4: bool, v6: bool) -> Result<(), String> {
    let a = find(index)?;
    let base = doh_key(&a.guid);
    if v4 {
        netsh(&netsh_dhcp_args(false, a.index))?;
        sys::delete_tree(&format!(r"{base}\Doh"));
    }
    if v6 {
        netsh(&netsh_dhcp_args(true, v6_index(&a)))?;
        sys::delete_tree(&format!(r"{base}\Doh6"));
    }
    flush();
    Ok(())
}

pub fn flush() -> bool {
    crate::util::run_hidden(&crate::util::system32("ipconfig.exe"), &["/flushdns"]).is_ok_and(|o| o.status.success())
}

// ---------- локальный DoH-резолвер на адаптере ----------

/// Что включено и что было до включения — хранится в настройках, пока
/// резолвер прописан на адаптере.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StubConfig {
    pub guid: String,
    pub name: String,
    pub template: String,
    pub bootstrap: Vec<String>,
    /// Обычный DNS вторым адресом: если приложение закрыто, интернет не пропадёт.
    pub fallback: Option<String>,
    pub ipv6: bool,
    /// Адрес петли резолвера (127.0.0.1 или запасной, если тот занят).
    #[serde(default = "default_stub_addr")]
    pub addr: String,
    /// None — DNS был автоматическим (DHCP).
    pub prev_v4: Option<Vec<String>>,
    pub prev_v6: Option<Vec<String>>,
}

pub const STUB_V4: &str = "127.0.0.1";

fn default_stub_addr() -> String {
    STUB_V4.into()
}
pub const STUB_V6: &str = "::1";

/// Списки адресов для адаптера (чистая функция).
pub fn stub_servers(addr: &str, ipv6: bool, fallback: Option<&str>) -> (Vec<String>, Option<Vec<String>>) {
    let mut v4 = vec![addr.to_string()];
    if let Some(f) = fallback {
        v4.push(f.to_string());
    }
    (v4, ipv6.then(|| vec![STUB_V6.to_string()]))
}

/// Прежние ручные адреса. Если на адаптере уже наш резолвер (остался после
/// сбоя), прежнее состояние неизвестно — вернём DHCP.
pub fn prev_servers(is_static: bool, list: &[String]) -> Option<Vec<String>> {
    let ours = list.iter().any(|s| s.starts_with("127.") || s == STUB_V6);
    (is_static && !ours && !list.is_empty()).then(|| list.to_vec())
}

fn find_guid(guid: &str) -> Result<Adapter, String> {
    sys::adapters()
        .into_iter()
        .find(|a| a.guid.eq_ignore_ascii_case(guid))
        .ok_or_else(|| crate::tr!("адаптер {guid} не найден", "adapter {guid} not found"))
}

/// Прописать резолвер на адаптер. Возвращает конфигурацию с прежними адресами.
pub fn stub_point(index: u32, addr: std::net::Ipv4Addr, ipv6: bool, template: &str, bootstrap: &[IpAddr], fallback: Option<IpAddr>) -> Result<StubConfig, String> {
    let a = find(index)?;
    let cfg = StubConfig {
        guid: a.guid.clone(),
        name: a.name.clone(),
        template: template.to_string(),
        bootstrap: bootstrap.iter().map(|i| i.to_string()).collect(),
        fallback: fallback.map(|f| f.to_string()),
        ipv6,
        addr: addr.to_string(),
        prev_v4: prev_servers(a.static_v4, &a.dns_v4),
        prev_v6: prev_servers(a.static_v6, &a.dns_v6),
    };
    let (v4, v6) = stub_servers(&cfg.addr, ipv6, cfg.fallback.as_deref());
    apply(&ApplyReq { index, v4: Some(v4), v6, doh_template: None, doh_fallback: false })?;
    Ok(cfg)
}

/// Вернуть адаптеру DNS, который был до резолвера.
pub fn stub_restore(cfg: &StubConfig) -> Result<(), String> {
    let a = find_guid(&cfg.guid)?;
    match &cfg.prev_v4 {
        Some(list) => apply(&ApplyReq { index: a.index, v4: Some(list.clone()), v6: None, doh_template: None, doh_fallback: false })?,
        None => reset(a.index, true, false)?,
    }
    if cfg.ipv6 {
        match &cfg.prev_v6 {
            Some(list) => apply(&ApplyReq { index: a.index, v4: None, v6: Some(list.clone()), doh_template: None, doh_fallback: false })?,
            None => reset(a.index, false, true)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn stub_lists() {
        assert_eq!(stub_servers("127.0.0.1", false, None), (s(&["127.0.0.1"]), None));
        assert_eq!(stub_servers("127.0.0.53", true, Some("1.1.1.1")), (s(&["127.0.0.53", "1.1.1.1"]), Some(s(&["::1"]))));
        // Списки резолвера проходят ту же проверку, что и ручные адреса.
        assert_eq!(parse_servers(false, &stub_servers("127.0.0.1", true, Some("1.1.1.1")).0).unwrap().len(), 2);
        assert_eq!(prev_servers(true, &s(&["127.0.0.53"])), None);
        assert_eq!(prev_servers(false, &s(&["192.168.0.1"])), None);
        assert_eq!(prev_servers(true, &s(&["8.8.8.8"])), Some(s(&["8.8.8.8"])));
        // После сбоя на адаптере остался наш адрес — считаем, что было «автоматически».
        assert_eq!(prev_servers(true, &s(&["127.0.0.1", "1.1.1.1"])), None);
        assert_eq!(prev_servers(true, &s(&["127.0.0.1"])), None);
    }

    #[test]
    fn presets_are_valid() {
        let mut ids = std::collections::HashSet::new();
        for p in PRESETS {
            assert!(ids.insert(p.id), "duplicate id {}", p.id);
            assert!(!p.v4.is_empty(), "{}", p.id);
            assert_eq!(parse_servers(false, &s(p.v4)).unwrap().len(), p.v4.len(), "{}", p.id);
            assert_eq!(parse_servers(true, &s(p.v6)).unwrap().len(), p.v6.len(), "{}", p.id);
            if let Some(t) = p.doh {
                validate_template(t).unwrap();
            }
        }
    }

    #[test]
    fn server_validation() {
        assert_eq!(parse_servers(false, &s(&[" 1.1.1.1 ", "", "1.1.1.1", "127.0.0.1"])).unwrap().len(), 2);
        assert!(parse_servers(false, &s(&["2606:4700:4700::1111"])).is_err());
        assert!(parse_servers(true, &s(&["8.8.8.8"])).is_err());
        assert!(parse_servers(false, &s(&["0.0.0.0"])).is_err());
        assert!(parse_servers(false, &s(&["255.255.255.255"])).is_err());
        assert!(parse_servers(false, &s(&["224.0.0.1"])).is_err());
        assert!(parse_servers(true, &s(&["::"])).is_err());
        assert!(parse_servers(false, &s(&["1.1.1.1; calc"])).is_err());
        assert!(parse_servers(false, &s(&["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"])).is_err());
    }

    #[test]
    fn template_validation() {
        assert!(validate_template("https://dns.google/dns-query").is_ok());
        assert!(validate_template("http://dns.google/dns-query").is_err());
        assert!(validate_template("https://").is_err());
        assert!(validate_template("https://a b").is_err());
        assert!(validate_template("https://a\"&calc").is_err());
    }

    #[test]
    fn netsh_args() {
        let ips = parse_servers(false, &s(&["1.1.1.1", "1.0.0.1"])).unwrap();
        let c = netsh_set_args(false, 12, &ips);
        assert_eq!(c.len(), 2);
        assert_eq!(
            c[0].join(" "),
            "interface ipv4 set dnsservers name=12 source=static address=1.1.1.1 register=primary validate=no"
        );
        assert_eq!(c[1].join(" "), "interface ipv4 add dnsservers name=12 address=1.0.0.1 index=2 validate=no");
        let ips6 = parse_servers(true, &s(&["2620:fe::fe"])).unwrap();
        assert_eq!(netsh_set_args(true, 7, &ips6)[0][1], "ipv6");
        assert_eq!(netsh_dhcp_args(true, 7).join(" "), "interface ipv6 set dnsservers name=7 source=dhcp");
        assert_eq!(
            netsh_encryption_args("add", &"9.9.9.9".parse().unwrap(), "https://dns.quad9.net/dns-query", false).join(" "),
            "dns add encryption server=9.9.9.9 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no"
        );
    }

    #[test]
    fn placeholder_v6() {
        assert!(is_placeholder_v6(&"fec0:0:0:ffff::1".parse().unwrap()));
        assert!(!is_placeholder_v6(&"2620:fe::fe".parse().unwrap()));
    }

    #[test]
    fn parse_encryption_en_ru() {
        let en = "\r\nEncryption settings for 1.1.1.1\r\n----------------------------------------------------------------------\r\nDNS-over-HTTPS template           : https://cloudflare-dns.com/dns-query\r\nAuto-upgrade                      : yes\r\nUDP-fallback                      : no\r\n\r\nEncryption settings for 2620:fe::fe\r\n----------------------------------------------------------------------\r\nDNS-over-HTTPS template           : https://dns.quad9.net/dns-query\r\nAuto-upgrade                      : no\r\nUDP-fallback                      : yes\r\n";
        let r = parse_encryption(en);
        assert_eq!(r.len(), 2);
        assert_eq!(
            r[0],
            DohTemplate { server: "1.1.1.1".into(), template: "https://cloudflare-dns.com/dns-query".into(), autoupgrade: true, fallback: false }
        );
        assert_eq!(r[1].server, "2620:fe::fe");
        assert!(!r[1].autoupgrade && r[1].fallback);

        let ru = "Параметры шифрования для 8.8.8.8\n---------\nШаблон DNS через HTTPS          : https://dns.google/dns-query\nАвтоматическое обновление      : да\nОткат на UDP                   : нет\n";
        let r = parse_encryption(ru);
        assert_eq!(r.len(), 1);
        assert!(r[0].autoupgrade && !r[0].fallback);
        assert_eq!(r[0].template, "https://dns.google/dns-query");
    }

    /// Только чтение: адаптеры и шаблоны DoH этой машины. Ничего не меняет.
    /// `cargo test dump_dns -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn dump_dns() {
        println!("{}", serde_json::to_string_pretty(&info()).unwrap());
    }
}
