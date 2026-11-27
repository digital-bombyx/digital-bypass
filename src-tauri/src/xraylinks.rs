//! Ссылки и подписки для Xray: `vless://`, `vmess://`, `trojan://`, `ss://`,
//! `socks://`, `http(s)://`; подписки — base64-список, простой список или
//! JSON (массив полных конфигов Xray, как отдают 3x-ui/Marzban/Remnawave).
//!
//! Результат — исходящее соединение Xray (`outbound` без тега) и, для JSON,
//! цепочка (`chain`: соединения, на которые ссылается `sockopt.dialerProxy`).
//! Параметры ссылок — как в v2rayN (ResolveUriQuery / FillBoundStreamSettings):
//! type, security, sni, fp, alpn, pbk, sid, spx, pqv, ech, pcs, vcn, fm (finalmask),
//! path, host, mode, extra (xhttp), x_padding_bytes, serviceName, authority, headerType.
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Server {
    /// Имя для списка (из `#имя` или `remarks`).
    pub name: String,
    /// vless | vmess | trojan | shadowsocks | socks | http
    pub protocol: String,
    pub address: String,
    pub port: u16,
    /// raw, ws, xhttp, grpc, httpupgrade + tls/reality — для подписи в списке.
    pub transport: String,
    /// Исходящее соединение Xray без `tag`.
    pub outbound: Value,
    /// Дополнительные соединения цепочки (с тегами), только из JSON-подписок.
    #[serde(default)]
    pub chain: Vec<Value>,
}

// ---------- мелкие разборщики ----------

/// Процентное декодирование (`+` не трогаем: в ссылках это часть base64).
pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16);
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Base64 обычный и URL-safe, с переводами строк и без `=`.
pub fn b64_any(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = s.trim_end_matches('=');
    if s.is_empty() {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.as_bytes().chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn b64_text(s: &str) -> Option<String> {
    String::from_utf8(b64_any(s)?).ok()
}

/// `scheme://userinfo@host:port?query#name` → части.
struct Uri {
    user: String,
    host: String,
    port: u16,
    query: Vec<(String, String)>,
    name: String,
}

fn split_hostport(hp: &str) -> Option<(String, u16)> {
    let hp = hp.trim_end_matches('/');
    if let Some(rest) = hp.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        return Some((h.to_string(), p.parse().ok()?));
    }
    let (h, p) = hp.rsplit_once(':')?;
    Some((h.to_string(), p.trim_end_matches('/').parse().ok()?))
}

fn parse_uri(s: &str) -> Result<Uri, String> {
    let (_, rest) = s.split_once("://").ok_or("нет схемы")?;
    let (rest, name) = match rest.split_once('#') {
        Some((r, n)) => (r, pct_decode(n)),
        None => (rest, String::new()),
    };
    let (main, q) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let (user, hp) = match main.rsplit_once('@') {
        Some((u, h)) => (pct_decode(u), h),
        None => (String::new(), main),
    };
    let (host, port) = split_hostport(hp).ok_or_else(|| crate::tr!("нет адреса или порта", "no address or port"))?;
    let query = q
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_string(), pct_decode(v)),
            None => (kv.to_string(), String::new()),
        })
        .collect();
    Ok(Uri { user, host, port, query, name })
}

fn q<'a>(query: &'a [(String, String)], k: &str) -> &'a str {
    query.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str()).unwrap_or("")
}

fn parse_json_opt(s: &str) -> Option<Value> {
    (!s.trim().is_empty()).then(|| serde_json::from_str(s).ok()).flatten()
}

fn put(m: &mut Map<String, Value>, k: &str, v: &str) {
    if !v.is_empty() {
        m.insert(k.into(), Value::String(v.into()));
    }
}

/// `streamSettings` по параметрам ссылки. Ошибка — для неподдерживаемого транспорта.
pub fn stream_settings(query: &[(String, String)], default_security: &str) -> Result<(Value, String), String> {
    let mut net = q(query, "type").to_ascii_lowercase();
    if net.is_empty() || net == "tcp" {
        net = "raw".into();
    }
    let security = match q(query, "security") {
        "" => default_security.to_string(),
        s => s.to_ascii_lowercase(),
    };
    let host = q(query, "host");
    let path = q(query, "path");
    let mut ss = Map::new();
    ss.insert("network".into(), json!(net));
    match net.as_str() {
        "raw" => {
            if q(query, "headerType") == "http" {
                let hosts: Vec<&str> = host.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
                let paths: Vec<&str> = if path.is_empty() { vec!["/"] } else { path.split(',').collect() };
                let mut req = json!({ "version": "1.1", "method": "GET", "path": paths, "headers": {} });
                if !hosts.is_empty() {
                    req["headers"]["Host"] = json!(hosts);
                }
                ss.insert("rawSettings".into(), json!({ "header": { "type": "http", "request": req } }));
            }
        }
        "ws" | "httpupgrade" => {
            let mut m = Map::new();
            put(&mut m, "path", if path.is_empty() { "/" } else { path });
            put(&mut m, "host", host);
            ss.insert(format!("{net}Settings"), Value::Object(m));
        }
        "xhttp" | "splithttp" => {
            net = "xhttp".into();
            ss.insert("network".into(), json!("xhttp"));
            let mut m = Map::new();
            put(&mut m, "path", if path.is_empty() { "/" } else { path });
            put(&mut m, "host", host);
            let mode = q(query, "mode");
            if ["auto", "packet-up", "stream-up", "stream-one"].contains(&mode) {
                put(&mut m, "mode", mode);
            }
            put(&mut m, "xPaddingBytes", q(query, "x_padding_bytes"));
            if let Some(extra) = parse_json_opt(q(query, "extra")) {
                m.insert("extra".into(), extra);
            }
            ss.insert("xhttpSettings".into(), Value::Object(m));
        }
        "grpc" => {
            let mut m = Map::new();
            m.insert("serviceName".into(), json!(q(query, "serviceName")));
            put(&mut m, "authority", q(query, "authority"));
            m.insert("multiMode".into(), json!(q(query, "mode") == "multi"));
            ss.insert("grpcSettings".into(), Value::Object(m));
        }
        other => {
            return Err(crate::tr!(
                "транспорт {other} пока не поддерживается (есть raw/tcp, ws, httpupgrade, xhttp, grpc)",
                "transport {other} is not supported yet (raw/tcp, ws, httpupgrade, xhttp, grpc are)"
            ))
        }
    }
    let fp = match q(query, "fp") {
        "" => "chrome",
        f => f,
    };
    match security.as_str() {
        "tls" => {
            let mut t = Map::new();
            let sni = match q(query, "sni") {
                "" => host.split(',').next().unwrap_or("").trim(),
                s => s,
            };
            put(&mut t, "serverName", sni);
            put(&mut t, "fingerprint", fp);
            let alpn: Vec<&str> = q(query, "alpn").split(',').map(str::trim).filter(|a| !a.is_empty()).collect();
            if !alpn.is_empty() {
                t.insert("alpn".into(), json!(alpn));
            }
            put(&mut t, "echConfigList", q(query, "ech"));
            put(&mut t, "pinnedPeerCertSha256", q(query, "pcs"));
            put(&mut t, "verifyPeerCertByName", q(query, "vcn"));
            ss.insert("security".into(), json!("tls"));
            ss.insert("tlsSettings".into(), Value::Object(t));
        }
        "reality" => {
            let pbk = q(query, "pbk");
            if pbk.is_empty() {
                return Err(crate::tr!("REALITY без открытого ключа (pbk)", "REALITY without a public key (pbk)"));
            }
            let mut r = Map::new();
            put(&mut r, "serverName", q(query, "sni"));
            put(&mut r, "fingerprint", fp);
            put(&mut r, "publicKey", pbk);
            put(&mut r, "shortId", q(query, "sid"));
            put(&mut r, "spiderX", q(query, "spx"));
            put(&mut r, "mldsa65Verify", q(query, "pqv"));
            ss.insert("security".into(), json!("reality"));
            ss.insert("realitySettings".into(), Value::Object(r));
        }
        "" | "none" => {}
        other => return Err(crate::tr!("неизвестная защита {other}", "unknown security {other}")),
    }
    if let Some(fm) = parse_json_opt(q(query, "fm")) {
        ss.insert("finalmask".into(), fm);
    }
    let label = if matches!(security.as_str(), "tls" | "reality") { format!("{net}+{security}") } else { net.clone() };
    Ok((Value::Object(ss), label))
}

// ---------- ссылки ----------

/// Разобрать одну ссылку.
pub fn parse_link(link: &str) -> Result<Server, String> {
    let link = link.trim();
    let scheme = link.split("://").next().unwrap_or("").to_ascii_lowercase();
    match scheme.as_str() {
        "vless" => {
            let u = parse_uri(link)?;
            if u.user.is_empty() {
                return Err(crate::tr!("VLESS без UUID", "VLESS without a UUID"));
            }
            let (stream, tr) = stream_settings(&u.query, "none")?;
            let mut settings = json!({ "address": u.host, "port": u.port, "id": u.user, "encryption": match q(&u.query, "encryption") { "" => "none", e => e } });
            if !q(&u.query, "flow").is_empty() {
                settings["flow"] = json!(q(&u.query, "flow"));
            }
            Ok(server(u.name, "vless", &u.host, u.port, tr, json!({ "protocol": "vless", "settings": settings, "streamSettings": stream })))
        }
        "trojan" => {
            let u = parse_uri(link)?;
            if u.user.is_empty() {
                return Err(crate::tr!("Trojan без пароля", "Trojan without a password"));
            }
            let (stream, tr) = stream_settings(&u.query, "tls")?;
            let settings = json!({ "servers": [{ "address": u.host, "port": u.port, "password": u.user }] });
            Ok(server(u.name, "trojan", &u.host, u.port, tr, json!({ "protocol": "trojan", "settings": settings, "streamSettings": stream })))
        }
        "vmess" => parse_vmess(link),
        "ss" => parse_ss(link),
        "socks" | "socks5" | "http" | "https" => {
            let u = parse_uri(link)?;
            let (user, pass) = match u.user.split_once(':') {
                Some((a, b)) => (a.to_string(), b.to_string()),
                // v2rayN: base64(user:pass)
                None => b64_text(&u.user).and_then(|t| t.split_once(':').map(|(a, b)| (a.to_string(), b.to_string()))).unwrap_or_default(),
            };
            let proto = if scheme.starts_with("socks") { "socks" } else { "http" };
            let mut srv = json!({ "address": u.host, "port": u.port });
            if !user.is_empty() {
                srv["users"] = json!([{ "user": user, "pass": pass }]);
            }
            let mut ob = json!({ "protocol": proto, "settings": { "servers": [srv] } });
            if scheme == "https" {
                ob["streamSettings"] = json!({ "security": "tls", "tlsSettings": { "serverName": u.host } });
            }
            Ok(server(u.name, proto, &u.host, u.port, proto.into(), ob))
        }
        "hysteria2" | "hy2" | "tuic" | "wireguard" | "wg" | "anytls" | "naive+https" => Err(crate::tr!(
            "протокол {scheme} пока не поддерживается (есть VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP)",
            "protocol {scheme} is not supported yet (VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP are)"
        )),
        _ => Err(crate::tr!("не ссылка на сервер", "not a server link")),
    }
}

fn server(name: String, protocol: &str, address: &str, port: u16, transport: String, outbound: Value) -> Server {
    let name = if name.trim().is_empty() { format!("{address}:{port}") } else { name.trim().to_string() };
    Server { name, protocol: protocol.into(), address: address.into(), port, transport, outbound, chain: Vec::new() }
}

/// `vmess://base64(JSON)` (формат v2rayN, v=2).
fn parse_vmess(link: &str) -> Result<Server, String> {
    let body = link.split_once("://").map(|x| x.1).unwrap_or("");
    let body = body.split('#').next().unwrap_or("");
    let text = b64_text(body).ok_or_else(|| crate::tr!("VMess: не base64", "VMess: not base64"))?;
    let v: Value = serde_json::from_str(&text).map_err(|_| crate::tr!("VMess: не JSON", "VMess: not JSON"))?;
    let s = |k: &str| -> String {
        match &v[k] {
            Value::String(x) => x.clone(),
            Value::Number(n) => n.to_string(),
            _ => String::new(),
        }
    };
    let port: u16 = s("port").parse().map_err(|_| crate::tr!("VMess: неверный порт", "VMess: bad port"))?;
    let host = s("add");
    if host.is_empty() || s("id").is_empty() {
        return Err(crate::tr!("VMess: нет адреса или id", "VMess: no address or id"));
    }
    let net = s("net");
    let mut query: Vec<(String, String)> = vec![
        ("type".into(), net.clone()),
        ("security".into(), s("tls")),
        ("sni".into(), s("sni")),
        ("alpn".into(), s("alpn")),
        ("fp".into(), s("fp")),
        ("host".into(), s("host")),
        ("path".into(), s("path")),
    ];
    // В VMess `type` — тип заголовка (raw: http) или режим gRPC.
    match net.as_str() {
        "grpc" => {
            query.push(("serviceName".into(), s("path")));
            query.push(("authority".into(), s("host")));
            query.push(("mode".into(), if s("type") == "multi" { "multi".into() } else { String::new() }));
        }
        "xhttp" => query.push(("mode".into(), s("type"))),
        _ => query.push(("headerType".into(), s("type"))),
    }
    let (stream, tr) = stream_settings(&query, "none")?;
    let aid: u32 = s("aid").parse().unwrap_or(0);
    let scy = match s("scy").as_str() {
        "" => "auto".to_string(),
        x => x.to_string(),
    };
    let settings = json!({ "vnext": [{ "address": host, "port": port, "users": [{ "id": s("id"), "alterId": aid, "security": scy }] }] });
    Ok(server(s("ps"), "vmess", &host, port, tr, json!({ "protocol": "vmess", "settings": settings, "streamSettings": stream })))
}

/// `ss://base64(method:pass)@host:port#name` (SIP002) или `ss://base64(method:pass@host:port)#name`.
fn parse_ss(link: &str) -> Result<Server, String> {
    let body = link.split_once("://").map(|x| x.1).unwrap_or("");
    let (body, name) = match body.split_once('#') {
        Some((b, n)) => (b, pct_decode(n)),
        None => (body, String::new()),
    };
    let body = body.split('?').next().unwrap_or("");
    if body.contains("plugin=") {
        return Err(crate::tr!("Shadowsocks с плагином не поддерживается", "Shadowsocks with a plugin is not supported"));
    }
    let (cred, hp) = match body.rsplit_once('@') {
        Some((c, h)) => {
            let c = pct_decode(c);
            let c = if c.contains(':') { c } else { b64_text(&c).ok_or_else(|| crate::tr!("Shadowsocks: не base64", "Shadowsocks: not base64"))? };
            (c, h.to_string())
        }
        None => {
            let t = b64_text(body).ok_or_else(|| crate::tr!("Shadowsocks: не base64", "Shadowsocks: not base64"))?;
            let (c, h) = t.rsplit_once('@').ok_or_else(|| crate::tr!("Shadowsocks: нет адреса", "Shadowsocks: no address"))?;
            (c.to_string(), h.to_string())
        }
    };
    let (method, password) = cred.split_once(':').ok_or_else(|| crate::tr!("Shadowsocks: нет метода или пароля", "Shadowsocks: no method or password"))?;
    let (host, port) = split_hostport(&hp).ok_or_else(|| crate::tr!("нет адреса или порта", "no address or port"))?;
    let settings = json!({ "servers": [{ "address": host, "port": port, "method": method, "password": password }] });
    Ok(server(name, "shadowsocks", &host, port, method.to_string(), json!({ "protocol": "shadowsocks", "settings": settings })))
}

// ---------- JSON-конфиги ----------

/// Сервер из полного конфига Xray: соединение `proxy` (или первое не служебное)
/// и соединения его цепочки (`sockopt.dialerProxy`).
pub fn from_config(cfg: &Value) -> Result<Server, String> {
    let obs = cfg["outbounds"].as_array().ok_or_else(|| crate::tr!("в конфиге нет outbounds", "the config has no outbounds"))?;
    let service = |o: &&Value| matches!(o["protocol"].as_str(), Some("freedom" | "blackhole" | "dns" | "loopback"));
    let main = obs
        .iter()
        .find(|o| o["tag"] == "proxy" && !service(o))
        .or_else(|| obs.iter().find(|o| !service(o)))
        .ok_or_else(|| crate::tr!("в конфиге нет соединения с сервером", "the config has no server outbound"))?;
    // Цепочка: теги из dialerProxy, рекурсивно (без циклов).
    let mut chain: Vec<Value> = Vec::new();
    let mut next = main["streamSettings"]["sockopt"]["dialerProxy"].as_str().map(String::from);
    while let Some(tag) = next.take() {
        if chain.iter().any(|c| c["tag"] == tag.as_str()) || chain.len() > 8 {
            break;
        }
        if let Some(o) = obs.iter().find(|o| o["tag"] == tag.as_str()) {
            next = o["streamSettings"]["sockopt"]["dialerProxy"].as_str().map(String::from);
            chain.push(o.clone());
        }
    }
    let mut ob = main.clone();
    if let Some(m) = ob.as_object_mut() {
        m.remove("tag");
    }
    let protocol = ob["protocol"].as_str().unwrap_or("?").to_string();
    let st = &ob["settings"];
    let first = |k: &str| st[k].as_array().and_then(|a| a.first()).cloned().unwrap_or(Value::Null);
    let srv = if st["address"].is_string() { st.clone() } else if !first("vnext").is_null() { first("vnext") } else { first("servers") };
    let address = srv["address"].as_str().unwrap_or("").to_string();
    let port = srv["port"].as_u64().unwrap_or(0) as u16;
    let ss = &ob["streamSettings"];
    let net = ss["network"].as_str().unwrap_or("raw");
    let net = if net == "tcp" { "raw" } else { net };
    let sec = ss["security"].as_str().unwrap_or("none");
    let transport = if matches!(sec, "tls" | "reality") { format!("{net}+{sec}") } else { net.to_string() };
    let name = cfg["remarks"].as_str().unwrap_or("").to_string();
    let mut s = server(name, &protocol, &address, port, transport, ob);
    s.chain = chain;
    Ok(s)
}

// ---------- подписки ----------

/// Сведения из заголовков подписки.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SubInfo {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    /// Unix-время окончания; 0 — бессрочно.
    pub expire: u64,
    /// Часы между обновлениями (Profile-Update-Interval).
    pub update_hours: u32,
    /// Profile-Title (может быть `base64:…`).
    pub title: String,
}

/// Разобрать заголовки ответа (как их печатает `curl -D`).
/// Те же сведения из комментариев в начале тела (`# profile-title: …`): так пишут
/// подписки, лежащие файлом на GitHub, где своих заголовков нет. Заголовки важнее.
pub fn fill_from_body(info: &mut SubInfo, body: &str) {
    let lines: String = body.lines().take(20).filter_map(|l| l.trim().strip_prefix('#')).map(|l| format!("{}
", l.trim())).collect();
    let b = parse_headers(&lines);
    if info.title.is_empty() {
        info.title = b.title;
    }
    if info.update_hours == 0 {
        info.update_hours = b.update_hours;
    }
}

pub fn parse_headers(raw: &str) -> SubInfo {
    let mut i = SubInfo::default();
    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "subscription-userinfo" => {
                for part in v.split(';') {
                    if let Some((a, b)) = part.split_once('=') {
                        let n: u64 = b.trim().parse().unwrap_or(0);
                        match a.trim() {
                            "upload" => i.upload = n,
                            "download" => i.download = n,
                            "total" => i.total = n,
                            "expire" => i.expire = n,
                            _ => {}
                        }
                    }
                }
            }
            "profile-update-interval" => i.update_hours = v.parse().unwrap_or(0),
            "profile-title" => {
                i.title = match v.strip_prefix("base64:") {
                    Some(b) => b64_text(b).unwrap_or_default(),
                    None => v.to_string(),
                }
            }
            _ => {}
        }
    }
    i
}

/// Серверы из тела подписки и ошибки по строкам, которые не разобрались.
pub fn parse_subscription(body: &str) -> (Vec<Server>, Vec<String>) {
    let t = body.trim().trim_start_matches('\u{feff}');
    if t.starts_with('[') || t.starts_with('{') {
        let v: Value = match serde_json::from_str(t) {
            Ok(v) => v,
            Err(e) => return (vec![], vec![crate::tr!("JSON-подписка не разобралась: {e}", "JSON subscription did not parse: {e}")]),
        };
        let list = match v {
            Value::Array(a) => a,
            o => vec![o],
        };
        let mut out = (vec![], vec![]);
        for (n, c) in list.iter().enumerate() {
            match from_config(c) {
                Ok(s) => out.0.push(s),
                Err(e) => out.1.push(format!("#{}: {e}", n + 1)),
            }
        }
        return out;
    }
    // base64 целиком или простой список ссылок.
    let text = if t.contains("://") { t.to_string() } else { b64_text(t).filter(|x| x.contains("://")).unwrap_or_else(|| t.to_string()) };
    let mut out = (vec![], vec![]);
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match parse_link(line) {
            Ok(s) => out.0.push(s),
            Err(e) => {
                let scheme = line.split("://").next().unwrap_or("?");
                out.1.push(format!("{scheme}://…: {e}"));
            }
        }
    }
    if out.0.is_empty() && out.1.is_empty() {
        out.1.push(crate::tr!("в подписке не нашлось ни одной ссылки", "no links found in the subscription"));
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn body_info() {
        let body = "# profile-title: 🏴 BLACK LISTS | Mobile-150
# profile-update-interval: 1
# Date/Time: 2026-11-27 / 12:59

vless://x@a:1#A
";
        let mut i = SubInfo::default();
        fill_from_body(&mut i, body);
        assert_eq!((i.title.as_str(), i.update_hours), ("🏴 BLACK LISTS | Mobile-150", 1));
        let mut h = SubInfo { title: "From header".into(), update_hours: 12, ..Default::default() };
        fill_from_body(&mut h, body);
        assert_eq!((h.title.as_str(), h.update_hours), ("From header", 12), "заголовки важнее");
    }

    use super::*;

    const U: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn vless_reality_xhttp() {
        let link = format!(
            "vless://{U}@ex.com:2053?encryption=mlkem768x25519plus.native.0rtt.KEY&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&fp=firefox&mode=auto&path=%2Fxhttp_reality&pbk=PUB&pqv=PQ&security=reality&sid=ab&sni=fin.example&spx=%2Fz&type=xhttp&x_padding_bytes=100-1000#%F0%9F%87%B1%F0%9F%87%BB%20Lat"
        );
        let s = parse_link(&link).unwrap();
        assert_eq!(s.name, "🇱🇻 Lat");
        assert_eq!((s.address.as_str(), s.port, s.transport.as_str()), ("ex.com", 2053, "xhttp+reality"));
        let o = &s.outbound;
        assert_eq!(o["settings"]["encryption"], "mlkem768x25519plus.native.0rtt.KEY");
        assert_eq!(o["settings"]["id"], U);
        let ss = &o["streamSettings"];
        assert_eq!(ss["xhttpSettings"]["path"], "/xhttp_reality");
        assert_eq!(ss["xhttpSettings"]["xPaddingBytes"], "100-1000");
        assert_eq!(ss["xhttpSettings"]["extra"]["xPaddingBytes"], "100-1000");
        assert_eq!(ss["realitySettings"]["publicKey"], "PUB");
        assert_eq!(ss["realitySettings"]["mldsa65Verify"], "PQ");
        assert_eq!(ss["realitySettings"]["spiderX"], "/z");
    }

    #[test]
    fn vless_tls_http_header_and_finalmask() {
        let fm = "%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%7D%5D%7D";
        let s = parse_link(&format!("vless://{U}@h.ex:6767?type=tcp&headerType=http&security=tls&sni=h.ex&alpn=h2%2Chttp%2F1.1&fm={fm}#x")).unwrap();
        let ss = &s.outbound["streamSettings"];
        assert_eq!(ss["network"], "raw");
        assert_eq!(ss["rawSettings"]["header"]["type"], "http");
        assert_eq!(ss["tlsSettings"]["alpn"], json!(["h2", "http/1.1"]));
        assert_eq!(ss["finalmask"]["tcp"][0]["type"], "fragment");
        assert_eq!(s.outbound["settings"]["encryption"], "none");
    }

    #[test]
    fn grpc_ws_trojan_ss_vmess() {
        let g = parse_link(&format!("vless://{U}@h:2087?type=grpc&serviceName=grpc_tls&security=tls&sni=h#g")).unwrap();
        assert_eq!(g.outbound["streamSettings"]["grpcSettings"]["serviceName"], "grpc_tls");
        let w = parse_link(&format!("vless://{U}@[2001:db8::1]:443?type=ws&path=%2Fws&host=a.b&security=tls#w")).unwrap();
        assert_eq!(w.address, "2001:db8::1");
        assert_eq!(w.outbound["streamSettings"]["tlsSettings"]["serverName"], "a.b");
        let t = parse_link("trojan://p%40ss@t.ex:443?sni=t.ex#t").unwrap();
        assert_eq!(t.outbound["settings"]["servers"][0]["password"], "p@ss");
        assert_eq!(t.outbound["streamSettings"]["security"], "tls");
        // SIP002 и старый формат.
        let a = parse_link("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss").unwrap();
        assert_eq!(a.outbound["settings"]["servers"][0]["method"], "aes-256-gcm");
        let b = parse_link("ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40OjgzODg=#old").unwrap();
        assert_eq!((b.address.as_str(), b.port), ("1.2.3.4", 8388));
        let vm = r#"{"v":"2","ps":"vm","add":"v.ex","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","type":"none","host":"v.ex","path":"/p","tls":"tls"}"#;
        let v = parse_link(&format!("vmess://{}", b64_encode(vm.as_bytes()))).unwrap();
        assert_eq!(v.outbound["settings"]["vnext"][0]["users"][0]["security"], "auto");
        assert_eq!(v.outbound["streamSettings"]["wsSettings"]["path"], "/p");
        assert!(parse_link("hysteria2://x@h:443").unwrap_err().contains("hysteria2"));
        assert!(parse_link(&format!("vless://{U}@h:1?type=kcp")).is_err());
    }

    #[test]
    fn subscriptions() {
        let links = format!("vless://{U}@a:1?security=none#A\nvless://{U}@b:2?type=ws#B\nhy2://x@c:3#C\n");
        let (s, e) = parse_subscription(&b64_encode(links.as_bytes()));
        assert_eq!(s.len(), 2);
        assert_eq!(e.len(), 1);
        let cfg = json!([{ "remarks": "R", "outbounds": [
            { "tag": "proxy", "protocol": "vless", "settings": { "address": "x", "port": 9, "id": U }, "streamSettings": { "network": "tcp", "security": "tls", "sockopt": { "dialerProxy": "frag" } } },
            { "tag": "frag", "protocol": "freedom", "settings": { "fragment": { "packets": "tlshello" } } },
            { "tag": "direct", "protocol": "freedom" } ] }]);
        let (s, e) = parse_subscription(&cfg.to_string());
        assert!(e.is_empty());
        assert_eq!((s[0].name.as_str(), s[0].address.as_str(), s[0].port, s[0].transport.as_str()), ("R", "x", 9, "raw+tls"));
        assert_eq!(s[0].chain.len(), 1);
        assert!(s[0].outbound.get("tag").is_none());
        let h = parse_headers("HTTP/1.1 200 OK\r\nSubscription-Userinfo: upload=1; download=2; total=30; expire=1700000000\r\nProfile-Update-Interval: 12\r\nProfile-Title: base64:0J/RgNC+0LHQsA==\r\n");
        assert_eq!((h.upload, h.download, h.total, h.expire, h.update_hours, h.title.as_str()), (1, 2, 30, 1_700_000_000, 12, "Проба"));
    }

    fn b64_encode(d: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in d.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..=c.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        s
    }
}
