//! MCP-сервер (Model Context Protocol): ИИ-ассистент пользователя (Claude,
//! Cursor и др.) может проверить, почему не открывается сайт, подобрать
//! стратегию zapret2, посмотреть журналы и поменять настройки.
//!
//! Транспорт — Streamable HTTP без потоков: `POST /mcp` с JSON-RPC, ответ
//! `application/json`. Слушаем только 127.0.0.1, нужен заголовок
//! `Authorization: Bearer <токен>`; запросы с чужим `Origin` отклоняются
//! (защита от DNS rebinding из браузера). Сервер выключен по умолчанию,
//! изменения (включить, применить, правка списков) — отдельным разрешением.

use crate::{tr, AppState, R};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

pub const PROTOCOL: &str = "2025-06-18";
const MAX_BODY: usize = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub enabled: bool,
    pub port: u16,
    pub token: String,
    /// Разрешить ассистенту менять настройки (иначе — только чтение и проверки).
    pub allow_changes: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { enabled: false, port: 8899, token: String::new(), allow_changes: false }
    }
}

pub fn new_token() -> String {
    let mut b = [0u8; 24];
    let _ = getrandom::getrandom(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub struct Server {
    stop: Arc<AtomicBool>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.accept.take() {
            let _ = t.join();
        }
    }
}

pub fn start(app: AppHandle, s: &Settings) -> R<Server> {
    let port = s.port;
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| tr!("порт {port} занят: {e}", "port {port} is busy: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let token = s.token.clone();
    let st = stop.clone();
    let accept = std::thread::spawn(move || {
        while !st.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((c, _)) => {
                    let (app, token) = (app.clone(), token.clone());
                    std::thread::spawn(move || {
                        let _ = c.set_nonblocking(false);
                        let _ = serve(&token, c, &|req: &Value| handle(&app, req));
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    });
    Ok(Server { stop, accept: Some(accept) })
}

fn respond(mut c: &TcpStream, code: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    write!(c, "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    c.write_all(body)?;
    c.flush()
}

fn local_origin(o: &str) -> bool {
    let o = o.trim().to_ascii_lowercase();
    ["http://127.0.0.1", "http://localhost", "https://127.0.0.1", "https://localhost"].iter().any(|p| o == *p || o.starts_with(&format!("{p}:")))
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn serve(token: &str, c: TcpStream, handler: &dyn Fn(&Value) -> Option<Value>) -> std::io::Result<()> {
    c.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut r = BufReader::new(c.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
    let (mut len, mut auth, mut origin) = (0usize, String::new(), None::<String>);
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().unwrap_or(0),
                "authorization" => auth = v.trim().to_string(),
                "origin" => origin = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    // Тело читаем до любых ответов: если закрыть соединение с непрочитанными
    // данными, Windows шлёт RST и клиент не увидит ответ.
    if len > MAX_BODY {
        return respond(&c, "413 Payload Too Large", "text/plain", b"too large");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    if origin.as_deref().is_some_and(|o| !local_origin(o)) {
        return respond(&c, "403 Forbidden", "text/plain", b"origin not allowed");
    }
    if !path.starts_with("/mcp") {
        return respond(&c, "404 Not Found", "text/plain", b"use /mcp");
    }
    if method != "POST" {
        return respond(&c, "405 Method Not Allowed", "text/plain", b"POST only");
    }
    let given = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")).unwrap_or("");
    if token.is_empty() || !same(given, token) {
        return respond(&c, "401 Unauthorized", "text/plain", b"bad token");
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let err = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":e.to_string()}});
            return respond(&c, "400 Bad Request", "application/json", err.to_string().as_bytes());
        }
    };
    let out = match req {
        Value::Array(items) => {
            let v: Vec<Value> = items.iter().filter_map(handler).collect();
            (!v.is_empty()).then_some(Value::Array(v))
        }
        one => handler(&one),
    };
    match out {
        Some(v) => respond(&c, "200 OK", "application/json", v.to_string().as_bytes()),
        // Уведомления и ответы клиента — без тела.
        None => respond(&c, "202 Accepted", "text/plain", b""),
    }
}

/// Один JSON-RPC запрос; None — для уведомлений.
pub fn handle(app: &AppHandle, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned()?;
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let ok = |result: Value| Some(json!({"jsonrpc":"2.0","id":id,"result":result}));
    let err = |code: i64, msg: &str| Some(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}}));
    match method {
        "initialize" => {
            let v = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or(PROTOCOL);
            let v = if ["2025-06-18", "2025-03-26", "2024-11-05"].contains(&v) { v } else { PROTOCOL };
            ok(json!({
                "protocolVersion": v,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "digital-bypass", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" => ok(json!({})),
        "tools/list" => ok(json!({"tools": tools()})),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let r = call(app, name, &args);
            let _ = app.emit("mcp-call", name);
            ok(match r {
                Ok(v) => json!({"content":[{"type":"text","text": serde_json::to_string_pretty(&v).unwrap_or_default()}], "structuredContent": v, "isError": false}),
                Err(e) => json!({"content":[{"type":"text","text": e}], "isError": true}),
            })
        }
        _ => err(-32601, "method not found"),
    }
}

const INSTRUCTIONS: &str = "digital-bypass is a Windows censorship-circumvention tool (zapret2/winws2 DPI bypass, a local bypass proxy, DNS/DoH, Telegram proxy). \
Typical flow for 'site X does not open': call diagnose_site(X) first; it tells whether the block is DNS spoofing, DPI on the site name (and at which stage), or an IP block. \
For DPI blocks call find_zapret_strategy(X) (it needs admin rights and takes up to a few minutes) or suggest the proxy. IP blocks cannot be fixed by zapret or the proxy splitting: suggest Xray if the user has a server or subscription (xray_control start, then add_domains_to_list list=proxy_xray), Tor (tor_control start, then add_domains_to_list list=proxy_tor; if Tor cannot connect, find_tor_bridges first), the user's Cloudflare Worker route, or a VPN. \
Tools that change settings fail unless the user enabled 'allow changes' in the app's MCP settings; then explain how to enable it instead of retrying.";

fn tool(name: &str, desc: &str, props: Value, required: &[&str]) -> Value {
    json!({"name": name, "description": desc, "inputSchema": {"type":"object","properties": props, "required": required}})
}

fn tools() -> Vec<Value> {
    let dom = json!({"type":"string","description":"Domain or URL, e.g. youtube.com"});
    vec![
        tool("get_status", "Current state: zapret2 (running, strategy, mode, errors), bypass proxy, Telegram proxy, DoH resolver, per-network rule, admin rights, whether changes are allowed.", json!({}), &[]),
        tool("diagnose_site", "Why a site does not open: compares system DNS with DoH, tries TCP and TLS to each address (twice), detects DNS spoofing / DPI on the site name / IP blocking, the DPI stage (request or server reply) and whether splitting the ClientHello helps. Returns a verdict and concrete advice. Read-only, ~5-20 s.", json!({"domain": dom}), &["domain"]),
        tool("find_zapret_strategy", "Find a zapret2 strategy that opens a given site: runs winws2 with each strategy and checks HTTPS to the site. Strategies that did best in the last full test go first; stops after `want` fully working ones. Needs admin rights; takes from 30 s to a few minutes. If the domain is not in the zapret lists it must be added (add_to_list, needs 'allow changes'). With apply=true the best strategy is selected and zapret2 is turned on.", json!({
            "domain": dom,
            "add_to_list": {"type":"boolean","description":"Add the domain to list-general-user.txt if it is not covered (default true)"},
            "apply": {"type":"boolean","description":"Select the best strategy and enable zapret2 (default false)"},
            "want": {"type":"integer","description":"Stop after this many fully working strategies (default 1)"},
            "timeout": {"type":"integer","description":"Seconds per check (default 4)"}
        }), &["domain"]),
        tool("list_strategies", "zapret2 strategies with their techniques, the selected one and the running one.", json!({}), &[]),
        tool("get_last_test_results", "Results of the last full strategy test: ranking, the ceiling (checks that failed with every strategy, likely IP blocks).", json!({"top": {"type":"integer","description":"How many strategies to return (default 8)"}}), &[]),
        tool("zapret_control", "Turn zapret2 on/off or select a strategy (restarts it if running). Needs 'allow changes' and admin rights.", json!({
            "action": {"type":"string","enum":["enable","disable","select"]},
            "strategy": {"type":"string","description":"Strategy file for action=select, e.g. 'general (ALT4).bat'"}
        }), &["action"]),
        tool("proxy_control", "Start or stop the bypass proxy (no admin rights needed). Needs 'allow changes'.", json!({"action":{"type":"string","enum":["start","stop"]}}), &["action"]),
        tool("proxy_set_options", "Change bypass proxy settings (restarts it if running). Keys: split (sni|first-byte|chunk|random|custom|none), unit (records|tcp|mixed), disorder, oob, auto, doh, system, ipv6, log, rcvbuf (bytes, 0 = off), port. Needs 'allow changes'.", json!({"options":{"type":"object"}}), &["options"]),
        tool("add_domains_to_list", "Add domains to a list: zapret (zapret2 hostlist), zapret_exclude (never touch), proxy_bypass (proxy splits only these when scope=listed), proxy_skip (proxy passes as is), proxy_block, proxy_tor (through Tor while it is connected; .onion always goes there), proxy_xray (through the user's Xray server while Xray runs), proxy_worker (through the user's Cloudflare Worker — for IP-blocked or geo-restricted sites; works only if the Worker is set up in the proxy tab). Needs 'allow changes'.", json!({
            "domains": {"type":"array","items":{"type":"string"}},
            "list": {"type":"string","enum":["zapret","zapret_exclude","proxy_bypass","proxy_skip","proxy_block","proxy_worker","proxy_tor","proxy_xray"]}
        }), &["domains","list"]),
        tool("get_proxy_log", "Recent bypass proxy connections: host, what was done, method, attempts, result. The connection log must be enabled in proxy settings.", json!({
            "limit": {"type":"integer","description":"Default 50"},
            "only_failed": {"type":"boolean"}
        }), &[]),
        tool("get_zapret_log", "Last lines of winws2 output (errors, startup problems).", json!({"lines": {"type":"integer","description":"Default 80"}}), &[]),
        tool("tor_control", "Tor: start, stop, status (bootstrap %, current transport tier, last error, recent log) or new_identity (fresh circuits). Starting uses the saved transport (auto tries found/own bridges, then built-in obfs4, snowflake, meek); bootstrap takes 10 s to a few minutes. Tor gives a SOCKS5 proxy and serves the bypass proxy's 'through Tor' domains. It bypasses blocks, it is not anonymity for the browser. start/stop/new_identity need 'allow changes'.", json!({
            "action": {"type":"string","enum":["start","stop","status","new_identity","set_scope"]},
            "scope": {"type":"string","enum":["list","zapret","all"],"description":"For set_scope: what the bypass proxy sends through Tor besides .onion — only the Tor domain list, plus zapret2 list domains, or all traffic (except the proxy's skip and Worker lists)"},
            "transport": {"type":"string","enum":["auto","obfs4","webtunnel","snowflake","meek","custom","direct"],"description":"Optional for start: save and use this transport"}
        }), &["action"]),
        tool("xray_control", "Xray (VLESS/VMess/Trojan/Shadowsocks client with the user's own servers): status, start, stop, test (real latency through every server), select (a server id or 'auto' — the balancer picks the fastest), update_subscriptions, set_scope. Russian sites and addresses go direct (geosite:category-ru, geoip:ru) unless the user turned it off. Gives SOCKS5/HTTP on 127.0.0.1:port and serves the bypass proxy's 'through Xray' domains. All actions except status need 'allow changes'. Never print subscription URLs or server UUIDs back to the user.", json!({
            "action": {"type":"string","enum":["status","start","stop","test","select","update_subscriptions","set_scope"]},
            "server": {"type":"string","description":"For select: a server id from status, or 'auto'"},
            "scope": {"type":"string","enum":["list","zapret","all"],"description":"For set_scope: what the bypass proxy sends through Xray — its domain list only, plus zapret2 list domains, or all traffic"}
        }), &["action"]),
        tool("find_tor_bridges", "Find working Tor bridges: downloads fresh obfs4/webtunnel lists, TCP-checks them and verifies each through lyrebird up to the Tor relay's TLS reply. Found bridges are saved and used first. ~30-90 s. Needs 'allow changes'.", json!({
            "want": {"type":"integer","description":"How many bridges to find (default 8)"},
            "kinds": {"type":"array","items":{"type":"string","enum":["obfs4","webtunnel"]},"description":"Default both"}
        }), &[]),
        tool("dns_check", "Does the ISP tamper with DNS: interception of queries to public resolvers and spoofed answers for given domains (compared with DoT).", json!({"domains":{"type":"array","items":{"type":"string"}}}), &[]),
    ]
}

fn arg_str<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(|v| v.as_str())
}

fn need_changes(st: &AppState) -> R<()> {
    if st.settings.lock().unwrap().mcp.allow_changes {
        Ok(())
    } else {
        Err("Changes are disabled. Ask the user to enable 'Allow changes' in digital-bypass → Settings → MCP, or tell them what to change by hand.".into())
    }
}

fn to_value<T: Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// Домен покрыт списками zapret2 (сам или родитель).
fn in_lists(lists: &[String], domain: &str) -> bool {
    let d = domain.trim_start_matches("www.");
    lists.iter().any(|l| {
        let l = l.trim().trim_start_matches("*.").to_ascii_lowercase();
        !l.is_empty() && (d == l || d.ends_with(&format!(".{l}")) || domain == l)
    })
}

fn advice(r: &crate::diag::Report, in_zapret: Option<bool>) -> String {
    use crate::diag::{Stage, Verdict};
    let mut s = match r.verdict {
        Verdict::Ok => "The site opens from this machine. If it still fails in the browser, check the browser's own DNS/proxy settings or QUIC (UDP), which only zapret2 bypasses.".to_string(),
        Verdict::Dns => "DNS spoofing by the ISP: the system DNS returns a stub or a wrong address, while DoH addresses work. Fix: switch DNS in the DNS tab (or enable the local DoH/DoT resolver), or use the bypass proxy with DoH on.".to_string(),
        Verdict::Ip => "IP block: TCP to every address fails. zapret2 and proxy splitting cannot help. Options: a VPN with a server abroad, or the bypass proxy's route through the user's own Cloudflare Worker (add_domains_to_list list=proxy_worker; the Worker must be set up in the proxy tab; not for sites hosted on Cloudflare).".to_string(),
        Verdict::DestNet => "Destination-network restriction, not a block by site name: either TLS to this address fails with ANY site name while this name passes on other addresses, or TLS works but the connection freezes after a few packets (~16-33 KB at home, less on mobile) without a reset. Since 2025 this hits foreign hostings by AS (Hetzner, OVH, DigitalOcean, Vultr, Scaleway, M247...). ClientHello splitting (zapret2, proxy) does not help; a UDP-based transport or a server in another network does.".to_string(),
        Verdict::NoDomain => "The domain does not resolve anywhere — check the spelling.".to_string(),
        Verdict::Unknown => "Could not determine the cause; see the per-address checks.".to_string(),
        Verdict::Dpi => match r.stage {
            Some(Stage::Response) => "DPI cuts the server's reply (certificate). Splitting the request usually does not help; try zapret2 strategies (find_zapret_strategy) or the proxy's experimental small receive buffer (proxy_set_options rcvbuf=2048).".to_string(),
            _ => "DPI blocks by the site name in the TLS ClientHello. zapret2 (find_zapret_strategy) or the bypass proxy can fix it.".to_string(),
        },
    };
    if let Some(x) = &r.extra {
        if x.split_ok == Some(true) {
            s.push_str(" A split ClientHello opens the site — the bypass proxy will work (proxy_control start).");
        }
        if x.small_buf_ok == Some(true) {
            s.push_str(" A small receive buffer helped — set proxy rcvbuf=2048.");
        }
        if x.ip_clean == Some(false) {
            s.push_str(" The address is cut even with another name: partial IP block.");
        }
    }
    if r.verdict == crate::diag::Verdict::Dpi && in_zapret == Some(false) {
        s.push_str(" The domain is NOT in the zapret2 lists, so zapret2 ignores it — add it first (add_domains_to_list list=zapret, or find_zapret_strategy add_to_list=true).");
    }
    if let Some(p) = &r.via_proxy {
        let direct_ok = r.verdict == crate::diag::Verdict::Ok;
        match (direct_ok, p.result == crate::diag::Probe::Ok) {
            (false, true) => s.push_str(" Through the running bypass proxy the site OPENS — the proxy fixes it (the browser must use the proxy)."),
            (true, false) => s.push_str(" The site opens directly but NOT through the running bypass proxy — the proxy breaks it; add it to proxy_skip."),
            (false, false) => s.push_str(" It does not open through the running bypass proxy either."),
            _ => {}
        }
    }
    if let Some(sn) = r.extra.as_ref().and_then(|x| x.sni_pass.as_ref()) {
        if sn.is_empty() {
            s.push_str(" No candidate SNI passes to this address either.");
        } else {
            s.push_str(&format!(" With these SNI names the address still answers: {} — a VLESS+Reality server on this network with such an SNI may work.", sn.join(", ")));
        }
    }
    if r.checks.iter().any(|c| c.unstable) {
        s.push_str(" Repeated checks disagreed: the ISP balances traffic or runs several DPIs.");
    }
    s
}

pub fn call(app: &AppHandle, name: &str, a: &Value) -> Result<Value, String> {
    let st = app.state::<AppState>();
    match name {
        "get_status" => {
            let ov = crate::overview_of(&st);
            let px = crate::proxy_status_of(&st);
            let tg = crate::tg_status_of(&st);
            let net = crate::net_status_of(&st);
            let stub = crate::stub_status_of(&st);
            let mcp = st.settings.lock().unwrap().mcp.clone();
            let tor = crate::tor_status_of(&st);
            let xr = crate::xray_status_of(&st);
            Ok(json!({
                "xray": {"running": xr.status.running, "socks_http": format!("127.0.0.1:{}", xr.port), "server": xr.status.server, "servers": xr.servers.len(), "subscriptions": xr.subs.len(), "ru_direct": xr.routing.ru_direct, "domains_through_xray": xr.domains, "xray_scope": xr.scope, "error": xr.status.error},
                "tor": {"running": tor.status.running, "connected": tor.status.ready, "bootstrap_percent": tor.status.percent, "socks": format!("127.0.0.1:{}", tor.config.socks_port), "transport": tor.config.transport, "domains_through_tor": tor.domains, "tor_scope": tor.tor_scope},
                "admin": ov.admin,
                "zapret2": {"status": to_value(&ov.status), "selected_strategy": ov.selected, "mode": ov.mode, "build_found": ov.dir.is_some(), "testing": ov.testing},
                "proxy": {"running": px.stats.running, "address": format!("127.0.0.1:{}", px.config.port), "config": to_value(&px.config), "stats": to_value(&px.stats)},
                "telegram_proxy": {"running": tg.stats.running, "port": tg.config.port},
                "doh_resolver": to_value(&stub),
                "network_rule": to_value(&net),
                "mcp_allow_changes": mcp.allow_changes,
            }))
        }
        "diagnose_site" => {
            let d = arg_str(a, "domain").ok_or("domain is required")?;
            let r = crate::diag::run_with(d, crate::proxy_port_if_running(&st))?;
            let in_zapret = st.dir().ok().map(|dir| in_lists(&crate::lists::bypass_domains(&dir), &r.domain));
            Ok(json!({"advice": advice(&r, in_zapret), "in_zapret_lists": in_zapret, "report": to_value(&r)}))
        }
        "find_zapret_strategy" => find_strategy(app, a),
        "list_strategies" => {
            let ov = crate::overview_of(&st);
            Ok(json!({
                "selected": ov.selected,
                "running": ov.status.running.then_some(ov.status.strategy.clone()).flatten(),
                "strategies": ov.strategies.iter().map(|s| json!({"file": s.file, "techniques": s.methods})).collect::<Vec<_>>(),
            }))
        }
        "get_last_test_results" => {
            let top = a.get("top").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            let g = st.last_test.lock().unwrap();
            let Some(t) = g.as_ref() else { return Ok(json!({"message": "No strategy test has been run yet."})) };
            let mut rs: Vec<&crate::tester::StrategyResult> = t.results.iter().filter(|r| r.started).collect();
            rs.sort_by(|a, b| b.ok.cmp(&a.ok));
            let (_, ceiling) = crate::evolve::baseline_from(t, &t.kind, &[]);
            let total = rs.first().map(|r| r.ok + r.fail + r.unsup + r.blocked).unwrap_or(0);
            Ok(json!({
                "kind": t.kind, "finished": t.finished, "best": t.best,
                "checks_per_strategy": total,
                "ceiling": ceiling,
                "ceiling_note": "checks that passed with at least one strategy; the rest fail with every strategy (likely IP blocks)",
                "ranking": rs.iter().take(top).map(|r| json!({"strategy": r.file, "ok": r.ok, "fail": r.fail, "unsupported": r.unsup, "blocked": r.blocked})).collect::<Vec<_>>(),
            }))
        }
        "zapret_control" => {
            need_changes(&st)?;
            match arg_str(a, "action").unwrap_or("") {
                "enable" => st.apply()?,
                "disable" => st.disable()?,
                "select" => {
                    let f = arg_str(a, "strategy").ok_or("strategy is required")?;
                    crate::select_strategy(app.clone(), app.state(), f.to_string())?;
                }
                _ => return Err("action must be enable, disable or select".into()),
            }
            notify(app);
            Ok(to_value(st.runner.status()))
        }
        "proxy_control" => {
            need_changes(&st)?;
            let r = match arg_str(a, "action").unwrap_or("") {
                "start" => {
                    let cfg = st.settings.lock().unwrap().proxy.clone();
                    crate::proxy_start(app.clone(), app.state(), cfg)?
                }
                "stop" => crate::proxy_stop(app.clone(), app.state()),
                _ => return Err("action must be start or stop".into()),
            };
            notify(app);
            Ok(json!({"running": r.stats.running, "address": format!("127.0.0.1:{}", r.config.port)}))
        }
        "proxy_set_options" => {
            need_changes(&st)?;
            let opts = a.get("options").and_then(|o| o.as_object()).ok_or("options object is required")?;
            let mut cur = to_value(st.settings.lock().unwrap().proxy.clone());
            for (k, v) in opts {
                if k == "rules" || k == "user" || k == "pass" {
                    return Err(format!("'{k}' cannot be changed here (use add_domains_to_list / the app)"));
                }
                cur[k] = v.clone();
            }
            let cfg: crate::proxy::Config = serde_json::from_value(cur).map_err(|e| e.to_string())?;
            let r = crate::proxy_set_config(app.clone(), app.state(), cfg)?;
            notify(app);
            Ok(json!({"running": r.stats.running, "config": to_value(&r.config)}))
        }
        "add_domains_to_list" => {
            need_changes(&st)?;
            let list = arg_str(a, "list").unwrap_or("");
            let domains: Vec<String> = a
                .get("domains")
                .and_then(|d| d.as_array())
                .map(|v| v.iter().filter_map(|x| x.as_str()).filter_map(|d| crate::diag::normalize(d).ok()).collect())
                .unwrap_or_default();
            if domains.is_empty() {
                return Err("no valid domains".into());
            }
            let added = add_to(app, list, &domains)?;
            notify(app);
            Ok(json!({"list": list, "added": added}))
        }
        "get_proxy_log" => {
            let limit = a.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let failed = a.get("only_failed").and_then(|v| v.as_bool()).unwrap_or(false);
            let enabled = st.settings.lock().unwrap().proxy.log;
            let log: Vec<crate::proxy::LogEntry> = crate::proxy_log(app.state()).into_iter().filter(|e| !failed || !e.ok).take(limit).collect();
            Ok(json!({"log_enabled": enabled, "entries": to_value(log)}))
        }
        "get_zapret_log" => {
            let n = a.get("lines").and_then(|v| v.as_u64()).unwrap_or(80) as usize;
            Ok(json!({"lines": st.runner.log_tail(n.min(500))}))
        }
        "dns_check" => {
            let d: Vec<String> = a.get("domains").and_then(|d| d.as_array()).map(|v| v.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            let d = if d.is_empty() { crate::dnscheck::DEFAULT_DOMAINS.iter().map(|s| s.to_string()).collect() } else { d };
            Ok(to_value(crate::dnscheck::run(&d)))
        }
        "tor_control" => {
            let action = arg_str(a, "action").unwrap_or("");
            if action != "status" {
                need_changes(&st)?;
            }
            match action {
                "start" => {
                    let mut cfg = st.settings.lock().unwrap().tor.clone();
                    if let Some(t) = arg_str(a, "transport") {
                        cfg.transport = t.into();
                    }
                    crate::tor_start(app.clone(), app.state(), cfg)?;
                }
                "stop" => {
                    crate::tor_stop(app.clone(), app.state());
                }
                "new_identity" => crate::tor_new_identity(app.state())?,
                "set_scope" => {
                    let sc = arg_str(a, "scope").filter(|s| crate::proxy::TOR_SCOPES.contains(s)).ok_or("scope must be list, zapret or all")?;
                    let d = st.settings.lock().unwrap().proxy.rules.tor.clone();
                    crate::tor_set_domains(app.clone(), app.state(), d, Some(sc.into()))?;
                }
                "status" => {}
                _ => return Err("action must be start, stop, status, new_identity or set_scope".into()),
            }
            let _ = app.emit("tor-changed", ());
            let t = crate::tor_status_of(&st);
            let log: Vec<String> = crate::tor_log(app.state()).into_iter().rev().take(25).collect();
            Ok(json!({"status": to_value(&t.status), "transport": t.config.transport, "tor_scope": t.tor_scope, "found_bridges": t.config.found.len(), "own_bridges": t.config.bridges.len(), "domains_through_tor": t.domains, "log_tail": log}))
        }
        "xray_control" => {
            let action = arg_str(a, "action").unwrap_or("");
            if action != "status" {
                need_changes(&st)?;
            }
            match action {
                "start" => {
                    crate::xray_start(app.clone(), app.state())?;
                }
                "stop" => {
                    crate::xray_stop(app.clone(), app.state());
                }
                "test" => {
                    crate::xray_test(app.state())?;
                }
                "update_subscriptions" => {
                    crate::xray_sub_update(app.state(), None)?;
                }
                "select" => {
                    let id = arg_str(a, "server").ok_or("server is required")?.to_string();
                    let c = st.settings.lock().unwrap().xray.clone();
                    crate::xray_set(app.state(), c.port, id, c.routing, c.fragment)?;
                }
                "set_scope" => {
                    let sc = arg_str(a, "scope").filter(|s| crate::proxy::TOR_SCOPES.contains(s)).ok_or("scope must be list, zapret or all")?;
                    let d = st.settings.lock().unwrap().proxy.rules.xray.clone();
                    crate::xray_set_domains(app.clone(), app.state(), d, Some(sc.into()))?;
                }
                "status" => {}
                _ => return Err("action must be status, start, stop, test, select, update_subscriptions or set_scope".into()),
            }
            let _ = app.emit("xray-changed", ());
            let x = crate::xray_status_of(&st);
            let servers: Vec<Value> = x
                .servers
                .iter()
                .map(|e| json!({"id": e.id, "name": e.name, "transport": e.transport, "ms": x.pings.get(&e.id).and_then(|p| p.ms), "error": x.pings.get(&e.id).and_then(|p| p.error.clone())}))
                .collect();
            let subs: Vec<Value> = x.subs.iter().map(|s| json!({"name": s.name, "updated": s.updated, "error": s.error, "expire": s.info.expire, "used_bytes": s.info.upload + s.info.download, "total_bytes": s.info.total})).collect();
            Ok(json!({"status": to_value(&x.status), "selected": x.selected, "servers": servers, "subscriptions": subs, "routing": to_value(&x.routing), "domains_through_xray": x.domains, "xray_scope": x.scope}))
        }
        "find_tor_bridges" => {
            need_changes(&st)?;
            let want = a.get("want").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            let kinds: Vec<String> = a.get("kinds").and_then(|d| d.as_array()).map(|v| v.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            let kinds = if kinds.is_empty() { vec!["obfs4".into(), "webtunnel".into()] } else { kinds };
            let r = crate::tor_find_bridges(app.clone(), app.state(), kinds, want)?;
            let _ = app.emit("tor-changed", ());
            Ok(json!({"found": r.found.iter().map(|f| json!({"transport": f.transport, "ms": f.ms})).collect::<Vec<_>>(), "checked": r.checked, "candidates": r.candidates, "seconds": r.secs, "errors": r.errors, "note": "Saved; Tor uses them first (restart Tor to apply if it is running)."}))
        }
        _ => Err(format!("unknown tool {name}")),
    }
}

fn notify(app: &AppHandle) {
    let _ = app.emit("proxy-changed", ());
    let st = app.state::<AppState>().runner.status();
    let _ = app.emit("status", &st);
    crate::refresh_tray(app);
}

fn add_to(app: &AppHandle, list: &str, domains: &[String]) -> R<Vec<String>> {
    let st = app.state::<AppState>();
    match list {
        "zapret" | "zapret_exclude" => {
            let kind = if list == "zapret" { "general" } else { "exclude" };
            let dir = st.dir()?;
            let text = crate::lists::read(&dir, kind)?;
            let have: Vec<String> = text.lines().map(|l| l.trim().to_ascii_lowercase()).collect();
            let added: Vec<String> = domains.iter().filter(|d| !have.contains(d)).cloned().collect();
            if !added.is_empty() {
                let content = format!("{}\n{}", text.trim_end(), added.join("\n"));
                crate::list_write(app.state(), kind.into(), content)?;
            }
            Ok(added)
        }
        "proxy_xray" => {
            let mut have = st.settings.lock().unwrap().proxy.rules.xray.clone();
            let added: Vec<String> = domains.iter().filter(|d| !have.contains(d)).cloned().collect();
            have.extend(added.iter().cloned());
            crate::xray_set_domains(app.clone(), app.state(), have, None)?;
            Ok(added)
        }
        "proxy_tor" => {
            let mut have = st.settings.lock().unwrap().proxy.rules.tor.clone();
            let added: Vec<String> = domains.iter().filter(|d| !have.contains(d)).cloned().collect();
            have.extend(added.iter().cloned());
            crate::tor_set_domains(app.clone(), app.state(), have, None)?;
            Ok(added)
        }
        "proxy_bypass" | "proxy_skip" | "proxy_block" | "proxy_worker" => {
            let mut cfg = st.settings.lock().unwrap().proxy.clone();
            let v = match list {
                "proxy_bypass" => &mut cfg.rules.bypass,
                "proxy_skip" => &mut cfg.rules.skip,
                "proxy_worker" => &mut cfg.rules.worker,
                _ => &mut cfg.rules.block,
            };
            let added: Vec<String> = domains.iter().filter(|d| !v.contains(d)).cloned().collect();
            v.extend(added.iter().cloned());
            crate::proxy_set_config(app.clone(), app.state(), cfg)?;
            Ok(added)
        }
        _ => Err("list must be zapret, zapret_exclude, proxy_bypass, proxy_skip, proxy_block, proxy_worker, proxy_tor or proxy_xray".into()),
    }
}

/// Подбор стратегии под один сайт.
fn find_strategy(app: &AppHandle, a: &Value) -> Result<Value, String> {
    let st = app.state::<AppState>();
    st.require_admin()?;
    let domain = crate::diag::normalize(arg_str(a, "domain").ok_or("domain is required")?)?;
    let dir = st.dir()?;
    let add = a.get("add_to_list").and_then(|v| v.as_bool()).unwrap_or(true);
    let apply = a.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    let want = a.get("want").and_then(|v| v.as_u64()).unwrap_or(1).clamp(1, 30) as usize;
    let timeout = a.get("timeout").and_then(|v| v.as_u64()).unwrap_or(4).clamp(2, 15) as u32;
    if apply {
        need_changes(&st)?;
    }
    let mut added = false;
    if !in_lists(&crate::lists::bypass_domains(&dir), &domain) {
        if !add {
            return Err(format!("{domain} is not in the zapret2 lists, so zapret2 ignores it; call again with add_to_list=true"));
        }
        need_changes(&st).map_err(|e| format!("{domain} is not in the zapret2 lists and must be added first. {e}"))?;
        add_to(app, "zapret", std::slice::from_ref(&domain))?;
        added = true;
    }
    if st.testing.swap(true, Ordering::SeqCst) {
        return Err("A strategy test is already running in the app".into());
    }
    st.cancel.store(false, Ordering::SeqCst);
    let result = (|| -> Result<Value, String> {
        // Порядок: лучшие в последнем тесте — первыми.
        let mut files: Vec<String> = crate::strategy::list(&dir).into_iter().map(|s| s.file).collect();
        if let Some(t) = st.last_test.lock().unwrap().as_ref() {
            let score = |f: &String| t.results.iter().find(|r| &r.file == f).map(|r| r.ok).unwrap_or(0);
            files.sort_by_key(|f| std::cmp::Reverse(score(f)));
        }
        let gf = crate::game_filter::load(&dir);
        let ctx = crate::tester::Ctx { dir: &dir, runner: &st.runner, cancel: &st.cancel, game_vars: crate::game_filter::vars(&gf) };
        let params = crate::tester::Params { timeout, parallel: 3 };
        let bench = crate::tester::Bench::open_urls(&ctx, params, vec![(domain.clone(), format!("https://{domain}/"))])?;
        let mut rows = Vec::new();
        let mut full = 0;
        for f in &files {
            if st.cancel.load(Ordering::Relaxed) {
                break;
            }
            let args = crate::strategy::build_args(&dir, f, &bench.vars);
            let r = bench.eval(&ctx, f, args, None, |_| {});
            let total = r.ok + r.fail + r.unsup + r.blocked;
            if r.error.is_none() && r.ok > 0 && r.ok == total {
                full += 1;
            }
            rows.push(json!({"strategy": f, "ok": r.ok, "of": total, "error": r.error, "checks": r.targets.first().map(|t| to_value(&t.checks))}));
            if full >= want {
                break;
            }
        }
        bench.close(&ctx);
        rows.sort_by(|x, y| y["ok"].as_u64().cmp(&x["ok"].as_u64()));
        let best = rows.first().filter(|r| r["ok"].as_u64().unwrap_or(0) > 0).and_then(|r| r["strategy"].as_str()).map(String::from);
        Ok(json!({"domain": domain, "added_to_list": added, "tested": rows.len(), "of_strategies": files.len(), "best": best, "results": rows}))
    })();
    st.testing.store(false, Ordering::SeqCst);
    let mut v = result?;
    if apply {
        if let Some(best) = v["best"].as_str().map(String::from) {
            crate::select_strategy(app.clone(), app.state(), best.clone())?;
            if !st.runner.status().running {
                st.apply()?;
            }
            v["applied"] = json!(best);
        }
    }
    notify(app);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTP-слой: токен, Origin, уведомления, ответы.
    #[test]
    fn http_layer() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let _ = serve("tok", c, &|r: &Value| r.get("id").map(|id| json!({"jsonrpc":"2.0","id":id,"result":{"echo":r["method"]}})));
            }
        });
        let send = |auth: &str, origin: &str, body: &str| -> String {
            let mut c = TcpStream::connect(addr).unwrap();
            let head = |h: &str| if h.is_empty() { String::new() } else { format!("{h}\r\n") };
            write!(c, "POST /mcp HTTP/1.1\r\nHost: x\r\n{}{}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", head(auth), head(origin), body.len()).unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).unwrap();
            out
        };
        let call = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let tok = "Authorization: Bearer tok";
        assert!(send("", "", call).starts_with("HTTP/1.1 401"));
        assert!(send("Authorization: Bearer bad", "", call).starts_with("HTTP/1.1 401"));
        assert!(send(tok, "Origin: http://evil.com", call).starts_with("HTTP/1.1 403"));
        let ok = send(tok, "Origin: http://localhost:5173", call);
        assert!(ok.starts_with("HTTP/1.1 200") && ok.contains(r#""echo":"ping""#), "{ok}");
        let note = send(tok, "", r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(note.starts_with("HTTP/1.1 202"));
        let batch = send(tok, "", &format!("[{call},{call}]"));
        assert!(batch.contains(r#"[{"#));
    }

    #[test]
    fn origins() {
        assert!(local_origin("http://localhost:3000"));
        assert!(local_origin("http://127.0.0.1"));
        assert!(!local_origin("http://evil.com"));
        assert!(!local_origin("http://localhost.evil.com"));
    }

    #[test]
    fn list_cover() {
        let l = vec!["youtube.com".to_string(), "*.discord.gg".to_string()];
        assert!(in_lists(&l, "www.youtube.com"));
        assert!(in_lists(&l, "i.ytimg.youtube.com"));
        assert!(in_lists(&l, "discord.gg"));
        assert!(!in_lists(&l, "notyoutube.com"));
    }

    #[test]
    fn tool_schemas() {
        let t = tools();
        assert!(t.len() >= 10);
        for x in &t {
            assert!(x["name"].is_string() && x["inputSchema"]["type"] == "object");
        }
    }

    #[test]
    fn constant_time_compare() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "ab"));
    }
}
