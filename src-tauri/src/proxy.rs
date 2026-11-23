//! Обход DPI без прав администратора и без драйвера: локальный прокси.
//!
//! Один порт принимает и HTTP (CONNECT и обычные запросы), и SOCKS5 — протокол
//! определяется по первому байту. Браузер (или вся система через настройки
//! прокси Windows) открывает через него туннели. С `lan` прокси слушает все
//! интерфейсы и пускает только адреса локальной сети — телефон в той же Wi-Fi
//! может пользоваться обходом ПК. Первый пакет туннеля — TLS ClientHello — режется на
//! несколько TLS-записей так, что имя сайта (SNI) оказывается разорвано между
//! ними. Простые DPI собирают только первую запись и имя не видят.
//!
//! Способы отправки:
//! - `split` — записи уходят отдельными TCP-сегментами;
//! - `disorder` — первая запись уходит с TTL=1 и теряется по дороге, ядро
//!   пересылает её позже: DPI видит поток не по порядку.
//!
//! Адреса сайтов можно разрешать через DoH — тогда не мешает и подмена DNS.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const FIRST_DATA_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub port: u16,
    /// Из прошлых версий: `split` | `disorder`. Переводится в `disorder` (см. `normalize`).
    #[serde(skip_serializing)]
    pub method: Option<String>,
    /// Где резать ClientHello: sni | first-byte | chunk | random | none.
    pub split: String,
    /// Чем резать: records — отдельные TLS-записи; tcp — TCP-сегменты одной записи.
    pub unit: String,
    /// Размер куска для `chunk`, байт.
    pub chunk: u16,
    /// Свои позиции разреза для `custom` в синтаксисе ByeDPI, например `0+sm 1:3:5 -10`.
    pub positions: String,
    /// Первая часть уходит с TTL=1 и доходит позже — поток не по порядку.
    pub disorder: bool,
    /// Первая часть уходит со «срочным» (OOB) байтом: его видит DPI, но не сервер.
    pub oob: bool,
    /// Автоматический режим: при сбросе или молчании после ClientHello —
    /// переподключиться со следующим способом из `auto_chain`; рабочий
    /// способ запоминается для сайта.
    pub auto: bool,
    pub auto_chain: Vec<Variant>,
    /// Сколько ждать первого ответа сервера, секунд.
    pub auto_timeout: u16,
    /// Журнал соединений (последние 500) — для разбора, что и как обходится.
    pub log: bool,
    /// Запрашивать и использовать IPv6-адреса сайтов.
    pub ipv6: bool,
    /// Какие домены обрабатывать.
    pub rules: Rules,
    /// Разрешать адреса через DoH (Cloudflare → Google), иначе системным DNS.
    pub doh: bool,
    /// Прописать прокси в настройки Windows (HKCU).
    pub system: bool,
    /// Раздавать в локальную сеть (слушать 0.0.0.0, пускать только частные адреса).
    pub lan: bool,
    /// Логин и пароль для клиентов из сети (пустой логин — без пароля).
    /// С самого ПК (127.0.0.1) пароль не спрашивается: системный прокси Windows
    /// не умеет его передавать.
    pub user: String,
    pub pass: String,
    /// Свой Worker для доменов из `rules.worker`.
    pub worker: WorkerCfg,
    /// Экспериментально: маленький буфер приёма (байт, 0 — системный) на
    /// соединениях к сайтам. Сервер тогда шлёт ответ (сертификат) мелкими
    /// кусками — против DPI, который режет по ответу. После первого ответа
    /// буфер возвращается к большому.
    pub rcvbuf: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            port: 8881,
            method: None,
            split: "sni".into(),
            unit: "records".into(),
            chunk: 4,
            positions: String::new(),
            disorder: true,
            oob: false,
            auto: true,
            auto_chain: default_chain(),
            auto_timeout: 4,
            log: false,
            ipv6: false,
            rules: Rules::default(),
            doh: true,
            system: true,
            lan: false,
            user: String::new(),
            pass: String::new(),
            worker: WorkerCfg::default(),
            rcvbuf: 0,
        }
    }
}

/// Правила по доменам. Домен совпадает и со всеми поддоменами (`*.` можно не писать).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Rules {
    /// all — резать всё, кроме `skip`; listed — только домены из `bypass` (и списков zapret2).
    pub scope: String,
    /// Добавить к `bypass` домены списков zapret2 (list-general, list-google, list-general-user).
    pub zapret_lists: bool,
    pub bypass: Vec<String>,
    /// Пропускать без нарезки: банки, сайты, которые ломаются от фрагментации.
    pub skip: Vec<String>,
    /// Не пускать вовсе.
    pub block: Vec<String>,
    /// Через свой Cloudflare Worker (сайты, заблокированные по IP или с геоограничениями).
    #[serde(default)]
    pub worker: Vec<String>,
    /// Через Tor (когда он подключён). Адреса .onion идут в Tor всегда.
    #[serde(default)]
    pub tor: Vec<String>,
    /// Что ещё отправлять в Tor, пока он подключён: list — только `tor`,
    /// zapret — плюс домены списков zapret2, all — весь трафик (кроме `skip`, `worker`).
    #[serde(default = "default_tor_scope")]
    pub tor_scope: String,
}

fn default_tor_scope() -> String {
    "list".into()
}

pub const TOR_SCOPES: [&str; 3] = ["list", "zapret", "all"];

impl Default for Rules {
    fn default() -> Self {
        Rules { scope: "all".into(), zapret_lists: true, bypass: Vec::new(), skip: Vec::new(), block: Vec::new(), worker: Vec::new(), tor: Vec::new(), tor_scope: default_tor_scope() }
    }
}

/// Свой Cloudflare Worker: туннель WebSocket → TCP до сайта (код Worker — в приложении).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WorkerCfg {
    /// `имя.аккаунт.workers.dev` или свой домен.
    pub host: String,
    /// Ключ доступа — тот же, что в коде Worker.
    pub key: String,
    /// Нарезать ClientHello к Cloudflare (как в Telegram-модуле).
    pub fragment: bool,
}

impl Default for WorkerCfg {
    fn default() -> Self {
        WorkerCfg { host: String::new(), key: String::new(), fragment: true }
    }
}

impl WorkerCfg {
    pub fn ready(&self) -> bool {
        !self.host.trim().is_empty() && !self.key.trim().is_empty()
    }
}

/// Процентное кодирование для параметра запроса.
fn qenc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Путь туннеля Worker: `/tunnel?h=<хост>&p=<порт>&k=<ключ>`.
pub fn worker_path(host: &str, port: u16, key: &str) -> String {
    format!("/tunnel?h={}&p={port}&k={}", qenc(host), qenc(key))
}

pub const SPLITS: [&str; 6] = ["sni", "first-byte", "chunk", "random", "custom", "none"];

// ---------- свои позиции разреза (синтаксис ByeDPI) ----------

/// Одна позиция: `offset[:repeats[:skip]][+flags]`.
/// Флаги: `s` — от начала имени сайта (SNI), `e` — от конца имени, `m` — от
/// середины имени, `n` — от начала пакета. Отрицательное смещение без флагов
/// считается от конца пакета.
#[derive(Debug, Clone, PartialEq)]
pub struct Pos {
    pub offset: i64,
    pub repeats: u32,
    pub skip: i64,
    /// None — от начала (или конца для отрицательных); Some('s'|'e'|'m') — от имени сайта.
    pub sni: Option<char>,
    pub zero: bool,
}

pub fn parse_positions(text: &str) -> Result<Vec<Pos>, String> {
    let mut out = Vec::new();
    for tok in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';').filter(|t| !t.is_empty()) {
        let bad = || crate::tr!("позиция «{tok}» не разобрана: нужно offset[:повторы:шаг][+флаги]", "cannot parse position \"{tok}\": expected offset[:repeats:skip][+flags]");
        let (num, flags) = tok.split_once('+').unwrap_or((tok, ""));
        let mut parts = num.split(':');
        let offset: i64 = parts.next().filter(|s| !s.is_empty()).ok_or_else(bad)?.parse().map_err(|_| bad())?;
        let repeats: u32 = match parts.next() {
            Some(r) => r.parse().map_err(|_| bad())?,
            None => 1,
        };
        let skip: i64 = match parts.next() {
            Some(k) => k.parse().map_err(|_| bad())?,
            None => 1,
        };
        if parts.next().is_some() || repeats == 0 || repeats > 64 || offset.abs() > 65535 {
            return Err(bad());
        }
        let mut sni = None;
        let mut zero = false;
        for f in flags.chars() {
            match f {
                's' => sni = sni.or(Some('s')),
                'e' | 'm' => sni = Some(f),
                'n' => zero = true,
                'h' => {
                    return Err(crate::tr!(
                        "флаг +h (заголовок Host) — только для HTTP, а прокси режет TLS",
                        "flag +h (Host header) is for HTTP only, the proxy splits TLS"
                    ))
                }
                _ => return Err(bad()),
            }
        }
        out.push(Pos { offset, repeats, skip, sni, zero });
    }
    if out.is_empty() {
        return Err(crate::tr!("укажите хотя бы одну позицию, например 0+sm", "enter at least one position, e.g. 0+sm"));
    }
    if out.len() > 32 {
        return Err(crate::tr!("не больше 32 позиций", "at most 32 positions"));
    }
    Ok(out)
}

/// Позиции → точки разреза в пределах 1..len. Позиции от имени сайта без SNI пропускаются.
pub fn resolve_positions(positions: &[Pos], len: usize, sni: Option<(usize, usize)>) -> Vec<usize> {
    let mut cuts = Vec::new();
    for p in positions {
        let base: i64 = match (p.sni, sni) {
            (Some(_), None) => continue,
            (Some('e'), Some((s, n))) => (s + n) as i64,
            (Some('m'), Some((s, n))) => (s + n / 2) as i64,
            (Some(_), Some((s, _))) => s as i64,
            (None, _) if p.offset < 0 && !p.zero => len as i64,
            (None, _) => 0,
        };
        for k in 0..p.repeats as i64 {
            let c = base + p.offset + k * p.skip;
            if c > 0 && (c as usize) < len {
                cuts.push(c as usize);
            }
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

/// Единицы нарезки: TLS-записи, TCP-сегменты одной записи и TLS-записи с
/// разными версиями (первая 0x0303, остальные 0x0301 — DPI, разбирающий
/// только первую запись или сверяющий версии, теряет нить; CircumVolve, CCS'26).
pub const UNITS: [&str; 3] = ["records", "tcp", "mixed"];

/// Один способ нарезки — то, что перебирают подбор и автоматический режим.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(default)]
pub struct Variant {
    pub split: String,
    pub unit: String,
    pub disorder: bool,
    pub oob: bool,
}

impl Default for Variant {
    fn default() -> Self {
        Variant { split: "sni".into(), unit: "records".into(), disorder: true, oob: false }
    }
}

impl Variant {
    pub fn new(split: &str, unit: &str, disorder: bool, oob: bool) -> Self {
        Variant { split: split.into(), unit: unit.into(), disorder, oob }
    }

    /// Короткая запись для журнала: `chunk/records+disorder+oob`.
    pub fn short(&self) -> String {
        if self.split == "none" {
            return "none".into();
        }
        format!("{}/{}{}{}", self.split, self.unit, if self.disorder { "+disorder" } else { "" }, if self.oob { "+oob" } else { "" })
    }
}

// ---------- журнал соединений ----------

/// Запись журнала: куда шли, что сделал прокси, каким способом и чем кончилось.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Unix-время, мс.
    pub ts: u64,
    pub host: String,
    pub port: u16,
    /// bypass | pass | block
    pub action: &'static str,
    /// Способ нарезки, которым соединение установилось.
    pub method: Option<String>,
    /// Сколько способов перепробовал автоматический режим.
    pub tries: u8,
    /// Время до установления соединения.
    pub ms: Option<u64>,
    pub ok: bool,
    pub error: Option<String>,
}

pub const LOG_CAP: usize = 500;

/// Что известно о соединении по ходу обработки.
#[derive(Default)]
struct Trace {
    host: String,
    port: u16,
    action: Option<Action>,
    method: Option<Variant>,
    tries: u8,
    logged: bool,
}

fn action_name(a: Option<Action>) -> &'static str {
    match a {
        Some(Action::Block) => "block",
        Some(Action::Pass) => "pass",
        Some(Action::Worker) => "worker",
        Some(Action::Tor) => "tor",
        _ => "bypass",
    }
}

/// Запасные способы по умолчанию — те, что чаще работают у российских провайдеров.
pub fn default_chain() -> Vec<Variant> {
    vec![
        Variant::new("chunk", "records", true, false),
        Variant::new("sni", "records", true, false),
        Variant::new("chunk", "tcp", true, false),
        Variant::new("sni", "records", false, true),
    ]
}

/// Порядок попыток: способ, сохранённый для сайта, затем основной, затем запасные;
/// без повторов, не больше `max`.
pub fn attempt_order(primary: &Variant, cached: Option<&Variant>, chain: &[Variant], max: usize) -> Vec<Variant> {
    let mut out: Vec<Variant> = Vec::new();
    for v in cached.into_iter().chain(std::iter::once(primary)).chain(chain.iter()) {
        if !out.contains(v) {
            out.push(v.clone());
        }
    }
    out.truncate(max);
    out
}

impl Config {
    /// Перевести настройки прошлых версий и проверить значения.
    pub fn normalize(&mut self) {
        if self.rcvbuf != 0 {
            self.rcvbuf = self.rcvbuf.clamp(512, 65536);
        }
        match self.method.take().as_deref() {
            Some("split") => self.disorder = false,
            Some("disorder") => self.disorder = true,
            _ => {}
        }
        if !SPLITS.contains(&self.split.as_str()) {
            self.split = "sni".into();
        }
        if !UNITS.contains(&self.unit.as_str()) {
            self.unit = "records".into();
        }
        self.auto_timeout = self.auto_timeout.clamp(2, 15);
        self.auto_chain.retain(|v| SPLITS.contains(&v.split.as_str()) && v.split != "none");
        self.auto_chain.truncate(6);
        self.chunk = self.chunk.clamp(1, 1024);
        if self.rules.scope != "listed" {
            self.rules.scope = "all".into();
        }
        if !TOR_SCOPES.contains(&self.rules.tor_scope.as_str()) {
            self.rules.tor_scope = "list".into();
        }
        for list in [&mut self.rules.bypass, &mut self.rules.skip, &mut self.rules.block, &mut self.rules.tor] {
            let mut v: Vec<String> = list.iter().filter_map(|d| normalize_domain(d)).collect();
            v.dedup();
            *list = v;
        }
    }
}

/// `*.Example.COM.` → `example.com`; не домен — None.
pub fn normalize_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
    (d.contains('.') && d.len() <= 253 && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')).then_some(d)
}

/// Набор доменов: совпадение по имени и всем родительским доменам.
#[derive(Debug, Default, Clone)]
pub struct DomainSet(std::collections::HashSet<String>);

impl DomainSet {
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>>(it: I) -> Self {
        DomainSet(it.into_iter().filter_map(|d| normalize_domain(d.as_ref())).collect())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn matches(&self, host: &str) -> bool {
        if self.0.is_empty() || host.parse::<IpAddr>().is_ok() {
            return false;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut h = host.as_str();
        loop {
            if self.0.contains(h) {
                return true;
            }
            match h.find('.') {
                Some(i) => h = &h[i + 1..],
                None => return false,
            }
        }
    }
}

/// Что делать с соединением к хосту.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Bypass,
    Pass,
    Block,
    /// Через свой Worker.
    Worker,
    /// Через Tor.
    Tor,
}

/// Понятная причина отказа своего Worker'а по ответу на WebSocket-запрос
/// (коды — из кода Worker, который даёт приложение).
pub fn worker_reason(err: &str) -> String {
    let code = err.split("HTTP ").nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or("");
    match code {
        "403" => crate::tr!("неверный ключ (403) — ключ в приложении и в коде Worker'а должен совпадать", "wrong key (403) — the key in the app and in the Worker code must match"),
        "502" => crate::tr!(
            "Worker не смог подключиться к сайту (502) — сайт стоит за Cloudflare или недоступен",
            "the Worker could not reach the site (502) — the site is behind Cloudflare or down"
        ),
        "404" | "426" | "200" => crate::tr!(
            "по этому адресу не наш Worker (HTTP {code}) — задеплойте код из приложения",
            "this address is not our Worker (HTTP {code}) — deploy the code from the app"
        ),
        "1101" | "500" | "503" => crate::tr!(
            "ошибка или лимит Cloudflare (HTTP {code}) — бесплатный тариф: 100 000 запросов в день",
            "a Cloudflare error or limit (HTTP {code}) — the free plan allows 100,000 requests a day"
        ),
        "" if err.contains("timed out") || err.contains("10060") => crate::tr!(
            "нет ответа от Cloudflare — попробуйте включить нарезку ClientHello",
            "no answer from Cloudflare — try turning on ClientHello splitting"
        ),
        _ => err.to_string(),
    }
}

/// Адрес скрытого сервиса Tor.
pub fn is_onion(host: &str) -> bool {
    host.trim_end_matches('.').to_ascii_lowercase().ends_with(".onion")
}

pub struct Matcher {
    scope_listed: bool,
    bypass: DomainSet,
    skip: DomainSet,
    block: DomainSet,
    worker: DomainSet,
    tor: DomainSet,
    /// Домены списков zapret2 для режима Tor «списки zapret».
    tor_zapret: DomainSet,
    tor_all: bool,
}

impl Matcher {
    /// `extra_bypass` добавляется к `bypass` как есть (для тестов правил).
    #[cfg(test)]
    pub fn new(r: &Rules, extra_bypass: &[String]) -> Self {
        Self::build(r, extra_bypass, &[], false)
    }

    /// `zapret` — домены списков zapret2: идут в `bypass` при `zapret_lists` и в Tor
    /// при `tor_scope = zapret`. `worker_on` — Worker настроен: `rules.worker` идут через него.
    pub fn with_worker(r: &Rules, zapret: &[String], worker_on: bool) -> Self {
        let bypass_extra = if r.zapret_lists { zapret } else { &[] };
        let tor_extra = if r.tor_scope == "zapret" { zapret } else { &[] };
        Self::build(r, bypass_extra, tor_extra, worker_on)
    }

    fn build(r: &Rules, extra_bypass: &[String], tor_zapret: &[String], worker_on: bool) -> Self {
        Matcher {
            worker: DomainSet::new(if worker_on { &r.worker[..] } else { &[] }),
            tor: DomainSet::new(&r.tor),
            tor_zapret: DomainSet::new(tor_zapret),
            tor_all: r.tor_scope == "all",
            scope_listed: r.scope == "listed",
            bypass: DomainSet::new(r.bypass.iter().chain(extra_bypass.iter())),
            skip: DomainSet::new(&r.skip),
            block: DomainSet::new(&r.block),
        }
    }
    pub fn action(&self, host: &str) -> Action {
        self.action_with(host, crate::tor::ready_port().is_some())
    }

    /// Правила Tor действуют, только пока он подключён (`tor_ready`); иначе — обычные.
    /// Порядок: блок → .onion → список Tor → Worker → «не резать» → режим Tor → нарезка.
    pub fn action_with(&self, host: &str, tor_ready: bool) -> Action {
        if self.block.matches(host) {
            Action::Block
        } else if is_onion(host) || (tor_ready && self.tor.matches(host)) {
            Action::Tor
        } else if self.worker.matches(host) {
            Action::Worker
        } else if self.skip.matches(host) {
            Action::Pass
        } else if tor_ready && (self.tor_all || self.tor_zapret.matches(host)) {
            Action::Tor
        } else if self.scope_listed && !self.bypass.matches(host) {
            Action::Pass
        } else {
            Action::Bypass
        }
    }
}

// ---------- разбор и нарезка ClientHello ----------

/// Смещение и длина имени сервера (SNI) внутри TLS-записи с ClientHello.
pub fn find_sni(rec: &[u8]) -> Option<(usize, usize)> {
    if rec.len() < 5 || rec[0] != 0x16 || rec[1] != 0x03 {
        return None;
    }
    let end = (5 + u16::from_be_bytes([rec[3], rec[4]]) as usize).min(rec.len());
    let get = |i: usize| rec.get(i).copied().filter(|_| i < end);
    let u16_at = |i: usize| Some(u16::from_be_bytes([get(i)?, get(i + 1)?]) as usize);
    let mut i = 5;
    if get(i)? != 0x01 {
        return None; // не ClientHello
    }
    i += 4 + 2 + 32; // тип+длина, версия, random
    i += 1 + get(i)? as usize; // session id
    i += 2 + u16_at(i)?; // cipher suites
    i += 1 + get(i)? as usize; // compression
    let ext_end = (i + 2 + u16_at(i)?).min(end);
    i += 2;
    while i + 4 <= ext_end {
        let ty = u16_at(i)?;
        let len = u16_at(i + 2)?;
        if ty == 0 {
            // server_name: list_len(2) type(1) name_len(2) name
            let name_len = u16_at(i + 4 + 3)?;
            let start = i + 4 + 5;
            if start + name_len <= end {
                return Some((start, name_len));
            }
            return None;
        }
        i += 4 + len;
    }
    None
}

/// Внутренние точки разреза (возрастают, в пределах 1..len) для способа `split`.
/// `sni` — смещение и длина имени в тех же координатах.
pub fn cut_points(len: usize, sni: Option<(usize, usize)>, split: &str, chunk: usize, seed: u64) -> Vec<usize> {
    if len < 2 {
        return Vec::new();
    }
    let mut cuts: Vec<usize> = match split {
        "sni" => match sni {
            Some((s, n)) => vec![s, s + (n / 2).max(1)],
            None => vec![1],
        },
        "first-byte" => vec![1],
        "chunk" => {
            // Не больше 256 кусков: иначе однобайтные куски большого ClientHello
            // превращаются в сотни сегментов.
            let step = chunk.max(1).max(len.div_ceil(256));
            (1..).map(|i| i * step).take_while(|&c| c < len).collect()
        }
        "random" => {
            // xorshift — для одной точки разреза случайности хватает.
            let mut x = seed | 1;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            vec![1 + (x as usize) % (len - 1)]
        }
        _ => Vec::new(),
    };
    cuts.retain(|&c| c > 0 && c < len);
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

/// Параметры нарезки из настроек.
#[derive(Debug, Clone)]
pub struct SplitOpts {
    pub split: String,
    pub records: bool,
    /// Для записей: первая с версией 0x0303, остальные 0x0301.
    pub mixver: bool,
    pub chunk: usize,
    pub seed: u64,
    /// Для `custom`.
    pub positions: Vec<Pos>,
}

impl Default for SplitOpts {
    fn default() -> Self {
        SplitOpts { split: "sni".into(), records: true, mixver: false, chunk: 4, seed: 0, positions: Vec::new() }
    }
}

fn cuts_for(len: usize, sni: (usize, usize), o: &SplitOpts) -> Vec<usize> {
    if o.split == "custom" {
        resolve_positions(&o.positions, len, Some(sni))
    } else {
        cut_points(len, Some(sni), &o.split, o.chunk, o.seed)
    }
}

/// Разрезать первый пакет туннеля. Только TLS ClientHello; остальное — одним куском.
/// `records` — каждая часть оформляется отдельной TLS-записью; иначе режутся
/// TCP-сегменты одной записи.
pub fn split_with(data: &[u8], o: &SplitOpts) -> Vec<Vec<u8>> {
    let Some((sni, sni_len)) = find_sni(data) else { return vec![data.to_vec()] };
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + rec_len > data.len() {
        return vec![data.to_vec()];
    }
    if !o.records {
        let cuts = cuts_for(data.len(), (sni, sni_len), o);
        let mut b = vec![0];
        b.extend(cuts);
        b.push(data.len());
        return b.windows(2).map(|w| data[w[0]..w[1]].to_vec()).collect();
    }
    let payload = &data[5..5 + rec_len];
    let tail = &data[5 + rec_len..];
    // Точки разреза в координатах payload.
    let mut cuts = vec![0];
    cuts.extend(cuts_for(payload.len(), (sni - 5, sni_len), o));
    cuts.push(payload.len());
    let mut out: Vec<Vec<u8>> = cuts
        .windows(2)
        .filter(|w| w[1] > w[0])
        .enumerate()
        .map(|(i, w)| {
            let part = &payload[w[0]..w[1]];
            let (v1, v2) = match (o.mixver, i) {
                (true, 0) => (0x03, 0x03),
                (true, _) => (0x03, 0x01),
                _ => (data[1], data[2]),
            };
            let mut r = vec![0x16, v1, v2];
            r.extend_from_slice(&(part.len() as u16).to_be_bytes());
            r.extend_from_slice(part);
            r
        })
        .collect();
    if !tail.is_empty() {
        out.last_mut().unwrap().extend_from_slice(tail);
    }
    out
}

/// Прежний способ: три TLS-записи вокруг имени сайта (для тестов).
#[cfg(test)]
pub fn split_client_hello(data: &[u8]) -> Vec<Vec<u8>> {
    split_with(data, &SplitOpts::default())
}

/// Байт, который уходит «срочными» данными: стек сервера его отбрасывает
/// (SO_OOBINLINE выключен), а DPI видит его внутри потока.
pub const OOB_BYTE: u8 = b'a';

/// Отправить часть с одним дополнительным OOB-байтом в конце (`send` с MSG_OOB).
fn send_oob(up: &TcpStream, part: &[u8]) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{send, MSG_OOB, SOCKET};
    let mut buf = part.to_vec();
    buf.push(OOB_BYTE);
    let mut off = 0;
    // Обычная часть может уйти не целиком — дописываем; MSG_OOB помечает последний байт.
    while off < buf.len() {
        let n = unsafe { send(up.as_raw_socket() as SOCKET, buf[off..].as_ptr(), (buf.len() - off) as i32, MSG_OOB) };
        if n <= 0 {
            return Err(std::io::Error::last_os_error());
        }
        off += n as usize;
    }
    Ok(())
}

pub(crate) fn send_parts(up: &mut TcpStream, parts: &[Vec<u8>], disorder: bool, oob: bool) -> std::io::Result<()> {
    up.set_nodelay(true)?;
    // Паузы нужны, чтобы части не склеились в один сегмент; при сотнях кусков — короче.
    let pause = Duration::from_micros(if parts.len() > 16 { 200 } else { 2000 });
    for (i, p) in parts.iter().enumerate() {
        let first = i == 0 && parts.len() > 1;
        if first && disorder {
            // TTL работает только для IPv4-сокета; для IPv6 — обычная нарезка.
            if let Ok(ttl) = up.ttl() {
                if up.set_ttl(1).is_ok() {
                    if oob {
                        send_oob(up, p)?;
                    } else {
                        up.write_all(p)?;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                    up.set_ttl(ttl)?;
                    continue;
                }
            }
        }
        if first && oob {
            send_oob(up, p)?;
        } else {
            up.write_all(p)?;
        }
        if i + 1 < parts.len() {
            std::thread::sleep(pause);
        }
    }
    Ok(())
}

// ---------- HTTP-запрос клиента ----------

#[derive(Debug, PartialEq)]
pub enum Request {
    Connect { host: String, port: u16 },
    /// Обычный HTTP: адрес и заголовок, переписанный в origin-form.
    Http { host: String, port: u16, head: Vec<u8> },
}

pub fn parse_request(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let first = text.lines().next()?;
    let mut it = first.split_whitespace();
    let method = it.next()?;
    let target = it.next()?;
    let version = it.next()?;
    let split_hp = |hp: &str, def: u16| -> Option<(String, u16)> {
        if let Some(rest) = hp.strip_prefix('[') {
            let (h, p) = rest.split_once(']')?;
            let port = p.strip_prefix(':').map(|p| p.parse().ok()).unwrap_or(Some(def))?;
            return Some((h.to_string(), port));
        }
        match hp.rsplit_once(':') {
            Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
            None => Some((hp.to_string(), def)),
        }
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_hp(target, 443)?;
        return Some(Request::Connect { host, port });
    }
    let rest = target.strip_prefix("http://")?;
    let (hp, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_hp(hp, 80)?;
    let mut new_head = format!("{method} {path} {version}\r\n").into_bytes();
    let after_first = &head[first.len()..];
    let after_first = after_first.strip_prefix(b"\r\n").unwrap_or(after_first);
    new_head.extend_from_slice(after_first);
    Some(Request::Http { host, port, head: new_head })
}

// ---------- авторизация ----------

impl Config {
    /// Проверка логина и пароля перед запуском.
    pub fn validate_auth(&self) -> Result<(), String> {
        if self.user.is_empty() && self.pass.is_empty() {
            return Ok(());
        }
        let ok_chars = |s: &str| !s.is_empty() && s.len() <= 255 && !s.chars().any(char::is_control);
        if !ok_chars(&self.user) || self.user.contains(':') || !ok_chars(&self.pass) {
            return Err(crate::tr!(
                "логин и пароль: оба непустые, до 255 символов, в логине без «:»",
                "user and password: both non-empty, up to 255 characters, no ':' in the user"
            ));
        }
        Ok(())
    }
}

/// Base64 (стандартный алфавит) — только для заголовка Proxy-Authorization.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let s = s.trim().trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
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

/// Сравнение без раннего выхода — чтобы по времени ответа нельзя было подбирать.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Заголовок `Proxy-Authorization: Basic …` совпадает с логином и паролем.
pub fn check_basic(head: &[u8], user: &str, pass: &str) -> bool {
    let Ok(text) = std::str::from_utf8(head) else { return false };
    let expected = format!("{user}:{pass}");
    text.lines().any(|l| {
        let Some((name, value)) = l.split_once(':') else { return false };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            return false;
        }
        let mut it = value.trim().splitn(2, ' ');
        let scheme = it.next().unwrap_or("");
        let token = it.next().unwrap_or("");
        scheme.eq_ignore_ascii_case("basic") && b64_decode(token).is_some_and(|d| same(&d, expected.as_bytes()))
    })
}

// ---------- SOCKS5 ----------

/// Адрес из запроса SOCKS5 (ATYP + адрес + порт), начиная с байта ATYP.
/// Возвращает (хост, порт, длина разобранного).
pub fn parse_socks_addr(b: &[u8]) -> Option<(String, u16, usize)> {
    let (host, n) = match *b.first()? {
        1 => (IpAddr::from([*b.get(1)?, *b.get(2)?, *b.get(3)?, *b.get(4)?]).to_string(), 5),
        3 => {
            let len = *b.get(1)? as usize;
            (String::from_utf8(b.get(2..2 + len)?.to_vec()).ok()?, 2 + len)
        }
        4 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b.get(1..17)?);
            (IpAddr::from(a).to_string(), 17)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*b.get(n)?, *b.get(n + 1)?]);
    Some((host, port, n + 2))
}

/// Рукопожатие SOCKS5 (без пароля или с логином/паролем по RFC 1929) и запрос
/// CONNECT. Возвращает цель.
fn socks5_handshake(c: &mut (impl Read + Write), creds: Option<(&str, &str)>) -> std::io::Result<(String, u16)> {
    let mut hdr = [0u8; 2];
    c.read_exact(&mut hdr)?;
    let mut methods = vec![0u8; hdr[1] as usize];
    c.read_exact(&mut methods)?;
    match creds {
        None if methods.contains(&0) => c.write_all(&[5, 0])?,
        Some((user, pass)) if methods.contains(&2) => {
            c.write_all(&[5, 2])?;
            let mut v = [0u8; 2];
            c.read_exact(&mut v)?;
            let mut u = vec![0u8; v[1] as usize];
            c.read_exact(&mut u)?;
            let mut pl = [0u8; 1];
            c.read_exact(&mut pl)?;
            let mut p = vec![0u8; pl[0] as usize];
            c.read_exact(&mut p)?;
            // Сравниваем обе части всегда, без раннего выхода.
            let ok = same(&u, user.as_bytes()) & same(&p, pass.as_bytes());
            c.write_all(&[1, if ok { 0 } else { 1 }])?;
            if !ok {
                return Err(std::io::Error::other("socks5: wrong user or password"));
            }
        }
        _ => {
            c.write_all(&[5, 0xFF])?;
            return Err(std::io::Error::other("socks5: no acceptable auth method"));
        }
    }
    let mut req = [0u8; 4];
    c.read_exact(&mut req)?;
    if req[1] != 1 {
        // Только CONNECT: BIND и UDP ASSOCIATE не поддерживаем.
        c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Err(std::io::Error::other("socks5: only CONNECT is supported"));
    }
    let mut addr = vec![req[3]];
    let rest = match req[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l)?;
            addr.push(l[0]);
            l[0] as usize + 2
        }
        _ => {
            c.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0])?;
            return Err(std::io::Error::other("socks5: bad address type"));
        }
    };
    let mut tail = vec![0u8; rest];
    c.read_exact(&mut tail)?;
    addr.extend_from_slice(&tail);
    let (host, port, _) = parse_socks_addr(&addr).ok_or_else(|| std::io::Error::other("socks5: bad address"))?;
    Ok((host, port))
}

/// Можно ли пускать клиента: петля и частные сети (для раздачи в LAN).
pub fn is_lan_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_lan_peer(IpAddr::V4(v4));
            }
            a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn read_head(s: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(p + 4);
            return Ok((buf, rest));
        }
        if buf.len() > 32 * 1024 {
            return Err(std::io::Error::other("header too large"));
        }
        let n = s.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

// ---------- сервер ----------

#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub running: bool,
    pub port: u16,
    pub active: u64,
    pub total: u64,
    pub failed: u64,
    pub system: bool,
    pub lan: bool,
    pub auth: bool,
    /// Соединений с нарезкой / без неё / заблокировано правилами.
    pub bypassed: u64,
    pub passed: u64,
    pub blocked: u64,
    /// Через свой Worker.
    pub via_worker: u64,
    /// Через Tor.
    pub via_tor: u64,
    /// Доменов в кэше DNS и в списке обхода.
    pub dns_cached: usize,
    pub bypass_domains: usize,
    /// Автоматический режим: переподключений другим способом и сайтов в памяти.
    pub auto_retries: u64,
    pub auto_sites: usize,
    pub last_error: Option<String>,
}

struct Shared {
    cfg: Config,
    stop: AtomicBool,
    active: AtomicU64,
    total: AtomicU64,
    failed: AtomicU64,
    last_error: Mutex<Option<String>>,
    resolver: Option<crate::doh::CachedResolver>,
    matcher: Matcher,
    bypassed: AtomicU64,
    passed: AtomicU64,
    blocked: AtomicU64,
    via_worker: AtomicU64,
    via_tor: AtomicU64,
    /// Сайт → способ, который сработал (если не основной), с отметкой времени.
    auto_cache: Mutex<std::collections::HashMap<String, (Variant, std::time::Instant)>>,
    auto_retries: AtomicU64,
    /// Разобранные свои позиции (пусто, если не заданы).
    positions: Vec<Pos>,
    log: Mutex<std::collections::VecDeque<LogEntry>>,
}

/// Сколько помнить способ для сайта.
const AUTO_CACHE_TTL: Duration = Duration::from_secs(6 * 3600);

impl Shared {
    /// Туннель до `host:port` через свой Worker (WSS, с нарезкой ClientHello к CF).
    fn worker_connect(&self, host: &str, port: u16) -> std::io::Result<(crate::telegram::Ws, Vec<u8>)> {
        let w = &self.cfg.worker;
        let wh = w.host.trim();
        let path = worker_path(host, port, w.key.trim());
        let mut last = std::io::Error::other(crate::tr!(
            "Worker {wh}: адрес не найден (DNS) — проверьте адрес Worker'а",
            "Worker {wh}: address not found (DNS) — check the Worker address"
        ));
        for a in self.resolve(wh, 443).into_iter().filter(|a| a.is_ipv4()).take(3) {
            match crate::telegram::Ws::connect(a, wh, &path, w.fragment) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    let why = worker_reason(&e.to_string());
                    last = std::io::Error::other(format!("Worker {wh}: {why}"));
                    // Ответ самого Worker'а — другие адреса Cloudflare ответят так же.
                    if e.to_string().contains("HTTP ") {
                        break;
                    }
                }
            }
        }
        Err(last)
    }

    /// Соединение через SOCKS tor (имя разрешает сам tor).
    fn tor_up(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let p = crate::tor::ready_port().ok_or_else(|| std::io::Error::other(crate::tr!("Tor не подключён", "Tor is not connected")))?;
        crate::tor::socks_connect(p, host, port, Duration::from_secs(60))
    }

    fn resolve(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![SocketAddr::new(ip, port)];
        }
        let ips: Vec<IpAddr> = match self.resolver.as_ref().and_then(|r| r.resolve(host)) {
            Some(v) => v,
            None => (host, port).to_socket_addrs().map(|i| i.map(|a| a.ip()).collect()).unwrap_or_default(),
        };
        // IPv4 вперёд; без IPv6 — только IPv4.
        let mut v: Vec<SocketAddr> = ips.iter().filter(|i| i.is_ipv4()).map(|i| SocketAddr::new(*i, port)).collect();
        if self.cfg.ipv6 || v.is_empty() {
            v.extend(ips.iter().filter(|i| i.is_ipv6()).map(|i| SocketAddr::new(*i, port)));
        }
        v
    }

    fn primary(&self) -> Variant {
        Variant::new(&self.cfg.split, &self.cfg.unit, self.cfg.disorder, self.cfg.oob)
    }

    fn send_variant(&self, up: &mut TcpStream, first: &[u8], v: &Variant) -> std::io::Result<()> {
        if v.split == "none" {
            return up.write_all(first);
        }
        let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(7);
        let o = SplitOpts { split: v.split.clone(), records: v.unit != "tcp", mixver: v.unit == "mixed", chunk: self.cfg.chunk as usize, seed, positions: self.positions.clone() };
        send_parts(up, &split_with(first, &o), v.disorder, v.oob)
    }

    fn cached_variant(&self, host: &str) -> Option<Variant> {
        let c = self.auto_cache.lock().unwrap();
        c.get(host).filter(|(_, t)| t.elapsed() < AUTO_CACHE_TTL).map(|(v, _)| v.clone())
    }

    fn remember(&self, host: &str, v: &Variant) {
        let mut c = self.auto_cache.lock().unwrap();
        if *v == self.primary() {
            c.remove(host);
        } else {
            if c.len() > 4096 {
                c.clear();
            }
            c.insert(host.to_string(), (v.clone(), std::time::Instant::now()));
        }
    }

    /// Автоматический режим: попытки разными способами, пока сервер не ответит
    /// TLS-записью Handshake. Возвращает соединение и первые байты ответа.
    /// Записать соединение в журнал (один раз на соединение).
    fn log_entry(&self, tr: &mut Trace, t0: std::time::Instant, ok: bool, error: Option<String>) {
        if !self.cfg.log || tr.logged || tr.host.is_empty() {
            return;
        }
        tr.logged = true;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        let e = LogEntry {
            ts,
            host: tr.host.clone(),
            port: tr.port,
            action: action_name(tr.action),
            method: tr.method.as_ref().map(|v| v.short()),
            tries: tr.tries,
            ms: ok.then(|| t0.elapsed().as_millis() as u64),
            ok,
            error,
        };
        let mut l = self.log.lock().unwrap();
        if l.len() >= LOG_CAP {
            l.pop_front();
        }
        l.push_back(e);
    }

    fn auto_connect(&self, mut up: Option<TcpStream>, host: &str, port: u16, first: &[u8], tr: &mut Trace) -> std::io::Result<(TcpStream, Vec<u8>)> {
        let order = attempt_order(&self.primary(), self.cached_variant(host).as_ref(), &self.cfg.auto_chain, 4);
        let wait = Duration::from_secs(self.cfg.auto_timeout as u64);
        let mut last_reply: Option<(TcpStream, Vec<u8>)> = None;
        let mut last_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer");
        for (i, v) in order.iter().enumerate() {
            if i > 0 {
                self.auto_retries.fetch_add(1, Ordering::Relaxed);
            }
            tr.tries = i as u8 + 1;
            tr.method = Some(v.clone());
            let mut s = match up.take() {
                Some(s) => s,
                None => match self.connect(host, port) {
                    Ok(s) => s,
                    Err(e) => {
                        last_err = e;
                        continue;
                    }
                },
            };
            if let Err(e) = self.send_variant(&mut s, first, v) {
                last_err = e;
                continue;
            }
            s.set_read_timeout(Some(wait))?;
            let mut buf = vec![0u8; 16 * 1024];
            match s.read(&mut buf) {
                Ok(n) if n > 0 => {
                    buf.truncate(n);
                    if buf[0] == 0x16 {
                        self.remember(host, v);
                        return Ok((s, buf));
                    }
                    // Не ServerHello (например, alert) — пробуем дальше, но ответ сохраняем:
                    // если ничего не выйдет, клиент получит его как есть.
                    last_reply = Some((s, buf));
                }
                Ok(_) => last_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed by server"),
                Err(e) => last_err = e,
            }
        }
        last_reply.ok_or(last_err)
    }

    fn count(&self, a: Action) {
        match a {
            Action::Bypass => &self.bypassed,
            Action::Pass => &self.passed,
            Action::Block => &self.blocked,
            Action::Worker => &self.via_worker,
            Action::Tor => &self.via_tor,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let addrs = self.resolve(host, port);
        if addrs.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("{host}: no address")));
        }
        connect_race_buf(&addrs, CONNECT_TIMEOUT, self.cfg.rcvbuf)
    }

    /// Туннель: первый пакет клиента (обычно ClientHello) режется, дальше — пересылка.
    #[allow(clippy::too_many_arguments)]
    fn tunnel(&self, mut client: TcpStream, mut up: TcpStream, early: Vec<u8>, action: Action, host: &str, port: u16, tr: &mut Trace, t0: std::time::Instant) -> std::io::Result<()> {
        if action == Action::Pass {
            up.write_all(&early)?;
            self.log_entry(tr, t0, true, None);
            return relay(client, up);
        }
        let mut first = early;
        if first.is_empty() {
            let mut tmp = [0u8; 16 * 1024];
            let n = client.read(&mut tmp)?;
            if n == 0 {
                return Ok(());
            }
            first.extend_from_slice(&tmp[..n]);
        }
        if self.cfg.auto && find_sni(&first).is_some() {
            let (up, reply) = self.auto_connect(Some(up), &host.to_ascii_lowercase(), port, &first, tr)?;
            client.write_all(&reply)?;
            self.log_entry(tr, t0, true, None);
            return relay(client, up);
        }
        let v = self.primary();
        tr.tries = 1;
        tr.method = Some(v.clone());
        self.send_variant(&mut up, &first, &v)?;
        self.log_entry(tr, t0, true, None);
        relay(client, up)
    }

    /// Логин и пароль, если они нужны этому клиенту (не с самого ПК).
    fn creds_for(&self, peer: IpAddr) -> Option<(&str, &str)> {
        let local = match peer {
            IpAddr::V4(a) => a.is_loopback(),
            IpAddr::V6(a) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v| v.is_loopback()),
        };
        (!self.cfg.user.is_empty() && !local).then_some((self.cfg.user.as_str(), self.cfg.pass.as_str()))
    }

    fn handle(&self, client: TcpStream) -> std::io::Result<()> {
        let t0 = std::time::Instant::now();
        let mut tr = Trace::default();
        let r = self.handle_inner(client, &mut tr, t0);
        match &r {
            Err(e) => self.log_entry(&mut tr, t0, false, Some(e.to_string())),
            Ok(()) if tr.action == Some(Action::Block) => self.log_entry(&mut tr, t0, false, None),
            Ok(()) => {}
        }
        r
    }

    fn handle_inner(&self, mut client: TcpStream, tr: &mut Trace, t0: std::time::Instant) -> std::io::Result<()> {
        client.set_read_timeout(Some(FIRST_DATA_TIMEOUT))?;
        let creds = self.creds_for(client.peer_addr()?.ip());
        let mut b = [0u8; 1];
        if client.peek(&mut b)? == 1 && b[0] == 5 {
            let (host, port) = socks5_handshake(&mut client, creds)?;
            let action = self.matcher.action(&host);
            self.count(action);
            (tr.host, tr.port, tr.action) = (host.clone(), port, Some(action));
            if action == Action::Block {
                // 0x02: соединение запрещено правилами.
                let _ = client.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
                return Ok(());
            }
            if action == Action::Worker {
                let (ws, early) = match self.worker_connect(&host, port) {
                    Ok(w) => w,
                    Err(e) => {
                        let _ = client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
                        return Err(e);
                    }
                };
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
                self.log_entry(tr, t0, true, None);
                return crate::telegram::ws_pipe(client, ws, early, Vec::new());
            }
            if action == Action::Tor {
                let up = match self.tor_up(&host, port) {
                    Ok(u) => u,
                    Err(e) => {
                        let _ = client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
                        return Err(e);
                    }
                };
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
                self.log_entry(tr, t0, true, None);
                return relay(client, up);
            }
            let up = match self.connect(&host, port) {
                Ok(u) => u,
                Err(e) => {
                    let _ = client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
                    return Err(e);
                }
            };
            client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
            return self.tunnel(client, up, Vec::new(), action, &host, port, tr, t0);
        }
        let (head, early) = read_head(&mut client)?;
        if let Some((user, pass)) = creds {
            if !check_basic(&head, user, pass) {
                client.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"digital-bypass\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )?;
                return Err(std::io::Error::other("proxy auth failed"));
            }
        }
        let req = parse_request(&head).ok_or_else(|| std::io::Error::other("bad request"))?;
        match req {
            Request::Connect { host, port } => {
                let action = self.matcher.action(&host);
                self.count(action);
                (tr.host, tr.port, tr.action) = (host.clone(), port, Some(action));
                if action == Action::Block {
                    let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    return Ok(());
                }
                if action == Action::Worker {
                    let (ws, wearly) = match self.worker_connect(&host, port) {
                        Ok(w) => w,
                        Err(e) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                            return Err(e);
                        }
                    };
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                    self.log_entry(tr, t0, true, None);
                    return crate::telegram::ws_pipe(client, ws, wearly, early);
                }
                if action == Action::Tor {
                    let mut up = match self.tor_up(&host, port) {
                        Ok(u) => u,
                        Err(e) => {
                            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                            return Err(e);
                        }
                    };
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                    up.write_all(&early)?;
                    self.log_entry(tr, t0, true, None);
                    return relay(client, up);
                }
                let up = match self.connect(&host, port) {
                    Ok(u) => u,
                    Err(e) => {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                        return Err(e);
                    }
                };
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                self.tunnel(client, up, early, action, &host, port, tr, t0)
            }
            Request::Http { host, port, head } => {
                (tr.host, tr.port, tr.action) = (host.clone(), port, Some(Action::Pass));
                if self.matcher.action(&host) == Action::Block {
                    tr.action = Some(Action::Block);
                    self.count(Action::Block);
                    let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    return Ok(());
                }
                if self.matcher.action(&host) == Action::Worker {
                    tr.action = Some(Action::Worker);
                    self.count(Action::Worker);
                    let (ws, wearly) = self.worker_connect(&host, port)?;
                    let mut first = head.to_vec();
                    first.extend_from_slice(&early);
                    self.log_entry(tr, t0, true, None);
                    return crate::telegram::ws_pipe(client, ws, wearly, first);
                }
                if self.matcher.action(&host) == Action::Tor {
                    tr.action = Some(Action::Tor);
                    self.count(Action::Tor);
                    let mut up = self.tor_up(&host, port)?;
                    up.write_all(&head)?;
                    up.write_all(&early)?;
                    self.log_entry(tr, t0, true, None);
                    return relay(client, up);
                }
                self.count(Action::Pass);
                let mut up = self.connect(&host, port)?;
                up.write_all(&head)?;
                up.write_all(&early)?;
                self.log_entry(tr, t0, true, None);
                relay(client, up)
            }
        }
    }
}

/// Подключиться к первому ответившему адресу: попытки стартуют с шагом 250 мс
/// и идут параллельно. Часть адресов сайта может быть заблокирована по IP —
/// так один «мёртвый» адрес не задерживает соединение на весь таймаут.
#[cfg(test)]
pub fn connect_race(addrs: &[SocketAddr], timeout: Duration) -> std::io::Result<TcpStream> {
    connect_race_buf(addrs, timeout, 0)
}

/// Подключение с заданным буфером приёма (0 — системный). Буфер ставится до
/// подключения: от него зависит окно, объявленное серверу в SYN.
pub fn connect_one(a: SocketAddr, timeout: Duration, rcvbuf: usize) -> std::io::Result<TcpStream> {
    if rcvbuf == 0 {
        return TcpStream::connect_timeout(&a, timeout);
    }
    let s = socket2::Socket::new(socket2::Domain::for_address(a), socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    s.set_recv_buffer_size(rcvbuf)?;
    s.connect_timeout(&a.into(), timeout)?;
    Ok(s.into())
}

/// Буфер приёма меньше этого — наш маленький: после первого ответа вернуть большой.
const SMALL_BUF_LIMIT: usize = 32 * 1024;

fn restore_rcvbuf(s: &TcpStream) {
    let r = socket2::SockRef::from(s);
    if r.recv_buffer_size().is_ok_and(|n| n < SMALL_BUF_LIMIT) {
        let _ = r.set_recv_buffer_size(1024 * 1024);
    }
}

pub fn connect_race_buf(addrs: &[SocketAddr], timeout: Duration, rcvbuf: u32) -> std::io::Result<TcpStream> {
    let (tx, rx) = std::sync::mpsc::channel();
    let won = Arc::new(AtomicBool::new(false));
    let n = addrs.len().min(6);
    for (i, a) in addrs.iter().take(n).enumerate() {
        let (tx, a, won) = (tx.clone(), *a, won.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250 * i as u64));
            // Победитель уже есть — лишнее соединение не открываем.
            if won.load(Ordering::SeqCst) {
                return;
            }
            let _ = tx.send(connect_one(a, timeout, rcvbuf as usize));
        });
    }
    drop(tx);
    let mut last = std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out");
    for r in rx {
        match r {
            Ok(s) => {
                won.store(true, Ordering::SeqCst);
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Двунаправленная пересылка до закрытия любой стороны.
fn relay(client: TcpStream, up: TcpStream) -> std::io::Result<()> {
    client.set_read_timeout(None)?;
    up.set_read_timeout(None)?;
    let (mut c2, mut u2) = (client.try_clone()?, up.try_clone()?);
    let t = std::thread::spawn(move || {
        // Первый кусок ответа — с маленьким буфером (если он задан), дальше полный.
        let mut buf = vec![0u8; 16 * 1024];
        match u2.read(&mut buf) {
            Ok(n) if n > 0 => {
                restore_rcvbuf(&u2);
                if c2.write_all(&buf[..n]).is_ok() {
                    let _ = std::io::copy(&mut u2, &mut c2);
                }
            }
            _ => {}
        }
        let _ = c2.shutdown(Shutdown::Write);
    });
    let (mut c, mut u) = (client, up);
    let _ = std::io::copy(&mut c, &mut u);
    let _ = u.shutdown(Shutdown::Write);
    let _ = t.join();
    Ok(())
}

pub struct Proxy {
    shared: Arc<Shared>,
    /// Поток приёма соединений: при остановке ждём его, чтобы порт освободился
    /// до запуска нового прокси (перезапуск при смене настроек).
    accept: Option<std::thread::JoinHandle<()>>,
}

/// Занять порт; старый слушатель может отпускать его ещё мгновение — повторяем.
fn bind_retry(host: &str, port: u16) -> std::io::Result<TcpListener> {
    let mut last = None;
    for _ in 0..20 {
        match TcpListener::bind((host, port)) {
            Ok(l) => return Ok(l),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::AddrInUse)))
}

impl Proxy {
    /// `extra_bypass` — домены из списков zapret2 (если включено в правилах).
    pub fn start(mut cfg: Config, extra_bypass: &[String]) -> Result<Proxy, String> {
        cfg.validate_auth()?;
        cfg.normalize();
        // Свои позиции проверяются, только если они используются.
        let uses_custom = cfg.split == "custom" || cfg.auto_chain.iter().any(|v| v.split == "custom");
        let positions = if uses_custom { parse_positions(&cfg.positions)? } else { Vec::new() };
        let port = cfg.port;
        let host = if cfg.lan { "0.0.0.0" } else { "127.0.0.1" };
        let listener = bind_retry(host, port)
            .map_err(|e| crate::tr!("порт {port} занят: {e}", "port {port} is busy: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let resolver = cfg.doh.then(|| crate::doh::CachedResolver::public(cfg.ipv6));
        let matcher = Matcher::with_worker(&cfg.rules, extra_bypass, cfg.worker.ready());
        let shared = Arc::new(Shared {
            matcher,
            resolver,
            bypassed: AtomicU64::new(0),
            passed: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            via_worker: AtomicU64::new(0),
            via_tor: AtomicU64::new(0),
            auto_cache: Mutex::new(std::collections::HashMap::new()),
            auto_retries: AtomicU64::new(0),
            positions,
            log: Mutex::new(std::collections::VecDeque::new()),
            cfg,
            stop: AtomicBool::new(false),
            active: AtomicU64::new(0),
            total: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            last_error: Mutex::new(None),
        });
        let sh = shared.clone();
        let accept = std::thread::spawn(move || {
            while !sh.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, peer)) => {
                        // Раздача в LAN: чужие (публичные) адреса не пускаем.
                        if !is_lan_peer(peer.ip()) {
                            continue;
                        }
                        let sh = sh.clone();
                        std::thread::spawn(move || {
                            let _ = s.set_nonblocking(false);
                            sh.total.fetch_add(1, Ordering::Relaxed);
                            sh.active.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = sh.handle(s) {
                                if !matches!(e.kind(), std::io::ErrorKind::UnexpectedEof) {
                                    sh.failed.fetch_add(1, Ordering::Relaxed);
                                    *sh.last_error.lock().unwrap() = Some(e.to_string());
                                }
                            }
                            sh.active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(Proxy { shared, accept: Some(accept) })
    }

    /// Журнал, новые записи первыми.
    pub fn log(&self) -> Vec<LogEntry> {
        self.shared.log.lock().unwrap().iter().rev().cloned().collect()
    }

    pub fn clear_log(&self) {
        self.shared.log.lock().unwrap().clear();
    }

    pub fn stats(&self) -> Stats {
        Stats {
            running: true,
            port: self.shared.cfg.port,
            active: self.shared.active.load(Ordering::Relaxed),
            total: self.shared.total.load(Ordering::Relaxed),
            failed: self.shared.failed.load(Ordering::Relaxed),
            system: self.shared.cfg.system,
            lan: self.shared.cfg.lan,
            auth: !self.shared.cfg.user.is_empty(),
            bypassed: self.shared.bypassed.load(Ordering::Relaxed),
            passed: self.shared.passed.load(Ordering::Relaxed),
            blocked: self.shared.blocked.load(Ordering::Relaxed),
            via_worker: self.shared.via_worker.load(Ordering::Relaxed),
            via_tor: self.shared.via_tor.load(Ordering::Relaxed),
            dns_cached: self.shared.resolver.as_ref().map(|r| r.len()).unwrap_or(0),
            bypass_domains: self.shared.matcher.bypass.len(),
            auto_retries: self.shared.auto_retries.load(Ordering::Relaxed),
            auto_sites: self.shared.auto_cache.lock().unwrap().len(),
            last_error: self.shared.last_error.lock().unwrap().clone(),
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // Цикл приёма проверяет флаг раз в 50 мс; с его выходом закрывается слушатель.
        if let Some(t) = self.accept.take() {
            let _ = t.join();
        }
    }
}

// ---------- брандмауэр Windows для раздачи в LAN (нужны права администратора) ----------

const FW_RULE: &str = "digital-bypass proxy";

/// Разрешить входящие на порт прокси из частной сети. Без прав — ошибка.
pub fn firewall_allow(port: u16) -> Result<(), String> {
    firewall_remove();
    let netsh = crate::util::system32("netsh.exe");
    let args = [
        "advfirewall".to_string(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={FW_RULE}"),
        "dir=in".into(),
        "action=allow".into(),
        "protocol=TCP".into(),
        format!("localport={port}"),
        "profile=private,domain".into(),
        "remoteip=localsubnet".into(),
    ];
    let out = crate::util::hidden(&netsh).args(&args).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(crate::tr!("правило брандмауэра не добавлено", "firewall rule was not added"))
    }
}

pub fn firewall_remove() {
    let netsh = crate::util::system32("netsh.exe");
    let _ = crate::util::hidden(&netsh)
        .args(["advfirewall", "firewall", "delete", "rule", &format!("name={FW_RULE}")])
        .output();
}

// ---------- системный прокси Windows (HKCU, без прав администратора) ----------

/// Значения до включения — чтобы вернуть как было.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SystemProxy {
    pub enable: u32,
    pub server: Option<String>,
    pub r#override: Option<String>,
}

const INET: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

mod reg {
    use windows_sys::Win32::System::Registry::{
        RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD,
        RRF_RT_REG_SZ,
    };

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn get_dword(path: &str, name: &str) -> Option<u32> {
        let (p, n) = (w(path), w(name));
        let mut v = 0u32;
        let mut size = 4u32;
        let r = unsafe {
            RegGetValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), &mut v as *mut u32 as *mut _, &mut size)
        };
        (r == 0).then_some(v)
    }

    pub fn get_sz(path: &str, name: &str) -> Option<String> {
        let (p, n) = (w(path), w(name));
        let mut buf = vec![0u16; 4096];
        let mut size = (buf.len() * 2) as u32;
        let r = unsafe {
            RegGetValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut size)
        };
        if r != 0 {
            return None;
        }
        buf.truncate((size as usize / 2).saturating_sub(1));
        Some(String::from_utf16_lossy(&buf))
    }

    pub fn set_dword(path: &str, name: &str, v: u32) -> Result<(), String> {
        let (p, n) = (w(path), w(name));
        let r = unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr(), REG_DWORD, &v as *const u32 as *const _, 4) };
        if r == 0 {
            Ok(())
        } else {
            Err(format!("registry {name}: {r}"))
        }
    }

    pub fn set_sz(path: &str, name: &str, v: Option<&str>) -> Result<(), String> {
        let (p, n) = (w(path), w(name));
        let r = match v {
            Some(v) => {
                let data = w(v);
                unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr(), REG_SZ, data.as_ptr() as *const _, (data.len() * 2) as u32) }
            }
            None => unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, p.as_ptr(), n.as_ptr()) },
        };
        if r == 0 || (v.is_none() && r == 2) {
            Ok(())
        } else {
            Err(format!("registry {name}: {r}"))
        }
    }
}

/// Сообщить WinINet (браузеры, система), что настройки прокси изменились.
fn notify_wininet() {
    use windows_sys::Win32::Networking::WinInet::{InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED};
    unsafe {
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

pub fn system_current() -> SystemProxy {
    SystemProxy {
        enable: reg::get_dword(INET, "ProxyEnable").unwrap_or(0),
        server: reg::get_sz(INET, "ProxyServer"),
        r#override: reg::get_sz(INET, "ProxyOverride"),
    }
}

pub fn our_server(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Включить наш прокси в системе; вернуть прежние настройки.
pub fn system_set(port: u16) -> Result<SystemProxy, String> {
    let prev = system_current();
    reg::set_sz(INET, "ProxyServer", Some(&our_server(port)))?;
    reg::set_sz(INET, "ProxyOverride", Some("localhost;127.*;10.*;172.16.*;192.168.*;<local>"))?;
    reg::set_dword(INET, "ProxyEnable", 1)?;
    notify_wininet();
    Ok(prev)
}

/// Вернуть прежние настройки (если в системе всё ещё наш прокси).
pub fn system_restore(prev: &SystemProxy, port: u16) -> Result<(), String> {
    let cur = system_current();
    if cur.server.as_deref() != Some(our_server(port).as_str()) {
        return Ok(()); // пользователь уже поменял сам — не трогаем
    }
    reg::set_sz(INET, "ProxyServer", prev.server.as_deref())?;
    reg::set_sz(INET, "ProxyOverride", prev.r#override.as_deref())?;
    reg::set_dword(INET, "ProxyEnable", prev.enable)?;
    notify_wininet();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Минимальный ClientHello с SNI.
    fn hello(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        // Ещё одно расширение после SNI.
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_sni() {
        let h = hello("www.youtube.com");
        let (i, n) = find_sni(&h).unwrap();
        assert_eq!(&h[i..i + n], b"www.youtube.com");
        assert!(find_sni(b"GET / HTTP/1.1\r\n").is_none());
        assert!(find_sni(&h[..40]).is_none());
    }

    #[test]
    fn split_keeps_payload_and_cuts_sni() {
        let h = hello("discord.com");
        let parts = split_client_hello(&h);
        assert_eq!(parts.len(), 3);
        // Склейка payload всех записей = исходный payload.
        let mut payload = Vec::new();
        for p in &parts {
            assert_eq!(&p[..3], &[0x16, 0x03, 0x01]);
            let len = u16::from_be_bytes([p[3], p[4]]) as usize;
            assert_eq!(p.len(), 5 + len);
            payload.extend_from_slice(&p[5..]);
        }
        assert_eq!(payload, h[5..]);
        // Имя целиком не встречается ни в одной записи.
        for p in &parts {
            assert!(!p.windows(11).any(|w| w == b"discord.com"));
        }
        // Хвост после записи прикрепляется к последней части.
        let mut with_tail = h.clone();
        with_tail.extend_from_slice(b"TAIL");
        assert!(split_client_hello(&with_tail).last().unwrap().ends_with(b"TAIL"));
        assert_eq!(split_client_hello(b"plain"), vec![b"plain".to_vec()]);
    }

    #[test]
    fn parses_requests() {
        assert_eq!(
            parse_request(b"CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(Request::Connect { host: "www.youtube.com".into(), port: 443 })
        );
        assert_eq!(
            parse_request(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n"),
            Some(Request::Connect { host: "2001:db8::1".into(), port: 8443 })
        );
        match parse_request(b"GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap() {
            Request::Http { host, port, head } => {
                assert_eq!((host.as_str(), port), ("example.com", 80));
                assert_eq!(head, b"GET /a?b HTTP/1.1\r\nHost: example.com\r\n\r\n");
            }
            _ => panic!(),
        }
        assert!(parse_request(b"GET /relative HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn socks_addresses() {
        assert_eq!(parse_socks_addr(&[1, 93, 184, 216, 34, 1, 187]), Some(("93.184.216.34".into(), 443, 7)));
        let mut d = vec![3, 11];
        d.extend_from_slice(b"example.com");
        d.extend_from_slice(&[0, 80]);
        assert_eq!(parse_socks_addr(&d), Some(("example.com".into(), 80, 15)));
        let mut v6 = vec![4];
        v6.extend_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&[0x20, 0xFB]);
        assert_eq!(parse_socks_addr(&v6), Some(("2001:db8::1".into(), 8443, 19)));
        assert_eq!(parse_socks_addr(&[3, 5, b'a']), None);
        assert_eq!(parse_socks_addr(&[9, 0]), None);
    }

    #[test]
    fn auto_order() {
        let p = Variant::new("sni", "records", true, false);
        let chain = default_chain();
        let o = attempt_order(&p, None, &chain, 4);
        assert_eq!(o[0], p);
        assert_eq!(o.len(), 4);
        assert_eq!(o.iter().filter(|v| **v == p).count(), 1, "без повторов");
        let cached = Variant::new("chunk", "tcp", true, false);
        let o = attempt_order(&p, Some(&cached), &chain, 4);
        assert_eq!((o[0].clone(), o[1].clone()), (cached, p));
        // Старые настройки без новых полей: автоматический режим включён, цепочка по умолчанию.
        let mut c: Config = serde_json::from_str(r#"{"port":9000,"split":"chunk"}"#).unwrap();
        c.normalize();
        assert!(c.auto && !c.oob && c.auto_chain == default_chain());
    }

    /// OOB-байт не доходит до приложения на сервере: оно получает исходные данные.
    #[test]
    fn oob_byte_is_stripped() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let h = hello("discord.com");
        let expect = h.clone();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = server.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut got = vec![0u8; expect.len()];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got, expect);
        });
        let mut up = TcpStream::connect(addr).unwrap();
        // TCP-сегменты одной записи: без OOB-байта склейка равна исходному.
        let parts = split_with(&h, &SplitOpts { records: false, ..Default::default() });
        send_parts(&mut up, &parts, false, true).unwrap();
        srv.join().unwrap();
    }

    /// Автоматический режим: сервер сбрасывает первое соединение — прокси
    /// переподключается другим способом и запоминает его для сайта.
    #[test]
    fn auto_retries_and_remembers() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let sport = server.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let acc = accepted.clone();
        std::thread::spawn(move || {
            for s in server.incoming() {
                let mut s = s.unwrap();
                let n = acc.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    let mut b = [0u8; 4096];
                    let _ = s.read(&mut b);
                    if n == 0 {
                        return; // первое соединение — молча закрыть (как DPI)
                    }
                    let _ = s.write_all(&[0x16, 3, 3, 0, 1, 0]);
                    // Дочитать до конца: закрытие с непрочитанными данными на Windows
                    // шлёт RST, и клиент теряет уже пришедший ответ.
                    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                    while matches!(s.read(&mut b), Ok(n) if n > 0) {}
                });
            }
        });
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let pport = probe.local_addr().unwrap().port();
        drop(probe);
        let cfg = Config { port: pport, doh: false, system: false, auto_timeout: 2, log: true, ..Default::default() };
        let proxy = Proxy::start(cfg, &[]).unwrap();
        let fetch = || {
            let mut c = TcpStream::connect(("127.0.0.1", pport)).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            write!(c, "CONNECT localhost:{sport} HTTP/1.1\r\n\r\n").unwrap();
            let mut resp = [0u8; 39];
            c.read_exact(&mut resp).unwrap();
            c.write_all(&hello("localhost.example")).unwrap();
            let mut r = [0u8; 6];
            if let Err(e) = c.read_exact(&mut r) {
                panic!("read: {e}; accepted={}", accepted.load(Ordering::SeqCst));
            }
            assert_eq!(r[0], 0x16);
        };
        fetch();
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "второй способ после сброса");
        assert_eq!(proxy.stats().auto_retries, 1);
        assert_eq!(proxy.stats().auto_sites, 1);
        fetch();
        assert_eq!(accepted.load(Ordering::SeqCst), 3, "сразу запомненный способ");
        assert_eq!(proxy.stats().auto_retries, 1);
        // Журнал: первая запись — с двумя попытками, вторая — с одной (из памяти).
        let log = proxy.log();
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|e| e.ok && e.action == "bypass" && e.host == "localhost"));
        assert_eq!((log[1].tries, log[0].tries), (2, 1));
        assert_eq!(log[0].method, log[1].method);
        proxy.clear_log();
        assert!(proxy.log().is_empty());
    }

    /// Первый живой адрес выигрывает, даже если перед ним «мёртвый».
    #[test]
    fn race_picks_working_address() {
        let ok = TcpListener::bind("127.0.0.1:0").unwrap();
        let good = ok.local_addr().unwrap();
        // 192.0.2.1 (TEST-NET-1) не отвечает — подключение висит до таймаута.
        let dead: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let t0 = std::time::Instant::now();
        let s = connect_race(&[dead, good], Duration::from_secs(5)).unwrap();
        assert_eq!(s.peer_addr().unwrap(), good);
        assert!(t0.elapsed() < Duration::from_secs(2));
        let closed = { let l = TcpListener::bind("127.0.0.1:0").unwrap(); l.local_addr().unwrap() };
        assert!(connect_race(&[closed], Duration::from_secs(2)).is_err());
    }

    #[test]
    fn custom_positions() {
        let p = parse_positions("0+sm, 1:3:5 -10 2+se 0+n").unwrap();
        assert_eq!(p.len(), 5);
        assert_eq!(p[0], Pos { offset: 0, repeats: 1, skip: 1, sni: Some('m'), zero: false });
        assert_eq!(p[1], Pos { offset: 1, repeats: 3, skip: 5, sni: None, zero: false });
        // Длина 100, имя сайта на 40..50.
        let sni = Some((40, 10));
        assert_eq!(resolve_positions(&parse_positions("0+sm").unwrap(), 100, sni), vec![45]);
        assert_eq!(resolve_positions(&parse_positions("1:3:5").unwrap(), 100, sni), vec![1, 6, 11]);
        assert_eq!(resolve_positions(&parse_positions("-10").unwrap(), 100, sni), vec![90]);
        assert_eq!(resolve_positions(&parse_positions("2+se").unwrap(), 100, sni), vec![52]);
        assert_eq!(resolve_positions(&parse_positions("-2+s").unwrap(), 100, sni), vec![38]);
        // Без SNI позиции от имени пропускаются; вне пакета — отбрасываются; повторы склеиваются.
        assert!(resolve_positions(&parse_positions("0+s").unwrap(), 100, None).is_empty());
        assert_eq!(resolve_positions(&parse_positions("0 200 5 5").unwrap(), 100, None), vec![5]);
        for bad in ["", "x", "1:0", "1:2:3:4", "5+h", "5+q", "+s"] {
            assert!(parse_positions(bad).is_err(), "{bad:?}");
        }
        // Нарезка своими позициями сохраняет данные.
        let h = hello("www.youtube.com");
        let o = SplitOpts { split: "custom".into(), records: false, positions: parse_positions("1 0+sm -3").unwrap(), ..Default::default() };
        let parts = split_with(&h, &o);
        assert_eq!(parts.len(), 4);
        assert_eq!(parts.concat(), h);
        // Неверные позиции не дают запустить прокси.
        let cfg = Config { port: 1, split: "custom".into(), positions: "zzz".into(), system: false, ..Default::default() };
        assert!(Proxy::start(cfg, &[]).is_err());
    }

    #[test]
    fn cut_points_modes() {
        assert_eq!(cut_points(100, Some((40, 10)), "sni", 4, 0), vec![40, 45]);
        assert_eq!(cut_points(100, None, "sni", 4, 0), vec![1]);
        assert_eq!(cut_points(100, None, "first-byte", 4, 0), vec![1]);
        assert_eq!(cut_points(10, None, "chunk", 4, 0), vec![4, 8]);
        // Не больше 256 кусков даже при chunk = 1.
        assert!(cut_points(2000, None, "chunk", 1, 0).len() < 256);
        let r = cut_points(100, None, "random", 4, 12345);
        assert!(r.len() == 1 && r[0] >= 1 && r[0] < 100);
        assert!(cut_points(100, None, "none", 4, 0).is_empty());
        assert!(cut_points(1, None, "first-byte", 4, 0).is_empty());
    }

    #[test]
    fn split_modes_keep_data() {
        let h = hello("www.youtube.com");
        for split in ["sni", "first-byte", "chunk", "random"] {
            // TCP-сегменты: склейка равна исходному.
            let o = SplitOpts { split: split.into(), records: false, chunk: 7, seed: 99, ..Default::default() };
            let parts = split_with(&h, &o);
            assert!(parts.len() > 1, "{split}");
            assert_eq!(parts.concat(), h, "{split}");
            // TLS-записи: склейка payload равна исходному payload.
            let o = SplitOpts { records: true, ..o };
            let mut payload = Vec::new();
            for p in split_with(&h, &o) {
                let len = u16::from_be_bytes([p[3], p[4]]) as usize;
                assert_eq!(p.len(), 5 + len, "{split}");
                payload.extend_from_slice(&p[5..]);
            }
            assert_eq!(payload, h[5..], "{split}");
        }
    }

    #[test]
    fn rules_and_domains() {
        assert_eq!(normalize_domain("*.YouTube.com."), Some("youtube.com".into()));
        assert_eq!(normalize_domain("localhost"), None);
        let r = Rules {
            scope: "all".into(),
            zapret_lists: false,
            bypass: vec![],
            skip: vec!["sberbank.ru".into()],
            block: vec!["ads.example.com".into()],
            worker: vec![],
            tor: vec![],
            tor_scope: "list".into(),
        };
        let m = Matcher::new(&r, &[]);
        assert_eq!(m.action("www.youtube.com"), Action::Bypass);
        assert_eq!(m.action("online.sberbank.ru"), Action::Pass);
        assert_eq!(m.action("notsberbank.ru"), Action::Bypass);
        assert_eq!(m.action("ads.example.com"), Action::Block);
        assert_eq!(m.action("example.com"), Action::Bypass);
        let listed = Matcher::new(&Rules { scope: "listed".into(), ..r.clone() }, &["googlevideo.com".to_string()]);
        assert_eq!(listed.action("rr3---sn-abc.googlevideo.com"), Action::Bypass);
        assert_eq!(listed.action("ya.ru"), Action::Pass);
        assert_eq!(listed.action("1.2.3.4"), Action::Pass);
        // Старые настройки: method → disorder.
        let mut c: Config = serde_json::from_str(r#"{"method":"split","port":9000}"#).unwrap();
        c.normalize();
        assert!(!c.disorder && c.method.is_none() && c.split == "sni" && c.port == 9000);
        assert!(!serde_json::to_string(&c).unwrap().contains("method"));
    }

    #[test]
    fn basic_auth() {
        assert_eq!(b64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(b64_decode("YQ==").unwrap(), b"a");
        assert_eq!(b64_decode("YWI=").unwrap(), b"ab");
        assert!(b64_decode("!!!!").is_none());
        let head = b"CONNECT x:443 HTTP/1.1\r\nproxy-authorization: Basic dXNlcjpwYXNz\r\n\r\n";
        assert!(check_basic(head, "user", "pass"));
        assert!(!check_basic(head, "user", "pas"));
        assert!(!check_basic(b"CONNECT x:443 HTTP/1.1\r\n\r\n", "user", "pass"));
        let ok = |u: &str, p: &str| Config { user: u.into(), pass: p.into(), ..Default::default() }.validate_auth().is_ok();
        assert!(ok("", "") && ok("phone", "s3cret"));
        assert!(!ok("phone", "") && !ok("", "x") && !ok("a:b", "x"));
    }

    /// SOCKS5 с логином и паролем (RFC 1929): верный пускает, неверный — нет.
    #[test]
    fn socks5_user_pass() {
        let run = |user: &[u8], pass: &[u8]| {
            let mut req = vec![5, 1, 2, 1, user.len() as u8];
            req.extend_from_slice(user);
            req.push(pass.len() as u8);
            req.extend_from_slice(pass);
            req.extend_from_slice(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
            let mut io = std::io::Cursor::new(req);
            let mut sink = Vec::new();
            struct Duplex<'a>(&'a mut std::io::Cursor<Vec<u8>>, &'a mut Vec<u8>);
            impl Read for Duplex<'_> {
                fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                    self.0.read(b)
                }
            }
            impl Write for Duplex<'_> {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    self.1.write(b)
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let r = socks5_handshake(&mut Duplex(&mut io, &mut sink), Some(("phone", "s3cret")));
            (r.ok(), sink)
        };
        let (ok, out) = run(b"phone", b"s3cret");
        assert_eq!(ok, Some(("1.2.3.4".into(), 80)));
        assert_eq!(&out[..4], &[5, 2, 1, 0]);
        let (bad, out) = run(b"phone", b"nope");
        assert!(bad.is_none());
        assert_eq!(&out[..4], &[5, 2, 1, 1]);
    }

    #[test]
    fn lan_peers() {
        for ok in ["127.0.0.1", "192.168.0.10", "10.1.2.3", "172.20.0.5", "169.254.1.1", "::1", "fe80::1", "fd00::1", "::ffff:192.168.1.5"] {
            assert!(is_lan_peer(ok.parse().unwrap()), "{ok}");
        }
        for bad in ["8.8.8.8", "100.64.0.1", "2a00:1450::1", "::ffff:8.8.8.8"] {
            assert!(!is_lan_peer(bad.parse().unwrap()), "{bad}");
        }
    }

    /// SOCKS5 на том же порту: имя сайта — «удалённое» (ATYP=3), туннель работает.
    #[test]
    fn socks5_loopback() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let sport = server.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = server.accept().unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).unwrap();
            assert_eq!(&b, b"ping");
            s.write_all(b"pong").unwrap();
        });
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let pport = probe.local_addr().unwrap().port();
        drop(probe);
        let cfg = Config { port: pport, disorder: false, doh: false, system: false, ..Default::default() };
        let _proxy = Proxy::start(cfg, &[]).unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", pport)).unwrap();
        c.write_all(&[5, 1, 0]).unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).unwrap();
        assert_eq!(r, [5, 0]);
        let mut req = vec![5, 1, 0, 3, 9];
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&sport.to_be_bytes());
        c.write_all(&req).unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).unwrap();
        assert_eq!(rep[1], 0, "socks reply {rep:?}");
        c.write_all(b"ping").unwrap();
        let mut pong = [0u8; 4];
        c.read_exact(&mut pong).unwrap();
        assert_eq!(&pong, b"pong");
        srv.join().unwrap();
    }

    /// Сеть: curl через прокси до PROXY_URL (по умолчанию YouTube) всеми способами.
    /// Системный прокси не трогается.
    #[test]
    #[ignore]
    fn live_proxy() {
        let url = std::env::var("PROXY_URL").unwrap_or_else(|_| "https://www.youtube.com/".into());
        let mut variants = Vec::new();
        for split in ["none", "sni", "first-byte", "chunk", "random"] {
            for unit in ["records", "tcp"] {
                for disorder in [false, true] {
                    if split == "none" && (unit == "tcp" || disorder) {
                        continue;
                    }
                    variants.push((split, unit, disorder));
                }
            }
        }
        for (split, unit, disorder) in variants {
            let method = format!("{split}/{unit}{}", if disorder { "+disorder" } else { "" });
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let cfg = Config { port, split: split.into(), unit: unit.into(), chunk: 4, disorder, system: false, ..Default::default() };
            let _p = Proxy::start(cfg, &[]).unwrap();
            let out = std::process::Command::new(crate::util::system32("curl.exe"))
                .args(["-s", "-o", "NUL", "-w", "%{http_code} %{time_total}", "--max-time", "12"])
                .args(["-x", &format!("http://127.0.0.1:{port}"), &url])
                .output()
                .unwrap();
            println!("{method}: {} (exit {:?}) {:?}", String::from_utf8_lossy(&out.stdout), out.status.code(), _p.stats().last_error);
        }
    }

    /// Сеть: автоматический режим с заведомо нерабочим основным способом
    /// («без нарезки»): сайты должны открыться запасными, повтор — из памяти.
    #[test]
    #[ignore]
    fn live_auto() {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let cfg = Config { port, split: "none".into(), disorder: false, system: false, log: true, ..Default::default() };
        let p = Proxy::start(cfg, &[]).unwrap();
        for round in 1..=2 {
            for host in ["www.youtube.com", "x.com", "discord.com", "www.instagram.com"] {
                let out = std::process::Command::new(crate::util::system32("curl.exe"))
                    .args(["-s", "-o", "NUL", "-w", "%{http_code} %{time_total}", "--max-time", "25"])
                    .args(["-x", &format!("http://127.0.0.1:{port}"), &format!("https://{host}/")])
                    .output()
                    .unwrap();
                println!("round {round} {host:<20} {}", String::from_utf8_lossy(&out.stdout));
            }
        }
        let s = p.stats();
        println!("auto_retries {} auto_sites {}", s.auto_retries, s.auto_sites);
        for e in p.log() {
            println!("LOG {:<20} {:<7} {:<30} tries {} {:?} ok {} {:?}", e.host, e.action, e.method.unwrap_or_default(), e.tries, e.ms, e.ok, e.error);
        }
    }

    /// Сквозной тест на loopback: «сервер» получает три TLS-записи, склейка
    /// их payload равна исходному ClientHello.
    #[test]
    fn mixed_record_versions() {
        let h = hello("www.example.com");
        let o = SplitOpts { mixver: true, ..Default::default() };
        let parts = split_with(&h, &o);
        assert!(parts.len() >= 2);
        assert_eq!(&parts[0][..3], &[0x16, 0x03, 0x03]);
        assert!(parts[1..].iter().all(|p| p[..3] == [0x16, 0x03, 0x01]));
        // Содержимое записей — тот же ClientHello.
        let body: Vec<u8> = parts.iter().flat_map(|p| p[5..].to_vec()).collect();
        assert_eq!(body, h[5..].to_vec());
    }

    #[test]
    fn worker_route() {
        assert_eq!(worker_path("www.instagram.com", 443, "a b&c"), "/tunnel?h=www.instagram.com&p=443&k=a%20b%26c");
        assert_eq!(worker_path("2001:db8::1", 8443, "k"), "/tunnel?h=2001%3Adb8%3A%3A1&p=8443&k=k");
        let rules = Rules { worker: vec!["instagram.com".into()], skip: vec!["instagram.com".into()], ..Default::default() };
        // Worker важнее «не резать»; без настроенного Worker — обычные правила.
        assert_eq!(Matcher::with_worker(&rules, &[], true).action("i.instagram.com"), Action::Worker);
        assert_eq!(Matcher::with_worker(&rules, &[], false).action("i.instagram.com"), Action::Pass);
        assert_eq!(Matcher::with_worker(&rules, &[], true).action("x.com"), Action::Bypass);
        let blocked = Rules { worker: vec!["a.com".into()], block: vec!["a.com".into()], ..Default::default() };
        assert_eq!(Matcher::with_worker(&blocked, &[], true).action("a.com"), Action::Block);
        assert!(!WorkerCfg::default().ready());
        // Tor не подключён: список «через Tor» не действует, .onion — всегда в Tor.
        let tor = Rules { tor: vec!["rutracker.org".into()], ..Default::default() };
        assert_eq!(Matcher::new(&tor, &[]).action("rutracker.org"), Action::Bypass);
        assert_eq!(Matcher::new(&tor, &[]).action("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"), Action::Tor);
        assert!(is_onion("x.ONION.") && !is_onion("onion.com"));
        assert!(worker_reason("websocket: HTTP 403").contains("403"));
        assert!(worker_reason("websocket: HTTP 502").contains("502"));
        assert_eq!(worker_reason("connection reset"), "connection reset");
        // Режимы Tor: только при подключённом Tor; «не резать» и Worker важнее режима.
        let z = ["youtube.com".to_string()];
        let all = Rules { tor_scope: "all".into(), skip: vec!["sberbank.ru".into()], ..Default::default() };
        let m = Matcher::with_worker(&all, &z, false);
        assert_eq!(m.action_with("example.com", true), Action::Tor);
        assert_eq!(m.action_with("sberbank.ru", true), Action::Pass);
        assert_eq!(m.action_with("example.com", false), Action::Bypass);
        let zr = Rules { tor_scope: "zapret".into(), zapret_lists: false, ..Default::default() };
        let m = Matcher::with_worker(&zr, &z, false);
        assert_eq!(m.action_with("www.youtube.com", true), Action::Tor);
        assert_eq!(m.action_with("example.com", true), Action::Bypass);
        let list = Rules { tor: vec!["a.org".into()], ..Default::default() };
        assert_eq!(Matcher::with_worker(&list, &z, false).action_with("youtube.com", true), Action::Bypass);
        assert_eq!(Matcher::with_worker(&list, &z, false).action_with("x.a.org", true), Action::Tor);
        let mut bad = Config::default();
        bad.rules.tor_scope = "everything".into();
        bad.normalize();
        assert_eq!(bad.rules.tor_scope, "list");
        // Старый конфиг без новых полей читается.
        let c: Config = serde_json::from_str(r#"{"rules":{"scope":"all","zapret_lists":true,"bypass":[],"skip":[],"block":[]}}"#).unwrap();
        assert!(c.rules.worker.is_empty() && c.worker.fragment);
    }

    /// Перезапуск на том же порту сразу после остановки (смена настроек).
    #[test]
    fn restart_same_port() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let cfg = Config { port, doh: false, system: false, ..Default::default() };
        for _ in 0..5 {
            let p = Proxy::start(cfg.clone(), &[]).expect("port must be free after drop");
            drop(p);
        }
    }

    #[test]
    fn end_to_end_loopback() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let sport = server.local_addr().unwrap().port();
        let h = hello("example.com");
        let expect = h[5..].to_vec();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = server.accept().unwrap();
            let mut payload = Vec::new();
            let mut records = 0;
            while payload.len() < expect.len() {
                let mut hdr = [0u8; 5];
                s.read_exact(&mut hdr).unwrap();
                assert_eq!(hdr[0], 0x16);
                let mut part = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
                s.read_exact(&mut part).unwrap();
                payload.extend_from_slice(&part);
                records += 1;
            }
            assert_eq!(payload, expect);
            assert_eq!(records, 3);
            s.write_all(b"pong").unwrap();
        });
        // Свободный порт для прокси.
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let pport = probe.local_addr().unwrap().port();
        drop(probe);
        let cfg = Config { port: pport, disorder: false, doh: false, system: false, ..Default::default() };
        let _proxy = Proxy::start(cfg, &[]).unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", pport)).unwrap();
        write!(c, "CONNECT 127.0.0.1:{sport} HTTP/1.1\r\n\r\n").unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200"));
        c.write_all(&h).unwrap();
        let mut pong = [0u8; 4];
        c.read_exact(&mut pong).unwrap();
        assert_eq!(&pong, b"pong");
        srv.join().unwrap();
    }
}
