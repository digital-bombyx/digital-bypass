//! Telegram: локальный MTProto-прокси, который ведёт трафик Telegram Desktop
//! через WebSocket к веб-адресам Telegram (`kws{N}.web.telegram.org`).
//!
//! Порт идеи tg-ws-proxy (Flowseal, MIT): https://github.com/Flowseal/tg-ws-proxy
//!
//! 1. Telegram Desktop подключается к `127.0.0.1:port` с секретом (`dd…`).
//! 2. Первые 64 байта — init obfuscated2: ключ = SHA-256(prekey + secret),
//!    внутри — тег протокола и номер дата-центра.
//! 3. Прокси создаёт свой init (обычная обфускация, без секрета) и открывает
//!    WebSocket через TLS к `kws{dc}.web.telegram.org` по IP веб-фронта
//!    Telegram. Каждый MTProto-пакет уходит отдельным кадром WebSocket.
//! 4. Трафик перешифровывается в обе стороны (AES-256-CTR).
//! 5. Свой Cloudflare Worker (`/apiws?dst=IP&dc=N`): Worker открывает TCP к DC.
//! 6. Если WS-маршрута нет или он не работает — через CF-прокси: домены за
//!    Cloudflare (`kws{dc}.домен`), которые пересылают WebSocket к Telegram.
//! 7. Последний запасной путь — обычное TCP-подключение к DC.
//!
//! TLS к Telegram можно открывать с нарезкой ClientHello — как в прокси-обходчике.
//! Подмена SNI (как в tg-ws-proxy): в ClientHello прямого маршрута уходит
//! другое имя (например, из белого списка), заголовок Host остаётся
//! `kws{dc}.web.telegram.org`. Сертификат проверяется по цепочке без сверки
//! имени — сообщения всё равно защищены собственным шифрованием MTProto.

use aes::cipher::{BlockEncrypt, KeyInit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SKIP_LEN: usize = 8;
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;
const TAG_ABRIDGED: [u8; 4] = [0xef; 4];
const TAG_INTERMEDIATE: [u8; 4] = [0xee; 4];
const TAG_SECURE: [u8; 4] = [0xdd; 4];
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Ожидание TCP-подключения к WS/CF: заблокированный адрес не должен съедать
/// время запасных путей.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Прямые адреса дата-центров (запасной путь по TCP).
pub fn dc_ip(dc: i32, test: bool) -> Option<&'static str> {
    if test {
        return match dc {
            1 => Some("149.154.175.10"),
            2 => Some("149.154.167.40"),
            3 => Some("149.154.175.117"),
            _ => None,
        };
    }
    match dc {
        1 => Some("149.154.175.50"),
        2 => Some("149.154.167.51"),
        3 => Some("149.154.175.100"),
        4 => Some("149.154.167.91"),
        5 => Some("149.154.171.5"),
        203 => Some("91.105.192.100"),
        _ => None,
    }
}

/// Имена WS-эндпоинтов для дата-центра.
pub fn ws_domains(dc: i32, media: bool) -> Vec<String> {
    let dc = if dc == 203 { 2 } else { dc };
    if media {
        vec![format!("kws{dc}-1.web.telegram.org"), format!("kws{dc}.web.telegram.org")]
    } else {
        vec![format!("kws{dc}.web.telegram.org")]
    }
}

// ---------- настройки ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub port: u16,
    /// 16 байт в hex. Пусто — сгенерировать.
    pub secret: String,
    /// `dc:ip` — через какой IP веб-фронта ходить к дата-центру по WebSocket.
    pub dc_ip: Vec<String>,
    /// Нарезать ClientHello при TLS к Telegram (против DPI).
    pub fragment: bool,
    /// Запасной путь через CF-прокси (домены за Cloudflare).
    pub cf_proxy: bool,
    /// Свои CF-домены; пусто — встроенный список tg-ws-proxy.
    pub cf_domains: Vec<String>,
    /// Свои Cloudflare Worker'ы (`имя.аккаунт.workers.dev`) — пробуются первыми.
    pub cf_workers: Vec<String>,
    /// Подменное имя в TLS для прямого WebSocket (пусто — без подмены).
    /// Сначала пробуется с подменой, затем с настоящим именем.
    pub sni: String,
    /// Включать при запуске приложения.
    pub enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            port: 1443,
            secret: String::new(),
            dc_ip: vec!["2:149.154.167.220".into(), "4:149.154.167.220".into()],
            fragment: true,
            cf_proxy: true,
            cf_domains: Vec::new(),
            cf_workers: Vec::new(),
            sni: String::new(),
            enabled: false,
        }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("getrandom");
    b
}

pub fn new_secret() -> String {
    random_bytes::<16>().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_secret(s: &str) -> Result<[u8; 16], String> {
    let s = s.trim().trim_start_matches("dd").trim_start_matches("ee");
    let bad = || crate::tr!("секрет — 32 шестнадцатеричных символа", "the secret is 32 hex characters");
    if s.len() != 32 {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// `2:149.154.167.220` → (2, ip).
pub fn parse_dc_ip(list: &[String]) -> Result<Vec<(i32, IpAddr)>, String> {
    list.iter()
        .map(|e| {
            let (dc, ip) = e.trim().split_once(':').ok_or_else(|| crate::tr!("запись «{e}»: нужно dc:ip", "entry \"{e}\": dc:ip expected"))?;
            let dc: i32 = dc.trim().parse().map_err(|_| crate::tr!("запись «{e}»: номер DC", "entry \"{e}\": DC number"))?;
            let ip: IpAddr = ip.trim().parse().map_err(|_| crate::tr!("запись «{e}»: IP-адрес", "entry \"{e}\": IP address"))?;
            Ok((dc, ip))
        })
        .collect()
}

/// Встроенные CF-домены tg-ws-proxy (зашифрованы сдвигом, как в оригинале,
/// чтобы их не вычищали автоматически). Список может устареть — свои домены
/// задаются в настройках.
const CF_ENCODED: [&str; 20] = [
    "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com", "awzwsldi.com", "clngqrflngqin.com",
    "tjacxbqtj.com", "bxaxtxmrw.com", "dmohrsgmohcrwb.com", "vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com",
    "xwuwoqbm.com", "orgcnunpj.com", "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
];

/// Расшифровка домена: сдвиг назад на число букв, суффикс `.com` → `.co.uk`.
pub fn decode_cf_domain(s: &str) -> String {
    let Some(p) = s.strip_suffix(".com") else { return s.to_string() };
    let n = p.chars().filter(|c| c.is_ascii_alphabetic()).count() as i32;
    let body: String = p
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' } as i32;
                (((c as i32 - base - n).rem_euclid(26)) + base) as u8 as char
            } else {
                c
            }
        })
        .collect();
    format!("{body}.co.uk")
}

pub fn default_cf_domains() -> Vec<String> {
    CF_ENCODED.iter().map(|d| decode_cf_domain(d)).collect()
}

pub fn link(host: &str, port: u16, secret: &str) -> String {
    format!("tg://proxy?server={host}&port={port}&secret=dd{secret}")
}

// ---------- AES-256-CTR ----------

/// AES-256 в режиме CTR (счётчик — 128-битное big-endian число, как в OpenSSL).
pub struct AesCtr {
    cipher: aes::Aes256,
    counter: [u8; 16],
    ks: [u8; 16],
    pos: usize,
}

impl AesCtr {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        let mut counter = [0u8; 16];
        counter.copy_from_slice(&iv[..16]);
        AesCtr { cipher: aes::Aes256::new_from_slice(&key[..32]).expect("key"), counter, ks: [0; 16], pos: 16 }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.pos == 16 {
                let mut block = aes::Block::from(self.counter);
                self.cipher.encrypt_block(&mut block);
                self.ks.copy_from_slice(&block);
                self.pos = 0;
                for c in self.counter.iter_mut().rev() {
                    *c = c.wrapping_add(1);
                    if *c != 0 {
                        break;
                    }
                }
            }
            *b ^= self.ks[self.pos];
            self.pos += 1;
        }
    }

}

fn sha256(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

// ---------- рукопожатие ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// Номер дата-центра (для тестовых — без +10000).
    pub dc: i32,
    pub media: bool,
    pub test: bool,
    pub tag: [u8; 4],
}

/// Разобрать init клиента. Возвращает параметры и расшифровщик потока клиента
/// (уже сдвинутый на 64 байта).
pub fn client_hello(init: &[u8; 64], secret: &[u8; 16]) -> Option<(Hello, AesCtr)> {
    let prekey = &init[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let iv = &init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut dec = AesCtr::new(&sha256(prekey, secret), iv);
    let mut plain = *init;
    dec.apply(&mut plain);
    let tag: [u8; 4] = plain[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().ok()?;
    if tag != TAG_ABRIDGED && tag != TAG_INTERMEDIATE && tag != TAG_SECURE {
        return None;
    }
    let idx = i16::from_le_bytes([plain[DC_IDX_POS], plain[DC_IDX_POS + 1]]) as i32;
    let mut dc = idx.abs();
    let test = dc >= 10000;
    if test {
        dc -= 10000;
    }
    Some((Hello { dc, media: idx < 0, test, tag }, dec))
}

/// Шифровщик потока к клиенту: ключ из перевёрнутых prekey+iv клиента.
pub fn client_encryptor(init: &[u8; 64], secret: &[u8; 16]) -> AesCtr {
    let mut rev = init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].to_vec();
    rev.reverse();
    AesCtr::new(&sha256(&rev[..PREKEY_LEN], secret), &rev[PREKEY_LEN..])
}

/// Случайный init без «зарезервированных» начал (как у официальных клиентов).
pub fn random_init() -> [u8; 64] {
    loop {
        let r = random_bytes::<64>();
        let bad_start = [b"HEAD", b"POST", b"GET ", &[0xee; 4], &[0xdd; 4], &[0x16, 3, 1, 2], b"OPTI"]
            .iter()
            .any(|s| r[..4] == s[..]);
        if r[0] == 0xef || bad_start || r[4..8] == [0, 0, 0, 0] {
            continue;
        }
        return r;
    }
}

/// Init к Telegram (без секрета) с тегом и номером DC; шифровщики в обе стороны.
pub fn relay_init(tag: [u8; 4], dc_idx: i16) -> ([u8; 64], AesCtr, AesCtr) {
    let mut init = random_init();
    let key = init[SKIP_LEN..SKIP_LEN + PREKEY_LEN].to_vec();
    let iv = init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].to_vec();
    let mut enc = AesCtr::new(&key, &iv);
    let mut tail = [0u8; 8];
    tail[..4].copy_from_slice(&tag);
    tail[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    tail[6..].copy_from_slice(&random_bytes::<2>());
    init[PROTO_TAG_POS..].copy_from_slice(&tail);
    let mut enc_full = init;
    enc.apply(&mut enc_full);
    // Первые 56 байт уходят как есть, последние 8 — зашифрованными.
    init[PROTO_TAG_POS..].copy_from_slice(&enc_full[PROTO_TAG_POS..]);
    let mut rev = init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].to_vec();
    // Расшифровщик ответа строится из исходных (не зашифрованных) байт 8..56 — они не менялись.
    rev.reverse();
    let dec = AesCtr::new(&rev[..PREKEY_LEN], &rev[PREKEY_LEN..]);
    (init, enc, dec)
}

// ---------- разбиение на пакеты MTProto ----------

/// Режет поток на транспортные пакеты MTProto (abridged / intermediate),
/// чтобы каждый ушёл отдельным кадром WebSocket. Длина читается из открытого
/// текста, режется зашифрованный поток — смещения у них совпадают.
pub struct Splitter {
    tag: [u8; 4],
    cipher: Vec<u8>,
    plain: Vec<u8>,
    disabled: bool,
}

impl Splitter {
    pub fn new(tag: [u8; 4]) -> Self {
        Splitter { tag, cipher: Vec::new(), plain: Vec::new(), disabled: false }
    }

    fn next_len(&self, off: usize) -> Option<usize> {
        let avail = self.plain.len() - off;
        if avail == 0 {
            return None;
        }
        let (hdr, payload) = if self.tag == TAG_ABRIDGED {
            let first = self.plain[off];
            if first == 0x7f || first == 0xff {
                if avail < 4 {
                    return None;
                }
                (4, u32::from_le_bytes([self.plain[off + 1], self.plain[off + 2], self.plain[off + 3], 0]) as usize * 4)
            } else {
                (1, (first & 0x7f) as usize * 4)
            }
        } else {
            if avail < 4 {
                return None;
            }
            (4, (u32::from_le_bytes(self.plain[off..off + 4].try_into().unwrap()) & 0x7fff_ffff) as usize)
        };
        if payload == 0 {
            return Some(0);
        }
        (avail >= hdr + payload).then_some(hdr + payload)
    }

    pub fn split(&mut self, cipher: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if self.disabled {
            return vec![cipher.to_vec()];
        }
        self.cipher.extend_from_slice(cipher);
        self.plain.extend_from_slice(plain);
        let mut out = Vec::new();
        let mut off = 0;
        while let Some(n) = self.next_len(off) {
            if n == 0 {
                // Непонятный формат — дальше без разбиения.
                out.push(self.cipher[off..].to_vec());
                off = self.cipher.len();
                self.disabled = true;
                break;
            }
            out.push(self.cipher[off..off + n].to_vec());
            off += n;
        }
        self.cipher.drain(..off);
        self.plain.drain(..off);
        out
    }

    pub fn flush(&mut self) -> Option<Vec<u8>> {
        self.plain.clear();
        (!self.cipher.is_empty()).then(|| std::mem::take(&mut self.cipher))
    }
}

// ---------- TLS, который можно читать и писать из разных потоков ----------

/// rustls-соединение: один поток читает, другой пишет. Блокирующее чтение
/// сокета идёт без блокировки, обработка TLS — под мьютексом.
pub struct TlsDuplex {
    conn: Mutex<(rustls::ClientConnection, TcpStream)>,
    rd: Mutex<TcpStream>,
    raw: TcpStream,
}

impl TlsDuplex {
    /// Обычное подключение (для тестов; в работе — через `connect_as`).
    #[cfg(test)]
    pub fn connect(addr: SocketAddr, sni: &str, fragment: bool) -> std::io::Result<Self> {
        Self::connect_as(addr, sni, None, fragment)
    }

    /// `sni_override` — подменное имя в ClientHello (сертификат тогда
    /// проверяется по цепочке без сверки имени).
    pub fn connect_as(addr: SocketAddr, sni: &str, sni_override: Option<&str>, fragment: bool) -> std::io::Result<Self> {
        let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(IO_TIMEOUT))?;
        let name = rustls::pki_types::ServerName::try_from(sni_override.unwrap_or(sni).to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let config = if sni_override.is_some() { crate::doh::tls_config_any_name() } else { crate::doh::tls_config() };
        let mut conn = rustls::ClientConnection::new(config, name).map_err(std::io::Error::other)?;
        let mut io = crate::diag::Fragmenting { inner: tcp.try_clone()?, first: fragment, got: 0 };
        while conn.is_handshaking() {
            conn.complete_io(&mut io)?;
        }
        tcp.set_read_timeout(None)?;
        Ok(TlsDuplex { conn: Mutex::new((conn, tcp.try_clone()?)), rd: Mutex::new(tcp.try_clone()?), raw: tcp })
    }

    pub fn send(&self, data: &[u8]) -> std::io::Result<()> {
        let mut g = self.conn.lock().unwrap();
        let (c, w) = &mut *g;
        c.writer().write_all(data)?;
        while c.wants_write() {
            c.write_tls(w)?;
        }
        Ok(())
    }

    /// Дочитать расшифрованные данные в `out`. 0 — соединение закрыто.
    pub fn recv(&self, out: &mut Vec<u8>) -> std::io::Result<usize> {
        let mut buf = [0u8; 16 * 1024];
        loop {
            {
                let mut g = self.conn.lock().unwrap();
                let (c, _) = &mut *g;
                match c.reader().read(&mut buf) {
                    Ok(0) => return Ok(0),
                    Ok(n) => {
                        out.extend_from_slice(&buf[..n]);
                        return Ok(n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
            let n = self.rd.lock().unwrap().read(&mut buf)?;
            if n == 0 {
                return Ok(0);
            }
            let mut g = self.conn.lock().unwrap();
            let (c, w) = &mut *g;
            let mut slice = &buf[..n];
            while !slice.is_empty() {
                c.read_tls(&mut slice)?;
                c.process_new_packets().map_err(std::io::Error::other)?;
                // Освобождаем буфер расшифрованного, иначе read_tls откажется читать дальше.
                let mut tmp = [0u8; 16 * 1024];
                loop {
                    match c.reader().read(&mut tmp) {
                        Ok(0) => break,
                        Ok(k) => out.extend_from_slice(&tmp[..k]),
                        Err(_) => break,
                    }
                }
            }
            while c.wants_write() {
                c.write_tls(w)?;
            }
            if !out.is_empty() {
                return Ok(out.len());
            }
        }
    }

    pub fn shutdown(&self) {
        let _ = self.raw.shutdown(Shutdown::Both);
    }
}

// ---------- WebSocket (клиент) ----------

pub fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80 | opcode];
    let n = payload.len();
    if n < 126 {
        f.push(0x80 | n as u8);
    } else if n < 65536 {
        f.push(0x80 | 126);
        f.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        f.push(0x80 | 127);
        f.extend_from_slice(&(n as u64).to_be_bytes());
    }
    let mask = random_bytes::<4>();
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// Кадр из буфера: (fin, opcode, payload, длина кадра) или None, если мало данных.
pub fn ws_parse(buf: &[u8]) -> Option<(bool, u8, Vec<u8>, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let fin = buf[0] & 0x80 != 0;
    let op = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let mut len = (buf[1] & 0x7f) as usize;
    let mut i = 2;
    if len == 126 {
        len = u16::from_be_bytes(buf.get(2..4)?.try_into().ok()?) as usize;
        i = 4;
    } else if len == 127 {
        len = u64::from_be_bytes(buf.get(2..10)?.try_into().ok()?) as usize;
        i = 10;
    }
    let mask = if masked {
        let m: [u8; 4] = buf.get(i..i + 4)?.try_into().ok()?;
        i += 4;
        Some(m)
    } else {
        None
    };
    let body = buf.get(i..i + len)?;
    let payload = match mask {
        Some(m) => body.iter().enumerate().map(|(k, b)| b ^ m[k % 4]).collect(),
        None => body.to_vec(),
    };
    Some((fin, op, payload, i + len))
}

pub struct Ws {
    tls: Arc<TlsDuplex>,
}

impl Ws {
    /// WebSocket `wss://domain/path` через IP `addr` (SNI и Host — domain).
    pub fn connect(addr: SocketAddr, domain: &str, path: &str, fragment: bool) -> std::io::Result<(Ws, Vec<u8>)> {
        Self::connect_as(addr, domain, None, path, fragment)
    }

    /// Как `connect`, но в TLS — подменное имя `sni`, в Host — настоящее.
    pub fn connect_as(addr: SocketAddr, domain: &str, sni: Option<&str>, path: &str, fragment: bool) -> std::io::Result<(Ws, Vec<u8>)> {
        let tls = TlsDuplex::connect_as(addr, domain, sni, fragment)?;
        let key = random_bytes::<16>();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
            b64(&key)
        );
        tls.send(req.as_bytes())?;
        let mut buf = Vec::new();
        let end = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            if buf.len() > 16 * 1024 || tls.recv(&mut buf)? == 0 {
                return Err(std::io::Error::other("websocket: no handshake response"));
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_string();
        let status = head.split_whitespace().nth(1).unwrap_or("");
        if status != "101" {
            return Err(std::io::Error::other(format!("websocket: HTTP {status}")));
        }
        // Байты после заголовков — уже кадры.
        Ok((Ws { tls: Arc::new(tls) }, buf[end..].to_vec()))
    }

    pub fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        self.tls.send(&ws_frame(0x2, payload))
    }
}

/// Простая пересылка: байты клиента ↔ двоичные кадры WebSocket (туннель через
/// свой Worker в прокси-обходчике). `early` — байты после заголовков ответа
/// WebSocket, `first` — то, что клиент уже прислал.
pub fn ws_pipe(client: TcpStream, ws: Ws, early: Vec<u8>, first: Vec<u8>) -> std::io::Result<()> {
    client.set_read_timeout(None)?;
    if !first.is_empty() {
        ws.send(&first)?;
    }
    let tls = ws.tls.clone();
    let mut cw = client.try_clone()?;
    let down = std::thread::spawn(move || {
        let mut buf = early;
        loop {
            while let Some((_, op, payload, used)) = ws_parse(&buf) {
                buf.drain(..used);
                match op {
                    0 | 1 | 2 => {
                        if cw.write_all(&payload).is_err() {
                            return;
                        }
                    }
                    8 => {
                        let _ = cw.shutdown(Shutdown::Write);
                        return;
                    }
                    9 => {
                        let _ = tls.send(&ws_frame(0xA, &payload));
                    }
                    _ => {}
                }
            }
            match tls.recv(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = cw.shutdown(Shutdown::Write);
                    return;
                }
                Ok(_) => {}
            }
        }
    });
    let mut cr = client;
    let mut b = [0u8; 16 * 1024];
    loop {
        match cr.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if ws.send(&b[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = ws.tls.send(&ws_frame(0x8, &[]));
    ws.tls.shutdown();
    let _ = down.join();
    Ok(())
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

// ---------- сервер ----------

#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub running: bool,
    pub active: u64,
    pub total: u64,
    pub ws: u64,
    pub cf: u64,
    pub worker: u64,
    /// Из прямых WS — сколько установлено с подменой SNI.
    pub fronted: u64,
    pub tcp: u64,
    pub bad: u64,
    pub failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_error: Option<String>,
}

struct Shared {
    secret: [u8; 16],
    routes: Vec<(i32, IpAddr)>,
    fragment: bool,
    cf_domains: Vec<String>,
    cf_workers: Vec<String>,
    worker: AtomicU64,
    sni: Option<String>,
    fronted: AtomicU64,
    /// DC → CF-домен, который сработал в прошлый раз.
    cf_last: Mutex<std::collections::HashMap<i32, String>>,
    /// DC → до какого момента не пробовать прямой WS (он не отвечал).
    ws_down: Mutex<std::collections::HashMap<i32, std::time::Instant>>,
    resolver: crate::doh::CachedResolver,
    cf: AtomicU64,
    stop: AtomicBool,
    active: AtomicU64,
    total: AtomicU64,
    ws: AtomicU64,
    tcp: AtomicU64,
    bad: AtomicU64,
    failed: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl Shared {
    fn handle(&self, mut client: TcpStream) -> std::io::Result<()> {
        client.set_nodelay(true)?;
        client.set_read_timeout(Some(IO_TIMEOUT))?;
        let mut init = [0u8; 64];
        client.read_exact(&mut init)?;
        let Some((hello, clt_dec)) = client_hello(&init, &self.secret) else {
            self.bad.fetch_add(1, Ordering::Relaxed);
            return Err(std::io::Error::other(crate::tr!("неверный секрет или протокол", "wrong secret or protocol")));
        };
        client.set_read_timeout(None)?;
        let clt_enc = client_encryptor(&init, &self.secret);
        let dc_idx = (if hello.test { hello.dc + 10000 } else { hello.dc }) as i16 * if hello.media { -1 } else { 1 };
        let (rinit, tg_enc, tg_dec) = relay_init(hello.tag, dc_idx);

        // 1. WebSocket к веб-фронту Telegram, если для этого DC есть маршрут
        //    и он недавно не отказывал.
        let ws_ok = self.ws_down.lock().unwrap().get(&hello.dc).is_none_or(|t| *t < std::time::Instant::now());
        if let Some((_, ip)) = self.routes.iter().find(|(d, _)| *d == hello.dc).filter(|_| ws_ok) {
            let path = if hello.test { "/apiws_test" } else { "/apiws" };
            // С подменой SNI (если задана) — первой, затем с настоящим именем.
            let snis: Vec<Option<&str>> = match self.sni.as_deref() {
                Some(s) => vec![Some(s), None],
                None => vec![None],
            };
            for domain in ws_domains(hello.dc, hello.media) {
                for sni in &snis {
                    match Ws::connect_as(SocketAddr::new(*ip, 443), &domain, *sni, path, self.fragment) {
                        Ok((ws, early)) => {
                            ws.send(&rinit)?;
                            self.ws.fetch_add(1, Ordering::Relaxed);
                            if sni.is_some() {
                                self.fronted.fetch_add(1, Ordering::Relaxed);
                            }
                            return self.bridge_ws(client, ws, early, hello.tag, clt_dec, clt_enc, tg_enc, tg_dec);
                        }
                        Err(e) => {
                            let via = sni.map(|s| format!(" (SNI {s})")).unwrap_or_default();
                            *self.last_error.lock().unwrap() = Some(format!("DC{} {domain}{via}: {e}", hello.dc));
                        }
                    }
                }
            }
            // Не отвечает — минуту не тратим на него время.
            self.ws_down.lock().unwrap().insert(hello.dc, std::time::Instant::now() + Duration::from_secs(60));
        }
        // 2. Свой Cloudflare Worker: он сам открывает TCP к дата-центру.
        if !self.cf_workers.is_empty() && !hello.test {
            if let Some((ws, early)) = self.worker_connect(hello.dc) {
                ws.send(&rinit)?;
                self.worker.fetch_add(1, Ordering::Relaxed);
                return self.bridge_ws(client, ws, early, hello.tag, clt_dec, clt_enc, tg_enc, tg_dec);
            }
        }
        // 3. CF-прокси: домены за Cloudflare пересылают WebSocket к дата-центру.
        if !self.cf_domains.is_empty() && !hello.test {
            if let Some((ws, early)) = self.cf_connect(hello.dc) {
                ws.send(&rinit)?;
                self.cf.fetch_add(1, Ordering::Relaxed);
                return self.bridge_ws(client, ws, early, hello.tag, clt_dec, clt_enc, tg_enc, tg_dec);
            }
        }
        // Запасной путь — TCP к дата-центру.
        let ip = dc_ip(hello.dc, hello.test).ok_or_else(|| std::io::Error::other(format!("DC{}: no address", hello.dc)))?;
        let mut up = TcpStream::connect_timeout(&SocketAddr::new(ip.parse().unwrap(), 443), IO_TIMEOUT)?;
        up.set_nodelay(true)?;
        up.write_all(&rinit)?;
        self.tcp.fetch_add(1, Ordering::Relaxed);
        self.bridge_tcp(client, up, clt_dec, clt_enc, tg_enc, tg_dec)
    }

    fn resolve_v4(&self, host: &str) -> Vec<IpAddr> {
        let ips = match self.resolver.resolve(host) {
            Some(v) => v,
            None => {
                use std::net::ToSocketAddrs;
                (host, 443).to_socket_addrs().map(|i| i.map(|a| a.ip()).collect()).unwrap_or_default()
            }
        };
        ips.into_iter().filter(|i| i.is_ipv4()).take(2).collect()
    }

    /// Свой Worker: `wss://worker/apiws?dst=<IP DC>&dc=<N>`.
    fn worker_connect(&self, dc: i32) -> Option<(Ws, Vec<u8>)> {
        let dst = dc_ip(dc, false)?;
        let path = format!("/apiws?dst={dst}&dc={dc}");
        for host in self.cf_workers.iter().take(3) {
            for ip in self.resolve_v4(host) {
                match Ws::connect(SocketAddr::new(ip, 443), host, &path, self.fragment) {
                    Ok(w) => return Some(w),
                    Err(e) => *self.last_error.lock().unwrap() = Some(format!("Worker {host}: {e}")),
                }
            }
        }
        None
    }

    /// Подключиться к `kws{dc}.<домен>` через CF: сначала домен, сработавший
    /// в прошлый раз, затем остальные (до 5 попыток).
    fn cf_connect(&self, dc: i32) -> Option<(Ws, Vec<u8>)> {
        let last = self.cf_last.lock().unwrap().get(&dc).cloned();
        let mut order: Vec<String> = last.iter().cloned().collect();
        let mut rest: Vec<String> = self.cf_domains.iter().filter(|d| Some(*d) != last.as_ref()).cloned().collect();
        // Разные DC — на разные домены: у Cloudflare лимит WS-подключений на домен.
        let shift = (dc as usize + random_bytes::<1>()[0] as usize) % rest.len().max(1);
        rest.rotate_left(shift);
        order.extend(rest);
        let dc_n = if dc == 203 { 2 } else { dc };
        for base in order.into_iter().take(5) {
            let host = format!("kws{dc_n}.{base}");
            for ip in self.resolve_v4(&host) {
                match Ws::connect(SocketAddr::new(ip, 443), &host, "/apiws", self.fragment) {
                    Ok(w) => {
                        self.cf_last.lock().unwrap().insert(dc, base.clone());
                        return Some(w);
                    }
                    Err(e) => *self.last_error.lock().unwrap() = Some(format!("CF {host}: {e}")),
                }
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn bridge_ws(
        &self,
        client: TcpStream,
        ws: Ws,
        early: Vec<u8>,
        tag: [u8; 4],
        mut clt_dec: AesCtr,
        mut clt_enc: AesCtr,
        mut tg_enc: AesCtr,
        mut tg_dec: AesCtr,
    ) -> std::io::Result<()> {
        let tls = ws.tls.clone();
        let mut c_w = client.try_clone()?;
        let c_close = client.try_clone()?;
        std::thread::scope(|s| {
            // Telegram → клиент.
            let down = s.spawn(|| {
                let mut buf = early;
                let mut msg: Vec<u8> = Vec::new();
                loop {
                    while let Some((fin, op, payload, used)) = ws_parse(&buf) {
                        buf.drain(..used);
                        match op {
                            0x0 | 0x2 => {
                                msg.extend_from_slice(&payload);
                                if fin {
                                    let mut data = std::mem::take(&mut msg);
                                    tg_dec.apply(&mut data);
                                    clt_enc.apply(&mut data);
                                    self.down.fetch_add(data.len() as u64, Ordering::Relaxed);
                                    if c_w.write_all(&data).is_err() {
                                        return;
                                    }
                                }
                            }
                            0x9 => {
                                let _ = tls.send(&ws_frame(0xA, &payload));
                            }
                            0x8 => return,
                            _ => {}
                        }
                    }
                    match tls.recv(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            });
            // Клиент → Telegram: каждый пакет MTProto — отдельный кадр.
            let mut client = client;
            let mut splitter = Splitter::new(tag);
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match client.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                self.up.fetch_add(n as u64, Ordering::Relaxed);
                let mut plain = buf[..n].to_vec();
                clt_dec.apply(&mut plain);
                let mut enc = plain.clone();
                tg_enc.apply(&mut enc);
                if splitter.split(&enc, &plain).iter().any(|p| ws.send(p).is_err()) {
                    break;
                }
            }
            if let Some(tail) = splitter.flush() {
                let _ = ws.send(&tail);
            }
            let _ = ws.tls.send(&ws_frame(0x8, &[]));
            ws.tls.shutdown();
            let _ = c_close.shutdown(Shutdown::Both);
            let _ = down.join();
        });
        Ok(())
    }

    fn bridge_tcp(&self, client: TcpStream, up: TcpStream, mut clt_dec: AesCtr, mut clt_enc: AesCtr, mut tg_enc: AesCtr, mut tg_dec: AesCtr) -> std::io::Result<()> {
        let (mut c_r, mut c_w) = (client.try_clone()?, client);
        let (mut u_r, mut u_w) = (up.try_clone()?, up);
        std::thread::scope(|s| {
            let down = s.spawn(|| {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = u_r.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let d = &mut buf[..n];
                    tg_dec.apply(d);
                    clt_enc.apply(d);
                    self.down.fetch_add(n as u64, Ordering::Relaxed);
                    if c_w.write_all(d).is_err() {
                        break;
                    }
                }
                let _ = c_w.shutdown(Shutdown::Both);
            });
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = c_r.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let d = &mut buf[..n];
                clt_dec.apply(d);
                tg_enc.apply(d);
                self.up.fetch_add(n as u64, Ordering::Relaxed);
                if u_w.write_all(d).is_err() {
                    break;
                }
            }
            let _ = u_w.shutdown(Shutdown::Both);
            let _ = down.join();
        });
        Ok(())
    }
}

pub struct TgProxy {
    shared: Arc<Shared>,
}

impl TgProxy {
    pub fn start(cfg: &Config) -> Result<TgProxy, String> {
        let secret = parse_secret(&cfg.secret)?;
        let routes = parse_dc_ip(&cfg.dc_ip)?;
        let cf_domains: Vec<String> = if !cfg.cf_proxy {
            Vec::new()
        } else if cfg.cf_domains.iter().any(|d| !d.trim().is_empty()) {
            cfg.cf_domains.iter().filter_map(|d| crate::proxy::normalize_domain(d)).collect()
        } else {
            default_cf_domains()
        };
        let port = cfg.port;
        let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| crate::tr!("порт {port} занят: {e}", "port {port} is busy: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let shared = Arc::new(Shared {
            secret,
            routes,
            fragment: cfg.fragment,
            cf_domains,
            cf_workers: cfg.cf_workers.iter().filter_map(|d| crate::proxy::normalize_domain(d)).collect(),
            worker: AtomicU64::new(0),
            sni: crate::proxy::normalize_domain(&cfg.sni),
            fronted: AtomicU64::new(0),
            cf_last: Mutex::new(std::collections::HashMap::new()),
            ws_down: Mutex::new(std::collections::HashMap::new()),
            resolver: crate::doh::CachedResolver::public(false),
            cf: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            active: AtomicU64::new(0),
            total: AtomicU64::new(0),
            ws: AtomicU64::new(0),
            tcp: AtomicU64::new(0),
            bad: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            last_error: Mutex::new(None),
        });
        let sh = shared.clone();
        std::thread::spawn(move || {
            while !sh.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, _)) => {
                        let sh = sh.clone();
                        std::thread::spawn(move || {
                            let _ = s.set_nonblocking(false);
                            sh.total.fetch_add(1, Ordering::Relaxed);
                            sh.active.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = sh.handle(s) {
                                if e.kind() != std::io::ErrorKind::UnexpectedEof {
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
        Ok(TgProxy { shared })
    }

    pub fn stats(&self) -> Stats {
        let s = &self.shared;
        Stats {
            running: true,
            active: s.active.load(Ordering::Relaxed),
            total: s.total.load(Ordering::Relaxed),
            ws: s.ws.load(Ordering::Relaxed),
            cf: s.cf.load(Ordering::Relaxed),
            worker: s.worker.load(Ordering::Relaxed),
            fronted: s.fronted.load(Ordering::Relaxed),
            tcp: s.tcp.load(Ordering::Relaxed),
            bad: s.bad.load(Ordering::Relaxed),
            failed: s.failed.load(Ordering::Relaxed),
            bytes_up: s.up.load(Ordering::Relaxed),
            bytes_down: s.down.load(Ordering::Relaxed),
            last_error: s.last_error.lock().unwrap().clone(),
        }
    }
}

impl Drop for TgProxy {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Init клиента так, как его делает Telegram Desktop с секретом.
    fn client_init(secret: &[u8; 16], tag: [u8; 4], dc: i16) -> ([u8; 64], AesCtr, AesCtr) {
        let mut init = random_init();
        init[56..60].copy_from_slice(&tag);
        init[60..62].copy_from_slice(&dc.to_le_bytes());
        let mut enc = AesCtr::new(&sha256(&init[8..40], secret), &init[40..56]);
        let mut e = init;
        enc.apply(&mut e);
        let mut wire = init;
        wire[56..].copy_from_slice(&e[56..]);
        let dec = client_encryptor(&init, secret);
        (wire, enc, dec)
    }

    #[test]
    fn aes_ctr_known_vector() {
        // NIST SP 800-38A F.5.5 (CTR-AES256), первый блок.
        let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        AesCtr::new(&key, &iv).apply(&mut data);
        assert_eq!(data, hex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"));
        // По байту — то же, что целиком.
        let mut a = vec![7u8; 100];
        let mut b = a.clone();
        AesCtr::new(&key, &iv).apply(&mut a);
        let mut c = AesCtr::new(&key, &iv);
        for x in b.chunks_mut(13) {
            c.apply(x);
        }
        assert_eq!(a, b);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn handshake_roundtrip() {
        let secret = [9u8; 16];
        let (wire, mut c_enc, mut c_dec) = client_init(&secret, TAG_SECURE, -4);
        let (h, mut dec) = client_hello(&wire, &secret).unwrap();
        assert_eq!(h, Hello { dc: 4, media: true, test: false, tag: TAG_SECURE });
        // Поток клиента после init расшифровывается.
        let mut msg = b"hello telegram".to_vec();
        c_enc.apply(&mut msg);
        dec.apply(&mut msg);
        assert_eq!(msg, b"hello telegram");
        // И обратно — к клиенту.
        let mut back = b"answer".to_vec();
        client_encryptor(&wire, &secret).apply(&mut back);
        c_dec.apply(&mut back);
        assert_eq!(back, b"answer");
        // Неверный секрет — нет.
        assert!(client_hello(&wire, &[1u8; 16]).is_none());
        let (wire, _, _) = client_init(&secret, TAG_ABRIDGED, 10002);
        let (h, _) = client_hello(&wire, &secret).unwrap();
        assert!(h.test && h.dc == 2 && !h.media);
    }

    #[test]
    fn relay_init_is_valid() {
        let (init, mut enc, mut dec) = relay_init(TAG_INTERMEDIATE, -2);
        // Сервер Telegram расшифровывает init тем же ключом и видит тег и DC.
        let mut srv = AesCtr::new(&init[8..40], &init[40..56]);
        let mut p = init;
        srv.apply(&mut p);
        assert_eq!(&p[56..60], &TAG_INTERMEDIATE);
        assert_eq!(i16::from_le_bytes([p[60], p[61]]), -2);
        // Шифровщик к серверу уже сдвинут на 64 байта — поток продолжается.
        let mut m = b"data".to_vec();
        enc.apply(&mut m);
        srv.apply(&mut m);
        assert_eq!(m, b"data");
        // Ответ сервера: ключ из перевёрнутых байт 8..56.
        let mut rev = init[8..56].to_vec();
        rev.reverse();
        let mut answer = b"pong".to_vec();
        AesCtr::new(&rev[..32], &rev[32..]).apply(&mut answer);
        dec.apply(&mut answer);
        assert_eq!(answer, b"pong");
        assert!(init[0] != 0xef && init[4..8] != [0, 0, 0, 0]);
    }

    #[test]
    fn splitter_packets() {
        // Intermediate: 4 байта длины + тело. Два пакета, второй приходит частями.
        let mut s = Splitter::new(TAG_SECURE);
        let mut stream = Vec::new();
        for body in [&b"abcdefgh"[..], &b"0123456789ab"[..]] {
            stream.extend_from_slice(&(body.len() as u32).to_le_bytes());
            stream.extend_from_slice(body);
        }
        let parts = s.split(&stream[..15], &stream[..15]);
        assert_eq!(parts, vec![stream[..12].to_vec()]);
        let parts = s.split(&stream[15..], &stream[15..]);
        assert_eq!(parts, vec![stream[12..].to_vec()]);
        assert!(s.flush().is_none());
        // Abridged: длина в словах по 4 байта.
        let mut s = Splitter::new(TAG_ABRIDGED);
        let mut st = vec![2u8];
        st.extend_from_slice(&[1; 8]);
        st.push(0x7f);
        st.extend_from_slice(&[1, 0, 0]);
        st.extend_from_slice(&[2; 4]);
        let parts = s.split(&st, &st);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len(), 8);
    }

    #[test]
    fn websocket_frames() {
        let f = ws_frame(0x2, &[1, 2, 3]);
        let (fin, op, p, used) = ws_parse(&f).unwrap();
        assert!(fin && op == 2 && p == vec![1, 2, 3] && used == f.len());
        let big = vec![5u8; 70_000];
        let f = ws_frame(0x2, &big);
        assert_eq!(ws_parse(&f).unwrap().2, big);
        assert!(ws_parse(&f[..100]).is_none());
        // Кадр сервера — без маски.
        let srv = [0x82u8, 0x02, 9, 8];
        assert_eq!(ws_parse(&srv).unwrap().2, vec![9, 8]);
        assert_eq!(b64(b"hello"), "aGVsbG8=");
        assert_eq!(b64(&[0u8; 16]), "AAAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn config_parsing() {
        let s = new_secret();
        assert_eq!(s.len(), 32);
        assert!(parse_secret(&s).is_ok() && parse_secret(&format!("dd{s}")).is_ok());
        assert!(parse_secret("xyz").is_err());
        assert_eq!(parse_dc_ip(&["2:149.154.167.220".into()]).unwrap(), vec![(2, "149.154.167.220".parse().unwrap())]);
        assert!(parse_dc_ip(&["2-1.1.1.1".into()]).is_err());
        assert_eq!(link("127.0.0.1", 1443, "ab"), "tg://proxy?server=127.0.0.1&port=1443&secret=ddab");
        // Расшифровка совпадает с оригиналом на Python.
        assert_eq!(decode_cf_domain("virkgj.com"), "pclead.co.uk");
        assert_eq!(decode_cf_domain("zaewayzmplad.com"), "noskomnadzor.co.uk");
        assert_eq!(decode_cf_domain("plain.org"), "plain.org");
        assert_eq!(default_cf_domains().len(), 20);
    }

    /// Сеть: проверка без сверки имени. 1.1.1.1 отдаёт сертификат
    /// cloudflare-dns.com: с подменным SNI обычная проверка его отвергает,
    /// а `AnyName` принимает (цепочка настоящая). Только чтение.
    #[test]
    #[ignore]
    fn live_any_name() {
        let a: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let strict = TlsDuplex::connect(a, "sprinthost.ru", false);
        println!("strict: {:?}", strict.as_ref().err().map(|e| e.to_string()));
        assert!(strict.is_err());
        let lenient = TlsDuplex::connect_as(a, "cloudflare-dns.com", Some("sprinthost.ru"), false);
        println!("any-name: {:?}", lenient.as_ref().err().map(|e| e.to_string()));
        assert!(lenient.is_ok());
    }

    /// Сеть: настоящий запрос к Telegram через прокси, как от Telegram Desktop.
    /// Отправляем req_pq_multi (без авторизации) в DC2, ждём resPQ.
    /// Только запрос, ничего не меняет. `TG_FRAGMENT=0` — без нарезки.
    #[test]
    #[ignore]
    fn live_req_pq() {
        let secret_hex = new_secret();
        let secret = parse_secret(&secret_hex).unwrap();
        let fragment = std::env::var("TG_FRAGMENT").map(|v| v != "0").unwrap_or(true);
        for (dc, label) in [(2i16, "WS/CF"), (1, "CF/TCP")] {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let cfg = Config { port, secret: secret_hex.clone(), fragment, ..Default::default() };
            let p = TgProxy::start(&cfg).unwrap();
            let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(40))).unwrap();
            let (wire, mut enc, mut dec) = client_init(&secret, TAG_SECURE, dc);
            c.write_all(&wire).unwrap();
            // req_pq_multi#be7e8ef1 nonce:int128 в незашифрованном сообщении MTProto.
            let mut body = vec![0u8; 8];
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            body.extend_from_slice(&((now << 32) | 4).to_le_bytes());
            body.extend_from_slice(&20u32.to_le_bytes());
            body.extend_from_slice(&0xbe7e8ef1u32.to_le_bytes());
            body.extend_from_slice(&random_bytes::<16>());
            let mut pkt = (body.len() as u32).to_le_bytes().to_vec();
            pkt.extend_from_slice(&body);
            enc.apply(&mut pkt);
            c.write_all(&pkt).unwrap();
            let mut len = [0u8; 4];
            let r = c.read_exact(&mut len);
            if r.is_err() {
                println!("{label} DC{dc}: no answer {:?} stats {:?}", r, p.stats());
                continue;
            }
            dec.apply(&mut len);
            let n = (u32::from_le_bytes(len) & 0x7fff_ffff) as usize;
            let mut ans = vec![0u8; n];
            c.read_exact(&mut ans).unwrap();
            dec.apply(&mut ans);
            let ctor = u32::from_le_bytes(ans[20..24].try_into().unwrap());
            println!("{label} DC{dc}: {n} bytes, constructor {ctor:#010x} (resPQ = 0x05162463) stats {:?}", p.stats());
            assert_eq!(ctor, 0x05162463);
        }
    }
}
