//! Российские сайты по базам Xray (`geoip.dat`, `geosite.dat` из встроенного
//! релиза Xray-core): `geoip:ru` и `geosite:category-ru` + `category-gov-ru`.
//! Нужны прокси-обходчику, чтобы в режимах Tor «списки zapret» и «весь трафик»
//! российские сайты шли напрямую (банки и Госуслуги не пускают выходы Tor).
//!
//! Формат — protobuf v2fly/Xray:
//! - GeoIPList { repeated GeoIP entry = 1 }, GeoIP { string country_code = 1; repeated CIDR cidr = 2 },
//!   CIDR { bytes ip = 1; uint32 prefix = 2 };
//! - GeoSiteList { repeated GeoSite entry = 1 }, GeoSite { string country_code = 1; repeated Domain domain = 2 },
//!   Domain { Type type = 1 (Plain=0 подстрока, Regex=1, RootDomain=2, Full=3); string value = 2 }.
//!   Regex пропускаем (их в category-ru единицы), остальное — точно как в Xray.
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Default)]
pub struct Geo {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    suffix: HashSet<String>,
    full: HashSet<String>,
    keyword: Vec<String>,
    pub regex_skipped: usize,
}

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut r = 0u64;
    let mut s = 0;
    loop {
        let x = *b.get(*i)?;
        *i += 1;
        r |= ((x & 0x7f) as u64) << s;
        if x & 0x80 == 0 {
            return Some(r);
        }
        s += 7;
        if s > 63 {
            return None;
        }
    }
}

/// Поля сообщения: (номер, тип, значение-срез для length-delimited / число).
fn fields(b: &[u8]) -> Vec<(u64, &[u8], u64)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let Some(key) = varint(b, &mut i) else { break };
        let (num, wt) = (key >> 3, key & 7);
        match wt {
            0 => {
                let Some(v) = varint(b, &mut i) else { break };
                out.push((num, &b[0..0], v));
            }
            2 => {
                let Some(len) = varint(b, &mut i) else { break };
                let end = i + len as usize;
                if end > b.len() {
                    break;
                }
                out.push((num, &b[i..end], 0));
                i = end;
            }
            5 => i += 4,
            1 => i += 8,
            _ => break,
        }
    }
    out
}

/// Записи списка с нужными кодами (без учёта регистра).
fn entries<'a>(file: &'a [u8], codes: &[&str]) -> Vec<&'a [u8]> {
    fields(file)
        .into_iter()
        .filter(|(n, _, _)| *n == 1)
        .map(|(_, e, _)| e)
        .filter(|e| fields(e).iter().any(|(n, v, _)| *n == 1 && codes.iter().any(|c| c.eq_ignore_ascii_case(&String::from_utf8_lossy(v)))))
        .collect()
}

impl Geo {
    pub fn parse(geoip: &[u8], geosite: &[u8]) -> Geo {
        let mut g = Geo::default();
        for e in entries(geoip, &["RU"]) {
            for (n, cidr, _) in fields(e) {
                if n != 2 {
                    continue;
                }
                let f = fields(cidr);
                let ip = f.iter().find(|x| x.0 == 1).map(|x| x.1).unwrap_or(&[]);
                let prefix = f.iter().find(|x| x.0 == 2).map(|x| x.2).unwrap_or(0) as u32;
                match ip.len() {
                    4 => {
                        let a = u32::from_be_bytes([ip[0], ip[1], ip[2], ip[3]]);
                        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) };
                        g.v4.push((a & mask, (a & mask) | !mask));
                    }
                    16 => {
                        let a = u128::from_be_bytes(ip.try_into().unwrap());
                        let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix.min(128)) };
                        g.v6.push((a & mask, (a & mask) | !mask));
                    }
                    _ => {}
                }
            }
        }
        g.v4.sort_unstable();
        g.v6.sort_unstable();
        for e in entries(geosite, &["CATEGORY-RU", "CATEGORY-GOV-RU"]) {
            for (n, d, _) in fields(e) {
                if n != 2 {
                    continue;
                }
                let f = fields(d);
                let ty = f.iter().find(|x| x.0 == 1).map(|x| x.2).unwrap_or(0);
                let v = f.iter().find(|x| x.0 == 2).map(|x| String::from_utf8_lossy(x.1).to_ascii_lowercase()).unwrap_or_default();
                if v.is_empty() {
                    continue;
                }
                match ty {
                    0 => g.keyword.push(v),
                    1 => g.regex_skipped += 1,
                    2 => {
                        g.suffix.insert(v);
                    }
                    _ => {
                        g.full.insert(v);
                    }
                }
            }
        }
        g
    }

    pub fn load(dir: &Path) -> Option<Geo> {
        let ip = std::fs::read(dir.join("geoip.dat")).ok()?;
        let site = std::fs::read(dir.join("geosite.dat")).ok()?;
        let g = Geo::parse(&ip, &site);
        (!g.v4.is_empty() || !g.suffix.is_empty()).then_some(g)
    }

    /// Российский домен: зоны .ru/.su/.рф или geosite:category-ru(-gov).
    pub fn ru_host(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if h.parse::<IpAddr>().is_ok() {
            return false;
        }
        if ru_zone(&h) {
            return true;
        }
        if self.full.contains(&h) {
            return true;
        }
        let mut cur = h.as_str();
        loop {
            if self.suffix.contains(cur) {
                return true;
            }
            match cur.split_once('.') {
                Some((_, rest)) => cur = rest,
                None => break,
            }
        }
        self.keyword.iter().any(|k| h.contains(k.as_str()))
    }

    /// Адрес из geoip:ru.
    pub fn ru_ip(&self, ip: IpAddr) -> bool {
        fn find<T: Ord + Copy>(v: &[(T, T)], x: T) -> bool {
            // Последний диапазон с началом <= x.
            let i = v.partition_point(|r| r.0 <= x);
            i > 0 && v[..i].iter().rev().take(4).any(|r| x <= r.1)
        }
        match ip {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(a)),
            },
        }
    }

    pub fn sizes(&self) -> (usize, usize) {
        (self.v4.len() + self.v6.len(), self.suffix.len() + self.full.len() + self.keyword.len())
    }
}

/// Зоны .ru, .su и .рф — без баз.
pub fn ru_zone(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    [".ru", ".su", ".xn--p1ai"].iter().any(|t| h.ends_with(t)) || ["ru", "su", "xn--p1ai"].contains(&h.as_str())
}

static DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static GEO: OnceLock<Option<Geo>> = OnceLock::new();

/// Папка с базами (ресурсы Xray). Загрузка — при первом обращении.
pub fn set_dir(dir: Option<PathBuf>) {
    *DIR.lock().unwrap() = dir;
}

pub fn get() -> Option<&'static Geo> {
    GEO.get_or_init(|| DIR.lock().unwrap().clone().and_then(|d| Geo::load(&d))).as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pb_len(num: u64, data: &[u8]) -> Vec<u8> {
        let mut v = vec![((num << 3) | 2) as u8];
        let mut n = data.len();
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            v.push(if n > 0 { b | 0x80 } else { b });
            if n == 0 {
                break;
            }
        }
        v.extend_from_slice(data);
        v
    }
    fn pb_var(num: u64, x: u64) -> Vec<u8> {
        vec![((num << 3) as u8), x as u8]
    }

    #[test]
    fn parse_synthetic() {
        let cidr = [pb_len(1, &[5, 8, 0, 0]), pb_var(2, 13)].concat();
        let ru = [pb_len(1, b"RU"), pb_len(2, &cidr)].concat();
        let us = [pb_len(1, b"US"), pb_len(2, &[pb_len(1, &[8, 8, 8, 0]), pb_var(2, 24)].concat())].concat();
        let geoip = [pb_len(1, &ru), pb_len(1, &us)].concat();
        let dom = |t: u64, v: &str| pb_len(2, &[pb_var(1, t), pb_len(2, v.as_bytes())].concat());
        let site = [pb_len(1, b"category-ru"), dom(2, "yandex.net"), dom(3, "only.example.com"), dom(0, "sberbank"), dom(1, "^x$")].concat();
        let geosite = pb_len(1, &site);
        let g = Geo::parse(&geoip, &geosite);
        assert!(g.ru_ip("5.8.3.1".parse().unwrap()));
        assert!(g.ru_ip("5.15.255.255".parse().unwrap()));
        assert!(!g.ru_ip("5.16.0.0".parse().unwrap()));
        assert!(!g.ru_ip("8.8.8.8".parse().unwrap()), "чужая страна не попала");
        assert!(g.ru_host("mc.yandex.net") && g.ru_host("yandex.net"));
        assert!(g.ru_host("only.example.com") && !g.ru_host("x.only.example.com"));
        assert!(g.ru_host("online.sberbank.com"));
        assert!(g.ru_host("gosuslugi.ru") && g.ru_host("xn--80ak6aa92e.xn--p1ai"));
        assert!(!g.ru_host("youtube.com"));
        assert_eq!(g.regex_skipped, 1);
    }

    #[test]
    fn bundled_bases() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("xray");
        let Some(g) = Geo::load(&dir) else { return };
        let (ips, doms) = g.sizes();
        println!("ru: {ips} подсетей, {doms} доменов, regex пропущено {}", g.regex_skipped);
        assert!(ips > 1000 && doms > 100);
        assert!(g.ru_ip("77.88.55.88".parse().unwrap()), "ya.ru");
        assert!(g.ru_ip("213.180.193.3".parse().unwrap()), "yandex");
        assert!(!g.ru_ip("8.8.8.8".parse().unwrap()) && !g.ru_ip("1.1.1.1".parse().unwrap()));
        assert!(g.ru_host("vk.com") && g.ru_host("yandex.net") && g.ru_host("ozon.ru"));
        assert!(!g.ru_host("youtube.com") && !g.ru_host("google.com"));
    }
}
