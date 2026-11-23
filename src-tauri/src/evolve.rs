//! Автоподбор стратегии zapret2 — по мотивам Geneva (Bock et al., «Geneva:
//! Evolving Censorship Evasion Strategies», ACM CCS 2019).
//!
//! ВНИМАНИЕ: это НЕ полноценный генетический алгоритм, а его упрощение —
//! локальный поиск «по соседям» с залом славы:
//! - нет скрещивания (crossover) двух родителей; ближе всего к нему — мутация
//!   «вставить действие из другой стратегии сборки»;
//! - нет популяции с вероятностным отбором (рулетка, турнир): в следующий
//!   раунд просто идут K лучших из зала славы;
//! - мутации не придумывают значений, а берут их из словаря, собранного по
//!   готовым стратегиям сборки (техники, blob, pos, seqovl, repeats, порча
//!   пакетов) — так кандидаты почти всегда понятны winws2;
//! - мутируется только TCP-часть (TLS/HTTP): тестер проверяет сайты curl'ом,
//!   UDP/QUIC/игровые профили он не оценил бы.
//!
//! Из Geneva взято: засев известными стратегиями (в т. ч. «вымершими» —
//! рабочая часто находится в 2–4 шагах от них), оценка двумя прогонами с
//! худшим результатом (DPI срабатывает нестабильно), штраф за сложность
//! (побеждает самая простая рабочая), зал славы (мутации не теряют лучших),
//! перемешивание целей и пауза между кандидатами (против штрафной блокировки
//! пары «клиент ↔ сайт», как 90 с в Китае).
//!
//! Если когда-нибудь делать полный ГА: популяция N с турнирным отбором,
//! скрещивание по профилям (`--new`) двух родителей, вероятности мутаций,
//! больше поколений — оценка (`Bench::eval`) и мутации отсюда подойдут.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::Ordering;

const KEY: &str = "--lua-desync=";
/// Техники, которые работают по TCP-потоку (их и мутируем).
const TCP_TECHS: &[&str] = &["fake", "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit", "syndata"];
/// Пары «похожих» техник: замена одной на другую — одна из мутаций.
const SWAPS: &[(&str, &str)] = &[
    ("multisplit", "multidisorder"),
    ("fakedsplit", "fakeddisorder"),
    ("multisplit", "fakedsplit"),
    ("multidisorder", "fakeddisorder"),
];
/// Без этих параметров действие теряет смысл — их не удаляем.
const ESSENTIAL: &[&str] = &["blob", "host"];
/// Пауза между кандидатами, мс.
const PAUSE_MS: u64 = 1500;
/// Сколько раз подтверждать победителя перед сохранением.
const CONFIRM: usize = 3;

/// Действие `--lua-desync=техника:k=v:...` в тексте bat-файла.
#[derive(Debug, Clone, PartialEq)]
struct Action {
    start: usize,
    end: usize,
    value: String,
    /// Номер профиля (сколько `--new` перед действием).
    profile: usize,
}

fn tech(v: &str) -> &str {
    v.split(':').next().unwrap_or(v)
}

fn params(v: &str) -> Vec<(String, String)> {
    v.split(':').skip(1).filter_map(|p| p.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))).collect()
}

fn join(t: &str, ps: &[(String, String)]) -> String {
    let mut s = t.to_string();
    for (k, v) in ps {
        s.push(':');
        s.push_str(k);
        s.push('=');
        s.push_str(v);
    }
    s
}

/// Действие можно мутировать: TCP-техника, фейк — с TLS/HTTP-блобом,
/// не профиль игр (`payload=all`).
fn mutable(v: &str) -> bool {
    let t = tech(v);
    if !TCP_TECHS.contains(&t) || v.contains("payload=all") {
        return false;
    }
    if t == "fake" {
        return params(v).iter().any(|(k, b)| k == "blob" && (b.starts_with("tls") || b.starts_with("http")));
    }
    true
}

/// Начало команды winws2 (действия до неё — в комментариях, не считаем).
fn command_start(text: &str) -> Option<usize> {
    let mut off = 0;
    for line in text.split_inclusive('\n') {
        let l = line.trim_start();
        let lower = l.to_ascii_lowercase();
        if !(l.starts_with("::") || lower.starts_with("rem ")) {
            if let Some(p) = lower.find("winws2.exe") {
                return Some(off + (line.len() - l.len()) + p);
            }
        }
        off += line.len();
    }
    None
}

fn actions(text: &str) -> Vec<Action> {
    let Some(cmd) = command_start(text) else { return Vec::new() };
    let mut out = Vec::new();
    let mut from = cmd;
    while let Some(p) = text[from..].find(KEY) {
        let start = from + p;
        let vstart = start + KEY.len();
        let len = text[vstart..].find(|c: char| c.is_whitespace() || c == '^' || c == '"').unwrap_or(text.len() - vstart);
        let end = vstart + len;
        let profile = text[cmd..start].matches("--new").count();
        out.push(Action { start, end, value: text[vstart..end].to_string(), profile });
        from = end;
    }
    out
}

/// Словарь из стратегий сборки.
#[derive(Debug, Default)]
pub struct Vocab {
    techs: Vec<String>,
    /// Значения параметра по имени.
    values: HashMap<String, Vec<String>>,
    /// Параметры, встречавшиеся у техники.
    by_tech: HashMap<String, Vec<(String, String)>>,
    /// Целые действия — для вставки.
    whole: Vec<String>,
}

impl Vocab {
    pub fn from_texts<'a>(texts: impl IntoIterator<Item = &'a str>) -> Vocab {
        let mut v = Vocab::default();
        let push = |vec: &mut Vec<String>, s: &str| {
            if !vec.iter().any(|x| x == s) {
                vec.push(s.to_string());
            }
        };
        for text in texts {
            for a in actions(text).into_iter().filter(|a| mutable(&a.value)) {
                let t = tech(&a.value).to_string();
                push(&mut v.techs, &t);
                push(&mut v.whole, &a.value);
                for (k, val) in params(&a.value) {
                    push(v.values.entry(k.clone()).or_default(), &val);
                    let e = v.by_tech.entry(t.clone()).or_default();
                    if !e.iter().any(|(a, b)| *a == k && *b == val) {
                        e.push((k, val));
                    }
                }
            }
        }
        v
    }
}

/// Простой xorshift — без зависимостей.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> Option<&'a T> {
        if v.is_empty() {
            None
        } else {
            Some(&v[self.below(v.len())])
        }
    }
}

fn replace(text: &str, a: &Action, new: &str) -> String {
    format!("{}{KEY}{new}{}", &text[..a.start], &text[a.end..])
}

/// Одна случайная мутация текста стратегии. Возвращает новый текст и описание.
pub fn mutate(text: &str, vocab: &Vocab, rng: &mut Rng) -> Option<(String, String)> {
    let all = actions(text);
    let muts: Vec<&Action> = all.iter().filter(|a| mutable(&a.value)).collect();
    let a = *rng.pick(&muts)?;
    let t = tech(&a.value).to_string();
    let mut ps = params(&a.value);
    // Несколько попыток: не каждая мутация применима к действию.
    for _ in 0..12 {
        match rng.below(6) {
            // Другое значение параметра.
            0 | 1 => {
                if ps.is_empty() {
                    continue;
                }
                let i = rng.below(ps.len());
                let opts: Vec<&String> = vocab.values.get(&ps[i].0).map(|v| v.iter().filter(|x| **x != ps[i].1).collect()).unwrap_or_default();
                let Some(nv) = rng.pick(&opts) else { continue };
                let desc = format!("{t}: {}={} → {}", ps[i].0, ps[i].1, nv);
                ps[i].1 = (*nv).clone();
                return Some((replace(text, a, &join(&t, &ps)), desc));
            }
            // Похожая техника.
            2 => {
                let other: Vec<&str> = SWAPS
                    .iter()
                    .filter_map(|(x, y)| if *x == t { Some(*y) } else if *y == t { Some(*x) } else { None })
                    .filter(|o| vocab.techs.iter().any(|v| v == o))
                    .collect();
                let Some(o) = rng.pick(&other) else { continue };
                return Some((replace(text, a, &join(o, &ps)), format!("{t} → {o}")));
            }
            // Добавить параметр, встречавшийся у этой техники.
            3 => {
                let cand: Vec<&(String, String)> =
                    vocab.by_tech.get(&t).map(|v| v.iter().filter(|(k, _)| !ps.iter().any(|(pk, _)| pk == k)).collect()).unwrap_or_default();
                let Some((k, v)) = rng.pick(&cand).copied() else { continue };
                ps.push((k.clone(), v.clone()));
                return Some((replace(text, a, &join(&t, &ps)), format!("{t}: +{k}={v}")));
            }
            // Убрать параметр.
            4 => {
                let idx: Vec<usize> = (0..ps.len()).filter(|&i| !ESSENTIAL.contains(&ps[i].0.as_str())).collect();
                let Some(&i) = rng.pick(&idx) else { continue };
                let (k, v) = ps.remove(i);
                return Some((replace(text, a, &join(&t, &ps)), format!("{t}: −{k}={v}")));
            }
            // Убрать действие (если в профиле есть ещё) или вставить действие из другой стратегии.
            _ => {
                let same = all.iter().filter(|x| x.profile == a.profile).count();
                if same > 1 && rng.below(2) == 0 {
                    // Вместе с пробелом перед ним.
                    let mut s = a.start;
                    while s > 0 && text.as_bytes()[s - 1] == b' ' {
                        s -= 1;
                    }
                    return Some((format!("{}{}", &text[..s], &text[a.end..]), format!("−{}", a.value)));
                }
                let cand: Vec<&String> = vocab.whole.iter().filter(|w| !all.iter().any(|x| x.profile == a.profile && &x.value == *w)).collect();
                let Some(w) = rng.pick(&cand) else { continue };
                return Some((format!("{} {KEY}{w}{}", &text[..a.end], &text[a.end..]), format!("+{w}")));
            }
        }
    }
    None
}

/// Сложность: число действий и параметров плюс повторы фейков.
pub fn complexity(text: &str) -> f64 {
    actions(text)
        .iter()
        .filter(|a| mutable(&a.value))
        .map(|a| {
            let ps = params(&a.value);
            let repeats: f64 = ps.iter().find(|(k, _)| k == "repeats").and_then(|(_, v)| v.parse().ok()).unwrap_or(1.0);
            1.0 + ps.len() as f64 * 0.25 + repeats / 8.0
        })
        .sum()
}

/// Ключ для отсева повторов: только TCP-действия по профилям.
fn signature(text: &str) -> String {
    actions(text).iter().map(|a| format!("{}:{}", a.profile, a.value)).collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone, Serialize)]
pub struct Cand {
    pub name: String,
    /// Исходный bat-файл.
    pub parent: String,
    /// Что изменено относительно исходной стратегии.
    pub changes: Vec<String>,
    pub ok: u32,
    pub fail: u32,
    /// Итог с учётом штрафа за сложность (больше — лучше).
    pub score: f64,
    pub complexity: f64,
    /// Два прогона дали разное число OK (засчитан худший).
    pub unstable: bool,
    pub error: Option<String>,
    pub seed: bool,
    #[serde(skip)]
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EvolveRun {
    pub kind: String,
    pub round: u32,
    pub rounds: u32,
    pub done: usize,
    pub planned: usize,
    pub current: Option<String>,
    /// Лучшие (по score).
    pub hall: Vec<Cand>,
    /// Все проверенные — по порядку.
    pub tried: Vec<Cand>,
    pub finished: bool,
    pub cancelled: bool,
    pub message: Option<String>,
    /// Сохранённые bat-файлы.
    pub saved: Vec<String>,
    /// Лучший результат засева в обычном тесте (планка для сохранения).
    pub baseline: u32,
    /// Потолок по обычному тесту: проверки, прошедшие хоть с одной стратегией.
    pub ceiling: Option<u32>,
}

pub struct Opts {
    pub kind: String,
    pub seeds: Vec<String>,
    pub rounds: u32,
    /// Мутантов на каждого из зала славы за раунд.
    pub per_parent: usize,
    pub hall: usize,
    /// Лучший OK засева в обычном тесте того же вида (0 — теста не было).
    pub baseline: u32,
    pub ceiling: Option<u32>,
}

/// Планка и потолок из обычного теста того же вида: лучший OK среди
/// `seeds` и число проверок, прошедших хотя бы с одной стратегией
/// (остальные недостижимы нарезкой — обычно блокировка по IP).
pub fn baseline_from(test: &crate::tester::TestRun, kind: &str, seeds: &[String]) -> (u32, Option<u32>) {
    if !test.finished || test.kind != kind {
        return (0, None);
    }
    let started: Vec<&crate::tester::StrategyResult> = test.results.iter().filter(|r| r.started && r.error.is_none()).collect();
    let baseline = started.iter().filter(|r| seeds.contains(&r.file)).map(|r| r.ok).max().unwrap_or(0);
    let ceiling = (started.len() >= 2).then(|| {
        let mut passed = HashSet::new();
        for r in &started {
            for t in &r.targets {
                for (label, st) in &t.checks {
                    if st == "OK" {
                        passed.insert((t.key.clone(), label.clone()));
                    }
                }
            }
        }
        passed.len() as u32
    });
    (baseline, ceiling)
}

fn rank(hall: &mut Vec<Cand>, keep: usize) {
    hall.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    hall.truncate(keep);
}

/// Оценка: два прогона с разным порядком целей, засчитывается худший.
/// Если первый прогон ничего не открыл — второй не нужен.
fn evaluate(bench: &crate::tester::Bench, ctx: &crate::tester::Ctx, c: &mut Cand, rng: &mut Rng) {
    let args = crate::strategy::args_from_text(&c.name, &c.text, &bench.vars);
    let a = bench.eval(ctx, &c.name, args.clone(), Some(rng.next()), |_| {});
    if let Some(e) = a.error {
        c.error = Some(e);
        c.score = -1.0;
        return;
    }
    let (mut ok, mut fail) = (a.ok, a.fail);
    if a.ok > 0 && !ctx.cancel.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(PAUSE_MS));
        let b = bench.eval(ctx, &c.name, args, Some(rng.next()), |_| {});
        if b.error.is_none() {
            c.unstable = b.ok != a.ok;
            if b.ok < ok {
                ok = b.ok;
                fail = b.fail;
            }
        }
    }
    c.ok = ok;
    c.fail = fail;
    c.complexity = complexity(&c.text);
    // Штраф маленький: решает при равном числе OK.
    c.score = ok as f64 - 0.05 * c.complexity;
}

/// Следующий свободный номер `general (AUTO N).bat`.
fn auto_name(dir: &Path) -> String {
    let mut n = 1;
    loop {
        let f = format!("general (AUTO {n}).bat");
        if !dir.join(&f).exists() {
            return f;
        }
        n += 1;
    }
}

/// Сохранить кандидата как bat-файл стратегии; возвращает имя файла.
pub fn save(dir: &Path, c: &Cand) -> Result<String, String> {
    let file = auto_name(dir);
    let note = format!(":: digital-bypass auto-tune from \"{}\": {}\r\n", c.parent, c.changes.join("; "));
    // Комментарий — после первой строки (обычно @echo off).
    let text = match c.text.find('\n') {
        Some(i) => format!("{}{note}{}", &c.text[..=i], &c.text[i + 1..]),
        None => format!("{note}{}", c.text),
    };
    std::fs::write(dir.join(&file), text).map_err(|e| e.to_string())?;
    Ok(file)
}

pub fn run(ctx: crate::tester::Ctx, params: crate::tester::Params, opts: Opts, emit: impl Fn(&EvolveRun)) -> EvolveRun {
    let mut st = EvolveRun { kind: opts.kind.clone(), rounds: opts.rounds, baseline: opts.baseline, ceiling: opts.ceiling, ..Default::default() };
    let finish = |mut st: EvolveRun, msg: Option<String>| {
        st.finished = true;
        st.current = None;
        st.cancelled = ctx.cancel.load(Ordering::Relaxed);
        if msg.is_some() {
            st.message = msg;
        }
        emit(&st);
        st
    };
    let all = crate::strategy::list(ctx.dir);
    let texts: Vec<(String, String)> = all.iter().filter_map(|s| crate::util::read_text(&ctx.dir.join(&s.file)).ok().map(|t| (s.file.clone(), t))).collect();
    let vocab = Vocab::from_texts(texts.iter().map(|(_, t)| t.as_str()));
    let seeds: Vec<&(String, String)> = texts.iter().filter(|(f, _)| opts.seeds.contains(f)).collect();
    if seeds.is_empty() {
        return finish(st, Some(crate::tr!("Не выбраны стратегии для засева", "No seed strategies selected")));
    }
    let bench = match crate::tester::Bench::open(&ctx, &opts.kind, params) {
        Ok(b) => b,
        Err(e) => return finish(st, Some(e)),
    };
    let mut rng = Rng::new(crate::util::now_secs() ^ ((std::process::id() as u64) << 20));
    st.planned = seeds.len() + opts.rounds as usize * opts.hall * opts.per_parent;
    let mut seen: HashSet<String> = HashSet::new();
    let mut hall: Vec<Cand> = Vec::new();

    // Раунд 0: засев.
    for (file, text) in seeds {
        if ctx.cancel.load(Ordering::Relaxed) {
            break;
        }
        seen.insert(signature(text));
        let mut c = Cand {
            name: file.trim_end_matches(".bat").to_string(),
            parent: file.clone(),
            changes: Vec::new(),
            ok: 0,
            fail: 0,
            score: 0.0,
            complexity: 0.0,
            unstable: false,
            error: None,
            seed: true,
            text: text.clone(),
        };
        st.current = Some(c.name.clone());
        emit(&st);
        evaluate(&bench, &ctx, &mut c, &mut rng);
        st.done += 1;
        st.tried.push(c.clone());
        hall.push(c);
        rank(&mut hall, opts.hall);
        st.hall = hall.clone();
        emit(&st);
    }
    let seed_best = hall.iter().map(|c| c.ok).max().unwrap_or(0);

    // Раунды мутаций вокруг зала славы.
    let mut n = 0;
    for round in 1..=opts.rounds {
        st.round = round;
        let parents = hall.clone();
        for p in &parents {
            for _ in 0..opts.per_parent {
                if ctx.cancel.load(Ordering::Relaxed) {
                    break;
                }
                // 1–2 мутации подряд; повторы отсеиваются.
                let mut text = p.text.clone();
                let mut changes = p.changes.clone();
                let steps = 1 + rng.below(2);
                for _ in 0..steps {
                    if let Some((t, d)) = mutate(&text, &vocab, &mut rng) {
                        text = t;
                        changes.push(d);
                    }
                }
                if !seen.insert(signature(&text)) {
                    st.done += 1;
                    continue;
                }
                n += 1;
                let mut c = Cand {
                    name: format!("AUTO {round}.{n}"),
                    parent: p.parent.clone(),
                    changes,
                    ok: 0,
                    fail: 0,
                    score: 0.0,
                    complexity: 0.0,
                    unstable: false,
                    error: None,
                    seed: false,
                    text,
                };
                st.current = Some(c.name.clone());
                emit(&st);
                std::thread::sleep(std::time::Duration::from_millis(PAUSE_MS));
                evaluate(&bench, &ctx, &mut c, &mut rng);
                st.done += 1;
                st.tried.push(c.clone());
                hall.push(c);
                rank(&mut hall, opts.hall);
                st.hall = hall.clone();
                emit(&st);
            }
        }
    }
    // Сохранить лучшего, только если он открыл больше засева и в нашей
    // перепроверке, и в обычном тесте: иначе «улучшение» — это шум DPI
    // (засев в перепроверке мог случайно недобрать). Перед сохранением —
    // подтверждение (как в b4 Discovery): ещё CONFIRM прогонов, каждый должен
    // быть выше планки; провалил хоть один — очередь следующего кандидата.
    let bar = seed_best.max(opts.baseline);
    let candidates: Vec<Cand> = hall.iter().filter(|c| !c.seed && c.ok > bar).cloned().collect();
    let mut winner: Option<Cand> = None;
    for c in candidates {
        if ctx.cancel.load(Ordering::Relaxed) {
            break;
        }
        let name = &c.name;
        st.current = Some(crate::tr!("подтверждение {name}", "confirming {name}"));
        emit(&st);
        let mut ok = true;
        for _ in 0..CONFIRM {
            std::thread::sleep(std::time::Duration::from_millis(PAUSE_MS));
            let args = crate::strategy::args_from_text(&c.name, &c.text, &bench.vars);
            let r = bench.eval(&ctx, &c.name, args, Some(rng.next()), |_| {});
            if r.error.is_some() || r.ok <= bar {
                ok = false;
                break;
            }
        }
        if ok {
            winner = Some(c);
            break;
        }
    }
    bench.close(&ctx);
    if let Some(best) = winner {
        match save(ctx.dir, &best) {
            Ok(f) => st.saved.push(f),
            Err(e) => st.message = Some(e),
        }
    } else if !ctx.cancel.load(Ordering::Relaxed) {
        st.message = Some(crate::tr!(
            "Лучше засева ({bar} OK) ничего не нашлось или не подтвердилось — попробуйте больше раундов или другие стратегии для засева",
            "Nothing beat the seeds ({bar} OK) or it did not hold up — try more rounds or other seed strategies"
        ));
    }
    finish(st, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BAT: &str = "@echo off\r\n:: --lua-desync=fake:blob=tls_x\r\nstart \"z\" /min \"%BIN%winws2.exe\" --wf-tcp-out=443 ^\r\n--filter-tcp=443 --hostlist=\"%LISTS%list general.txt\" --lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=8 --lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google --new ^\r\n--filter-udp=443 --lua-desync=fake:blob=quic_google:repeats=11 --new ^\r\n--filter-tcp=80 --lua-desync=hostfakesplit:host=www.google.com:ip_id=zero\r\n";

    #[test]
    fn finds_actions_after_command() {
        let a = actions(BAT);
        assert_eq!(a.len(), 4);
        assert_eq!(a[0].value, "fake:blob=tls_google:tcp_ts=-600000:repeats=8");
        assert_eq!((a[1].profile, a[2].profile, a[3].profile), (0, 1, 2));
        assert!(mutable(&a[0].value) && mutable(&a[1].value) && !mutable(&a[2].value) && mutable(&a[3].value));
    }

    #[test]
    fn mutations_stay_valid() {
        let other = "x \"%BIN%winws2.exe\" --lua-desync=multidisorder:pos=midsld --lua-desync=fake:blob=tls_sferum:repeats=6\r\n";
        let vocab = Vocab::from_texts([BAT, other]);
        assert!(vocab.techs.iter().any(|t| t == "multidisorder"));
        let vars = crate::strategy::Vars { bin: r"C:\z\bin\".into(), lists: r"C:\z\lists\".into(), lua: r"C:\z\lua\".into(), game_tcp: "12".into(), game_udp: "12".into() };
        let mut rng = Rng::new(42);
        let mut changed = 0;
        for _ in 0..300 {
            let Some((t, d)) = mutate(BAT, &vocab, &mut rng) else { continue };
            assert!(!d.is_empty());
            if signature(&t) != signature(BAT) {
                changed += 1;
            }
            // Текст остаётся разбираемой стратегией, UDP-профиль не тронут.
            let args = crate::strategy::args_from_text("t.bat", &t, &vars).unwrap();
            assert!(args.iter().any(|a| a == "--lua-desync=fake:blob=quic_google:repeats=11"));
            assert!(args.iter().filter(|a| a.starts_with(KEY)).all(|a| !a[KEY.len()..].is_empty()));
            assert!(args.iter().any(|a| a == "--hostlist=C:\\z\\lists\\list general.txt"));
        }
        assert!(changed > 200);
    }

    #[test]
    fn baseline_and_ceiling() {
        use crate::tester::{StrategyResult, TargetResult, TestRun};
        let tr = |key: &str, st: &[&str]| TargetResult {
            key: key.into(),
            checks: st.iter().enumerate().map(|(i, s)| (format!("c{i}"), s.to_string())).collect(),
            ..Default::default()
        };
        let sr = |f: &str, ok, targets| StrategyResult { file: f.into(), started: true, ok, targets, ..Default::default() };
        let run = TestRun {
            kind: "dpi".into(),
            finished: true,
            results: vec![
                sr("a.bat", 2, vec![tr("x", &["OK", "OK"]), tr("y", &["FAIL", "FAIL"]), tr("dead", &["FAIL"])]),
                sr("b.bat", 1, vec![tr("x", &["FAIL", "FAIL"]), tr("y", &["OK", "FAIL"]), tr("dead", &["FAIL"])]),
            ],
            ..Default::default()
        };
        let seeds = vec!["b.bat".to_string()];
        assert_eq!(baseline_from(&run, "dpi", &seeds), (1, Some(3)));
        assert_eq!(baseline_from(&run, "standard", &seeds), (0, None));
    }

    #[test]
    fn simpler_is_cheaper() {
        let simple = "x \"winws2.exe\" --lua-desync=multisplit:pos=1";
        let heavy = "x \"winws2.exe\" --lua-desync=fake:blob=tls_google:repeats=11 --lua-desync=multisplit:pos=1:seqovl=681";
        assert!(complexity(simple) < complexity(heavy));
    }

    #[test]
    fn save_adds_note_and_numbers() {
        let dir = std::env::temp_dir().join(format!("digital-bypass-evolve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let c = Cand {
            name: "AUTO 1.1".into(),
            parent: "general.bat".into(),
            changes: vec!["multisplit: pos=1 → 2".into()],
            ok: 5,
            fail: 0,
            score: 5.0,
            complexity: 1.0,
            unstable: false,
            error: None,
            seed: false,
            text: BAT.into(),
        };
        assert_eq!(save(&dir, &c).unwrap(), "general (AUTO 1).bat");
        assert_eq!(save(&dir, &c).unwrap(), "general (AUTO 2).bat");
        let t = std::fs::read_to_string(dir.join("general (AUTO 1).bat")).unwrap();
        assert!(t.starts_with("@echo off\r\n:: digital-bypass auto-tune from \"general.bat\""));
        assert_eq!(actions(&t).len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Реальная сборка: словарь непустой, мутации всех стратегий разбираются.
    #[test]
    fn real_bundle_mutations() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("zapret");
        let list = crate::strategy::list(&dir);
        if list.is_empty() {
            return;
        }
        let texts: Vec<String> = list.iter().map(|s| crate::util::read_text(&dir.join(&s.file)).unwrap()).collect();
        let vocab = Vocab::from_texts(texts.iter().map(|t| t.as_str()));
        assert!(vocab.techs.len() >= 3 && vocab.whole.len() >= 5);
        let vars = crate::strategy::Vars::new(&dir, "12", "12");
        let mut rng = Rng::new(7);
        for t in &texts {
            for _ in 0..20 {
                if let Some((m, _)) = mutate(t, &vocab, &mut rng) {
                    crate::strategy::args_from_text("m.bat", &m, &vars).unwrap();
                }
            }
        }
    }
}
