<script lang="ts">
  import PowerButton from "./PowerButton.svelte";
  import { onMount } from "svelte";
  import { api, on, type ProxyConfig, type ProxyStatus } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import Segmented from "./Segmented.svelte";
  import Switch from "./Switch.svelte";
  import ProxyTest from "./ProxyTest.svelte";
  import ProxyLog from "./ProxyLog.svelte";
  import ProxyWorker from "./ProxyWorker.svelte";
  import SubTabs from "./SubTabs.svelte";
  import More from "./More.svelte";
  import { Copy, Wifi, KeyRound, ShieldAlert, ListFilter } from "@lucide/svelte";

  let st = $state<ProxyStatus | null>(null);
  let cfg = $state<ProxyConfig>({
    port: 8881,
    split: "sni",
    unit: "records",
    chunk: 4,
    positions: "",
    disorder: true,
    oob: false,
    auto: true,
    auto_chain: [],
    auto_timeout: 4,
    log: false,
    ipv6: false,
    rules: { scope: "all", zapret_lists: true, bypass: [], skip: [], block: [], worker: [] },
    worker: { host: "", key: "", fragment: true },
    doh: true,
    system: true,
    lan: false,
    user: "",
    pass: "",
    rcvbuf: 0,
  });
  /** Списки правил в textarea — по домену в строке. */
  let ruleText = $state({ bypass: "", skip: "", block: "" });
  let positionsText = $state("");
  const toLines = (v: string[]) => v.join("\n");
  const fromLines = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
  let lanIps = $state<string[]>([]);
  let showPass = $state(false);
  const running = $derived(!!st?.stats.running);
  let sub = $state<"main" | "autotune" | "rules" | "lan" | "log">("main");
  /** Включённое в «Дополнительно» (отличия от умолчаний). */
  const advCount = $derived(
    (cfg.split !== "none" && cfg.oob ? 1 : 0) + (cfg.ipv6 ? 1 : 0) + (cfg.rcvbuf > 0 ? 1 : 0) + (!cfg.doh ? 1 : 0),
  );
  /** Записей в правилах (для значка на подвкладке). */
  const ruleCount = $derived(cfg.rules.skip.length + cfg.rules.block.length + (cfg.rules.worker?.length ?? 0) + (cfg.rules.scope === "listed" ? cfg.rules.bypass.length : 0));

  async function load() {
    try {
      st = await api.proxyStatus();
      cfg = { ...st.config, rules: { ...st.config.rules, worker: st.config.rules.worker ?? [] }, worker: st.config.worker ?? { host: "", key: "", fragment: true } };
      ruleText = { bypass: toLines(cfg.rules.bypass), skip: toLines(cfg.rules.skip), block: toLines(cfg.rules.block) };
      positionsText = cfg.positions;
      lanIps = await api.lanAddresses().catch(() => []);
    } catch (e) {
      toast(String(e));
    }
  }
  onMount(() => {
    load();
    // Счётчики соединений — пока вкладка открыта.
    const id = setInterval(async () => {
      if (running) st = await api.proxyStatus().catch(() => st);
    }, 2000);
    // Прокси переключили из трея.
    const un = on("proxy-changed", load);
    return () => {
      clearInterval(id);
      un.then((f) => f());
    };
  });

  async function start() {
    const r = await act(() => api.proxyStart({ ...cfg, port: Number(cfg.port) }), t("Прокси включён", "Proxy is on"));
    if (r) st = r;
  }
  async function stop() {
    const r = await act(() => api.proxyStop(), t("Прокси выключен", "Proxy is off"));
    if (r) st = r;
  }
  function variantName(v: ProxyConfig["auto_chain"][number]) {
    const split = ({ sni: "SNI", "first-byte": "First byte", chunk: "Chunks", random: "Random", custom: "Custom", none: "None" } as Record<string, string>)[v.split];
    return `${split} · ${v.unit === "tcp" ? "TCP" : v.unit === "mixed" ? "TLS±ver" : "TLS"}${v.disorder ? " · disorder" : ""}${v.oob ? " · OOB" : ""}`;
  }

  function saveRules() {
    change({ rules: { ...cfg.rules, bypass: fromLines(ruleText.bypass), skip: fromLines(ruleText.skip), block: fromLines(ruleText.block) } });
  }
  const rulesDirty = $derived(
    ruleText.bypass !== toLines(cfg.rules.bypass) || ruleText.skip !== toLines(cfg.rules.skip) || ruleText.block !== toLines(cfg.rules.block),
  );
  const splitHint = $derived(
    ({
      sni: t("разрез внутри имени сайта", "cut inside the site name"),
      "first-byte": t("отделить первый байт", "split off the first byte"),
      chunk: t("чанки фиксированного размера", "fixed-size chunks"),
      random: t("одна случайная точка", "one random point"),
      custom: t("свои позиции разреза — для знающих", "custom cut positions — for experts"),
      none: t("без нарезки", "no splitting"),
    })[cfg.split],
  );

  /** Настройки сохраняются сразу; работающий прокси перезапускается с новыми. */
  async function change(patch: Partial<ProxyConfig>) {
    cfg = { ...cfg, ...patch };
    const r = await act(() => api.proxySetConfig({ ...cfg, port: Number(cfg.port) }));
    if (r) st = r;
  }
  const addr = $derived(`127.0.0.1:${cfg.port}`);
  /** Сгенерировать пароль: 16 символов без похожих (0/O, 1/l). */
  function genPass() {
    const abc = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const r = crypto.getRandomValues(new Uint8Array(16));
    cfg.pass = Array.from(r, (b) => abc[b % abc.length]).join("");
    if (!cfg.user) cfg.user = "phone";
    showPass = true;
  }
  const authOk = $derived((!cfg.user && !cfg.pass) || (!!cfg.user && !!cfg.pass && !cfg.user.includes(":")));
</script>

<div class="proxy fade-in">
  <SubTabs
    key="proxy"
    bind:value={sub}
    tabs={[
      { id: "main", label: "Main", title: t("Включение и способ нарезки", "On/off and the split method") },
      { id: "autotune", label: "Auto-tune", title: t("Подбор способа нарезки под ваши сайты", "Find the split method for your sites") },
      { id: "rules", label: "Rules", badge: ruleCount || null, title: t("Правила по доменам и свой Worker", "Domain rules and your own Worker") },
      { id: "lan", label: "LAN", badge: cfg.lan ? "on" : null, title: t("Раздача в локальную сеть", "Share on the local network") },
      { id: "log", label: "Log", badge: cfg.log ? "on" : null, title: t("Журнал соединений", "Connection log") },
    ]} />
  {#if sub === "main"}
    <section class="card block hero">
      <div class="prompt mono">{t("прокси-обходчик · без прав администратора и драйвера", "bypass proxy · no admin rights, no driver")}</div>
      <PowerButton on={running} disabled={app.busy} onclick={running ? stop : start} />
      <div class="state-line mono">
        {#if app.busy}<span class="muted">…</span>{:else if running}<span class="on">● {addr}</span>{:else}<span class="faint">○ {t("выключен", "off")}</span>{/if}
      </div>
      {#if st && running}
        <div class="stats mono">
          <span><b>{st.stats.active}</b> {t("активных", "active")}</span>
          <span><b>{st.stats.total}</b> {t("всего", "total")}</span>
          <span><b>{st.stats.failed}</b> {t("ошибок", "failed")}</span>
          <span title={t("с нарезкой / без / заблокировано", "split / passed / blocked")}><b>{st.stats.bypassed}</b>/<b>{st.stats.passed}</b>/<b>{st.stats.blocked}</b></span>
          {#if cfg.doh}<span title={t("доменов в кэше DNS", "domains in the DNS cache")}>dns <b>{st.stats.dns_cached}</b></span>{/if}
          {#if cfg.auto}<span title={t("переподключений другим способом / сайтов со своим способом", "retries with another method / sites with their own method")}>auto <b>{st.stats.auto_retries}</b>/<b>{st.stats.auto_sites}</b></span>{/if}
          <button class="btn sm ghost addr" title={t("Скопировать адрес", "Copy address")} onclick={() => navigator.clipboard?.writeText(addr).then(() => toast(addr, "ok"))}>
            {addr} <Copy size={11} />
          </button>
        </div>
        {#if st.stats.last_error}
          <div class="err mono">{st.stats.last_error}</div>
        {/if}
      {/if}
      <p class="muted text">
        {t(
          "Локальный прокси (HTTP и SOCKS5 на одном порту) режет TLS ClientHello так, что имя сайта не видно простым DPI. Работает только для HTTPS через прокси; UDP, QUIC и голос Discord не обходит — для них нужен zapret2.",
          "A local proxy (HTTP and SOCKS5 on one port) splits the TLS ClientHello so simple DPI cannot see the site name. Works for HTTPS through the proxy only; UDP, QUIC and Discord voice need zapret2.",
        )}
      </p>
    </section>

    <section class="card opts">
      <div class="opt">
        <div>
          <div class="label">{t("нарезка", "split")}</div>
          <div class="hint faint mono">{splitHint}</div>
        </div>
        <Segmented
          small
          disabled={app.busy}
          value={cfg.split}
          onchange={(m) => {
            // Пустые позиции не сохранятся — подставляем пример: середина имени сайта.
            if (m === "custom" && !cfg.positions.trim()) {
              positionsText = "0+sm";
              change({ split: m, positions: "0+sm" });
            } else change({ split: m });
          }}
          options={[
            { value: "chunk", label: "Chunks" },
            { value: "sni", label: "SNI" },
            { value: "first-byte", label: "First byte" },
            { value: "random", label: "Random" },
            { value: "custom", label: "Custom" },
            { value: "none", label: "None" },
          ]} />
      </div>
      {#if cfg.split === "custom"}
        <div class="positions">
          <div class="prow">
            <input class="input mono" spellcheck="false" placeholder="0+sm 1:3:5 -10" bind:value={positionsText} onkeydown={(e) => e.key === "Enter" && change({ positions: positionsText })} disabled={app.busy} />
            <button class="btn sm" disabled={app.busy || positionsText === cfg.positions || !positionsText.trim()} onclick={() => change({ positions: positionsText })}>{t("Сохранить", "Save")}</button>
          </div>
          <div class="syntax mono">
            <div><b>{t("смещение[:повторы:шаг][+флаги]", "offset[:repeats:skip][+flags]")}</b> {t("— через пробел или запятую, отсчёт в байтах", "— separated by spaces or commas, in bytes")}</div>
            <div><b>+s</b> {t("от начала имени сайта", "from the start of the site name")} · <b>+e</b> {t("от конца имени", "from its end")} · <b>+m</b> {t("от середины", "from its middle")} · <b>+n</b> {t("от начала пакета", "from the packet start")}</div>
            <div>{t("Без флагов: от начала, отрицательное — от конца пакета.", "No flags: from the start; negative — from the packet end.")}</div>
            <div class="faint">0+sm — {t("середина имени", "middle of the name")} · 1:3:5 — {t("позиции 1, 6, 11", "positions 1, 6, 11")} · -10 — {t("за 10 байт до конца", "10 bytes before the end")} · 2+se — {t("через 2 байта после имени", "2 bytes after the name")}</div>
          </div>
        </div>
      {/if}
      {#if cfg.split !== "none"}
      <div class="opt joined">
        <div>
          <div class="label">{t("куски нарезки", "split pieces")}</div>
          <div class="hint faint mono">
            {cfg.unit === "records"
              ? t("как уходят куски нарезки: каждый — отдельная TLS-запись", "how split pieces are sent: each is a separate TLS record")
              : cfg.unit === "mixed"
                ? t("как уходят куски нарезки: TLS-записи с разными версиями (первая 1.2, остальные 1.0)", "how split pieces are sent: TLS records with different versions (first 1.2, the rest 1.0)")
                : t("как уходят куски нарезки: TCP-сегменты одной TLS-записи", "how split pieces are sent: TCP segments of one TLS record")}
          </div>
        </div>
        <div class="inline">
          {#if cfg.split === "chunk"}
            <input class="input chunk" type="number" min="1" max="1024" title={t("Размер чанка, байт", "Chunk size, bytes")} bind:value={cfg.chunk} onchange={() => change({ chunk: Number(cfg.chunk) })} disabled={app.busy} />
          {/if}
          <Segmented
            small
            disabled={app.busy}
            value={cfg.unit}
            onchange={(m) => change({ unit: m })}
            options={[
              { value: "records", label: "TLS records" },
              { value: "tcp", label: "TCP segments" },
              { value: "mixed", label: "Mixed versions" },
            ]} />
        </div>
      </div>
      {/if}
      {#if cfg.split !== "none"}
      <div class="opt">
        <div>
          <div class="label">disorder</div>
          <div class="hint faint mono">{t("первая часть с TTL=1 — поток приходит не по порядку", "first part with TTL=1 — out-of-order stream")}</div>
        </div>
        <Switch checked={cfg.disorder} disabled={app.busy} onchange={(v) => change({ disorder: v })} />
      </div>
      {/if}
      <div class="opt">
        <div>
          <div class="label">{t("автоматический режим", "auto mode")}</div>
          <div class="hint faint mono">
            {t("если сайт сбросил соединение или молчит — повторить запасными способами и запомнить рабочий", "if a site resets or stays silent — retry with fallback methods and remember the one that works")}
          </div>
          {#if cfg.auto}
            <div class="chain mono">
              {#each cfg.auto_chain as v, i (i)}
                <span class="chip">{i + 1}. {variantName(v)}</span>
              {:else}
                <span class="faint">{t("запасных способов нет — запустите подбор", "no fallback methods — run the finder")}</span>
              {/each}
            </div>
          {/if}
        </div>
        <div class="inline">
          {#if cfg.auto}
            <input class="input chunk" type="number" min="2" max="15" title={t("Сколько ждать ответа сервера, с", "How long to wait for the server, s")} bind:value={cfg.auto_timeout} onchange={() => change({ auto_timeout: Number(cfg.auto_timeout) })} disabled={app.busy} />
          {/if}
          <Switch checked={cfg.auto} disabled={app.busy} onchange={(v) => change({ auto: v })} />
        </div>
      </div>
      <div class="opt">
        <div>
          <div class="label">{t("системный прокси", "system proxy")}</div>
          <div class="hint faint mono">{t("прописать в Windows; при выключении вернуть как было", "set in Windows; restored when turned off")}</div>
        </div>
        <Switch checked={cfg.system} disabled={app.busy} onchange={(v) => change({ system: v })} />
      </div>
      <div class="opt">
        <div>
          <div class="label">{t("порт", "port")}</div>
          <div class="hint faint mono">{t("для ручной настройки браузера", "for manual browser setup")}</div>
        </div>
        <input class="input port" type="number" min="1024" max="65535" bind:value={cfg.port} disabled={app.busy || running} />
      </div>
    </section>

    <More key="proxy.main" active={advCount}>
      {#if cfg.split !== "none"}
      <div class="opt">
        <div>
          <div class="label">OOB</div>
          <div class="hint faint mono">{t("к первой части — «срочный» байт: его видит DPI, но не сервер", "an urgent byte after the first part: DPI sees it, the server does not")}</div>
        </div>
        <Switch checked={cfg.oob} disabled={app.busy} onchange={(v) => change({ oob: v })} />
      </div>
      {/if}
      <div class="opt">
        <div>
          <div class="label">IPv6</div>
          <div class="hint faint mono">{t("запрашивать и использовать IPv6-адреса сайтов", "query and use IPv6 site addresses")}</div>
        </div>
        <Switch checked={cfg.ipv6} disabled={app.busy} onchange={(v) => change({ ipv6: v })} />
      </div>
      <div class="opt">
        <div>
          <div class="label">{t("маленький буфер приёма", "small receive buffer")} <span class="chip">{t("эксперимент", "experimental")}</span></div>
          <div class="hint faint mono">{t("сервер шлёт ответ мелкими кусками — против DPI, который режет по сертификату (см. Check); первый ответ медленнее", "the server sends its reply in small pieces — against DPI that cuts on the certificate (see Check); the first reply is slower")}</div>
        </div>
        <Switch checked={cfg.rcvbuf > 0} disabled={app.busy} onchange={(v) => change({ rcvbuf: v ? 2048 : 0 })} />
      </div>
      <div class="opt">
        <div>
          <div class="label">DoH</div>
          <div class="hint faint mono">{t("адреса сайтов через Cloudflare/Google — мимо подмены DNS", "resolve via Cloudflare/Google — past DNS spoofing")}</div>
        </div>
        <Switch checked={cfg.doh} disabled={app.busy} onchange={(v) => change({ doh: v })} />
      </div>
    </More>
  {:else if sub === "autotune"}
    <ProxyTest
      current={{ split: cfg.split, unit: cfg.unit, disorder: cfg.disorder, oob: cfg.oob }}
      apply={(v, chain) => change({ split: v.split, unit: v.unit, disorder: v.disorder, oob: v.oob, auto_chain: chain })} />
  {:else if sub === "rules"}
    <section class="card block">
      <div class="row">
        <div>
          <div class="label"><ListFilter size={11} /> {t("правила", "rules")}</div>
          <div class="hint faint mono">
            {cfg.rules.scope === "all"
              ? t("режется любой сайт, кроме списка «не резать»", "every site is split except the \"do not split\" list")
              : t("режутся только домены из списков; остальные идут без нарезки", "only listed domains are split; others pass without splitting")}
          </div>
        </div>
        <Segmented
          small
          disabled={app.busy}
          value={cfg.rules.scope}
          onchange={(v) => change({ rules: { ...cfg.rules, scope: v } })}
          options={[
            { value: "all", label: t("Резать всё", "Split all") },
            { value: "listed", label: t("Только списки", "Listed only") },
          ]} />
      </div>
      {#if cfg.rules.scope === "listed"}
        <label class="check mono">
          <input type="checkbox" checked={cfg.rules.zapret_lists} disabled={app.busy} onchange={(e) => change({ rules: { ...cfg.rules, zapret_lists: e.currentTarget.checked } })} />
          {t("добавить домены из списков zapret2", "include domains from the zapret2 lists")}
          {#if running && st}<span class="faint">· {st.stats.bypass_domains}</span>{/if}
        </label>
      {/if}
      <div class="hint faint mono">{t("Домен в правиле совпадает и со всеми поддоменами.", "A domain in a rule also matches all its subdomains.")}</div>
      <div class="rules">
        {#if cfg.rules.scope === "listed"}
          <label class="field">
            <span class="k mono">{t("обходить", "bypass")}</span>
            <textarea class="textarea" rows="4" spellcheck="false" placeholder="youtube.com" bind:value={ruleText.bypass}></textarea>
          </label>
        {/if}
        <label class="field">
          <span class="k mono">{t("не резать", "do not split")}</span>
          <textarea class="textarea" rows="4" spellcheck="false" placeholder="sberbank.ru" bind:value={ruleText.skip}></textarea>
        </label>
        <label class="field">
          <span class="k mono">{t("блокировать", "block")}</span>
          <textarea class="textarea" rows="4" spellcheck="false" placeholder="ads.example.com" bind:value={ruleText.block}></textarea>
        </label>
      </div>
      <div class="actions">
        <span class="faint mono hint grow">
          {cfg.rules.scope === "listed"
            ? t("Остальные сайты идут через прокси без нарезки. Для SOCKS5 включите удалённый DNS в приложении — иначе вместо домена придёт IP.", "Other sites pass through without splitting. For SOCKS5 enable remote DNS in the app — otherwise an IP comes instead of a domain.")
            : t("«Не резать» — для банков и сайтов, которые ломаются от нарезки.", "\"Do not split\" is for banks and sites that break with splitting.")}
        </span>
        <button class="btn sm" disabled={app.busy || !rulesDirty} onclick={saveRules}>{t("Сохранить", "Save")}</button>
      </div>
    </section>

    <ProxyWorker {cfg} {change} via={st?.stats.via_worker ?? 0} />
  {:else if sub === "lan"}
    <section class="card block">
      <div class="row">
        <div>
          <div class="label"><Wifi size={11} /> {t("раздача в локальную сеть", "share on local network")}</div>
          <div class="hint faint mono">{t("телефон в той же Wi-Fi пользуется обходом этого ПК", "a phone on the same Wi-Fi uses this PC's bypass")}</div>
        </div>
        <Switch checked={cfg.lan} disabled={app.busy || (cfg.lan === false && !authOk)} onchange={(v) => change({ lan: v })} />
      </div>
      {#if cfg.lan}
        <div class="kv mono">
          <span class="k">{t("адрес", "address")}</span>
          <span class="v">
            {#each lanIps as ip (ip)}
              <button class="btn sm ghost" title={t("Скопировать", "Copy")} onclick={() => navigator.clipboard?.writeText(`${ip}:${cfg.port}`).then(() => toast(`${ip}:${cfg.port}`, "ok"))}>
                {ip}:{cfg.port} <Copy size={11} />
              </button>
            {:else}
              <span class="faint">{t("нет подключения к локальной сети", "no local network connection")}</span>
            {/each}
          </span>
          <span class="k">{t("протокол", "protocol")}</span>
          <span class="v">{t("HTTP-прокси или SOCKS5, порт тот же", "HTTP proxy or SOCKS5, same port")}</span>
        </div>
        {#if !app.ov?.admin}
          <div class="note mono"><ShieldAlert size={12} /> {t("Без прав администратора правило брандмауэра Windows не добавится — разрешите входящие вручную (и в simplewall).", "Without admin rights the Windows firewall rule is not added — allow inbound connections manually (and in simplewall).")}</div>
        {/if}
      {/if}
      <div class="auth">
        <div class="label"><KeyRound size={11} /> {t("логин и пароль", "user and password")}</div>
        <div class="hint faint mono">{t("для устройств из сети; с этого ПК не спрашивается. Пусто — без пароля", "for network devices; not asked on this PC. Empty — no password")}</div>
        <div class="creds">
          <input class="input" placeholder={t("логин", "user")} autocomplete="off" bind:value={cfg.user} disabled={app.busy} />
          <input class="input" placeholder={t("пароль", "password")} autocomplete="off" type={showPass ? "text" : "password"} bind:value={cfg.pass} disabled={app.busy} />
          <button class="btn sm" disabled={app.busy} onclick={genPass} title={t("Сгенерировать пароль", "Generate a password")}>{t("Сгенерировать", "Generate")}</button>
          <button class="btn sm" disabled={app.busy || !authOk} onclick={() => change({})}>{t("Сохранить", "Save")}</button>
        </div>
        {#if !authOk}
          <div class="err mono">{t("Нужны и логин, и пароль; в логине без «:».", "Both user and password are required; no ':' in the user.")}</div>
        {:else if cfg.lan && !cfg.user}
          <div class="note mono"><ShieldAlert size={12} /> {t("Без пароля прокси доступен любому устройству в этой сети.", "Without a password any device on this network can use the proxy.")}</div>
        {/if}
        <div class="hint faint mono">{t("Встроенный прокси Wi-Fi на Android пароль не передаёт — браузер спросит его сам; приложения с SOCKS5 (Telegram, v2rayNG) принимают логин и пароль.", "Android's built-in Wi-Fi proxy does not send a password — the browser will ask for it; SOCKS5 apps (Telegram, v2rayNG) accept user and password.")}</div>
      </div>
    </section>
  {:else}
    <section class="card opts">
      <div class="opt">
        <div>
          <div class="label">{t("журнал соединений", "connection log")}</div>
          <div class="hint faint mono">{t("какой сайт, что сделано, каким способом и чем кончилось", "which site, what was done, which method and the outcome")}</div>
        </div>
        <Switch checked={cfg.log} disabled={app.busy} onchange={(v) => change({ log: v })} />
      </div>
    </section>
    {#if cfg.log}
      <ProxyLog {running} />
    {/if}
  {/if}
</div>

<style>
  .hero {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 16px 18px 18px;
  }
  .prompt {
    align-self: flex-start;
    font-size: 12px;
    color: var(--muted);
  }
  .state-line {
    font-size: 12px;
    height: 16px;
    margin-bottom: 6px;
  }
  .state-line .on {
    color: var(--sage);
  }
  .proxy {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .block {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .row,
  .opt {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .hint {
    font-size: 11px;
    margin-top: 3px;
  }
  .text {
    margin: 0;
    font-size: 12px;
    line-height: 1.5;
  }
  .stats {
    display: flex;
    align-items: center;
    gap: 14px;
    font-size: 11.5px;
    color: var(--muted);
  }
  .stats b {
    color: var(--text);
  }
  .addr {
    margin-left: auto;
  }
  .err {
    font-size: 11px;
    color: var(--danger-text);
    word-break: break-all;
  }
  .opts {
    padding: 4px 14px;
  }
  .opt {
    padding: 10px 0;
  }
  .opt + .opt {
    border-top: 1px solid var(--border-soft);
  }
  /* Продолжение предыдущей строки (куски нарезки под нарезкой) — без черты. */
  .opt.joined {
    border-top: 0;
    padding-top: 0;
  }
  .positions + .opt.joined {
    padding-top: 12px;
  }
  .port {
    width: 96px;
  }
  .positions {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 0 0 10px;
  }
  .prow {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 6px;
  }
  .syntax {
    display: flex;
    flex-direction: column;
    gap: 2px;
    font-size: 11.5px;
    color: var(--muted);
    line-height: 1.5;
  }
  .syntax b {
    color: var(--text);
    font-weight: 600;
  }
  .chain {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 6px;
  }
  .inline {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .chunk {
    width: 64px;
    height: 26px;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11.5px;
    color: var(--muted);
    cursor: pointer;
  }
  .check input {
    accent-color: var(--accent);
    margin: 0;
  }
  .rules {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 8px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .field .k {
    font-size: 11px;
    color: var(--faint);
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .grow {
    flex: 1;
  }
  .label {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .kv {
    display: grid;
    grid-template-columns: 74px 1fr;
    gap: 4px 8px;
    align-items: center;
    font-size: 12px;
  }
  .k {
    color: var(--faint);
  }
  .v {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .note {
    display: flex;
    gap: 6px;
    align-items: flex-start;
    font-size: 11px;
    color: var(--warn);
  }
  .auth {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding-top: 10px;
    border-top: 1px solid var(--border-soft);
  }
  .creds {
    display: grid;
    grid-template-columns: 1fr 1fr auto auto;
    gap: 6px;
    align-items: center;
  }
</style>
