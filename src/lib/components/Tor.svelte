<script lang="ts">
  import PowerButton from "./PowerButton.svelte";
  import Segmented from "./Segmented.svelte";
  import Switch from "./Switch.svelte";
  import { onMount } from "svelte";
  import { api, on, type TorConfig, type TorStatus, type TorTransport, type TorScope, type BridgeReport, type BridgeProgress } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { Copy, RefreshCw, Search, Square, Globe, ScrollText, TriangleAlert, ListPlus, MonitorCog } from "@lucide/svelte";

  let st = $state<TorStatus | null>(null);
  let cfg = $state<TorConfig | null>(null);
  let bridgesText = $state("");
  let domainsText = $state("");
  let portText = $state("");
  let kinds = $state({ obfs4: true, webtunnel: true });
  let want = $state(8);
  let finding = $state(false);
  let prog = $state<BridgeProgress | null>(null);
  let report = $state<BridgeReport | null>(null);
  let showLog = $state(false);
  let log = $state<string[]>([]);

  const run = $derived(st?.status);
  const running = $derived(!!run?.running);
  const ready = $derived(!!run?.ready);
  const lines = (v: string[]) => v.join("\n");
  const fromLines = (s: string) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const fromWords = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

  function sync(r: TorStatus) {
    st = r;
    cfg = { ...r.config };
    bridgesText = lines(r.config.bridges);
    domainsText = lines(r.domains);
    portText = String(r.config.socks_port);
  }
  async function load() {
    try {
      sync(await api.torStatus());
    } catch (e) {
      toast(String(e));
    }
  }
  async function poll() {
    try {
      const r = await api.torStatus();
      st = { ...r, config: st?.config ?? r.config, domains: st?.domains ?? r.domains };
      if (showLog) log = await api.torLog();
    } catch {}
  }
  onMount(() => {
    load();
    // Пока идёт подключение — чаще, потом реже.
    let n = 0;
    const id = setInterval(() => {
      n++;
      if (running && (!ready || n % 3 === 0)) poll();
    }, 1000);
    const un = [
      on("tor-changed", load),
      on("proxy-changed", poll),
      on<BridgeProgress>("tor-bridges-progress", (p) => (prog = p)),
    ];
    return () => {
      clearInterval(id);
      un.forEach((p) => p.then((f) => f()));
    };
  });
  $effect(() => {
    if (showLog) api.torLog().then((l) => (log = l)).catch(() => {});
  });

  async function toggle() {
    if (!cfg) return;
    const r = running
      ? await act(() => api.torStop(), t("Tor выключен", "Tor is off"))
      : await act(() => api.torStart({ ...cfg! }), t("Tor запускается…", "Tor is starting…"));
    if (r) sync(r);
  }
  async function save(patch: Partial<TorConfig>, msg?: string) {
    if (!cfg) return;
    const r = await act(() => api.torSetConfig({ ...cfg!, ...patch }), msg);
    if (r) sync(r);
  }
  const bridgesDirty = $derived(!!cfg && bridgesText !== lines(cfg.bridges));
  const domainsDirty = $derived(!!st && domainsText !== lines(st.domains));
  const portDirty = $derived(!!cfg && portText !== String(cfg.socks_port));

  async function find() {
    const k = Object.entries(kinds).filter(([, v]) => v).map(([k]) => k);
    finding = true;
    prog = null;
    report = null;
    try {
      report = await api.torFindBridges(k, Math.max(1, Math.min(30, Number(want) || 8)));
      if (report.found.length) {
        toast(t(`Найдено мостов: ${report.found.length}`, `Bridges found: ${report.found.length}`), "ok");
      } else if (!report.cancelled) {
        toast(t("Рабочих мостов не нашлось — попробуйте позже или другой транспорт", "No working bridges found — try later or another transport"));
      }
      await load();
    } catch (e) {
      toast(String(e));
    }
    finding = false;
    prog = null;
  }
  async function reconnect() {
    if (!cfg) return;
    const r = await act(() => api.torStart({ ...cfg! }), t("Переподключение…", "Reconnecting…"));
    if (r) sync(r);
  }
  async function saveDomains() {
    const r = await act(() => api.torSetDomains(fromWords(domainsText)), t("Список сохранён", "List saved"));
    if (r) sync(r);
  }
  async function setScope(scope: TorScope) {
    const r = await act(() => api.torSetDomains(fromWords(domainsText), scope));
    if (r) sync(r);
  }
  async function setSystem(on: boolean) {
    const r = await act(
      () => api.torSystemProxy(on),
      on ? t("Прокси-обходчик прописан системным прокси", "The bypass proxy is now the system proxy") : t("Системный прокси снят", "System proxy removed"),
    );
    if (r) sync(r);
  }
  /** Найденные мосты — в «свои» (без повторов). */
  async function toOwn() {
    if (!cfg || !report) return;
    const have = new Set(cfg.bridges);
    const add = report.found.map((f) => f.line).filter((l) => !have.has(l));
    if (!add.length) return toast(t("Эти мосты уже в своих", "These bridges are already in your list"), "ok");
    await save({ bridges: [...cfg.bridges, ...add] }, t(`Добавлено в свои мосты: ${add.length}`, `Added to own bridges: ${add.length}`));
  }
  const scopes: { value: TorScope; label: () => string; hint: () => string }[] = [
    { value: "list", label: () => t("Только список", "List only"), hint: () => t("в Tor идут домены из списка ниже и .onion, остальное — как обычно", "the domains below and .onion go to Tor, the rest as usual") },
    { value: "zapret", label: () => t("Списки zapret", "zapret lists"), hint: () => t("плюс все домены из списков zapret2 (YouTube, Discord и т. д.) — когда zapret не справляется", "plus every domain from the zapret2 lists (YouTube, Discord, etc.) — when zapret cannot cope") },
    { value: "all", label: () => t("Весь трафик", "All traffic"), hint: () => t("всё, что идёт через прокси-обходчик, кроме «не резать» и Worker. Медленнее, а часть сайтов покажет капчу", "everything that goes through the bypass proxy except “do not split” and Worker. Slower, and some sites show a captcha") },
  ];
  async function newIdentity() {
    await act(() => api.torNewIdentity(), t("Новые цепочки для новых соединений", "New circuits for new connections"));
  }
  const copy = (s: string, msg: string) => navigator.clipboard?.writeText(s).then(() => toast(msg, "ok"));

  const transports: { value: TorTransport; label: () => string; hint: () => string }[] = [
    { value: "auto", label: () => t("Авто", "Auto"), hint: () => t("по очереди: свои и найденные мосты → встроенные obfs4 → snowflake → meek; ступень меняется, если подключение стоит 90 с", "in turn: own and found bridges → built-in obfs4 → snowflake → meek; moves on if connecting stalls for 90 s") },
    { value: "obfs4", label: () => "obfs4", hint: () => t("свои и найденные obfs4, затем встроенные (встроенные в России почти все заблокированы)", "own and found obfs4, then built-in ones (built-in ones are mostly blocked in Russia)") },
    { value: "webtunnel", label: () => "webtunnel", hint: () => t("выглядит как обычный HTTPS-сайт; нужны найденные или свои мосты. Если провайдер глушит его TLS — включите «мосты через прокси-обходчик»", "looks like a regular HTTPS site; needs found or own bridges. If your ISP chokes its TLS, turn on “bridges through the bypass proxy”") },
    { value: "snowflake", label: () => "snowflake", hint: () => t("через волонтёрские прокси по WebRTC: медленнее, но мосты не кончаются", "through volunteer WebRTC proxies: slower, but bridges never run out") },
    { value: "meek", label: () => "meek", hint: () => t("через CDN (domain fronting): медленно, запасной вариант", "through a CDN (domain fronting): slow, a last resort") },
    { value: "custom", label: () => t("Свои", "Own"), hint: () => t("только ваши мосты: bridges.torproject.org, @GetBridgesBot в Telegram или bridges@torproject.org", "only your bridges: bridges.torproject.org, @GetBridgesBot on Telegram or bridges@torproject.org") },
    { value: "direct", label: () => t("Напрямую", "Direct"), hint: () => t("без мостов — если Tor у провайдера не заблокирован", "no bridges — if your ISP does not block Tor") },
  ];
  const tierName = (n: string) =>
    ({ bridges: t("свои и найденные мосты", "own and found bridges"), custom: t("свои мосты", "own bridges"), direct: t("напрямую", "direct") })[n] ?? n;
  const stageName = (p: BridgeProgress) =>
    p.stage === "download" ? t("скачиваю списки…", "downloading lists…") : p.stage === "tcp" ? t(`проверка адресов ${p.done}/${p.total}`, `checking addresses ${p.done}/${p.total}`) : t(`проверка мостов ${p.done}/${p.total} · найдено ${p.found}`, `checking bridges ${p.done}/${p.total} · found ${p.found}`);
  const short = (l: string) => {
    const w = l.split(" ");
    return w[0] === "webtunnel" ? `webtunnel ${(w.find((x) => x.startsWith("url=")) ?? "").replace(/^url=https?:\/\//, "").split("/")[0]}` : `${w[0]} ${w[1] ?? ""}`;
  };
</script>

<div class="tor fade-in">
  {#if st && cfg && run}
    {#if !st.available}
      <section class="card block">
        <div class="err mono">{t("В этой сборке нет Tor: соберите приложение заново (npm run sync-tor скачает его).", "This build has no Tor: rebuild the app (npm run sync-tor downloads it).")}</div>
      </section>
    {/if}

    <section class="card block hero">
      <div class="prompt mono">{t("tor · обход блокировок по IP и геоограничений, .onion", "tor · bypass of IP blocks and geo-restrictions, .onion")}</div>
      <PowerButton on={running} disabled={app.busy || !st.available} onclick={toggle} />
      <div class="state-line mono">
        {#if app.busy}<span class="muted">…</span>
        {:else if ready}<span class="on">● SOCKS5 127.0.0.1:{run.socks_port}</span>
        {:else if running}<span class="warn">◐ {t("подключение", "connecting")} {run.percent}%</span>
        {:else}<span class="faint">○ {t("выключен", "off")}</span>{/if}
      </div>
      {#if running}
        <div class="bar" class:done={ready}><span style:width="{Math.max(run.percent, 2)}%"></span></div>
        <div class="stats mono">
          <span>{t("способ", "method")}: <b>{tierName(run.tier)}</b>{#if cfg.transport === "auto" && run.tiers.length > 1} <span class="faint">({run.tiers.indexOf(run.tier) + 1}/{run.tiers.length})</span>{/if}</span>
          {#if !ready && run.phase}<span>{run.phase}</span>{/if}
          {#if !ready}<span>{run.elapsed} {t("с", "s")}</span>{/if}
        </div>
        {#if run.error && !ready}<div class="err mono">{run.error}</div>{/if}
        {#if ready}
          <div class="actions">
            <button class="btn sm" onclick={() => copy(`127.0.0.1:${run.socks_port}`, t("Адрес скопирован", "Address copied"))}><Copy size={12} /> SOCKS5</button>
            <button class="btn sm" disabled={app.busy} onclick={newIdentity}><RefreshCw size={12} /> {t("Новая личность", "New identity")}</button>
          </div>
        {/if}
      {:else if run.error}
        <div class="err mono">{run.error}</div>
      {/if}
      <p class="muted text">
        {t(
          "Tor открывает то, что не берут zapret и нарезка: сайты, заблокированные по IP, геоограничения и адреса .onion. Сайты из списка ниже прокси-обходчик отправит через Tor, остальное пойдёт как обычно. Любая программа может подключиться к Tor напрямую по SOCKS5.",
          "Tor opens what zapret and splitting cannot: IP-blocked sites, geo-restrictions and .onion addresses. The bypass proxy sends the sites listed below through Tor, everything else goes as usual. Any program can connect to Tor directly over SOCKS5.",
        )}
      </p>
    </section>

    <section class="card block">
      <div class="label">{t("способ подключения", "connection method")}</div>
      <Segmented small options={transports.map((x) => ({ value: x.value, label: x.label() }))} value={cfg.transport} disabled={app.busy} onchange={(v) => save({ transport: v })} />
      <div class="hint faint mono">{transports.find((x) => x.value === cfg!.transport)?.hint()}</div>
      <div class="opt">
        <div>
          <div class="label">{t("мосты через прокси-обходчик", "bridges through the bypass proxy")}</div>
          <div class="hint faint mono">
            {t(
              "tor ходит к мостам через наш прокси (Socks5Proxy), а тот режет ClientHello — для webtunnel, если провайдер глушит его TLS. Прокси должен быть включён; snowflake и meek так не ходят.",
              "tor reaches bridges through our proxy (Socks5Proxy), which splits the ClientHello — for webtunnel if your ISP chokes its TLS. The proxy must be on; snowflake and meek do not go this way.",
            )}
            {#if cfg.via_proxy && !st.proxy_running}<span class="warn"> {t("Прокси сейчас выключен.", "The proxy is off now.")}</span>{/if}
          </div>
        </div>
        <Switch checked={cfg.via_proxy} disabled={app.busy} onchange={(v) => save({ via_proxy: v })} />
      </div>
      <label class="field">
        <span class="k mono">{t("свои мосты (по одному в строке)", "own bridges (one per line)")}</span>
        <textarea class="textarea" rows="3" spellcheck="false" placeholder="obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0" bind:value={bridgesText} disabled={app.busy}></textarea>
      </label>
      <div class="actions">
        <label class="mono portl"><span class="k">{t("порт SOCKS5", "SOCKS5 port")}</span>
          <input class="input port" type="number" min="1024" max="65534" bind:value={portText} disabled={app.busy} />
        </label>
        <span class="grow"></span>
        <button class="btn sm" disabled={app.busy || (!bridgesDirty && !portDirty)} onclick={() => save({ bridges: fromLines(bridgesText), socks_port: Number(portText) }, t("Сохранено", "Saved"))}>{t("Сохранить", "Save")}</button>
      </div>
    </section>

    <section class="card block">
      <div class="row">
        <div>
          <div class="label"><Search size={11} /> {t("поиск мостов", "bridge search")}</div>
          <div class="hint faint mono">
            {t(
              "свежие списки obfs4 и webtunnel (scriptzteam/Tor-Bridges-Collector-v2, из BridgeDB) → проверка адресов → рукопожатие через lyrebird до ответа реле Tor. Найденные сохраняются и идут первыми.",
              "fresh obfs4 and webtunnel lists (scriptzteam/Tor-Bridges-Collector-v2, from BridgeDB) → address check → handshake through lyrebird up to the Tor relay's reply. Found bridges are saved and go first.",
            )}
          </div>
        </div>
        {#if cfg.found.length}<span class="chip sage">{t("сохранено", "saved")} {cfg.found.length}</span>{/if}
      </div>
      <div class="actions">
        <label class="check mono"><input type="checkbox" bind:checked={kinds.obfs4} disabled={finding} /> obfs4</label>
        <label class="check mono"><input type="checkbox" bind:checked={kinds.webtunnel} disabled={finding} /> webtunnel</label>
        <label class="check mono">{t("найти", "find")} <input class="input num" type="number" min="1" max="30" bind:value={want} disabled={finding} /></label>
        <span class="grow"></span>
        {#if finding}
          <button class="btn sm" onclick={() => api.torFindCancel()}><Square size={12} /> {t("Стоп", "Stop")}</button>
        {:else}
          <button class="btn sm primary" disabled={!st.available || (!kinds.obfs4 && !kinds.webtunnel)} onclick={find}><Search size={12} /> {t("Найти мосты", "Find bridges")}</button>
        {/if}
      </div>
      {#if finding}
        <div class="hint mono"><span class="spin"></span> {prog ? stageName(prog) : t("начинаю…", "starting…")}</div>
      {/if}
      {#if report}
        <div class="hint faint mono">
          {t(`проверено ${report.checked} из ${report.candidates} живых адресов за ${report.secs} с`, `checked ${report.checked} of ${report.candidates} live addresses in ${report.secs} s`)}
          {#each report.errors as e}<div class="err">{e}</div>{/each}
        </div>
        {#if report.found.length}
          <div class="found mono">
            {#each report.found as f (f.line)}
              <div class="fr">
                <span class="chip">{f.transport}</span>
                <span class="ln" title={f.line}>{short(f.line)}</span>
                <span class="ms">{f.ms} ms</span>
                <button class="btn sm ghost" title={t("Скопировать строку", "Copy line")} onclick={() => copy(f.line, t("Мост скопирован", "Bridge copied"))}><Copy size={12} /></button>
              </div>
            {/each}
          </div>
          <div class="actions">
            <button class="btn sm" onclick={() => copy(report!.found.map((f) => f.line).join("\n"), t(`Скопировано мостов: ${report!.found.length}`, `Bridges copied: ${report!.found.length}`))}><Copy size={12} /> {t("Скопировать все", "Copy all")}</button>
            <button class="btn sm" disabled={app.busy} onclick={toOwn}><ListPlus size={12} /> {t("В свои мосты", "To own bridges")}</button>
            <span class="grow"></span>
            {#if running}<button class="btn sm" disabled={app.busy} onclick={reconnect}>{t("Переподключить с найденными", "Reconnect with found bridges")}</button>{/if}
          </div>
        {/if}
      {/if}
    </section>

    <section class="card block">
      <div class="row">
        <div>
          <div class="label"><Globe size={11} /> {t("сайты через tor", "sites through tor")}</div>
          <div class="hint faint mono">
            {t(
              "прокси-обходчик отправит эти домены (с поддоменами) через Tor, пока он подключён; .onion — всегда. Браузер должен ходить через прокси-обходчик (системный прокси или SOCKS5/HTTP 127.0.0.1:",
              "the bypass proxy sends these domains (with subdomains) through Tor while it is connected; .onion always. The browser must use the bypass proxy (system proxy or SOCKS5/HTTP 127.0.0.1:",
            )}{st.proxy_port}).
          </div>
        </div>
        {#if st.proxy_running}<span class="chip sage">{t("прокси включён", "proxy on")}</span>{:else}<span class="chip">{t("прокси выключен", "proxy off")}</span>{/if}
      </div>
      <Segmented small options={scopes.map((x) => ({ value: x.value, label: x.label() }))} value={st.tor_scope} disabled={app.busy} onchange={setScope} />
      <div class="hint faint mono">{scopes.find((x) => x.value === st!.tor_scope)?.hint()}</div>
      <textarea class="textarea" rows="4" spellcheck="false" placeholder="rutracker.org&#10;linkedin.com" bind:value={domainsText} disabled={app.busy}></textarea>
      <div class="actions"><span class="grow"></span><button class="btn sm" disabled={app.busy || !domainsDirty} onclick={saveDomains}>{t("Сохранить", "Save")}</button></div>
    </section>

    <section class="card block">
      <div class="opt">
        <div>
          <div class="label"><MonitorCog size={11} /> {t("системный прокси windows", "windows system proxy")}</div>
          <div class="hint faint mono">
            {t(
              "Системный прокси у Windows один, поэтому им всегда становится прокси-обходчик, а Tor работает через него по режиму выше. Так браузеры и программы, которые слушают системный прокси, пойдут через Tor без настройки. Переключатель тот же, что «системный прокси» на вкладке «Прокси».",
              "Windows has a single system proxy, so it is always the bypass proxy, and Tor works through it according to the mode above. Browsers and programs that follow the system proxy then use Tor with no setup. This is the same switch as “system proxy” on the Proxy tab.",
            )}
            {#if st.proxy_system && !ready}<span class="warn"> {t("Пока Tor не подключён, сайты идут как обычно.", "Until Tor is connected, sites go as usual.")}</span>{/if}
          </div>
        </div>
        <Switch checked={st.proxy_system} disabled={app.busy} onchange={setSystem} />
      </div>
    </section>

    <section class="card block note">
      <div class="label"><TriangleAlert size={11} /> {t("это не анонимность", "this is not anonymity")}</div>
      <p class="muted text">
        {t(
          "Через прокси-обходчик ваш браузер виден сайтам по своему отпечатку, куки и входам в аккаунты — Tor здесь только обходит блокировки. Для анонимности нужен Tor Browser. Скорость ниже, чем у VPN; часть сайтов показывает выходным узлам Tor капчу.",
          "Through the bypass proxy your browser is still identifiable by its fingerprint, cookies and logins — Tor here only bypasses blocks. For anonymity use Tor Browser. It is slower than a VPN; some sites show Tor exit nodes a captcha.",
        )}
      </p>
    </section>

    <details class="card block logbox" bind:open={showLog}>
      <summary class="mono"><ScrollText size={12} /> {t("журнал tor", "tor log")}{st.version ? ` · Tor Expert Bundle ${st.version}` : ""}</summary>
      {#if log.length}<pre class="code mono">{log.join("\n")}</pre>{:else}<div class="hint faint mono">{t("пусто — Tor не запускался", "empty — Tor has not run")}</div>{/if}
    </details>
  {/if}
</div>

<style>
  .tor {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
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
  .block {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .hero.block {
    gap: 8px;
  }
  .row,
  .opt {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .label {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .hint {
    font-size: 11px;
    margin-top: 3px;
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .text {
    margin: 0;
    font-size: 12.5px;
    line-height: 1.55;
    align-self: stretch;
  }
  .bar {
    align-self: stretch;
    height: 4px;
    border-radius: 2px;
    background: var(--border-soft);
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--warn);
    transition: width 0.4s ease;
  }
  .bar.done span {
    background: var(--sage);
  }
  .stats {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 6px 16px;
    font-size: 12px;
    color: var(--muted);
  }
  .stats b {
    color: var(--text);
  }
  .warn {
    color: var(--warn);
  }
  .err {
    font-size: 11px;
    color: var(--danger-text);
    word-break: break-all;
    align-self: stretch;
  }
  .actions {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .grow {
    flex: 1;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .k {
    color: var(--muted);
    font-size: 11.5px;
  }
  .portl {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .port {
    width: 96px;
    height: 28px;
  }
  .num {
    width: 56px;
    height: 26px;
    margin-left: 4px;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    color: var(--muted);
  }
  .found {
    display: flex;
    flex-direction: column;
    gap: 2px;
    font-size: 11.5px;
  }
  .fr {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto auto;
    gap: 8px;
    align-items: center;
    padding: 2px 0;
    border-top: 1px solid var(--border-soft);
  }
  .ln {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    user-select: text;
  }
  .ms {
    color: var(--muted);
  }
  .spin {
    width: 10px;
    height: 10px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    flex: none;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .logbox summary {
    cursor: pointer;
    font-size: 12px;
    color: var(--muted);
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .code {
    margin: 0;
    padding: 10px 12px;
    max-height: 280px;
    overflow: auto;
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-sm);
    font-size: 11px;
    color: var(--muted);
    white-space: pre-wrap;
    word-break: break-all;
    user-select: text;
  }
</style>
