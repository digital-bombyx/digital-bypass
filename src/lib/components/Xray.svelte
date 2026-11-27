<script lang="ts">
  import PowerButton from "./PowerButton.svelte";
  import Segmented from "./Segmented.svelte";
  import Switch from "./Switch.svelte";
  import SubTabs from "./SubTabs.svelte";
  import More from "./More.svelte";
  import { XRAY_CATALOG, type CatalogSub } from "$lib/xrayCatalog";
  import { onMount } from "svelte";
  import { api, on, type XrayStatus, type XrayRouting, type TorScope } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { t, locale } from "$lib/i18n.svelte";
  import { Copy, Plus, RefreshCw, Trash2, Gauge, Route, Globe, MonitorCog, ScrollText, Link, Download, Square } from "@lucide/svelte";

  let st = $state<XrayStatus | null>(null);
  let addText = $state("");
  let adding = $state(false);
  let testing = $state(false);
  let speedRun = $state(false);
  let catalogAdding = $state<string | null>(null);
  let updating = $state<string | null>(null);
  let routes = $state({ direct: "", proxy: "", block: "" });
  let portText = $state("");
  let domainsText = $state("");
  let showLog = $state(false);
  let sub = $state<"servers" | "routing" | "connection">("servers");
  let log = $state<string[]>([]);

  const running = $derived(!!st?.status.running);
  const lines = (v: string[]) => v.join("\n");
  const fromLines = (s: string) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const fromWords = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

  function sync(r: XrayStatus) {
    st = r;
    routes = { direct: lines(r.routing.direct), proxy: lines(r.routing.proxy), block: lines(r.routing.block) };
    portText = String(r.port);
    domainsText = lines(r.domains);
  }
  async function load() {
    try {
      sync(await api.xrayStatus());
    } catch (e) {
      toast(String(e));
    }
  }
  onMount(() => {
    load();
    const id = setInterval(async () => {
      if (!running) return;
      try {
        const r = await api.xrayStatus();
        if (st) st = { ...st, status: r.status, proxy_running: r.proxy_running, proxy_system: r.proxy_system };
        if (showLog) log = await api.xrayLog();
      } catch {}
    }, 3000);
    const un = [on("xray-changed", load), on("proxy-changed", load)];
    return () => {
      clearInterval(id);
      un.forEach((p) => p.then((f) => f()));
    };
  });
  $effect(() => {
    if (showLog) api.xrayLog().then((l) => (log = l)).catch(() => {});
  });
  // Результаты скорости приходят по одному — подтягиваем их, пока идёт проверка.
  $effect(() => {
    if (!speedRun) return;
    const id = setInterval(async () => {
      try {
        const r = await api.xrayStatus();
        if (st) st = { ...st, speeds: r.speeds, speed_testing: r.speed_testing };
      } catch {}
    }, 1000);
    return () => clearInterval(id);
  });

  async function toggle() {
    const r = running ? await act(() => api.xrayStop(), t("Xray выключен", "Xray is off")) : await act(() => api.xrayStart(), t("Xray включён", "Xray is on"));
    if (r) sync(r);
  }
  async function set(p: { port?: number; selected?: string; routing?: XrayRouting; fragment?: boolean }, msg?: string) {
    if (!st) return;
    const r = await act(() => api.xraySet(p.port ?? st!.port, p.selected ?? st!.selected, p.routing ?? st!.routing, p.fragment ?? st!.fragment), msg);
    if (r) sync(r);
  }
  async function add() {
    adding = true;
    try {
      const r = await api.xrayAdd(addText);
      sync(r.status);
      addText = "";
      const skipped = r.errors.length ? t(` · пропущено: ${r.errors.length}`, ` · skipped: ${r.errors.length}`) : "";
      toast(t(`Добавлено серверов: ${r.added}`, `Servers added: ${r.added}`) + skipped, "ok");
      if (r.errors.length) toast(r.errors.slice(0, 3).join("\n"));
    } catch (e) {
      toast(String(e));
    }
    adding = false;
  }
  async function test() {
    testing = true;
    try {
      sync(await api.xrayTest());
    } catch (e) {
      toast(String(e));
    }
    testing = false;
  }
  async function speed() {
    if (speedRun) {
      api.xraySpeedStop().catch(() => {});
      return;
    }
    speedRun = true;
    try {
      sync(await api.xraySpeed(null));
    } catch (e) {
      toast(String(e));
    }
    speedRun = false;
  }
  async function addCatalog(c: CatalogSub) {
    catalogAdding = c.id;
    try {
      const r = await api.xrayAdd(c.url);
      sync(r.status);
      toast(t(`Подписка добавлена · серверов: ${r.added}`, `Subscription added · servers: ${r.added}`), "ok");
    } catch (e) {
      toast(String(e));
      await load();
    }
    catalogAdding = null;
  }
  const catalogAdded = (c: CatalogSub) => !!st?.subs.some((s) => s.url === c.url);
  const speedClass = (m: number | null | undefined) => (m == null ? "bad" : m >= 20 ? "good" : m >= 5 ? "mid" : "slow");
  async function updateSub(id: string | null) {
    updating = id ?? "*";
    try {
      sync(await api.xraySubUpdate(id));
      toast(t("Подписка обновлена", "Subscription updated"), "ok");
    } catch (e) {
      toast(String(e));
      await load();
    }
    updating = null;
  }
  async function removeSub(id: string, name: string) {
    if (!confirm(t(`Удалить подписку «${name}» и её серверы?`, `Remove subscription "${name}" and its servers?`))) return;
    const r = await act(() => api.xraySubRemove(id));
    if (r) sync(r);
  }
  async function removeServer(id: string) {
    const r = await act(() => api.xrayServerRemove(id));
    if (r) sync(r);
  }
  const routesDirty = $derived(!!st && (routes.direct !== lines(st.routing.direct) || routes.proxy !== lines(st.routing.proxy) || routes.block !== lines(st.routing.block)));
  function saveRoutes() {
    if (!st) return;
    set({ routing: { ...st.routing, direct: fromLines(routes.direct), proxy: fromLines(routes.proxy), block: fromLines(routes.block) } }, t("Маршрутизация сохранена", "Routing saved"));
  }
  async function saveDomains(scope?: TorScope) {
    const r = await act(() => api.xraySetDomains(fromWords(domainsText), scope), scope ? undefined : t("Список сохранён", "List saved"));
    if (r) sync(r);
  }
  async function setSystem(on: boolean) {
    const r = await act(() => api.torSystemProxy(on), on ? t("Прокси-обходчик прописан системным прокси", "The bypass proxy is now the system proxy") : t("Системный прокси снят", "System proxy removed"));
    if (r) await load();
  }
  const copy = (s: string, msg: string) => navigator.clipboard?.writeText(s).then(() => toast(msg, "ok"));
  const gb = (n: number) => (n >= 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(1)} GB` : n >= 1024 ** 2 ? `${(n / 1024 ** 2).toFixed(0)} MB` : `${Math.round(n / 1024)} KB`);
  const date = (ts: number) => new Date(ts * 1000).toLocaleDateString(locale(), { day: "numeric", month: "short", year: "numeric" });
  const ago = (ts: number) => {
    if (!ts) return t("не обновлялась", "never updated");
    const m = Math.round((Date.now() / 1000 - ts) / 60);
    return m < 60 ? t(`${m} мин назад`, `${m} min ago`) : m < 60 * 48 ? t(`${Math.round(m / 60)} ч назад`, `${Math.round(m / 60)} h ago`) : date(ts);
  };
  const subName = (id: string | null) => (id ? (st?.subs.find((s) => s.id === id)?.name ?? "") : t("вручную", "manual"));
  const groups = $derived.by(() => {
    if (!st) return [];
    const keys = [...st.subs.map((s) => s.id), null];
    return keys.map((k) => ({ key: k, items: st!.servers.filter((s) => s.sub === k) })).filter((g) => g.items.length);
  });
  const pingClass = (ms: number | null | undefined) => (ms == null ? "bad" : ms < 400 ? "good" : ms < 900 ? "mid" : "slow");
  const scopes: { value: TorScope; label: () => string; hint: () => string }[] = [
    { value: "list", label: () => t("Только список", "List only"), hint: () => t("через Xray идут домены из списка ниже, остальное — как обычно", "the domains below go through Xray, the rest as usual") },
    { value: "zapret", label: () => t("Списки zapret", "zapret lists"), hint: () => t("плюс все домены из списков zapret2 (YouTube, Discord и т. д.)", "plus every domain from the zapret2 lists (YouTube, Discord, etc.)") },
    { value: "all", label: () => t("Весь трафик", "All traffic"), hint: () => t("всё через Xray, кроме «не резать» и Worker; российские сайты Xray сам пустит напрямую", "everything through Xray except “do not split” and Worker; Xray itself sends Russian sites direct") },
  ];
</script>

<div class="xr fade-in">
  {#if st}
    {#if !st.available}
      <section class="card block"><div class="err mono">{t("В этой сборке нет Xray: соберите приложение заново (npm run sync-xray скачает его).", "This build has no Xray: rebuild the app (npm run sync-xray downloads it).")}</div></section>
    {/if}

    <SubTabs
      key="xray"
      bind:value={sub}
      tabs={[
        { id: "servers", label: "Servers", badge: running ? "on" : st.servers.length || null, title: t("Включение, подписки и серверы", "On/off, subscriptions and servers") },
        { id: "routing", label: "Routing", badge: st.scope !== "list" ? st.scope : null, title: t("Что идёт напрямую, что через сервер", "What goes direct and what through the server") },
        { id: "connection", label: "Connection", badge: st.fragment ? "split" : null, title: t("Порт, нарезка к серверу, журнал", "Port, splitting to the server, log") },
      ]} />
    {#if sub === "servers"}
    <section class="card block hero">
      <div class="prompt mono">{t("xray · свои серверы VLESS, VMess, Trojan, Shadowsocks", "xray · your own VLESS, VMess, Trojan, Shadowsocks servers")}</div>
      <PowerButton on={running} disabled={app.busy || !st.available || !st.servers.length} onclick={toggle} />
      <div class="state-line mono">
        {#if app.busy}<span class="muted">{t("подождите…", "please wait…")}</span>
        {:else if running}<span class="on">● SOCKS5/HTTP 127.0.0.1:{st.status.port}</span>
        {:else if !st.servers.length}<span class="faint">○ {t("добавьте сервер или подписку", "add a server or a subscription")}</span>
        {:else}<span class="faint">○ {t("выключен", "off")}</span>{/if}
      </div>
      {#if running}
        <div class="stats mono">
          <span>{t("сервер", "server")}: <b>{st.status.server}</b></span>
          <span>{st.routing.ru_direct ? t("RU — напрямую", "RU — direct") : t("всё через сервер", "all through the server")}</span>
        </div>
        <div class="actions"><button class="btn sm" onclick={() => copy(`127.0.0.1:${st!.status.port}`, t("Адрес скопирован", "Address copied"))}><Copy size={12} /> SOCKS5/HTTP</button></div>
      {/if}
      {#if st.status.error}<div class="err mono">{st.status.error}</div>{/if}
    </section>

    <section class="card block">
      <div class="label"><Link size={11} /> {t("добавить", "add")}</div>
      <textarea class="textarea" rows="3" spellcheck="false" placeholder={t("ссылка подписки (https://…), ссылки vless:// vmess:// trojan:// ss://, base64 или JSON-конфиг", "subscription URL (https://…), vless:// vmess:// trojan:// ss:// links, base64 or a JSON config")} bind:value={addText} disabled={adding}></textarea>
      <div class="actions">
        <span class="hint faint mono grow">{t("Ссылки и ключи хранятся только на этом ПК (settings.json). В журнале UUID скрыты.", "Links and keys stay on this PC only (settings.json). UUIDs are hidden in the log.")}</span>
        <button class="btn sm primary" disabled={adding || !addText.trim()} onclick={add}>{#if adding}<span class="spin"></span>{:else}<Plus size={12} />{/if} {t("Добавить", "Add")}</button>
      </div>
    </section>

    <More key="xray.catalog" title={t("бесплатные подписки", "free subscriptions")}>
      <div class="hint faint mono">
        {t(
          "Публичные серверы из коллекции igareck/vpn-configs-for-russia: их проверяют из России раз в несколько часов и убирают нерабочие. Чьи это серверы — неизвестно: не вводите через них пароли и банковские данные. Для личного надёжнее свой сервер.",
          "Public servers from the igareck/vpn-configs-for-russia collection: they are tested from Russia every few hours and dead ones are dropped. Nobody knows who runs them: don't enter passwords or bank details through them. Your own server is safer for anything personal.",
        )}
      </div>
      {#each XRAY_CATALOG as c (c.id)}
        <div class="sub mono">
          <span class="chip kind" title={c.kind === "black" ? t("чёрные списки — обычный интернет с блокировками", "blacklists — regular internet with blocks") : t("белые списки — мобильный оператор пускает только на разрешённые сайты", "whitelists — the mobile carrier only allows approved sites")}>{c.kind === "black" ? t("ЧС", "BL") : t("БС", "WL")}</span>
          <div class="grow">
            <div class="sname">{t(c.name[0], c.name[1])}</div>
            <div class="hint faint">{t(c.hint[0], c.hint[1])}</div>
          </div>
          {#if catalogAdded(c)}<span class="chip sage">{t("добавлена", "added")}</span>
          {:else}<button class="btn sm" disabled={!!catalogAdding || app.busy} onclick={() => addCatalog(c)}>{#if catalogAdding === c.id}<span class="spin"></span>{:else}<Plus size={12} />{/if} {t("Добавить", "Add")}</button>{/if}
        </div>
      {/each}
      <div class="hint faint mono">{t("ЧС — для обычного интернета с блокировками, БС — когда мобильный оператор пускает только на разрешённые сайты.", "BL (blacklists) — for regular internet with blocks; WL (whitelists) — for when a mobile carrier only allows approved sites.")}</div>
    </More>

    {#if st.subs.length}
      <section class="card block">
        <div class="row">
          <div class="label">{t("подписки", "subscriptions")}</div>
          <button class="btn sm ghost" disabled={!!updating} onclick={() => updateSub(null)}><RefreshCw size={12} /> {t("Обновить все", "Update all")}</button>
        </div>
        {#each st.subs as s (s.id)}
          {@const n = st.servers.filter((x) => x.sub === s.id).length}
          <div class="sub mono">
            <div class="grow">
              <div class="sname">{s.name} <span class="faint">· {n} {t("серв.", "srv")}</span></div>
              <div class="hint faint">
                {ago(s.updated)}
                {#if s.info.upload + s.info.download}· {gb(s.info.upload + s.info.download)}{s.info.total ? ` / ${gb(s.info.total)}` : ""}{/if}
                {#if s.info.expire}· {t("до", "until")} {date(s.info.expire)}{/if}
                {#if s.info.update_hours}· {t(`обновление раз в ${s.info.update_hours} ч`, `updates every ${s.info.update_hours} h`)}{/if}
              </div>
              {#if s.error}<div class="err">{s.error}</div>{/if}
            </div>
            <button class="btn sm ghost" title={t("Обновить", "Update")} disabled={!!updating} onclick={() => updateSub(s.id)}>{#if updating === s.id || updating === "*"}<span class="spin"></span>{:else}<RefreshCw size={12} />{/if}</button>
            <button class="btn sm ghost" title={t("Удалить", "Remove")} disabled={app.busy} onclick={() => removeSub(s.id, s.name)}><Trash2 size={12} /></button>
          </div>
        {/each}
      </section>
    {/if}

    {#if st.servers.length}
      <section class="card block">
        <div class="row">
          <div class="label">{t("серверы", "servers")} · {st.servers.length}</div>
          <div class="actions">
            <button class="btn sm" disabled={testing || speedRun || app.busy} onclick={test}>{#if testing}<span class="spin"></span>{:else}<Gauge size={12} />{/if} {t("Проверить задержку", "Test latency")}</button>
            <button class="btn sm" disabled={testing || app.busy} onclick={speed} title={t("Скачать файл через каждый сервер и замерить скорость", "Download a file through each server and measure the speed")}>{#if speedRun}<Square size={11} /> {t("Стоп", "Stop")}{:else}<Download size={12} /> {t("Скорость", "Speed")}{/if}</button>
          </div>
        </div>
        <button class="srv mono" class:on={st.selected === "auto"} disabled={app.busy} onclick={() => set({ selected: "auto" })}>
          <span class="dot"></span>
          <span class="nm">{t("Авто: самый быстрый", "Auto: the fastest")}</span>
          <span class="tr faint">{t("переключится сам, если сервер упадёт", "switches by itself if a server fails")}</span>
        </button>
        {#each groups as g (g.key ?? "manual")}
          <div class="grp mono faint">{subName(g.key)}</div>
          {#each g.items as s (s.id)}
            {@const p = st.pings[s.id]}
            {@const sp = st.speeds[s.id]}
            <div class="srvrow">
              <button class="srv mono" class:on={st.selected === s.id} disabled={app.busy} onclick={() => set({ selected: s.id })} title={p?.error ?? `${s.address}:${s.port}`}>
                <span class="dot"></span>
                <span class="nm">{s.name}</span>
                <span class="chip">{s.transport}</span>
                {#if sp}<span class="ms {speedClass(sp.mbps)}" title={sp.error ?? ""}>{sp.mbps != null ? `${sp.mbps} Mbps` : "—"}</span>
                {:else if speedRun && p?.ms != null}<span class="ms faint">…</span>{/if}
                {#if p}<span class="ms {pingClass(p.ms)}">{p.ms != null ? `${p.ms} ms` : "—"}</span>{/if}
              </button>
              {#if !s.sub}<button class="btn sm ghost" title={t("Удалить", "Remove")} disabled={app.busy} onclick={() => removeServer(s.id)}><Trash2 size={12} /></button>{/if}
            </div>
          {/each}
        {/each}
        <div class="hint faint mono">{t("Задержка — настоящий запрос через сервер (generate_204), а не ping. «—» — сервер не ответил; причина — при наведении.", "Latency is a real request through the server (generate_204), not a ping. “—” means no answer; hover for the reason.")}</div>
        <div class="hint faint mono">{t("Скорость — 8 секунд загрузки файла Cloudflare через сервер, по очереди: до 15 серверов, ответивших на проверку задержки, быстрые первыми. Пока идёт замер, канал занят.", "Speed — 8 seconds of downloading a Cloudflare file through each server, one at a time: up to 15 servers that passed the latency test, fastest first. The connection is busy while it runs.")}</div>
      </section>
    {/if}
    {:else if sub === "routing"}
    <section class="card block">
      <div class="label"><Route size={11} /> {t("маршрутизация", "routing")}</div>
      <div class="opt">
        <div>
          <div class="label sub2">{t("российские сайты — напрямую", "russian sites — direct")}</div>
          <div class="hint faint mono">{t("geosite:category-ru, .ru/.su/.рф и российские адреса (geoip:ru) идут мимо сервера: банки и Госуслуги видят российский IP. DNS для остальных — через сервер, без подмены провайдера.", "geosite:category-ru, .ru/.su/.рф and Russian addresses (geoip:ru) bypass the server: banks and Gosuslugi see a Russian IP. DNS for the rest goes through the server, free of ISP spoofing.")}</div>
        </div>
        <Switch checked={st.routing.ru_direct} disabled={app.busy} onchange={(v) => set({ routing: { ...st!.routing, ru_direct: v } })} />
      </div>
      <div class="opt">
        <div>
          <div class="label sub2">{t("блокировать рекламу", "block ads")}</div>
          <div class="hint faint mono">geosite:category-ads-all</div>
        </div>
        <Switch checked={st.routing.ads_block} disabled={app.busy} onchange={(v) => set({ routing: { ...st!.routing, ads_block: v } })} />
      </div>
      <div class="lists">
        <label class="field"><span class="k mono">{t("напрямую", "direct")}</span><textarea class="textarea" rows="3" spellcheck="false" placeholder="example.ru&#10;geosite:yandex" bind:value={routes.direct}></textarea></label>
        <label class="field"><span class="k mono">{t("через сервер", "through the server")}</span><textarea class="textarea" rows="3" spellcheck="false" placeholder="kinopoisk.ru&#10;geosite:youtube" bind:value={routes.proxy}></textarea></label>
        <label class="field"><span class="k mono">{t("блок", "block")}</span><textarea class="textarea" rows="3" spellcheck="false" placeholder="ads.example.com&#10;geoip:cn" bind:value={routes.block}></textarea></label>
      </div>
      <div class="actions">
        <span class="hint faint mono grow">{t("Домен (с поддоменами), geosite:тег, geoip:тег, IP или подсеть — по одному в строке. Порядок: блок → через сервер → напрямую → RU.", "A domain (with subdomains), geosite:tag, geoip:tag, IP or subnet — one per line. Order: block → through the server → direct → RU.")}</span>
        <button class="btn sm" disabled={app.busy || !routesDirty} onclick={saveRoutes}>{t("Сохранить", "Save")}</button>
      </div>
    </section>

    <section class="card block">
      <div class="row">
        <div>
          <div class="label"><Globe size={11} /> {t("сайты через xray", "sites through xray")}</div>
          <div class="hint faint mono">{t("прокси-обходчик отправит эти домены через Xray, пока он включён. Браузер должен ходить через прокси-обходчик (127.0.0.1:", "the bypass proxy sends these domains through Xray while it is on. The browser must use the bypass proxy (127.0.0.1:")}{st.proxy_port}).</div>
        </div>
        {#if st.proxy_running}<span class="chip sage">{t("прокси включён", "proxy on")}</span>{:else}<span class="chip">{t("прокси выключен", "proxy off")}</span>{/if}
      </div>
      <Segmented small options={scopes.map((x) => ({ value: x.value, label: x.label() }))} value={st.scope} disabled={app.busy} onchange={(v) => saveDomains(v)} />
      <div class="hint faint mono">{scopes.find((x) => x.value === st!.scope)?.hint()}</div>
      <textarea class="textarea" rows="3" spellcheck="false" placeholder="chatgpt.com&#10;instagram.com" bind:value={domainsText} disabled={app.busy}></textarea>
      <div class="actions"><span class="grow"></span><button class="btn sm" disabled={app.busy || domainsText === lines(st.domains)} onclick={() => saveDomains()}>{t("Сохранить", "Save")}</button></div>
      <div class="opt sep">
        <div>
          <div class="label sub2"><MonitorCog size={11} /> {t("системный прокси windows", "windows system proxy")}</div>
          <div class="hint faint mono">{t("Системным прокси становится прокси-обходчик, а Xray работает через него по режиму выше. Тот же переключатель, что на вкладках Proxy и Tor.", "The bypass proxy becomes the system proxy, and Xray works through it in the mode above. The same switch as on the Proxy and Tor tabs.")}</div>
        </div>
        <Switch checked={st.proxy_system} disabled={app.busy} onchange={setSystem} />
      </div>
    </section>
    {:else}
    <section class="card block">
      <div class="label">{t("подключение", "connection")}</div>
      <div class="opt">
        <div>
          <div class="label sub2">{t("нарезка clienthello к серверу", "split clienthello to the server")}</div>
          <div class="hint faint mono">{t("если сам сервер режут по SNI: первый пакет TLS уходит кусками (finalmask fragment). Для серверов, где нарезка уже задана в подписке, не меняется.", "if the server itself is cut by SNI: the first TLS packet goes in pieces (finalmask fragment). Servers that already set it in the subscription keep theirs.")}</div>
        </div>
        <Switch checked={st.fragment} disabled={app.busy} onchange={(v) => set({ fragment: v })} />
      </div>
      <div class="tip hint faint mono">
        {t(
          "Сервер за Cloudflare или на хостинге, который режут по адресу (соединение «замирает» после 16–20 КБ)? Нарезка тут не поможет — включите заодно Zapret2: он обрабатывает и соединение Xray к серверу. Нужно, чтобы сервер попал под его фильтры: ipset в режиме «Список» (в нём есть подсети Cloudflare) или домен сервера в своём списке (Zapret2 → Lists).",
          "Server behind Cloudflare or on a hosting cut by address (the connection freezes after 16–20 KB)? Splitting won't help — turn on Zapret2 as well: it also handles Xray's connection to the server. The server has to match its filters: ipset set to \"List\" (it includes Cloudflare subnets) or the server's domain in your own list (Zapret2 → Lists).",
        )}
      </div>
      <div class="actions">
        <label class="mono portl"><span class="k">{t("порт SOCKS5/HTTP", "SOCKS5/HTTP port")}</span>
          <input class="input port" type="number" min="1024" max="65535" bind:value={portText} disabled={app.busy} />
        </label>
        <span class="hint faint mono grow">{t("10808 обычно занят v2rayN — поэтому по умолчанию 10820.", "10808 is usually taken by v2rayN — hence 10820 by default.")}</span>
        <button class="btn sm" disabled={app.busy || portText === String(st.port)} onclick={() => set({ port: Number(portText) }, t("Порт сохранён", "Port saved"))}>{t("Сохранить", "Save")}</button>
      </div>
    </section>

    <details class="card block logbox" bind:open={showLog}>
      <summary class="mono"><ScrollText size={12} /> {t("журнал xray", "xray log")}{st.version ? ` · Xray ${st.version}` : ""}</summary>
      {#if log.length}<pre class="code mono">{log.join("\n")}</pre>{:else}<div class="hint faint mono">{t("пусто — Xray не запускался", "empty — Xray has not run")}</div>{/if}
    </details>
    {/if}
  {/if}
</div>

<style>
  .xr {
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
  .hero.block {
    gap: 8px;
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
  .row,
  .opt {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .opt.sep {
    border-top: 1px solid var(--border-soft);
    padding-top: 10px;
  }
  .label {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .hint {
    font-size: 11px;
    margin-top: 3px;
  }
  /* Совет под настройкой: отдельный абзац с полосой слева. */
  .tip {
    margin: 2px 0 10px;
    padding: 6px 10px;
    border-left: 2px solid var(--border);
    line-height: 1.45;
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
  .err {
    font-size: 11px;
    color: var(--danger-text);
    word-break: break-word;
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
    min-width: 0;
  }
  .sub {
    display: flex;
    align-items: center;
    gap: 6px;
    padding-top: 8px;
    border-top: 1px solid var(--border-soft);
    font-size: 12px;
  }
  .sname {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .grp {
    font-size: 11px;
    margin-top: 4px;
    text-transform: lowercase;
  }
  .srvrow {
    display: flex;
    gap: 4px;
    align-items: center;
  }
  .srv {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    font-size: 12px;
    text-align: left;
    color: var(--muted);
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .srv:hover:not(:disabled) {
    border-color: var(--border);
    color: var(--text);
  }
  .srv.on {
    color: var(--text);
    border-color: var(--accent);
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    border: 1px solid var(--border);
    flex: none;
  }
  .srv.on .dot {
    background: var(--accent);
    border-color: var(--accent);
  }
  .nm {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .tr {
    font-size: 11px;
  }
  .ms {
    font-size: 11px;
    min-width: 56px;
    text-align: right;
  }
  .ms.good {
    color: var(--sage);
  }
  .ms.mid {
    color: var(--text);
  }
  .ms.slow {
    color: var(--warn);
  }
  .ms.bad {
    color: var(--danger-text);
  }
  .kind {
    min-width: 28px;
    text-align: center;
  }
  .lists {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 8px;
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
  .spin {
    width: 10px;
    height: 10px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    display: inline-block;
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
