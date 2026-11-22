<script lang="ts">
  import { onMount } from "svelte";
  import { api, type DnsInfo, type DnsPreset, type DnsAdapter, type StubStatus } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { t, i18n } from "$lib/i18n.svelte";
  import Switch from "./Switch.svelte";
  import { RefreshCw, Eraser, Undo2, Check, Lock, Cable, Wifi, Network, ShieldCheck } from "@lucide/svelte";

  let info = $state<DnsInfo | null>(null);
  let presets = $state<DnsPreset[]>([]);
  let index = $state<number | null>(null);
  let preset = $state<string>("cloudflare");
  let v4 = $state(["", ""]);
  let v6 = $state(["", ""]);
  let useV4 = $state(true);
  let useV6 = $state(false);
  let doh = $state(false);
  let template = $state("");
  let fallback = $state(false);
  let stub = $state<StubStatus | null>(null);
  let stubFallback = $state(true);

  const adapter = $derived(info?.adapters.find((a) => a.index === index) ?? null);
  const current = $derived(
    adapter
      ? [
          { fam: "IPv4", list: adapter.dns_v4, manual: adapter.static_v4 },
          { fam: "IPv6", list: adapter.dns_v6, manual: adapter.static_v6 },
        ]
      : [],
  );
  const admin = $derived(!!app.ov?.admin);
  const tmplFor = (ip: string) => info?.templates.find((x) => x.server === ip);

  function choose(p: DnsPreset | null) {
    preset = p?.id ?? "custom";
    if (!p) return;
    v4 = [p.v4[0] ?? "", p.v4[1] ?? ""];
    v6 = [p.v6[0] ?? "", p.v6[1] ?? ""];
    template = p.doh ?? "";
    if (!p.doh) doh = false;
  }

  async function load() {
    try {
      const [i, p, sb] = await Promise.all([api.dnsInfo(), presets.length ? Promise.resolve(presets) : api.dnsPresets(), api.dnsStubStatus()]);
      info = i;
      stub = sb;
      presets = p;
      if (index === null || !i.adapters.some((a) => a.index === index)) {
        index = (i.adapters.find((a) => a.internet) ?? i.adapters.find((a) => a.up && a.gateway) ?? i.adapters.find((a) => a.up) ?? i.adapters[0])?.index ?? null;
      }
      if (!v4[0] && !v6[0] && preset !== "custom") choose(p.find((x) => x.id === preset) ?? p[0] ?? null);
    } catch (e) {
      toast(String(e));
    }
  }
  onMount(load);

  /** Ручная правка адреса — это уже «свой» набор. */
  function edited() {
    preset = "custom";
  }

  async function apply() {
    if (index === null) return;
    const req = {
      index,
      v4: useV4 ? v4.map((x) => x.trim()).filter(Boolean) : null,
      v6: useV6 ? v6.map((x) => x.trim()).filter(Boolean) : null,
      doh_template: doh ? template.trim() : null,
      doh_fallback: fallback,
    };
    const r = await act(() => api.dnsApply(req), t("DNS применён, кэш сброшен", "DNS applied, cache flushed"));
    if (r) info = r;
  }
  async function reset() {
    if (index === null || !adapter) return;
    const fams = [useV4 && "IPv4", useV6 && "IPv6"].filter(Boolean).join(" + ");
    if (!confirm(t(`Вернуть автоматический DNS (DHCP) для ${fams} на «${adapter.name}»?`, `Revert ${fams} DNS to automatic (DHCP) on "${adapter.name}"?`))) return;
    const r = await act(() => api.dnsReset(index!, useV4, useV6), t("DNS снова автоматический", "DNS is automatic again"));
    if (r) info = r;
  }
  async function flush() {
    await act(() => api.dnsFlush(), t("Кэш DNS сброшен", "DNS cache flushed"));
  }

  /** Резолвер берёт шаблон и адреса выбранного сервера; адреса — bootstrap (без системного DNS). */
  const stubTemplate = $derived(template.trim() || presets.find((x) => x.id === preset)?.doh || "");
  async function stubEnable() {
    if (index === null) return;
    const boot = [...v4, ...v6].map((x) => x.trim()).filter(Boolean);
    const r = await act(() => api.dnsStubEnable(index!, stubTemplate, boot, stubFallback), t("Резолвер включён", "Resolver enabled"));
    if (r) {
      stub = r;
      info = await api.dnsInfo();
    }
  }
  async function stubDisable() {
    const r = await act(() => api.dnsStubDisable(), t("DNS адаптера возвращён", "Adapter DNS restored"));
    if (r) {
      stub = r;
      info = await api.dnsInfo();
    }
  }

  const kindIcon = (a: DnsAdapter) => (a.kind === "wifi" ? Wifi : a.kind === "ethernet" ? Cable : Network);
  const canApply = $derived(
    admin && !app.busy && adapter !== null && (useV4 || useV6) && (!useV4 || !!v4[0].trim() || !!v4[1].trim()) && (!useV6 || !!v6[0].trim() || !!v6[1].trim()) && (!doh || template.trim().startsWith("https://")),
  );
</script>

<div class="dns fade-in">
  {#if info}
    <!-- Адаптер и его текущие DNS -->
    <section class="card block">
      <div class="head">
        <span class="label">{t("адаптер", "adapter")}</span>
        <button class="btn sm ghost" disabled={app.busy} onclick={load} title={t("Обновить", "Refresh")}><RefreshCw size={12} /></button>
      </div>
      {#if info.adapters.length}
        <select class="input" bind:value={index}>
          {#each info.adapters as a (a.index)}
            <option value={a.index}>{a.name}{a.up ? (a.internet ? t(" — интернет", " — internet") : "") : t(" — отключён", " — down")}</option>
          {/each}
        </select>
      {:else}
        <div class="faint mono small">{t("сетевые адаптеры не найдены", "no network adapters found")}</div>
      {/if}

      {#if adapter}
        {@const Icon = kindIcon(adapter)}
        <div class="meta mono">
          <Icon size={13} />
          <span class="desc" title={adapter.description}>{adapter.description}</span>
          <span class="chip" class:sage={adapter.up}>{adapter.up ? "up" : "down"}</span>
        </div>
        {#if adapter.addresses.length}
          <div class="kv mono"><span class="k">ip</span><span class="v">{adapter.addresses.join(", ")}</span></div>
        {/if}
        {#each current as c (c.fam)}
          <div class="kv mono">
            <span class="k">{c.fam}</span>
            <span class="v">
              {#each c.list as s (s)}
                <span class="srv">{s}{#if adapter.doh.includes(s)}<span class="doh" title={tmplFor(s)?.template ?? "DoH"}><Lock size={10} /> doh</span>{/if}</span>
              {:else}
                <span class="faint">—</span>
              {/each}
            </span>
            <span class="chip" class:amber={c.manual}>{c.manual ? t("вручную", "manual") : "dhcp"}</span>
          </div>
        {/each}
      {/if}
    </section>

    <!-- Серверы -->
    <section class="card block">
      <div class="label">{t("серверы", "servers")}</div>
      <div class="presets">
        {#each presets as p (p.id)}
          <button class="preset" class:sel={preset === p.id} onclick={() => choose(p)} title={i18n.lang === "en" ? p.note_en : p.note_ru}>
            <span class="pn">{p.name}</span>
            <span class="pv mono">{p.v4[0]}</span>
          </button>
        {/each}
        <button class="preset" class:sel={preset === "custom"} onclick={() => choose(null)}>
          <span class="pn">{t("Свой", "Custom")}</span>
          <span class="pv mono">x.x.x.x</span>
        </button>
      </div>
      {#if preset !== "custom"}
        {@const p = presets.find((x) => x.id === preset)}
        {#if p}<div class="note faint mono">{i18n.lang === "en" ? p.note_en : p.note_ru}</div>{/if}
      {/if}

      <div class="fam">
        <label class="famhead"><input type="checkbox" bind:checked={useV4} /> <span class="mono">IPv4</span></label>
        <div class="pair">
          <input class="input" placeholder={t("основной", "primary")} disabled={!useV4} bind:value={v4[0]} oninput={edited} />
          <input class="input" placeholder={t("запасной", "secondary")} disabled={!useV4} bind:value={v4[1]} oninput={edited} />
        </div>
      </div>
      <div class="fam">
        <label class="famhead"><input type="checkbox" bind:checked={useV6} /> <span class="mono">IPv6</span></label>
        <div class="pair">
          <input class="input" placeholder={t("основной", "primary")} disabled={!useV6} bind:value={v6[0]} oninput={edited} />
          <input class="input" placeholder={t("запасной", "secondary")} disabled={!useV6} bind:value={v6[1]} oninput={edited} />
        </div>
      </div>
    </section>

    <!-- DoH -->
    <section class="card block">
      <div class="row">
        <div>
          <div class="label">DNS-over-HTTPS</div>
          <div class="hint faint mono">
            {info.doh_supported
              ? t("шаблон netsh dns encryption + флаг на адаптере", "netsh dns encryption template + adapter flag")
              : t("недоступно: нужна Windows 11", "unavailable: Windows 11 required")}
          </div>
        </div>
        <Switch checked={doh} disabled={!info.doh_supported} onchange={(v) => (doh = v)} />
      </div>
      {#if doh}
        <input class="input" placeholder="https://…/dns-query" bind:value={template} oninput={edited} />
        <label class="check mono">
          <input type="checkbox" bind:checked={fallback} />
          {t("разрешить откат на обычный DNS, если DoH недоступен", "allow fallback to plain DNS if DoH is unreachable")}
        </label>
      {/if}
    </section>

    <div class="actions">
      <button class="btn" disabled={app.busy} onclick={flush} title="ipconfig /flushdns"><Eraser size={13} /> {t("Сброс кэша", "Flush cache")}</button>
      <span class="grow"></span>
      <button class="btn" disabled={app.busy || !admin || !adapter || (!useV4 && !useV6)} onclick={reset}><Undo2 size={13} /> DHCP</button>
      <button class="btn primary" disabled={!canApply} onclick={apply}><Check size={13} /> {t("Применить", "Apply")}</button>
    </div>
    {#if !admin}
      <div class="faint mono small">{t("Смена DNS требует прав администратора.", "Changing DNS requires administrator rights.")}</div>
    {/if}

    <!-- Локальный DoH-резолвер -->
    <section class="card block">
      <div class="row">
        <div>
          <div class="label">{t("локальный DoH-резолвер", "local DoH resolver")}</div>
          <div class="hint faint mono">{t("шифрованный DNS на Windows 10 и 11, слушает 127.0.0.x:53", "encrypted DNS on Windows 10 and 11, listens on 127.0.0.x:53")}</div>
        </div>
        {#if stub?.running}<span class="chip sage"><ShieldCheck size={11} /> {stub.stats?.addr}</span>{/if}
      </div>
      {#if stub?.config}
        <div class="kv2 mono">
          <span class="k">{t("адаптер", "adapter")}</span><span>{stub.config.name}</span>
          <span class="k">{t("сервер", "server")}</span><span class="wrap">{stub.config.template}</span>
          {#if stub.stats}
            <span class="k">{t("запросы", "queries")}</span>
            <span>{stub.stats.queries} · {t("кэш", "cache")} {stub.stats.cached} · {t("ошибки", "errors")} {stub.stats.errors}</span>
          {/if}
          {#if stub.config.fallback}<span class="k">{t("резерв", "fallback")}</span><span>{stub.config.fallback}</span>{/if}
        </div>
        {#if stub.stats?.last_error}<div class="err mono">{stub.stats.last_error}</div>{/if}
        {#if !stub.running}
          <div class="err mono">{t("Резолвер не запущен, хотя прописан на адаптере — выключите и включите снова.", "The resolver is not running but is set on the adapter — turn it off and on again.")}</div>
        {/if}
        <div class="actions">
          <span class="grow"></span>
          <button class="btn danger" disabled={app.busy || !admin} onclick={stubDisable}><Undo2 size={13} /> {t("Выключить и вернуть DNS", "Turn off and restore DNS")}</button>
        </div>
      {:else}
        <p class="muted text">
          {t(
            "Приложение само отвечает на DNS-запросы и пересылает их выбранному серверу по HTTPS. Пока оно запущено (и в трее), провайдер не видит и не подменяет DNS. При выходе прежний DNS адаптера возвращается.",
            "The app answers DNS queries itself and forwards them to the chosen server over HTTPS. While it runs (also in the tray), the ISP cannot see or spoof DNS. On exit the adapter's previous DNS is restored.",
          )}
        </p>
        <div class="kv2 mono">
          <span class="k">{t("сервер", "server")}</span><span class="wrap">{stubTemplate || t("выберите сервер с DoH", "pick a server with DoH")}</span>
        </div>
        <label class="check mono">
          <input type="checkbox" bind:checked={stubFallback} />
          {t("резервный обычный DNS: если приложение закрыто, интернет не пропадёт", "plain DNS fallback: internet keeps working if the app is closed")}
        </label>
        <div class="actions">
          <span class="grow"></span>
          <button class="btn primary" disabled={app.busy || !admin || !adapter || !stubTemplate.startsWith("https://")} onclick={stubEnable}>
            <ShieldCheck size={13} /> {t("Включить на адаптере", "Enable on adapter")}
          </button>
        </div>
      {/if}
    </section>
  {/if}
</div>

<style>
  .dns {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .block {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .head,
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }
  select.input {
    cursor: pointer;
    font-family: var(--sans);
    font-size: 12.5px;
  }
  select.input option {
    background: var(--panel);
    color: var(--text);
  }
  .meta {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    color: var(--muted);
  }
  .desc {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .kv {
    display: grid;
    grid-template-columns: 38px 1fr auto;
    align-items: start;
    gap: 8px;
    font-size: 11.5px;
    padding-top: 6px;
    border-top: 1px solid var(--border-soft);
  }
  .k {
    color: var(--faint);
    line-height: 22px;
  }
  .v {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 12px;
    line-height: 22px;
    user-select: text;
    min-width: 0;
    word-break: break-all;
  }
  .srv {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .doh {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    font-size: 9.5px;
    color: var(--ok);
    text-transform: uppercase;
  }
  .presets {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(118px, 1fr));
    gap: 6px;
  }
  .preset {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
    padding: 7px 9px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg);
    color: var(--text);
    cursor: pointer;
    text-align: left;
    transition: border-color 0.12s, background 0.12s;
  }
  .preset:hover {
    border-color: var(--border-strong);
  }
  .preset.sel {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .pn {
    font-size: 12px;
    font-weight: 600;
  }
  .pv {
    font-size: 10px;
    color: var(--muted);
  }
  .note {
    font-size: 10.5px;
  }
  .fam {
    display: grid;
    grid-template-columns: 64px 1fr;
    align-items: center;
    gap: 8px;
  }
  .famhead {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    cursor: pointer;
  }
  .pair {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
  }
  .input:disabled {
    opacity: 0.4;
  }
  .hint {
    font-size: 10.5px;
    margin-top: 3px;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    color: var(--muted);
    cursor: pointer;
  }
  input[type="checkbox"] {
    accent-color: var(--accent);
    width: 14px;
    height: 14px;
    margin: 0;
  }
  .actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .grow {
    flex: 1;
  }
  .small {
    font-size: 10.5px;
  }
  .text {
    margin: 0;
    font-size: 12px;
    line-height: 1.5;
  }
  .kv2 {
    display: grid;
    grid-template-columns: 74px 1fr;
    gap: 4px 8px;
    font-size: 11.5px;
  }
  .wrap {
    word-break: break-all;
    user-select: text;
  }
  .err {
    font-size: 10.5px;
    color: var(--danger-text);
    word-break: break-all;
  }
</style>
