<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, type TgConfig, type TgStatus } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { TG_WORKER_CODE } from "$lib/tgWorker";
  import Switch from "./Switch.svelte";
  import { Power, Copy, Send, RefreshCw, Cloud, Eye, EyeOff } from "@lucide/svelte";

  let st = $state<TgStatus | null>(null);
  let cfg = $state<TgConfig | null>(null);
  let text = $state({ dc_ip: "", cf_domains: "", cf_workers: "" });
  let showSecret = $state(false);
  let showWorker = $state(false);
  const running = $derived(!!st?.stats.running);

  const lines = (v: string[]) => v.join("\n");
  const fromLines = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

  async function load() {
    try {
      st = await api.tgStatus();
      cfg = { ...st.config };
      text = { dc_ip: lines(cfg.dc_ip), cf_domains: lines(cfg.cf_domains), cf_workers: lines(cfg.cf_workers) };
    } catch (e) {
      toast(String(e));
    }
  }
  onMount(() => {
    load();
    const id = setInterval(async () => {
      if (running) st = await api.tgStatus().catch(() => st);
    }, 2000);
    const un = on("tg-changed", load);
    return () => {
      clearInterval(id);
      un.then((f) => f());
    };
  });

  async function toggle() {
    if (!cfg) return;
    const r = running
      ? await act(() => api.tgStop(), t("Telegram-прокси выключен", "Telegram proxy is off"))
      : await act(() => api.tgStart({ ...cfg!, port: Number(cfg!.port) }), t("Telegram-прокси включён", "Telegram proxy is on"));
    if (r) st = r;
  }
  async function save(patch: Partial<TgConfig>) {
    if (!cfg) return;
    cfg = { ...cfg, ...patch };
    const r = await act(() => api.tgSetConfig({ ...cfg!, port: Number(cfg!.port) }));
    if (r) {
      st = r;
      cfg = { ...r.config };
    }
  }
  function saveLists() {
    save({ dc_ip: fromLines(text.dc_ip), cf_domains: fromLines(text.cf_domains), cf_workers: fromLines(text.cf_workers) });
  }
  const listsDirty = $derived(
    !!cfg && (text.dc_ip !== lines(cfg.dc_ip) || text.cf_domains !== lines(cfg.cf_domains) || text.cf_workers !== lines(cfg.cf_workers)),
  );
  async function regen() {
    if (!confirm(t("Создать новый секрет? Старая ссылка в Telegram перестанет работать.", "Create a new secret? The old link in Telegram will stop working."))) return;
    const r = await act(() => api.tgRegenSecret(), t("Новый секрет создан", "New secret created"));
    if (r) {
      st = r;
      cfg = { ...r.config };
    }
  }
  const copy = (s: string, msg: string) => navigator.clipboard?.writeText(s).then(() => toast(msg, "ok"));
  const mb = (n: number) => (n < 1024 * 1024 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);
</script>

<div class="tg fade-in">
  {#if st && cfg}
    <section class="card block">
      <div class="row">
        <div>
          <div class="label">{t("telegram-прокси", "telegram proxy")}</div>
          <div class="hint faint mono">{t("MTProto → WebSocket к Telegram; для Telegram Desktop", "MTProto → WebSocket to Telegram; for Telegram Desktop")}</div>
        </div>
        <button class="btn" class:primary={!running} class:danger={running} disabled={app.busy} onclick={toggle}>
          <Power size={13} />
          {running ? t("Выключить", "Turn off") : t("Включить", "Turn on")}
        </button>
      </div>
      {#if running}
        <div class="stats mono">
          <span><b>{st.stats.active}</b> {t("активных", "active")}</span>
          <span><b>{st.stats.total}</b> {t("всего", "total")}</span>
          <span title={t("прямой WS / свой Worker / CF-прокси / TCP", "direct WS / own Worker / CF proxy / TCP")}>
            WS <b>{st.stats.ws}</b> · Worker <b>{st.stats.worker}</b> · CF <b>{st.stats.cf}</b> · TCP <b>{st.stats.tcp}</b>
          </span>
          <span>↑ <b>{mb(st.stats.bytes_up)}</b> ↓ <b>{mb(st.stats.bytes_down)}</b></span>
          {#if st.stats.bad}<span class="warn">{t("неверный секрет", "wrong secret")}: <b>{st.stats.bad}</b></span>{/if}
        </div>
        {#if st.stats.last_error}<div class="err mono">{st.stats.last_error}</div>{/if}
      {/if}
      <p class="muted text">
        {t(
          "Telegram Desktop подключается к локальному прокси, а тот ведёт трафик через WebSocket к веб-адресам Telegram, а если они недоступны — через свой Worker или CF-прокси (домены за Cloudflare). Сообщения остаются зашифрованными MTProto: посредники их не видят. Порт tg-ws-proxy (Flowseal).",
          "Telegram Desktop connects to a local proxy that carries traffic over WebSocket to Telegram's web endpoints, or, if they are unreachable, through your own Worker or a CF proxy (domains behind Cloudflare). Messages stay MTProto-encrypted: intermediaries cannot read them. A port of tg-ws-proxy (Flowseal).",
        )}
      </p>
    </section>

    <section class="card block">
      <div class="label">{t("подключение telegram", "connect telegram")}</div>
      <div class="actions">
        <button class="btn primary" onclick={() => act(() => api.tgOpenLink())}><Send size={13} /> {t("Открыть в Telegram", "Open in Telegram")}</button>
        <button class="btn" onclick={() => copy(st!.link, t("Ссылка скопирована", "Link copied"))}><Copy size={13} /> {t("Скопировать ссылку", "Copy link")}</button>
      </div>
      <div class="kv mono">
        <span class="k">{t("тип", "type")}</span><span>MTProto</span>
        <span class="k">{t("сервер", "server")}</span><span>127.0.0.1</span>
        <span class="k">{t("порт", "port")}</span>
        <span><input class="input port" type="number" min="1024" max="65535" bind:value={cfg.port} onchange={() => save({ port: Number(cfg!.port) })} disabled={app.busy} /></span>
        <span class="k">{t("секрет", "secret")}</span>
        <span class="secret">
          <span class="val">{showSecret ? `dd${cfg.secret}` : "dd" + "•".repeat(32)}</span>
          <button class="btn sm ghost" title={t("Показать", "Show")} onclick={() => (showSecret = !showSecret)}>
            {#if showSecret}<EyeOff size={12} />{:else}<Eye size={12} />{/if}
          </button>
          <button class="btn sm ghost" title={t("Скопировать", "Copy")} onclick={() => copy(`dd${cfg!.secret}`, t("Секрет скопирован", "Secret copied"))}><Copy size={12} /></button>
          <button class="btn sm ghost" title={t("Новый секрет", "New secret")} disabled={app.busy} onclick={regen}><RefreshCw size={12} /></button>
        </span>
      </div>
      <div class="hint faint mono">
        {t(
          "Вручную: Telegram → Настройки → Продвинутые настройки → Тип подключения → Прокси → MTProto. Если не грузятся фото и видео — оставьте в «DC → IP» только 4:149.154.167.220.",
          "Manually: Telegram → Settings → Advanced → Connection type → Proxy → MTProto. If photos and videos do not load, keep only 4:149.154.167.220 in \"DC → IP\".",
        )}
      </div>
    </section>

    <section class="card opts">
      <div class="opt">
        <div>
          <div class="label">{t("нарезка clienthello", "split clienthello")}</div>
          <div class="hint faint mono">{t("TLS к Telegram и Cloudflare — с нарезкой, как в прокси-обходчике; без неё у многих провайдеров не работает", "TLS to Telegram and Cloudflare with a split hello, as in the bypass proxy; many ISPs need it")}</div>
        </div>
        <Switch checked={cfg.fragment} disabled={app.busy} onchange={(v) => save({ fragment: v })} />
      </div>
      <div class="opt">
        <div>
          <div class="label">{t("cf-прокси", "cf proxy")}</div>
          <div class="hint faint mono">{t("запасной путь через домены за Cloudflare", "fallback through domains behind Cloudflare")}</div>
        </div>
        <Switch checked={cfg.cf_proxy} disabled={app.busy} onchange={(v) => save({ cf_proxy: v })} />
      </div>
    </section>

    <section class="card block">
      <div class="label"><Cloud size={11} /> {t("маршруты", "routes")}</div>
      <div class="lists">
        <label class="field">
          <span class="k mono">DC → IP {t("(прямой WebSocket)", "(direct WebSocket)")}</span>
          <textarea class="textarea" rows="4" spellcheck="false" placeholder="2:149.154.167.220" bind:value={text.dc_ip}></textarea>
        </label>
        <label class="field">
          <span class="k mono">{t("свои Worker'ы", "own Workers")}</span>
          <textarea class="textarea" rows="4" spellcheck="false" placeholder="name.account.workers.dev" bind:value={text.cf_workers}></textarea>
        </label>
        <label class="field">
          <span class="k mono">{t("свои CF-домены", "own CF domains")}</span>
          <textarea class="textarea" rows="4" spellcheck="false" placeholder={t(`пусто — встроенные (${st.default_cf.length})`, `empty — built-in (${st.default_cf.length})`)} bind:value={text.cf_domains}></textarea>
        </label>
      </div>
      <div class="actions">
        <span class="hint faint mono grow">
          {t("Порядок: прямой WebSocket → свой Worker → CF-прокси → TCP к дата-центру. Встроенные CF-домены могут перестать работать — тогда помогут свои.", "Order: direct WebSocket → own Worker → CF proxy → TCP to the data center. Built-in CF domains may stop working — then your own help.")}
        </span>
        <button class="btn sm" disabled={app.busy || !listsDirty} onclick={saveLists}>{t("Сохранить", "Save")}</button>
      </div>
      <details class="how" bind:open={showWorker}>
        <summary class="mono">{t("Как сделать свой Worker (бесплатно)", "How to make your own Worker (free)")}</summary>
        <ol class="text">
          <li>{t("Войдите в Cloudflare (dash.cloudflare.com), подтвердите почту.", "Sign in to Cloudflare (dash.cloudflare.com) and confirm your email.")}</li>
          <li>{t("Compute → Workers & Pages → Create application → Start with Hello World! → Deploy.", "Compute → Workers & Pages → Create application → Start with Hello World! → Deploy.")}</li>
          <li>{t("Edit code → вставьте код ниже → Deploy.", "Edit code → paste the code below → Deploy.")}</li>
          <li>{t("Скопируйте домен Worker'а (…workers.dev) в поле «свои Worker'ы».", "Copy the Worker domain (…workers.dev) into \"own Workers\".")}</li>
          <li>{t("Если панель Cloudflare не открывается — добавьте cloudflare.com, cloudflare.dev и workers.dev в список обхода zapret2.", "If the Cloudflare dashboard does not load, add cloudflare.com, cloudflare.dev and workers.dev to the zapret2 bypass list.")}</li>
        </ol>
        <div class="code-head">
          <span class="k mono">worker.js · tg-ws-proxy (MIT)</span>
          <button class="btn sm" onclick={() => copy(TG_WORKER_CODE, t("Код Worker'а скопирован", "Worker code copied"))}><Copy size={12} /> {t("Скопировать код", "Copy code")}</button>
        </div>
        <pre class="code mono">{TG_WORKER_CODE}</pre>
      </details>
    </section>
  {/if}
</div>

<style>
  .tg {
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
    font-size: 12.5px;
    line-height: 1.55;
  }
  .stats {
    display: flex;
    flex-wrap: wrap;
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
  }
  .actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .grow {
    flex: 1;
  }
  .kv {
    display: grid;
    grid-template-columns: 80px 1fr;
    gap: 6px 10px;
    align-items: center;
    font-size: 12px;
  }
  .k {
    color: var(--muted);
    font-size: 11.5px;
  }
  .port {
    width: 96px;
    height: 28px;
  }
  .secret {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
  }
  .val {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    user-select: text;
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
  .lists {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 8px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .how summary {
    cursor: pointer;
    font-size: 12px;
    color: var(--accent);
  }
  .how ol {
    padding-left: 20px;
    margin: 8px 0;
  }
  .code-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 6px;
  }
  .code {
    margin: 6px 0 0;
    padding: 10px 12px;
    max-height: 260px;
    overflow: auto;
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-sm);
    font-size: 11px;
    color: var(--muted);
    user-select: text;
  }
</style>
