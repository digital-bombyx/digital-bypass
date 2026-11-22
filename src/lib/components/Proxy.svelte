<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, type ProxyConfig, type ProxyStatus } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import Segmented from "./Segmented.svelte";
  import Switch from "./Switch.svelte";
  import { Power, Copy } from "@lucide/svelte";

  let st = $state<ProxyStatus | null>(null);
  let cfg = $state<ProxyConfig>({ port: 8881, method: "disorder", doh: true, system: true });
  const running = $derived(!!st?.stats.running);

  async function load() {
    try {
      st = await api.proxyStatus();
      cfg = { ...st.config };
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
  /** Настройки меняются на ходу: работающий прокси перезапускается с новыми. */
  async function change(patch: Partial<ProxyConfig>) {
    cfg = { ...cfg, ...patch };
    if (running) await start();
  }
  const addr = $derived(`127.0.0.1:${cfg.port}`);
</script>

<div class="proxy fade-in">
  <section class="card block">
    <div class="row">
      <div>
        <div class="label">{t("прокси-обходчик", "bypass proxy")}</div>
        <div class="hint faint mono">{t("без прав администратора и без драйвера", "no admin rights, no driver")}</div>
      </div>
      <button class="btn" class:primary={!running} class:danger={running} disabled={app.busy} onclick={running ? stop : start}>
        <Power size={13} />
        {running ? t("выключить", "turn off") : t("включить", "turn on")}
      </button>
    </div>
    {#if st && running}
      <div class="stats mono">
        <span><b>{st.stats.active}</b> {t("активных", "active")}</span>
        <span><b>{st.stats.total}</b> {t("всего", "total")}</span>
        <span><b>{st.stats.failed}</b> {t("ошибок", "failed")}</span>
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
        "Локальный HTTP-прокси режет TLS ClientHello так, что имя сайта не видно простым DPI. Работает только для HTTPS через прокси; UDP, QUIC и голос Discord не обходит — для них нужен zapret2.",
        "A local HTTP proxy splits the TLS ClientHello so simple DPI cannot see the site name. Works for HTTPS through the proxy only; UDP, QUIC and Discord voice need zapret2.",
      )}
    </p>
  </section>

  <section class="card opts">
    <div class="opt">
      <div>
        <div class="label">{t("способ", "method")}</div>
        <div class="hint faint mono">
          {cfg.method === "disorder"
            ? t("первая часть с TTL=1, поток не по порядку", "first part with TTL=1, out-of-order stream")
            : t("части отдельными сегментами", "parts as separate segments")}
        </div>
      </div>
      <Segmented
        small
        disabled={app.busy}
        value={cfg.method}
        onchange={(m) => change({ method: m })}
        options={[
          { value: "disorder", label: "disorder" },
          { value: "split", label: "split" },
        ]} />
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
        <div class="label">DoH</div>
        <div class="hint faint mono">{t("адреса сайтов через Cloudflare/Google — мимо подмены DNS", "resolve via Cloudflare/Google — past DNS spoofing")}</div>
      </div>
      <Switch checked={cfg.doh} disabled={app.busy} onchange={(v) => change({ doh: v })} />
    </div>
    <div class="opt">
      <div>
        <div class="label">{t("порт", "port")}</div>
        <div class="hint faint mono">{t("для ручной настройки браузера", "for manual browser setup")}</div>
      </div>
      <input class="input port" type="number" min="1024" max="65535" bind:value={cfg.port} disabled={app.busy || running} />
    </div>
  </section>
</div>

<style>
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
    font-size: 10.5px;
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
    font-size: 11px;
    color: var(--muted);
  }
  .stats b {
    color: var(--text);
  }
  .addr {
    margin-left: auto;
  }
  .err {
    font-size: 10.5px;
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
  .port {
    width: 96px;
  }
</style>
