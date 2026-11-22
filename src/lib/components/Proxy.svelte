<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, type ProxyConfig, type ProxyStatus } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import Segmented from "./Segmented.svelte";
  import Switch from "./Switch.svelte";
  import { Power, Copy, Wifi, KeyRound, ShieldAlert } from "@lucide/svelte";

  let st = $state<ProxyStatus | null>(null);
  let cfg = $state<ProxyConfig>({ port: 8881, method: "disorder", doh: true, system: true, lan: false, user: "", pass: "" });
  let lanIps = $state<string[]>([]);
  let showPass = $state(false);
  const running = $derived(!!st?.stats.running);

  async function load() {
    try {
      st = await api.proxyStatus();
      cfg = { ...st.config };
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
  <section class="card block">
    <div class="row">
      <div>
        <div class="label">{t("прокси-обходчик", "bypass proxy")}</div>
        <div class="hint faint mono">{t("без прав администратора и без драйвера", "no admin rights, no driver")}</div>
      </div>
      <button class="btn" class:primary={!running} class:danger={running} disabled={app.busy} onclick={running ? stop : start}>
        <Power size={13} />
        {running ? t("Выключить", "Turn off") : t("Включить", "Turn on")}
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
        "Локальный прокси (HTTP и SOCKS5 на одном порту) режет TLS ClientHello так, что имя сайта не видно простым DPI. Работает только для HTTPS через прокси; UDP, QUIC и голос Discord не обходит — для них нужен zapret2.",
        "A local proxy (HTTP and SOCKS5 on one port) splits the TLS ClientHello so simple DPI cannot see the site name. Works for HTTPS through the proxy only; UDP, QUIC and Discord voice need zapret2.",
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
          { value: "disorder", label: "Disorder" },
          { value: "split", label: "Split" },
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
    font-size: 11.5px;
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
    font-size: 10.5px;
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
