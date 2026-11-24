<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, isTauri, type Status, type Modules } from "$lib/api";
  import { app, refresh, toast, act } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import TitleBar from "$lib/components/TitleBar.svelte";
  import Zapret2 from "$lib/components/Zapret2.svelte";
  import Hosts from "$lib/components/Hosts.svelte";
  import Settings from "$lib/components/Settings.svelte";
  import Dns from "$lib/components/Dns.svelte";
  import Proxy from "$lib/components/Proxy.svelte";
  import Diag from "$lib/components/Diag.svelte";
  import Telegram from "$lib/components/Telegram.svelte";
  import Tor from "$lib/components/Tor.svelte";
  import Xray from "$lib/components/Xray.svelte";
  import { Power, Globe, Network, Settings2, ShieldAlert, Waypoints, Stethoscope, Send, Layers, Rocket } from "@lucide/svelte";

  type Tab = "home" | "hosts" | "dns" | "proxy" | "telegram" | "tor" | "xray" | "diag" | "settings";
  let tab = $state<Tab>("home");
  let dirInput = $state("");
  /** Вкладки, которым нужна папка zapret; DNS и настройки работают без неё. */
  const needsZapret: Tab[] = ["home", "hosts"];
  /** Подвкладка Zapret2 — для пути в заголовке. */
  let zsub = $state<"bypass" | "tests" | "lists" | "addons">("bypass");

  // Названия — на английском в обоих языках (термины). Check первой: она подсказывает,
  // какой модуль нужен. Дальше — по способу: без сервера / туннели / DNS.
  const tabs: { id: Tab; label: () => string; icon: typeof Power; group?: () => string; hint: () => string }[] = [
    { id: "diag", label: () => "Check", icon: Stethoscope, hint: () => t("Почему сайт не открывается и что поможет", "Why a site does not open and what helps") },
    { id: "home", label: () => "Zapret2", icon: Power, group: () => "bypass", hint: () => t("Обход DPI драйвером WinDivert", "DPI bypass with the WinDivert driver") },
    { id: "proxy", label: () => "Proxy", icon: Waypoints, hint: () => t("Прокси-обходчик: нарезка ClientHello без прав администратора", "Bypass proxy: ClientHello splitting without admin rights") },
    { id: "xray", label: () => "Xray", icon: Rocket, group: () => "tunnels", hint: () => t("Свои серверы VLESS, VMess, Trojan, Shadowsocks", "Your own VLESS, VMess, Trojan, Shadowsocks servers") },
    { id: "tor", label: () => "Tor", icon: Layers, hint: () => t("Сеть Tor с мостами", "The Tor network with bridges") },
    { id: "telegram", label: () => "Telegram", icon: Send, hint: () => t("Прокси для Telegram Desktop", "A proxy for Telegram Desktop") },
    { id: "dns", label: () => "DNS", icon: Network, group: () => "dns", hint: () => t("DNS адаптера, DoH и проверка подмены", "Adapter DNS, DoH and spoofing check") },
    { id: "hosts", label: () => "Hosts", icon: Globe, hint: () => t("Файл hosts", "The hosts file") },
    { id: "settings", label: () => "Settings", icon: Settings2, group: () => "", hint: () => t("Настройки", "Settings") },
  ];
  /** Состояние модулей для точек в меню и строки системного прокси. */
  let mods = $state<Modules | null>(null);
  const modKey: Partial<Record<Tab, keyof Omit<Modules, "system_proxy">>> = { home: "zapret", proxy: "proxy", xray: "xray", tor: "tor", telegram: "telegram" };
  const stateText = (s: string) =>
    ({ on: t("работает", "running"), starting: t("подключается", "connecting"), error: t("ошибка", "error"), off: "" })[s] ?? "";
  async function pollModules() {
    if (document.visibilityState !== "visible") return;
    try {
      mods = await api.modules();
    } catch {}
  }

  const paths: Record<Tab, string> = {
    home: "zapret2",
    hosts: "hosts",
    dns: "dns",
    proxy: "proxy",
    telegram: "telegram",
    tor: "tor",
    xray: "xray",
    diag: "check",
    settings: "settings",
  };

  onMount(() => {
    if (!isTauri) {
      const q = new URLSearchParams(location.search);
      const t0 = q.get("tab") as Tab | null;
      if (t0 && tabs.some((x) => x.id === t0)) tab = t0;
      const l = q.get("lang");
      if (l === "en" || l === "ru") api.setLanguage(l);
    }
    refresh();
    pollModules();
    const timer = setInterval(pollModules, 2000);
    const un = [
      on<Status>("status", (s) => {
        if (app.ov) app.ov.status = s;
      }),
      on<string>("error", (e) => toast(e)),
      on("overview-changed", () => refresh()),
    ];
    // Окно снова показали из трея — подтянуть актуальное состояние.
    const vis = () => document.visibilityState === "visible" && refresh();
    document.addEventListener("visibilitychange", vis);
    return () => {
      un.forEach((p) => p.then((f) => f()));
      document.removeEventListener("visibilitychange", vis);
      clearInterval(timer);
    };
  });
</script>

<div class="shell">
  <TitleBar path={tab === "home" ? `zapret2/${zsub}` : paths[tab]} />

  {#if app.ov}
    {#if !app.ov.admin}
      <div class="banner mono"><ShieldAlert size={14} /> {t("нет прав администратора — только просмотр", "no administrator rights — view only")}</div>
    {/if}

    <div class="body">
    <nav class="tabs">
      {#each tabs as tb (tb.id)}
        {#if tb.group}
          <div class="group mono" class:spacer={!tb.group()}>{tb.group()}</div>
        {/if}
        {#if tb.id === "settings" && mods?.system_proxy}
          {@const sp = mods.system_proxy}
          <div class="sysproxy mono" title={t("Системный прокси Windows — прокси-обходчик; куда по умолчанию уходит трафик", "Windows system proxy is the bypass proxy; where traffic goes by default")}>
            <span class="dot on"></span>
            <span>
              {t("системный прокси", "system proxy")}<br />
              <span class="via">:{sp.port} → {sp.via === "tor" ? "Tor" : sp.via === "xray" ? "Xray" : "Proxy"}</span>
            </span>
          </div>
        {/if}
        {@const st = modKey[tb.id] && mods ? mods[modKey[tb.id]!] : "off"}
        <button class:active={tab === tb.id} onclick={() => (tab = tb.id)} title={tb.hint() + (stateText(st) ? ` — ${stateText(st)}` : "")}>
          <tb.icon size={14} />
          <span class="mono">{tb.label()}</span>
          {#if st !== "off"}<i class="dot {st}" aria-label={stateText(st)}></i>{/if}
        </button>
      {/each}
    </nav>
    <main class="content"><div class="page">
      {#if !app.ov.dir && needsZapret.includes(tab)}
        <section class="card setup fade-in">
          <div class="label">zapret2</div>
          <p class="muted">{t("Укажите папку со сборкой zapret-discord-youtube (в ней bin\\winws2.exe, lua\\ и lists\\).", "Set the zapret-discord-youtube build folder (it contains bin\\winws2.exe, lua\\ and lists\\).")}</p>
          <input class="input" placeholder="D:\zapret-discord-youtube" bind:value={dirInput} />
          <button class="btn primary" disabled={!dirInput.trim()} onclick={() => act(() => api.setZapretDir(dirInput))}
            >{t("Сохранить", "Save")}</button>
        </section>
      {:else if tab === "home"}<Zapret2 bind:sub={zsub} />
      {:else if tab === "hosts"}<Hosts />
      {:else if tab === "dns"}<Dns />
      {:else if tab === "proxy"}<Proxy />
      {:else if tab === "telegram"}<Telegram />
      {:else if tab === "tor"}<Tor />
      {:else if tab === "xray"}<Xray />
      {:else if tab === "diag"}<Diag go={(id) => (tab = id as Tab)} />
      {:else}<Settings />{/if}
    </div></main>
    </div>
  {/if}

  {#if app.toast}
    <div class="toast mono {app.toast.kind}" role="status">{app.toast.text}</div>
  {/if}
</div>

<style>
  .shell {
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: var(--bg);
  }
  .banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 14px;
    font-size: 11.5px;
    color: var(--yellow);
    background: rgba(210, 153, 34, 0.08);
    border-bottom: 1px solid rgba(210, 153, 34, 0.18);
  }
  /* Широкое окно: навигация слева, сгруппированная по модулям. */
  .body {
    flex: 1;
    min-height: 0;
    display: flex;
  }
  .tabs {
    width: 184px;
    flex: none;
    display: flex;
    flex-direction: column;
    gap: 1px;
    padding: 10px 8px;
    border-right: 1px solid var(--border-soft);
    background: var(--bg);
    overflow-y: auto;
  }
  .group {
    padding: 12px 10px 4px;
    font-size: 10.5px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--faint);
  }
  .group:first-child {
    padding-top: 2px;
  }
  .group.spacer {
    flex: 1;
    padding: 0;
  }
  .tabs button {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 32px;
    padding: 0 10px;
    border: 0;
    border-left: 2px solid transparent;
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    text-align: left;
    transition: color 0.12s, background 0.12s, border-color 0.12s;
  }
  .tabs button span {
    font-size: 12px;
    white-space: nowrap;
  }
  .tabs button:hover {
    color: var(--text);
    background: var(--panel);
  }
  .tabs button.active {
    border-left-color: var(--accent);
    background: var(--panel-2);
    color: var(--text);
  }
  /* Точка состояния модуля справа от названия. */
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex: none;
    margin-left: auto;
  }
  .dot.on {
    background: var(--sage);
    box-shadow: 0 0 6px color-mix(in srgb, var(--sage) 60%, transparent);
  }
  .dot.starting {
    background: var(--yellow);
    animation: blink 1.2s ease-in-out infinite;
  }
  .dot.error {
    background: var(--danger);
  }
  @keyframes blink {
    50% {
      opacity: 0.35;
    }
  }
  .sysproxy {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 6px 10px 8px 12px;
    font-size: 10.5px;
    line-height: 1.45;
    color: var(--faint);
    white-space: nowrap;
  }
  .sysproxy .dot {
    margin: 4px 0 0;
    width: 6px;
    height: 6px;
  }
  .sysproxy .via {
    color: var(--muted);
  }
  .content {
    flex: 1;
    overflow-y: auto;
    min-height: 0;
    min-width: 0;
  }
  /* Блоки растягиваются на всю ширину окна. */
  .page {
    padding: 16px 20px 20px;
    min-height: calc(100% - 36px);
    display: flex;
    flex-direction: column;
  }
  .page > :global(*) {
    flex: 1 0 auto;
  }
  /* Узкое окно: навигация сверху, как раньше. */
  @media (max-width: 720px) {
    .body {
      flex-direction: column;
    }
    .tabs {
      width: auto;
      flex-direction: row;
      gap: 0;
      padding: 0 8px;
      border-right: 0;
      border-bottom: 1px solid var(--border-soft);
      overflow: visible;
    }
    .group,
    .sysproxy {
      display: none;
    }
    .tabs button {
      position: relative;
    }
    .tabs .dot {
      position: absolute;
      top: 7px;
      right: calc(50% - 16px);
    }
    .tabs button {
      flex: 1;
      flex-direction: column;
      gap: 3px;
      height: auto;
      padding: 8px 0 7px;
      border-left: 0;
      border-bottom: 2px solid transparent;
      border-radius: 0;
      margin-bottom: -1px;
      align-items: center;
    }
    .tabs button span {
      font-size: 10px;
    }
    .tabs button:hover {
      background: transparent;
    }
    .tabs button.active {
      background: transparent;
      border-bottom-color: var(--accent);
    }
    .page {
      padding: 12px 14px 16px;
    }
  }
  /* Вкладка zapret2: управление и подбор стратегии одной колонкой. */
  .stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .setup {
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 20px;
  }
  .setup p {
    margin: 0;
    font-size: 12.5px;
  }
  .toast {
    position: fixed;
    left: 50%;
    bottom: 16px;
    transform: translateX(-50%);
    max-width: calc(100% - 40px);
    padding: 9px 14px;
    border-radius: var(--radius);
    font-size: 12px;
    background: var(--panel-3);
    border: 1px solid var(--border);
    box-shadow: 0 12px 30px -10px rgba(0, 0, 0, 0.8);
    animation: up 0.2s ease-out;
    white-space: pre-wrap;
    user-select: text;
  }
  .toast.error {
    color: var(--danger-text);
    border-color: rgba(229, 83, 75, 0.5);
  }
  .toast.ok {
    color: var(--sage);
  }
  @keyframes up {
    from {
      opacity: 0;
      transform: translate(-50%, 6px);
    }
  }
</style>
