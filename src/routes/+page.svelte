<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, isTauri, type Status } from "$lib/api";
  import { app, refresh, toast, act } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import TitleBar from "$lib/components/TitleBar.svelte";
  import Home from "$lib/components/Home.svelte";
  import Tests from "$lib/components/Tests.svelte";
  import Lists from "$lib/components/Lists.svelte";
  import Hosts from "$lib/components/Hosts.svelte";
  import Settings from "$lib/components/Settings.svelte";
  import Dns from "$lib/components/Dns.svelte";
  import { Power, FlaskConical, ListChecks, Globe, Network, Settings2, ShieldAlert } from "@lucide/svelte";

  type Tab = "home" | "tests" | "lists" | "hosts" | "dns" | "settings";
  let tab = $state<Tab>("home");
  let dirInput = $state("");
  /** Вкладки, которым нужна папка zapret; DNS и настройки работают без неё. */
  const needsZapret: Tab[] = ["home", "tests", "lists", "hosts"];

  const tabs: { id: Tab; label: () => string; icon: typeof Power }[] = [
    { id: "home", label: () => "zapret2", icon: Power },
    { id: "tests", label: () => t("тесты", "tests"), icon: FlaskConical },
    { id: "lists", label: () => t("списки", "lists"), icon: ListChecks },
    { id: "hosts", label: () => "hosts", icon: Globe },
    { id: "dns", label: () => "dns", icon: Network },
    { id: "settings", label: () => t("настройки", "settings"), icon: Settings2 },
  ];
  const paths: Record<Tab, string> = {
    home: "zapret2",
    tests: "zapret2/tests",
    lists: "zapret2/lists",
    hosts: "hosts",
    dns: "dns",
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
    };
  });
</script>

<div class="shell">
  <TitleBar path={paths[tab]} running={!!app.ov?.status.running} />

  {#if app.ov}
    {#if !app.ov.admin}
      <div class="banner mono"><ShieldAlert size={14} /> {t("нет прав администратора — только просмотр", "no administrator rights — view only")}</div>
    {/if}

    <nav class="tabs">
      {#each tabs as tb (tb.id)}
        <button class:active={tab === tb.id} onclick={() => (tab = tb.id)} title={tb.label()}>
          <tb.icon size={14} />
          <span class="mono">{tb.label()}</span>
        </button>
      {/each}
    </nav>
    <main class="content">
      {#if !app.ov.dir && needsZapret.includes(tab)}
        <section class="card setup fade-in">
          <div class="label">zapret2</div>
          <p class="muted">{t("Укажите папку со сборкой zapret-discord-youtube (в ней bin\\winws2.exe, lua\\ и lists\\).", "Set the zapret-discord-youtube build folder (it contains bin\\winws2.exe, lua\\ and lists\\).")}</p>
          <input class="input" placeholder="D:\zapret-discord-youtube" bind:value={dirInput} />
          <button class="btn primary" disabled={!dirInput.trim()} onclick={() => act(() => api.setZapretDir(dirInput))}
            >{t("сохранить", "save")}</button>
        </section>
      {:else if tab === "home"}<Home />
      {:else if tab === "tests"}<Tests />
      {:else if tab === "lists"}<Lists />
      {:else if tab === "hosts"}<Hosts />
      {:else if tab === "dns"}<Dns />
      {:else}<Settings />{/if}
    </main>
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
    font-size: 11px;
    color: var(--yellow);
    background: rgba(210, 153, 34, 0.08);
    border-bottom: 1px solid rgba(210, 153, 34, 0.18);
  }
  .tabs {
    display: flex;
    gap: 0;
    padding: 0 8px;
    border-bottom: 1px solid var(--border-soft);
    background: var(--bg);
  }
  .tabs button {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
    padding: 8px 0 7px;
    border: 0;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    background: transparent;
    color: var(--faint);
    cursor: pointer;
    transition: color 0.12s, border-color 0.12s;
  }
  .tabs button span {
    font-size: 10px;
  }
  .tabs button:hover {
    color: var(--muted);
  }
  .tabs button.active {
    border-bottom-color: var(--accent);
    color: var(--text);
  }
  .content {
    flex: 1;
    overflow-y: auto;
    padding: 12px 14px 16px;
    min-height: 0;
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
    font-size: 11.5px;
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
