<script lang="ts">
  import { onMount } from "svelte";
  import { api, type ProxyLogEntry } from "$lib/api";
  import { t, locale } from "$lib/i18n.svelte";
  import { ScrollText, Trash2 } from "@lucide/svelte";

  let { running }: { running: boolean } = $props();

  let entries = $state<ProxyLogEntry[]>([]);
  let filter = $state("");
  let onlyErrors = $state(false);

  async function load() {
    entries = await api.proxyLog().catch(() => entries);
  }
  onMount(() => {
    load();
    const id = setInterval(() => running && load(), 2000);
    return () => clearInterval(id);
  });

  const shown = $derived(
    entries.filter((e) => (!onlyErrors || !e.ok) && (!filter.trim() || e.host.includes(filter.trim().toLowerCase()))),
  );
  const time = (ts: number) => new Date(ts).toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const actionText = (a: ProxyLogEntry["action"]) =>
    ({ bypass: t("нарезка", "split"), pass: t("без нарезки", "pass"), block: t("блок", "blocked"), worker: "Worker", tor: "Tor", xray: "Xray" })[a];
</script>

<section class="card block">
  <div class="row">
    <div>
      <div class="label"><ScrollText size={11} /> {t("журнал соединений", "connection log")} · {entries.length}</div>
      <div class="hint faint mono">{t("последние 500 соединений, новые сверху; обновляется раз в 2 секунды", "last 500 connections, newest first; refreshes every 2 seconds")}</div>
    </div>
    <button class="btn sm ghost" disabled={!entries.length} onclick={() => api.proxyLogClear().then(load)}><Trash2 size={12} /> {t("Очистить", "Clear")}</button>
  </div>
  <div class="tools">
    <input class="input" placeholder={t("фильтр по сайту", "filter by site")} bind:value={filter} />
    <label class="check mono"><input type="checkbox" bind:checked={onlyErrors} /> {t("только ошибки", "errors only")}</label>
  </div>
  <div class="log mono">
    {#each shown as e, i (e.ts + e.host + i)}
      <div class="it" class:bad={!e.ok && e.action !== "block"} title={e.error ?? ""}>
        <span class="faint">{time(e.ts)}</span>
        <span class="host">{e.host}{e.port !== 443 ? `:${e.port}` : ""}</span>
        <span class="act {e.action}">{actionText(e.action)}</span>
        <span class="method">{e.method ?? "—"}{e.tries > 1 ? ` · ${t("попыток", "tries")} ${e.tries}` : ""}</span>
        <span class="res">{e.ok ? `${e.ms} ms` : e.action === "block" ? "—" : (e.error ?? t("ошибка", "error"))}</span>
      </div>
    {:else}
      <div class="faint empty">{running ? t("пока пусто — откройте сайт через прокси", "empty so far — open a site through the proxy") : t("прокси выключен", "the proxy is off")}</div>
    {/each}
  </div>
</section>

<style>
  .block {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .row {
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
  }
  .tools {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 10px;
    align-items: center;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    color: var(--muted);
    cursor: pointer;
  }
  .check input {
    accent-color: var(--accent);
    margin: 0;
  }
  .log {
    max-height: 360px;
    overflow: auto;
    display: flex;
    flex-direction: column;
  }
  .it {
    display: grid;
    grid-template-columns: 64px minmax(160px, 1.2fr) 86px minmax(150px, 1fr) minmax(90px, 0.8fr);
    gap: 10px;
    font-size: 11.5px;
    padding: 4px 2px;
    border-bottom: 1px solid var(--border-soft);
    user-select: text;
  }
  .it.bad {
    background: var(--danger-soft);
  }
  .host,
  .method,
  .res {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .act.bypass {
    color: var(--accent);
  }
  .act.pass {
    color: var(--muted);
  }
  .act.block {
    color: var(--warn);
  }
  .it.bad .res {
    color: var(--danger-text);
  }
  .empty {
    padding: 10px 2px;
    font-size: 12px;
  }
</style>
