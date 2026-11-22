<script lang="ts">
  import { onMount } from "svelte";
  import { api, type HostEntry, type HostsStatus } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { RefreshCw, Plus, X, ShieldAlert, ChevronRight } from "@lucide/svelte";

  let st = $state<HostsStatus | null>(null);
  let sel = $state<Set<string>>(new Set());
  let custom = $state<HostEntry[]>([]);
  let open = $state<Set<string>>(new Set());
  let ip = $state("");
  let host = $state("");

  const key = (e: HostEntry) => `${e.ip} ${e.host}`;

  async function load() {
    try {
      st = await api.hostsStatus();
      const all = st.groups.flatMap((g) => g.entries);
      const inBlock = all.filter((e) => e.in_block);
      // Блока ещё нет — по умолчанию отмечено всё.
      sel = new Set((st.block_present ? inBlock : all).map(key));
      custom = st.custom.map(({ ip, host }) => ({ ip, host }));
    } catch (e) {
      toast(String(e));
    }
  }
  onMount(load);

  function toggleGroup(entries: HostEntry[]) {
    const n = new Set(sel);
    const allOn = entries.every((e) => n.has(key(e)));
    for (const e of entries) allOn ? n.delete(key(e)) : n.add(key(e));
    sel = n;
  }
  function toggle(e: HostEntry) {
    const n = new Set(sel);
    n.has(key(e)) ? n.delete(key(e)) : n.add(key(e));
    sel = n;
  }
  function addCustom() {
    const i = ip.trim(),
      h = host.trim().toLowerCase();
    if (!i || !h) return;
    if (!/^[0-9a-f:.]+$/i.test(i)) return toast(t("Некорректный IP", "Invalid IP"));
    custom = [...custom, { ip: i, host: h }];
    ip = host = "";
  }
  async function apply() {
    const entries = st!.groups.flatMap((g) => g.entries).filter((e) => sel.has(key(e))).map(({ ip, host }) => ({ ip, host }));
    await act(() => api.hostsApply(entries, custom), t("hosts обновлён, DNS-кэш сброшен", "hosts updated, DNS cache flushed"));
    await load();
  }
  async function remove() {
    if (!confirm(t("Убрать блок digital-bypass из системного hosts?", "Remove the digital-bypass block from the system hosts?"))) return;
    await act(() => api.hostsRemove(), t("Блок удалён", "Block removed"));
    await load();
  }
  async function update() {
    const n = await act(() => api.hostsUpdate());
    if (n) toast(`${t("Скачано записей", "Entries downloaded")}: ${n}`, "ok");
    await load();
  }
</script>

<div class="hosts fade-in">
  {#if st}
    <section class="card top">
      <div class="grow">
        <div class="label">{t("источник", "source")}</div>
        <div class="mono src">{st.source}</div>
      </div>
      {#if st.block_present}
        <span class="chip" class:sage={!st.outdated} class:amber={st.outdated}>{st.outdated ? t("устарело", "outdated") : t("применено", "applied")}</span>
      {:else}
        <span class="chip">{t("не применено", "not applied")}</span>
      {/if}
      <button class="btn sm" disabled={app.busy} onclick={update} title={t("Скачать актуальный файл с GitHub", "Download the latest file from GitHub")}
        ><RefreshCw size={12} /> github</button>
    </section>

    <div class="warnbox mono">
      <ShieldAlert size={14} />
      <span>{t("Defender может отметить правку hosts как угрозу (HostsFileHijack). Перед записью делается копия hosts.digital-bypass.bak.", "Defender may flag hosts edits as a threat (HostsFileHijack). A hosts.digital-bypass.bak copy is made before writing.")}</span>
    </div>

    <section class="card groups">
      {#each st.groups as g (g.name)}
        {@const on = g.entries.filter((e) => sel.has(key(e))).length}
        <div class="group">
          <div class="ghead">
            <button class="exp" onclick={() => {
              const n = new Set(open);
              n.has(g.name) ? n.delete(g.name) : n.add(g.name);
              open = n;
            }}><ChevronRight size={14} class={open.has(g.name) ? "rot" : ""} /></button>
            <label class="gl">
              <input type="checkbox" checked={on === g.entries.length} indeterminate={on > 0 && on < g.entries.length}
                onchange={() => toggleGroup(g.entries)} />
              <span class="mono">{g.name}</span>
            </label>
            <span class="faint mono cnt">{on}/{g.entries.length}</span>
          </div>
          {#if open.has(g.name)}
            {#each g.entries as e (key(e))}
              <label class="entry mono">
                <input type="checkbox" checked={sel.has(key(e))} onchange={() => toggle(e)} />
                <span class="h">{e.host}</span>
                <span class="ip faint">{e.ip}</span>
                {#if e.manual}<span class="chip" title={t("Строка уже есть в hosts вне блока", "This line already exists in hosts outside the block")}>{t("вручную", "manual")}</span>{/if}
              </label>
            {/each}
          {/if}
        </div>
      {/each}
    </section>

    <section class="card customs">
      <div class="label">{t("свои записи", "custom entries")}</div>
      {#each custom as c, i (key(c) + i)}
        <div class="entry mono">
          <span class="h">{c.host}</span><span class="ip faint">{c.ip}</span>
          <button class="btn sm ghost" onclick={() => (custom = custom.filter((_, j) => j !== i))}><X size={12} /></button>
        </div>
      {/each}
      <div class="add">
        <input class="input" placeholder="1.2.3.4" bind:value={ip} />
        <input class="input" placeholder="example.com" bind:value={host} onkeydown={(e) => e.key === "Enter" && addCustom()} />
        <button class="btn sm" onclick={addCustom}><Plus size={12} /></button>
      </div>
    </section>

    <div class="actions">
      <button class="btn danger" disabled={app.busy || !st.block_present || !app.ov?.admin} onclick={remove}>{t("Убрать блок", "Remove block")}</button>
      <button class="btn primary" disabled={app.busy || !app.ov?.admin} onclick={apply}>{t("Записать в hosts", "Write to hosts")}</button>
    </div>
  {/if}
</div>

<style>
  .hosts {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .top {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 14px;
  }
  .grow {
    flex: 1;
  }
  .src {
    font-size: 11.5px;
    margin-top: 3px;
  }
  .warnbox {
    display: flex;
    gap: 8px;
    font-size: 10.5px;
    color: var(--muted);
    padding: 0 4px;
    align-items: flex-start;
  }
  .warnbox :global(svg) {
    flex: none;
    color: var(--yellow);
    margin-top: 1px;
  }
  .groups {
    padding: 6px 10px;
  }
  .group + .group {
    border-top: 1px solid var(--border-soft);
  }
  .ghead {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 6px 0;
  }
  .exp {
    border: 0;
    background: transparent;
    color: var(--faint);
    cursor: pointer;
    padding: 2px;
    display: grid;
  }
  .exp :global(svg) {
    transition: transform 0.15s;
  }
  .exp :global(.rot) {
    transform: rotate(90deg);
  }
  .gl {
    flex: 1;
    display: flex;
    gap: 8px;
    align-items: center;
    font-size: 12px;
    cursor: pointer;
  }
  .cnt {
    font-size: 10.5px;
  }
  .entry {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    padding: 4px 0 4px 26px;
    cursor: pointer;
  }
  .customs .entry {
    padding-left: 0;
  }
  .h {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ip {
    font-size: 10.5px;
  }
  input[type="checkbox"] {
    accent-color: var(--amber);
    width: 14px;
    height: 14px;
  }
  .customs {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .add {
    display: grid;
    grid-template-columns: 110px 1fr auto;
    gap: 6px;
    margin-top: 4px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
</style>
