<script lang="ts">
  import { api, type ListPreset } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import { onMount } from "svelte";
  import Segmented from "./Segmented.svelte";
  import { t } from "$lib/i18n.svelte";
  import { Save, RotateCcw, Plus } from "@lucide/svelte";

  type Kind = "general" | "exclude" | "ipset-exclude";
  const info: Record<Kind, { title: string; hint: () => string }> = {
    general: { title: "list-general-user.txt", hint: () => t("домены, которые нужно обходить — по одному в строке", "domains to bypass — one per line") },
    exclude: { title: "list-exclude-user.txt", hint: () => t("домены, которые обходить НЕ нужно", "domains NOT to bypass") },
    "ipset-exclude": { title: "ipset-exclude-user.txt", hint: () => t("IP и подсети (CIDR), исключённые из обхода", "IPs and subnets (CIDR) excluded from bypass") },
  };

  let kind = $state<Kind>("general");
  let text = $state("");
  let saved = $state("");
  let warnings = $state<string[]>([]);
  const dirty = $derived(text !== saved);

  async function load(k: Kind) {
    warnings = [];
    try {
      text = saved = await api.listRead(k);
    } catch (e) {
      text = saved = "";
    }
  }
  $effect(() => {
    load(kind);
  });

  async function save() {
    const r = await act(() => api.listWrite(kind, text), t("Сохранено", "Saved"));
    if (r) {
      warnings = r.warnings;
      await load(kind);
      warnings = r.warnings;
    }
  }
  let presets = $state<ListPreset[]>([]);
  let picked = $state<Set<string>>(new Set());
  onMount(async () => {
    presets = await api.listPresets().catch(() => []);
  });
  function togglePreset(id: string) {
    const n = new Set(picked);
    n.has(id) ? n.delete(id) : n.add(id);
    picked = n;
  }
  async function addPresets() {
    if (dirty && !confirm(t("Несохранённые правки списка пропадут. Продолжить?", "Unsaved list edits will be lost. Continue?"))) return;
    const n = await act(() => api.listAddPresets([...picked]));
    if (n === undefined) return;
    toast(n ? `${t("Добавлено доменов", "Domains added")}: ${n}` : t("Все домены уже в списке", "All domains are already listed"), "ok");
    picked = new Set();
    kind = "general";
    await load("general");
  }

  const lines = $derived(text.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#")).length);
</script>

<div class="lists fade-in">
  <Segmented
    value={kind}
    onchange={(v) => {
      if (!dirty || confirm(t("Есть несохранённые изменения. Переключиться?", "You have unsaved changes. Switch anyway?"))) kind = v;
    }}
    options={[
      { value: "general", label: t("Обходить", "Bypass") },
      { value: "exclude", label: t("Исключить", "Exclude") },
      { value: "ipset-exclude", label: t("IP-исключения", "IP exclude") },
    ]} />

  {#if kind === "general" && presets.length}
    <section class="card sets">
      <div class="label">{t("наборы", "sets")}</div>
      <div class="chips">
        {#each presets as p (p.id)}
          <button class="set" class:on={picked.has(p.id)} title={p.domains.join(", ") + (p.builtin ? `
${t("Ещё во встроенных списках", "Already in built-in lists")}: ${p.builtin}` : "")} onclick={() => togglePreset(p.id)}>
            {p.name} <span class="faint">{p.domains.length}</span>
          </button>
        {/each}
      </div>
      <div class="actions">
        <span class="faint mono note">{t("YouTube и Discord уже во встроенных списках; новые домены добавятся в конец list-general-user.txt без дублей", "YouTube and Discord are already in the built-in lists; new domains are appended to list-general-user.txt without duplicates")}</span>
        <button class="btn sm" disabled={!picked.size || app.busy || app.ov?.testing} onclick={addPresets}><Plus size={12} /> {t("Добавить", "Add")}</button>
      </div>
    </section>
  {/if}

  <section class="card ed">
    <div class="head">
      <div>
        <div class="label">{info[kind].title}</div>
        <div class="hint faint mono">{info[kind].hint()}</div>
      </div>
      <span class="chip">{lines} {t("строк", "lines")}</span>
    </div>
    <textarea class="textarea" spellcheck="false" bind:value={text}></textarea>
    {#if warnings.length}
      <div class="warn mono">
        {t("не похоже на", "doesn't look like")} {kind === "ipset-exclude" ? "IP/CIDR" : t("домен", "a domain")}: {warnings.slice(0, 6).join(", ")}{warnings.length > 6
          ? ` ${t("и ещё", "and")} ${warnings.length - 6}`
          : ""}
      </div>
    {/if}
    <div class="actions">
      <span class="faint mono note">{t("пустой файл заменится заглушкой; работающий обход перезапустится", "an empty file gets a placeholder; a running bypass restarts")}</span>
      <button class="btn ghost sm" disabled={!dirty} onclick={() => (text = saved)}><RotateCcw size={12} /></button>
      <button class="btn primary" disabled={!dirty || app.busy || app.ov?.testing} onclick={save}
        ><Save size={13} /> {t("Сохранить", "Save")}</button>
    </div>
  </section>
</div>

<style>
  .lists {
    display: flex;
    flex-direction: column;
    gap: 12px;
    height: 100%;
  }
  .ed {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 14px;
    min-height: 0;
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }
  .hint {
    font-size: 10.5px;
    margin-top: 3px;
  }
  textarea {
    flex: 1;
    min-height: 220px;
  }
  .warn {
    font-size: 10.5px;
    color: var(--yellow);
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .note {
    flex: 1;
    font-size: 10px;
  }
  .sets {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .set {
    height: 26px;
    padding: 0 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg);
    color: var(--muted);
    font-family: var(--mono);
    font-size: 11px;
    cursor: pointer;
  }
  .set:hover {
    color: var(--text);
    border-color: var(--border-strong);
  }
  .set.on {
    color: var(--text);
    border-color: var(--accent);
    background: var(--accent-soft);
  }
</style>
