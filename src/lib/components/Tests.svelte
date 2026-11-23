<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, strategyName, type TestRun, type StrategyResult } from "$lib/api";
  import { app, act, toast, refresh } from "$lib/state.svelte";
  import Segmented from "./Segmented.svelte";
  import Evolve from "./Evolve.svelte";
  import { t, locale } from "$lib/i18n.svelte";
  import { Play, Square, Trophy, History, ChevronRight, FlaskConical } from "@lucide/svelte";

  const ov = $derived(app.ov!);
  let kind = $state<"standard" | "dpi">("standard");
  let picked = $state<Set<string>>(new Set());
  let run = $state<TestRun | null>(null);
  let history = $state<TestRun[]>([]);
  let expanded = $state<string | null>(null);
  let showHistory = $state(false);

  onMount(() => {
    picked = new Set(ov.strategies.map((s) => s.file));
    api.testLast().then((r) => r && (run = r));
    api.testHistory().then((h) => (history = h));
    const un = [
      on<TestRun>("test-progress", (r) => (run = r)),
      on("test-finished", async () => {
        history = await api.testHistory();
        refresh();
      }),
    ];
    return () => un.forEach((p) => p.then((f) => f()));
  });

  const live = $derived(!!run && !run.finished);
  const testing = $derived(ov.testing || live);

  function togglePick(f: string) {
    const n = new Set(picked);
    n.has(f) ? n.delete(f) : n.add(f);
    picked = n;
  }

  async function start() {
    const files = ov.strategies.map((s) => s.file).filter((f) => picked.has(f));
    run = null;
    expanded = null;
    await act(() => api.testStart(kind, files));
  }

  const checksTotal = (r: StrategyResult) => r.ok + r.fail + r.unsup + r.blocked;
  const sorted = $derived.by(() => {
    if (!run) return [];
    const rs = [...run.results];
    if (run.finished) rs.sort((a, b) => b.ok - a.ok || b.ping_ok - a.ping_ok);
    return rs;
  });

  function liveTally(r: StrategyResult) {
    if (r.ok + r.fail + r.unsup + r.blocked > 0) return r;
    // Во время прогона счётчики ещё не посчитаны бэкендом — считаем на лету.
    const t = { ...r };
    for (const tg of r.targets)
      for (const [, s] of tg.checks) {
        if (s === "OK") t.ok++;
        else if (s === "UNSUP") t.unsup++;
        else if (s === "BLOCKED") t.blocked++;
        else t.fail++;
      }
    return t;
  }

  const dot = (s: string) =>
    s === "OK" ? "ok" : s === "UNSUP" ? "warn" : s === "BLOCKED" ? "warn" : "bad";

  const when = (id: number) =>
    new Date(id * 1000).toLocaleString(locale(), { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
</script>

<div class="tests fade-in">
  <section class="card ctl">
    <div class="label"><FlaskConical size={11} /> {t("подбор стратегии", "find the best strategy")}</div>
    <div class="row">
      <Segmented
        value={kind}
        disabled={testing}
        onchange={(v) => (kind = v)}
        options={[
          { value: "standard", label: t("Стандартный", "Standard") },
          { value: "dpi", label: "DPI 16-20" },
        ]} />
      {#if testing}
        <button class="btn danger" onclick={() => api.testCancel().then(() => toast(t("Останавливаю после текущих проверок", "Stopping after the current checks"), "ok"))}
          ><Square size={13} /> {t("Стоп", "Stop")}</button>
      {:else}
        <button class="btn primary" disabled={!ov.admin || picked.size === 0 || app.busy} onclick={start}
          ><Play size={13} /> {t("Запуск", "Run")}</button>
      {/if}
    </div>
    <div class="hint faint mono">
      {kind === "standard"
        ? t("curl HTTP / TLS1.2 / TLS1.3 + ping по utils\\targets.txt", "curl HTTP / TLS1.2 / TLS1.3 + ping over utils\\targets.txt")
        : t("POST 64 КБ на набор хостов dpi-checkers; ipset временно = все IP", "POST 64 KB to the dpi-checkers host suite; ipset temporarily = all IPs")}
    </div>

    <div class="pickhead">
      <span class="label">{t("стратегии", "strategies")} · {picked.size}/{ov.strategies.length}</span>
      <span class="links">
        <button class="btn sm ghost" disabled={testing} onclick={() => (picked = new Set(ov.strategies.map((s) => s.file)))}
          >{t("Все", "All")}</button>
        <button class="btn sm ghost" disabled={testing} onclick={() => (picked = new Set())}>{t("Ничего", "None")}</button>
      </span>
    </div>
    <div class="picks">
      {#each ov.strategies as s (s.file)}
        <button class="chip pick" class:amber={picked.has(s.file)} disabled={testing} onclick={() => togglePick(s.file)}
          >{s.name.replace(/^general\s*/i, "").replace(/^\((.*)\)$/, "$1") || "general"}</button>
      {/each}
    </div>
  </section>

  {#if run}
    {#if live}
      <section class="card prog">
        <div class="mono progline">
          <span>[{run.index}/{run.total}] {strategyName(run.current)}</span>
          <span class="faint">{Math.round(((run.index - 1) / Math.max(run.total, 1)) * 100)}%</span>
        </div>
        <div class="bar"><span style="width:{((run.index - 1) / Math.max(run.total, 1)) * 100}%"></span></div>
      </section>
    {/if}

    {#if run.message}
      <div class="card msg mono">{run.message}</div>
    {/if}

    {#if run.finished && run.best}
      <section class="card best">
        <Trophy size={18} />
        <div class="grow">
          <div class="label">{t("лучшая", "best")}</div>
          <div class="mono bname">{strategyName(run.best)}</div>
        </div>
        <button
          class="btn primary"
          disabled={app.busy || ov.selected === run.best}
          onclick={() => act(() => api.selectStrategy(run!.best!), t("Стратегия выбрана", "Strategy selected"))}
          >{ov.selected === run.best ? t("Выбрана", "Selected") : t("Применить", "Apply")}</button>
      </section>
    {/if}

    <section class="results">
      {#each sorted as r0 (r0.file)}
        {@const r = liveTally(r0)}
        {@const total = Math.max(checksTotal(r), 1)}
        <div class="card res" class:isbest={run.finished && run.best === r.file}>
          <button class="reshead" onclick={() => (expanded = expanded === r.file ? null : r.file)}>
            <ChevronRight size={14} class={expanded === r.file ? "rot" : ""} />
            <span class="mono rname">{strategyName(r.file)}</span>
            {#if r.error}
              <span class="chip red">{t("Не запустилась", "Failed to start")}</span>
            {:else}
              <span class="score mono">{r.ok}<span class="faint">/{checksTotal(r)}</span></span>
            {/if}
          </button>
          {#if !r.error}
            <div class="meter">
              <span class="m-ok" style="width:{(r.ok / total) * 100}%"></span>
              <span class="m-warn" style="width:{((r.unsup + r.blocked) / total) * 100}%"></span>
              <span class="m-bad" style="width:{(r.fail / total) * 100}%"></span>
            </div>
            <div class="tally mono">
              <span class="ok">ok {r.ok}</span>
              <span class="bad">err {r.fail}</span>
              {#if r.unsup}<span class="warn">unsup {r.unsup}</span>{/if}
              {#if r.blocked}<span class="warn">blocked {r.blocked}</span>{/if}
              {#if r.ping_ok + r.ping_fail > 0}<span class="faint">ping {r.ping_ok}/{r.ping_ok + r.ping_fail}</span>{/if}
            </div>
          {:else if expanded === r.file}
            <div class="mono errtxt">{r.error}</div>
          {/if}
          {#if expanded === r.file && r.targets.length}
            <div class="targets">
              {#each r.targets as tg (tg.key)}
                <div class="t mono" title={tg.detail ?? ""}>
                  <span class="tk">{tg.key}</span>
                  <span class="dots">
                    {#each tg.checks as [label, s]}
                      <span class="d {dot(s)}" title="{label}: {s}">{label.replace("TLS", "")}</span>
                    {/each}
                  </span>
                  {#if tg.ping_tried}
                    <span class="png" class:bad={tg.ping_ms === null}>{tg.ping_ms === null ? "—" : `${tg.ping_ms}ms`}</span>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </section>
  {/if}

  <Evolve {kind} {picked} last={run} busy={testing} />

  {#if history.length}
    <section class="card hist">
      <button class="histhead" onclick={() => (showHistory = !showHistory)}>
        <History size={14} /> <span class="label">{t("История", "History")}</span>
        <span class="faint mono">{history.length}</span>
      </button>
      {#if showHistory}
        {#each history as h (h.id)}
          <button class="hrow mono" disabled={testing} onclick={() => ((run = h), (expanded = null))}>
            <span class="faint">{when(h.id)}</span>
            <span>{h.kind === "dpi" ? "dpi" : "std"} · {h.results.length}</span>
            <span class="hb">{h.best ? strategyName(h.best) : "—"}</span>
          </button>
        {/each}
      {/if}
    </section>
  {/if}
</div>

<style>
  .tests {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .ctl > .label {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .ctl {
    padding: 12px 14px;
  }
  .row {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .row :global(.seg) {
    flex: 1;
  }
  .hint {
    font-size: 11px;
    margin: 8px 2px 4px;
  }
  .pickhead {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 10px;
  }
  .picks {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
    margin-top: 6px;
    max-height: none;
    overflow: auto;
  }
  .pick {
    cursor: pointer;
  }
  .pick:disabled {
    cursor: default;
    opacity: 0.6;
  }
  .prog {
    padding: 12px 14px;
  }
  .progline {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    margin-bottom: 8px;
  }
  .bar {
    height: 6px;
    border-radius: 6px;
    background: var(--bg);
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    border-radius: 6px;
    background: linear-gradient(90deg, var(--sage), var(--amber));
    transition: width 0.4s ease;
  }
  .msg {
    padding: 10px 12px;
    font-size: 12px;
    color: var(--danger-text);
    border-color: rgba(229, 83, 75, 0.35);
  }
  .best {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 14px;
    color: var(--amber);
    border-color: rgba(88, 166, 255, 0.35);
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  .bname {
    color: var(--text);
    font-size: 14px;
    font-weight: 700;
    margin-top: 2px;
  }
  .results {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .res {
    padding: 10px 12px;
    border-radius: var(--radius);
  }
  .res.isbest {
    border-color: rgba(88, 166, 255, 0.45);
  }
  .reshead {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 6px;
    border: 0;
    background: transparent;
    color: var(--text);
    cursor: pointer;
    padding: 0;
    text-align: left;
  }
  .reshead :global(svg) {
    color: var(--faint);
    transition: transform 0.15s;
  }
  .reshead :global(.rot) {
    transform: rotate(90deg);
  }
  .rname {
    flex: 1;
    font-size: 12.5px;
  }
  .score {
    font-size: 13px;
    font-weight: 700;
  }
  .meter {
    display: flex;
    height: 5px;
    border-radius: 5px;
    overflow: hidden;
    background: var(--bg);
    margin: 8px 0 6px;
  }
  .m-ok {
    background: var(--sage);
  }
  .m-warn {
    background: var(--yellow);
  }
  .m-bad {
    background: var(--red);
  }
  .meter span {
    transition: width 0.3s;
  }
  .tally {
    display: flex;
    gap: 10px;
    font-size: 11px;
  }
  .ok {
    color: var(--sage);
  }
  .bad {
    color: var(--red);
  }
  .warn {
    color: var(--yellow);
  }
  .errtxt {
    font-size: 11px;
    color: var(--danger-text);
    margin-top: 6px;
    white-space: pre-wrap;
  }
  .targets {
    margin-top: 8px;
    border-top: 1px solid var(--border-soft);
    padding-top: 6px;
  }
  .t {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    padding: 3px 0;
  }
  .tk {
    flex: 1;
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dots {
    display: flex;
    gap: 3px;
  }
  .d {
    min-width: 28px;
    text-align: center;
    padding: 1px 4px;
    border-radius: 6px;
    font-size: 10px;
  }
  .d.ok {
    background: var(--sage-soft);
    color: var(--sage);
  }
  .d.warn {
    background: rgba(210, 153, 34, 0.12);
    color: var(--yellow);
  }
  .d.bad {
    background: var(--red-soft);
    color: var(--danger-text);
  }
  .png {
    width: 44px;
    text-align: right;
    color: var(--sage);
  }
  .png.bad {
    color: var(--faint);
  }
  .hist {
    padding: 8px 12px;
  }
  .histhead {
    display: flex;
    align-items: center;
    gap: 8px;
    border: 0;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    padding: 4px 0;
    width: 100%;
  }
  .hrow {
    width: 100%;
    display: grid;
    grid-template-columns: 90px 60px 1fr;
    gap: 8px;
    padding: 6px 4px;
    border: 0;
    border-top: 1px solid var(--border-soft);
    background: transparent;
    color: var(--text);
    font-size: 11.5px;
    text-align: left;
    cursor: pointer;
  }
  .hrow:hover {
    color: var(--amber-2);
  }
  .hb {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
