<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, strategyName, type EvolveRun, type TestRun } from "$lib/api";
  import { app, act, toast, refresh } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { Dna, Play, Square, Save, X } from "@lucide/svelte";
  import Segmented from "./Segmented.svelte";

  let { kind, picked, last, busy }: { kind: "standard" | "dpi"; picked: Set<string>; last: TestRun | null; busy: boolean } = $props();

  const ov = $derived(app.ov!);
  let ev = $state<EvolveRun | null>(null);
  let rounds = $state(3);
  const live = $derived(!!ev && !ev.finished);

  /** Сколько стратегий в засеве. */
  const MAX_SEEDS = 4;
  // Засев вручную — для экспериментов; выбор помнится в этом браузере.
  const KEY = "evolve.seeds";
  const load = (): { mode: "auto" | "manual"; files: string[] } => {
    try {
      const v = JSON.parse(localStorage.getItem(KEY) ?? "null");
      if (v && (v.mode === "auto" || v.mode === "manual") && Array.isArray(v.files)) return v;
    } catch {}
    return { mode: "auto", files: [] };
  };
  const saved0 = load();
  let mode = $state<"auto" | "manual">(saved0.mode);
  let manual = $state<string[]>(saved0.files);
  let filter = $state("");
  $effect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify({ mode, files: manual }));
    } catch {}
  });
  // Удалённые стратегии из ручного выбора убираем.
  const manualValid = $derived(manual.filter((f) => ov.strategies.some((s) => s.file === f)));
  /** ok из последнего теста того же вида — подсказка при ручном выборе. */
  const okOf = $derived.by(() => {
    const m = new Map<string, number>();
    if (last?.finished && last.kind === kind) for (const r of last.results) if (!r.error) m.set(r.file, r.ok);
    return m;
  });
  const shown = $derived(
    ov.strategies
      .map((s) => s.file)
      .filter((f) => !filter.trim() || strategyName(f).toLowerCase().includes(filter.trim().toLowerCase()))
      .sort((a, b) => (okOf.get(b) ?? -1) - (okOf.get(a) ?? -1)),
  );
  function togglePick(f: string) {
    if (manual.includes(f)) manual = manual.filter((x) => x !== f);
    else if (manualValid.length < MAX_SEEDS) manual = [...manualValid, f];
  }

  // Засев: вручную — как выбрано; иначе 4 лучших из последнего теста того же вида,
  // а без теста — первые 4 выбранных.
  const autoSeeds = $derived.by(() => {
    const pickedList = ov.strategies.map((s) => s.file).filter((f) => picked.has(f));
    if (last?.finished && last.kind === kind && last.results.length) {
      const top = [...last.results].filter((r) => picked.has(r.file) && !r.error).sort((a, b) => b.ok - a.ok).map((r) => r.file);
      if (top.length) return top.slice(0, MAX_SEEDS);
    }
    return pickedList.slice(0, MAX_SEEDS);
  });
  const seeds = $derived(mode === "manual" ? manualValid : autoSeeds);
  // Оценка числа кандидатов: засев + раунды × зал славы (4) × 3 мутанта.
  const planned = $derived(seeds.length + rounds * 4 * 3);

  /** Первая точка отсчёта текущего прогона — для оценки оставшегося времени. */
  let mark: { at: number; done: number } | null = null;
  let eta = $state<number | null>(null);
  function progress(r: EvolveRun) {
    ev = r;
    if (r.finished) {
      mark = null;
      eta = null;
      return;
    }
    if (!mark || r.done < mark.done) mark = { at: Date.now(), done: r.done };
    const n = r.done - mark.done;
    // Нужно хотя бы 2 кандидата: первый идёт дольше (два прогона засева и т. п.).
    eta = n >= 2 ? ((Date.now() - mark.at) / n) * Math.max(r.planned - r.done, 0) : null;
  }
  function etaText(ms: number) {
    const m = Math.round(ms / 60000);
    return m < 1 ? t("меньше минуты", "under a minute") : t(`≈ ${m} мин`, `≈ ${m} min`);
  }

  onMount(() => {
    api.evolveLast().then((r) => r && (ev = r));
    const un = [
      on<EvolveRun>("evolve-progress", progress),
      on("evolve-finished", () => refresh()),
    ];
    return () => un.forEach((p) => p.then((f) => f()));
  });

  async function start() {
    ev = null;
    await act(() => api.evolveStart(kind, seeds, rounds));
  }
  async function save(name: string) {
    try {
      const file = await api.evolveSave(name);
      if (ev) ev.saved = [...ev.saved, file];
      await refresh();
      toast(t(`Сохранено: ${file}`, `Saved: ${file}`), "ok");
    } catch (e) {
      toast(String(e));
    }
  }
</script>

<section class="card evo">
  <div class="label"><Dna size={11} /> {t("автоподбор", "auto-tune")} <span class="chip">{t("эксперимент", "experimental")}</span></div>
  <div class="hint faint mono">
    {t(
      "мутирует TCP-часть лучших стратегий (техника, pos, seqovl, repeats, порча, фейк) и проверяет тестером; каждый кандидат — дважды, засчитывается худший; при равенстве побеждает более простая",
      "mutates the TCP part of the best strategies (technique, pos, seqovl, repeats, fooling, fake) and checks with the tester; each candidate twice, the worst counts; on a tie the simpler wins",
    )}
  </div>
  <Segmented
    small
    options={[
      { value: "auto", label: t("Засев: лучшие из теста", "Seeds: best from the test") },
      { value: "manual", label: t("Засев: выбрать вручную", "Seeds: pick by hand") },
    ]}
    value={mode}
    disabled={busy || live}
    onchange={(v) => (mode = v as "auto" | "manual")}
  />
  {#if mode === "manual"}
    <div class="pick">
      <div class="pickhead mono">
        <span>{t(`выбрано ${manualValid.length} из ${MAX_SEEDS}`, `${manualValid.length} of ${MAX_SEEDS} picked`)}</span>
        {#each manualValid as f (f)}
          <button class="chip sel" disabled={busy || live} onclick={() => togglePick(f)} title={t("Убрать", "Remove")}>{strategyName(f)} <X size={10} /></button>
        {/each}
        <span class="grow"></span>
        <input class="input flt" spellcheck="false" placeholder={t("поиск", "search")} bind:value={filter} />
      </div>
      <div class="list mono">
        {#each shown as f (f)}
          {@const on = manualValid.includes(f)}
          <button class="item" class:on disabled={busy || live || (!on && manualValid.length >= MAX_SEEDS)} onclick={() => togglePick(f)}>
            <span class="nm">{strategyName(f)}</span>
            {#if okOf.has(f)}<span class="ok">ok {okOf.get(f)}</span>{/if}
          </button>
        {/each}
      </div>
      <div class="hint faint mono">
        {t(
          "любые стратегии, в том числе не из теста; рядом — результат последнего теста этого вида. Планка для сохранения — лучший результат засева в тесте (если он там был).",
          "any strategies, including ones outside the test; next to them — the last test result of this kind. The bar for saving is the seeds' best result in the test (if they were in it).",
        )}
      </div>
    </div>
  {:else if !(last?.finished && last.kind === kind)}
    <div class="first mono">
      {t(
        "Сначала прогоните обычный тест стратегий выше (тот же вид — стандартный или DPI): автоподбор возьмёт для засева 4 лучшие из него. Без теста засев — первые выбранные стратегии наугад.",
        "Run the regular strategy test above first (same kind — standard or DPI): auto-tune seeds from its 4 best. Without it the seeds are just the first selected strategies.",
      )}
    </div>
  {/if}
  <div class="row">
    <label class="mono rl">{t("раундов", "rounds")}
      <input class="input" type="number" min="1" max="5" bind:value={rounds} disabled={busy || live} />
    </label>
    <div class="seeds mono grow">
      {t("засев", "seeds")}: {seeds.map((s) => strategyName(s)).join(", ") || "—"}
      <div class="faint">~{planned} {t("кандидатов", "candidates")} · {t("десятки минут", "tens of minutes")}</div>
    </div>
    {#if live}
      <button class="btn danger" onclick={() => api.testCancel().then(() => toast(t("Останавливаю после текущего кандидата", "Stopping after the current candidate"), "ok"))}
        ><Square size={13} /> {t("Стоп", "Stop")}</button>
    {:else}
      <button class="btn" disabled={!ov.admin || busy || !seeds.length || app.busy} onclick={start}><Play size={13} /> {t("Подобрать", "Tune")}</button>
    {/if}
  </div>

  {#if ev}
    {#if live}
      <div class="mono progline">
        <span>{t("раунд", "round")} {ev.round}/{ev.rounds} · {ev.current ?? ""}</span>
        <span class="faint">{ev.done}/{ev.planned}{#if eta !== null} · {t("осталось", "left")} {etaText(eta)}{/if}</span>
      </div>
      <div class="bar"><span style="width:{(ev.done / Math.max(ev.planned, 1)) * 100}%"></span></div>
    {/if}
    {#if ev.message}<div class="msg mono">{ev.message}</div>{/if}
    {#if ev.hall.length}
      <div class="label sub">{t("лучшие", "best")}
        {#if ev.baseline}<span class="faint mono nocase">· {t("в тесте", "in the test")} {ev.baseline}{ev.ceiling !== null ? ` · ${t("потолок", "ceiling")} ${ev.ceiling}` : ""}</span>{/if}
      </div>
      {#each ev.hall as c (c.name)}
        <div class="cand">
          <div class="chead mono">
            <span class="cname">{c.seed ? strategyName(c.parent) : c.name}</span>
            {#if c.seed}<span class="chip">{t("засев", "seed")}</span>{:else}<span class="faint">← {strategyName(c.parent)}</span>{/if}
            {#if c.unstable}<span class="chip amber">{t("нестабильно", "unstable")}</span>{/if}
            <span class="grow"></span>
            {#if c.error}<span class="chip red">{t("не запустилась", "failed")}</span>{:else}<span class="score">ok {c.ok}</span>{/if}
            {#if !c.seed && !c.error && ev.finished}
              <button class="btn sm ghost" disabled={app.busy} title={t("Сохранить как стратегию", "Save as a strategy")} onclick={() => save(c.name)}><Save size={12} /></button>
            {/if}
          </div>
          {#if c.changes.length}
            <div class="changes mono faint">{c.changes.join(" · ")}</div>
          {/if}
        </div>
      {/each}
    {/if}
    {#if ev.saved.length}
      <div class="saved mono">
        {t("сохранено", "saved")}:
        {#each ev.saved as f (f)}
          <button class="btn sm" disabled={app.busy || ov.selected === f} onclick={() => act(() => api.selectStrategy(f), t("Стратегия выбрана", "Strategy selected"))}
            >{strategyName(f)} · {ov.selected === f ? t("выбрана", "selected") : t("применить", "apply")}</button>
        {/each}
      </div>
    {/if}
  {/if}
</section>

<style>
  .evo {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .label {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .nocase {
    text-transform: none;
    letter-spacing: 0;
  }
  .label.sub {
    margin-top: 4px;
  }
  .hint {
    font-size: 11px;
  }
  .first {
    font-size: 11.5px;
    color: var(--yellow);
    border-left: 2px solid var(--yellow);
    padding: 2px 0 2px 8px;
  }
  .row {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .rl {
    display: flex;
    flex-direction: column;
    gap: 3px;
    font-size: 11px;
    color: var(--muted);
    width: 70px;
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  .seeds {
    font-size: 11.5px;
  }
  .pick {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .pickhead {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    color: var(--muted);
  }
  .chip.sel {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    color: var(--text);
    border-color: var(--accent);
  }
  .flt {
    width: 160px;
    height: 26px;
  }
  .list {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
    gap: 4px;
    max-height: 190px;
    overflow: auto;
    padding: 2px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    font-size: 11.5px;
    text-align: left;
    color: var(--muted);
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .item:hover:not(:disabled) {
    border-color: var(--border);
    color: var(--text);
  }
  .item.on {
    color: var(--text);
    border-color: var(--accent);
  }
  .item:disabled:not(.on) {
    opacity: 0.45;
    cursor: default;
  }
  .nm {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ok {
    color: var(--sage);
    font-size: 11px;
  }
  .progline {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
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
    background: linear-gradient(90deg, var(--sage), var(--amber));
    transition: width 0.4s ease;
  }
  .msg {
    font-size: 12px;
    color: var(--muted);
  }
  .cand {
    border-top: 1px solid var(--border-soft);
    padding: 6px 0 2px;
  }
  .chead {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
  }
  .score {
    font-weight: 700;
    color: var(--sage);
  }
  .changes {
    font-size: 11px;
    margin-top: 3px;
    word-break: break-word;
  }
  .saved {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    font-size: 12px;
  }
</style>
