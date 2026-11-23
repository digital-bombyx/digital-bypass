<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, strategyName, type EvolveRun, type TestRun } from "$lib/api";
  import { app, act, toast, refresh } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { Dna, Play, Square, Save } from "@lucide/svelte";

  let { kind, picked, last, busy }: { kind: "standard" | "dpi"; picked: Set<string>; last: TestRun | null; busy: boolean } = $props();

  const ov = $derived(app.ov!);
  let ev = $state<EvolveRun | null>(null);
  let rounds = $state(3);
  const live = $derived(!!ev && !ev.finished);

  // Засев: 4 лучших из последнего теста того же вида, иначе первые 4 выбранных.
  const seeds = $derived.by(() => {
    const pickedList = ov.strategies.map((s) => s.file).filter((f) => picked.has(f));
    if (last?.finished && last.kind === kind && last.results.length) {
      const top = [...last.results].filter((r) => picked.has(r.file) && !r.error).sort((a, b) => b.ok - a.ok).map((r) => r.file);
      if (top.length) return top.slice(0, 4);
    }
    return pickedList.slice(0, 4);
  });
  // Оценка числа кандидатов: засев + раунды × зал славы (4) × 3 мутанта.
  const planned = $derived(seeds.length + rounds * 4 * 3);

  onMount(() => {
    api.evolveLast().then((r) => r && (ev = r));
    const un = [
      on<EvolveRun>("evolve-progress", (r) => (ev = r)),
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
  {#if !(last?.finished && last.kind === kind)}
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
        <span class="faint">{ev.done}/{ev.planned}</span>
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
