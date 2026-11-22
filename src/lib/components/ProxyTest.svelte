<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, type ProxyVariant, type ProxyVariantResult } from "$lib/api";
  import { toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { FlaskConical, Loader, Square, Check } from "@lucide/svelte";

  let { current, apply }: { current: ProxyVariant; apply: (v: ProxyVariant, chain: ProxyVariant[]) => void } = $props();

  let targets = $state("");
  let timeout = $state(8);
  let running = $state(false);
  let total = $state(0);
  let results = $state<ProxyVariantResult[]>([]);
  let best = $state<ProxyVariant | null>(null);

  onMount(() => {
    api.proxyTestTargets().then((d) => (targets = d.join(" "))).catch(() => {});
    const un = on<{ done: number; total: number; result: ProxyVariantResult }>("proxy-test-progress", (p) => {
      total = p.total;
      results = [...results, p.result];
    });
    return () => {
      un.then((f) => f());
    };
  });

  async function run() {
    running = true;
    results = [];
    best = null;
    total = 17;
    try {
      const r = await api.proxyTest(targets, timeout);
      results = r.results;
      best = r.best;
      if (r.cancelled) toast(t("Подбор остановлен", "Test stopped"), "ok");
      else if (!r.best) toast(t("Ни один способ не открыл сайты — похоже на блокировку по IP", "No method opened the sites — looks like IP blocking"));
    } catch (e) {
      toast(String(e));
    } finally {
      running = false;
    }
  }

  const same = (a: ProxyVariant | null, b: ProxyVariant) =>
    !!a && a.split === b.split && a.unit === b.unit && a.disorder === b.disorder && a.oob === b.oob;
  const name = (v: ProxyVariant) => {
    const split = ({ sni: "SNI", "first-byte": t("первый байт", "first byte"), chunk: t("куски", "chunks"), random: t("случайно", "random"), none: t("без нарезки", "no split") } as Record<string, string>)[v.split];
    if (v.split === "none") return split;
    return `${split} · ${v.unit === "tcp" ? "TCP" : "TLS"}${v.disorder ? " · disorder" : ""}${v.oob ? " · OOB" : ""}`;
  };
  /** Выбранный способ — основной, следующие рабочие (до 4) — запасные для автоматического режима. */
  function pick(v: ProxyVariant) {
    const chain = sorted.filter((r) => r.ok > 0 && r.variant.split !== "none" && !same(v, r.variant)).slice(0, 4).map((r) => r.variant);
    apply(v, chain);
  }
  // Сначала лучшие: больше открытых, затем быстрее.
  const sorted = $derived(
    [...results].sort((a, b) => b.ok - a.ok || (a.avg_ms ?? 1e9) - (b.avg_ms ?? 1e9)),
  );
</script>

<section class="card block">
  <div class="row">
    <div>
      <div class="label"><FlaskConical size={11} /> {t("подбор способа", "find the best method")}</div>
      <div class="hint faint mono">
        {t("каждый вариант нарезки — на временном прокси; рабочий и системный прокси не трогаются", "each split variant runs on a temporary proxy; the working and system proxy are untouched")}
      </div>
    </div>
    {#if running}
      <button class="btn danger" onclick={() => api.proxyTestCancel()}><Square size={13} /> {t("Стоп", "Stop")}</button>
    {:else}
      <button class="btn primary" disabled={!targets.trim()} onclick={run}><FlaskConical size={13} /> {t("Запуск", "Run")}</button>
    {/if}
  </div>
  <div class="inputs">
    <label class="field">
      <span class="k mono">{t("сайты", "sites")}</span>
      <input class="input" bind:value={targets} disabled={running} placeholder="www.youtube.com x.com" />
    </label>
    <label class="field small">
      <span class="k mono">{t("таймаут, с", "timeout, s")}</span>
      <input class="input" type="number" min="3" max="20" bind:value={timeout} disabled={running} />
    </label>
  </div>

  {#if running || results.length}
    <div class="progress"><div class="bar" style="width: {total ? (results.length / total) * 100 : 0}%"></div></div>
    <div class="list mono">
      {#each sorted as r (name(r.variant))}
        <div class="it" class:best={same(best, r.variant)} class:cur={same(current, r.variant)}>
          <span class="nm">{name(r.variant)}</span>
          <span class="sites">
            {#each r.targets as tg (tg.host)}
              <span class="dot" class:ok={tg.ok} title={`${tg.host}: ${tg.ok ? `${tg.code} · ${tg.ms} ms` : tg.error}`}></span>
            {/each}
          </span>
          <span class="score" class:zero={!r.ok}>{r.ok}/{r.total}</span>
          <span class="ms faint">{r.avg_ms !== null ? `${r.avg_ms} ms` : "—"}</span>
          {#if same(current, r.variant)}
            <span class="chip sage"><Check size={10} /> {t("сейчас", "current")}</span>
          {:else if r.ok > 0 && !running}
            <button class="btn sm" class:primary={same(best, r.variant)} onclick={() => pick(r.variant)}>{t("Применить", "Apply")}</button>
          {:else}
            <span></span>
          {/if}
        </div>
      {/each}
      {#if running}
        <div class="it faint"><span class="spin"><Loader size={12} /></span> {results.length}/{total}</div>
      {/if}
    </div>
  {/if}
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
    font-size: 10.5px;
    margin-top: 3px;
  }
  .inputs {
    display: grid;
    grid-template-columns: 1fr 110px;
    gap: 8px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .k {
    font-size: 10.5px;
    color: var(--faint);
  }
  .progress {
    height: 3px;
    background: var(--panel-2);
  }
  .bar {
    height: 100%;
    background: var(--accent);
    transition: width 0.2s;
  }
  .list {
    display: flex;
    flex-direction: column;
  }
  .it {
    display: grid;
    grid-template-columns: minmax(220px, 1fr) auto 48px 70px 104px;
    gap: 12px;
    align-items: center;
    font-size: 11.5px;
    padding: 5px 6px;
    border-bottom: 1px solid var(--border-soft);
  }
  .it.best {
    background: var(--accent-soft);
  }
  .sites {
    display: flex;
    gap: 4px;
  }
  .dot {
    width: 8px;
    height: 8px;
    background: var(--danger);
    opacity: 0.8;
  }
  .dot.ok {
    background: var(--ok);
  }
  .score {
    text-align: right;
    font-weight: 700;
  }
  .score.zero {
    color: var(--faint);
    font-weight: 400;
  }
  .ms {
    text-align: right;
  }
  .spin {
    display: inline-grid;
    animation: spin 1s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
