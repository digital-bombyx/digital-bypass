<script lang="ts">
  import { api, strategyName, type GameFilter } from "$lib/api";
  import { app, act } from "$lib/state.svelte";
  import Segmented from "./Segmented.svelte";
  import { t } from "$lib/i18n.svelte";
  import { Power, ChevronDown, Search, TerminalSquare, Check } from "@lucide/svelte";

  const ov = $derived(app.ov!);
  const st = $derived(ov.status);
  const running = $derived(st.running);
  // Работающая стратегия важнее выбранной (служба могла быть поставлена из bat).
  const shown = $derived(st.running && st.strategy ? st.strategy : ov.selected);
  const shownInfo = $derived(ov.strategies.find((s) => s.file === shown));

  let open = $state(false);
  let q = $state("");
  let log = $state<string[] | null>(null);
  const filtered = $derived(
    ov.strategies.filter((s) => s.name.toLowerCase().includes(q.trim().toLowerCase())),
  );

  const modeLabel = (m: string) =>
    m === "process" ? t("процесс", "process") : m === "service" ? t("служба", "service") : m === "external" ? t("запущен извне", "external") : t("выключен", "off");

  async function toggle() {
    if (running) await act(() => api.disable());
    else await act(() => api.enable());
  }
  async function pick(file: string) {
    open = false;
    q = "";
    await act(() => api.selectStrategy(file), running ? t("Стратегия переключена", "Strategy switched") : undefined);
  }
  function setGf(mode: GameFilter["mode"]) {
    act(() => api.setGameFilter({ ...ov.game_filter, mode }));
  }
  async function showLog() {
    log = log ? null : await api.logTail();
  }
</script>

<div class="home fade-in">
  <!-- Герой: тумблер -->
  <section class="card hero">
    <div class="prompt mono">zapret2 · winws2</div>
    <button
      class="power"
      class:on={running}
      disabled={app.busy || !ov.admin || ov.testing}
      onclick={toggle}
      aria-label={running ? t("Выключить", "Turn off") : t("Включить", "Turn on")}>
      <svg viewBox="0 0 120 120" class="dial">
        <circle cx="60" cy="60" r="56" class="dash" />
        <circle cx="60" cy="60" r="46" class="track" />
      </svg>
      <span class="core"><Power size={30} strokeWidth={2.2} /></span>
    </button>
    <div class="state-line mono">
      {#if app.busy}
        <span class="muted">…</span>
      {:else if running}
        <span class="on">● {modeLabel(st.mode)}</span>
      {:else}
        <span class="faint">○ {t("выключен", "off")}</span>
      {/if}
    </div>
    <h1 class="mono">{strategyName(shown) || "—"}</h1>
    {#if shownInfo?.methods.length}
      <div class="methods mono" title={t("Техники обхода (--lua-desync) этой стратегии", "Bypass techniques (--lua-desync) of this strategy")}>
        {shownInfo.methods.join(" · ")}
      </div>
    {/if}
  </section>

  {#if st.mode === "external"}
    <div class="note card">
      {t("winws2 запущен не из GUI (bat-файлом).", "winws2 was started outside the GUI (by a bat file).")}
      <button class="btn sm danger" disabled={app.busy} onclick={() => act(() => api.disable())}>{t("Остановить", "Stop")}</button>
    </div>
  {/if}

  {#if st.last_error}
    <div class="note card err">
      <div class="err-text mono">{st.last_error}</div>
      <button class="btn sm ghost" onclick={showLog}><TerminalSquare size={13} /> {t("Лог", "Log")}</button>
    </div>
  {/if}
  {#if log}
    <pre class="log card mono">{log.length ? log.join("\n") : t("вывод winws2 пуст", "winws2 output is empty")}</pre>
  {/if}

  <!-- Выбор стратегии -->
  <section class="card picker" class:open>
    <button class="current" onclick={() => (open = !open)}>
      <span class="label">{t("Стратегия", "Strategy")}</span>
      <span class="mono name">{strategyName(ov.selected)}</span>
      <span class="count faint mono">{ov.strategies.length}</span>
      <ChevronDown size={16} class="chev" />
    </button>
    {#if open}
      <div class="list">
        <div class="search">
          <Search size={14} />
          <!-- svelte-ignore a11y_autofocus -->
          <input class="input" placeholder="ALT, FAKE TLS…" bind:value={q} autofocus />
        </div>
        <div class="rows">
          {#each filtered as s (s.file)}
            <button class="row" class:sel={s.file === ov.selected} onclick={() => pick(s.file)}>
              <span class="mono">{s.name}</span>
              {#if s.file === ov.selected}<Check size={14} />{/if}
            </button>
          {:else}
            <div class="faint mono empty">{t("ничего не найдено", "nothing found")}</div>
          {/each}
        </div>
      </div>
    {/if}
  </section>

  <!-- Быстрые настройки -->
  <section class="card opts">
    <div class="opt">
      <div>
        <div class="label">game filter</div>
        <div class="hint faint mono">
          {ov.game_filter.mode === "disabled" ? t("игровые порты не трогаем", "game ports untouched") : `tcp ${ov.game_filter.tcp} · udp ${ov.game_filter.udp}`}
        </div>
      </div>
      <Segmented
        small
        disabled={app.busy || ov.testing}
        value={ov.game_filter.mode}
        onchange={setGf}
        options={[
          { value: "disabled", label: t("Выкл", "Off") },
          { value: "all", label: "TCP+UDP" },
          { value: "tcp", label: "TCP" },
          { value: "udp", label: "UDP" },
        ]} />
    </div>
    <div class="opt">
      <div>
        <div class="label">ipset</div>
        <div class="hint faint mono">
          {ov.ipset === "loaded" ? t("по списку IP", "IP list") : ov.ipset === "any" ? t("все IP", "all IPs") : t("выключен", "off")}
        </div>
      </div>
      <Segmented
        small
        disabled={app.busy || ov.testing}
        value={ov.ipset}
        onchange={(m) => act(() => api.setIpset(m))}
        options={[
          { value: "loaded", label: t("Список", "List") },
          { value: "none", label: t("Выкл", "Off") },
          { value: "any", label: t("Все", "All") },
        ]} />
    </div>
    <div class="opt">
      <div>
        <div class="label">{t("режим", "mode")}</div>
        <div class="hint faint mono">{ov.mode === "service" ? t("служба, работает без GUI", "service, runs without the GUI") : t("процесс, пока открыт GUI", "process, while the GUI is open")}</div>
      </div>
      <Segmented
        small
        disabled={app.busy || ov.testing}
        value={ov.mode}
        onchange={(m) => act(() => api.setMode(m))}
        options={[
          { value: "process", label: t("Процесс", "Process") },
          { value: "service", label: t("Служба", "Service") },
        ]} />
    </div>
  </section>
</div>

<style>
  .home {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .hero {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 16px 18px 18px;
  }
  .prompt {
    align-self: flex-start;
    font-size: 12px;
    color: var(--muted);
  }
  .power {
    position: relative;
    width: 132px;
    height: 132px;
    margin: 6px 0 4px;
    border: 0;
    background: transparent;
    cursor: pointer;
    display: grid;
    place-items: center;
  }
  .power:disabled {
    cursor: default;
    opacity: 0.6;
  }
  .dial {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
  }
  .dial .dash {
    fill: none;
    stroke: var(--faint);
    stroke-width: 1;
    stroke-dasharray: 1 5.4;
    opacity: 0.6;
    transform-origin: 60px 60px;
    transition: stroke 0.3s, opacity 0.3s;
  }
  .dial .track {
    fill: none;
    stroke: var(--border);
    stroke-width: 3;
    transition: stroke 0.2s;
  }
  .power.on .dash {
    stroke: var(--accent);
    opacity: 0.8;
  }
  .power.on .track {
    stroke: var(--amber);
  }
  .core {
    width: 76px;
    height: 76px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    color: var(--faint);
    background: var(--panel-2);
    border: 1px solid var(--border);
    transition: color 0.3s, background 0.3s, transform 0.15s;
  }
  .power:not(:disabled):hover .core {
    color: var(--text);
    border-color: var(--border-strong);
  }
  .power.on .core {
    color: #06121f;
    background: var(--accent);
    border-color: var(--accent);
  }
  .state-line {
    font-size: 12px;
    height: 16px;
  }
  .state-line .on {
    color: var(--sage);
  }
  h1 {
    margin: 4px 0 8px;
    font-size: 19px;
    font-weight: 700;
    letter-spacing: -0.01em;
    text-align: center;
  }
  .methods {
    font-size: 11.5px;
    color: var(--muted);
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .note {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 10px 12px;
    font-size: 12px;
    color: var(--muted);
  }
  .note.err {
    align-items: flex-start;
    border-color: rgba(229, 83, 75, 0.35);
    background: var(--red-soft);
  }
  .err-text {
    white-space: pre-wrap;
    font-size: 11.5px;
    color: var(--danger-text);
    max-height: 90px;
    overflow: auto;
    user-select: text;
  }
  .log {
    margin: 0;
    padding: 10px 12px;
    font-size: 11px;
    max-height: 160px;
    overflow: auto;
    white-space: pre-wrap;
    color: var(--muted);
    user-select: text;
  }

  .picker {
    overflow: hidden;
  }
  .current {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 14px;
    border: 0;
    background: transparent;
    color: var(--text);
    cursor: pointer;
    text-align: left;
  }
  .current .name {
    flex: 1;
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .current .count {
    font-size: 11.5px;
  }
  .current :global(.chev) {
    color: var(--muted);
    transition: transform 0.2s;
  }
  .open .current :global(.chev) {
    transform: rotate(180deg);
  }
  .list {
    border-top: 1px solid var(--border-soft);
    padding: 10px;
  }
  .search {
    position: relative;
    display: flex;
    align-items: center;
    color: var(--faint);
  }
  .search :global(svg) {
    position: absolute;
    left: 10px;
  }
  .search .input {
    padding-left: 30px;
  }
  .rows {
    margin-top: 8px;
    max-height: 230px;
    overflow: auto;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 10px;
    border: 0;
    border-radius: var(--radius);
    background: transparent;
    color: var(--text);
    font-size: 12px;
    cursor: pointer;
    text-align: left;
  }
  .row:hover {
    background: var(--panel-2);
  }
  .row.sel {
    background: var(--amber-soft);
    color: var(--amber-2);
  }
  .empty {
    padding: 10px;
    font-size: 12px;
  }

  .opts {
    padding: 4px 14px;
  }
  .opt {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 0;
  }
  .opt + .opt {
    border-top: 1px solid var(--border-soft);
  }
  .hint {
    font-size: 11px;
    margin-top: 3px;
  }
</style>
