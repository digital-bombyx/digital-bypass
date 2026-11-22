<script lang="ts">
  import { onMount } from "svelte";
  import { api, type SniReport, type SniOutcome } from "$lib/api";
  import { toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { Radar, Loader, Copy, RotateCcw } from "@lucide/svelte";

  let target = $state("");
  let snis = $state("");
  let defaults = $state<{ target: string; snis: string[] } | null>(null);
  let timeout = $state(5);
  let busy = $state(false);
  let report = $state<SniReport | null>(null);
  let filter = $state<"all" | "pass" | "blocked">("all");

  onMount(async () => {
    try {
      defaults = await api.sniDefaults();
      target = defaults.target;
      snis = defaults.snis.join("\n");
    } catch (e) {
      toast(String(e));
    }
  });

  async function run() {
    if (busy) return;
    busy = true;
    report = null;
    try {
      report = await api.sniScan(target, snis, timeout);
    } catch (e) {
      toast(String(e));
    } finally {
      busy = false;
    }
  }

  const count = $derived(snis.split(/[\s,;]+/).filter((s) => s.includes(".") && !s.startsWith("#")).length);
  const shown = $derived(
    (report?.items ?? []).filter((i) => filter === "all" || (filter === "pass" ? i.outcome === "pass" : i.outcome === "reset" || i.outcome === "timeout")),
  );
  const outcomeText = (o: SniOutcome) =>
    ({ pass: t("проходит", "passes"), reset: t("сброс", "reset"), timeout: t("таймаут", "timeout"), no_tcp: t("нет TCP", "no TCP") })[o];
  const outcomeCls = (o: SniOutcome) => (o === "pass" ? "ok" : o === "no_tcp" ? "" : "bad");
  function copyPassed() {
    const list = (report?.items ?? []).filter((i) => i.outcome === "pass").map((i) => i.sni).join("\n");
    navigator.clipboard?.writeText(list).then(() => toast(t("Скопировано", "Copied"), "ok"));
  }
</script>

<div class="scan">
  <section class="card block">
    <div class="label">{t("сканер SNI", "SNI scanner")}</div>
    <p class="muted text">
      {t(
        "К одному адресу отправляется TLS-приветствие с разными именами сайтов. Если сервер ответил — DPI имя пропустил, если соединение сброшено или зависло — имя режется. Помогает понять, включены ли белые списки, и подобрать имя для VLESS Reality или поддельный SNI для стратегий.",
        "A TLS hello with different site names is sent to one address. If the server answers, DPI let the name through; a reset or a hang means the name is blocked. Helps to tell whether whitelists are on and to pick a name for VLESS Reality or a fake SNI for strategies.",
      )}
    </p>
    <div class="row">
      <label class="field">
        <span class="k mono">{t("адрес", "address")}</span>
        <input class="input" placeholder="104.16.132.229:443" bind:value={target} />
      </label>
      <label class="field small">
        <span class="k mono">{t("таймаут, с", "timeout, s")}</span>
        <input class="input" type="number" min="2" max="15" bind:value={timeout} />
      </label>
    </div>
    <div class="hint faint mono">
      {t(
        "По умолчанию — адрес Cloudflare: он отвечает на любое имя. Для подбора Reality укажите IP своего сервера.",
        "Default is a Cloudflare address: it answers any name. To pick a Reality name, enter your server's IP.",
      )}
    </div>
    <label class="field">
      <span class="k mono">{t("имена", "names")} · {count}</span>
      <textarea class="textarea" spellcheck="false" rows="6" bind:value={snis}></textarea>
    </label>
    <div class="actions">
      <button class="btn sm ghost" disabled={busy || !defaults} onclick={() => defaults && (snis = defaults.snis.join("\n"))} title={t("Вернуть список по умолчанию", "Restore the default list")}>
        <RotateCcw size={12} />
      </button>
      <span class="grow"></span>
      <button class="btn primary" disabled={busy || !target.trim() || !count} onclick={run}>
        {#if busy}<span class="spin"><Loader size={13} /></span>{:else}<Radar size={13} />{/if}
        {busy ? t("сканирую…", "scanning…") : t("сканировать", "scan")}
      </button>
    </div>
  </section>

  {#if report}
    <section class="card verdict" class:warn={report.whitelist_suspected}>
      <div class="vt">
        {report.passed} {t("проходят", "pass")} · {report.blocked} {t("режутся", "blocked")}
      </div>
      <div class="vx">
        {report.whitelist_suspected
          ? t("Похоже на белые списки: проходят почти только российские имена.", "Looks like whitelists: almost only Russian names pass.")
          : report.blocked
            ? t("Режутся отдельные имена — обычная блокировка DPI по SNI.", "Individual names are blocked — regular DPI blocking by SNI.")
            : t("Все имена проходят — фильтрации по SNI к этому адресу нет.", "All names pass — no SNI filtering to this address.")}
      </div>
    </section>

    <section class="card block">
      <div class="head">
        <div class="seg mono">
          <button class:on={filter === "all"} onclick={() => (filter = "all")}>{t("все", "all")}</button>
          <button class:on={filter === "pass"} onclick={() => (filter = "pass")}>{t("проходят", "pass")}</button>
          <button class:on={filter === "blocked"} onclick={() => (filter = "blocked")}>{t("режутся", "blocked")}</button>
        </div>
        <button class="btn sm ghost" disabled={!report.passed} onclick={copyPassed}><Copy size={12} /> {t("копировать проходящие", "copy passing")}</button>
      </div>
      <div class="grid mono">
        {#each shown as i (i.sni)}
          <div class="it" title={i.detail ?? ""}>
            <span class="sni">{i.sni}</span>
            <span class="chip {outcomeCls(i.outcome)}">{outcomeText(i.outcome)}{i.ms !== null ? ` · ${i.ms} ms` : ""}</span>
          </div>
        {/each}
      </div>
    </section>
  {/if}
</div>

<style>
  .scan {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .block {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .text {
    margin: 0;
    font-size: 12px;
    line-height: 1.5;
  }
  .row {
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
  .hint {
    font-size: 10.5px;
  }
  .actions,
  .head {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .head {
    justify-content: space-between;
  }
  .grow {
    flex: 1;
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
  .verdict {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    border-left: 3px solid var(--ok);
  }
  .verdict.warn {
    border-left-color: var(--warn);
  }
  .vt {
    font-weight: 700;
    font-size: 14px;
  }
  .vx {
    font-size: 12.5px;
  }
  .seg {
    display: flex;
    gap: 2px;
    padding: 2px;
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-sm);
    background: var(--bg);
  }
  .seg button {
    height: 22px;
    padding: 0 9px;
    border: 0;
    border-radius: 3px;
    background: transparent;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 10.5px;
    cursor: pointer;
  }
  .seg button.on {
    background: var(--panel-3);
    color: var(--text);
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 4px 16px;
  }
  .it {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    font-size: 11.5px;
    padding: 4px 0;
    border-bottom: 1px solid var(--border-soft);
  }
  .sni {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    user-select: text;
  }
  .chip.ok {
    color: var(--ok);
    border-color: rgba(63, 185, 120, 0.4);
    background: var(--ok-soft);
  }
  .chip.bad {
    color: var(--danger-text);
    border-color: var(--danger-line);
    background: var(--danger-soft);
  }
</style>
