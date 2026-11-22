<script lang="ts">
  import { onMount } from "svelte";
  import { api, type DnsCheckReport, type DnsDomainVerdict } from "$lib/api";
  import { toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { SearchCheck, Loader } from "@lucide/svelte";

  let { go }: { go: (tab: string) => void } = $props();

  let domains = $state("");
  let busy = $state(false);
  let report = $state<DnsCheckReport | null>(null);

  onMount(() => {
    api.dnsCheckDefaults().then((d) => (domains = d.join(" "))).catch(() => {});
  });

  async function run() {
    busy = true;
    report = null;
    try {
      report = await api.dnsCheck(domains);
    } catch (e) {
      toast(String(e));
    } finally {
      busy = false;
    }
  }

  const verdicts: Record<DnsDomainVerdict, { cls: string; text: () => string }> = {
    ok: { cls: "ok", text: () => t("честно", "genuine") },
    cdn: { cls: "ok", text: () => t("другой узел CDN", "another CDN node") },
    stub_system: { cls: "bad", text: () => t("заглушка провайдера", "ISP stub") },
    stub_intercepted: { cls: "bad", text: () => t("заглушка при перехвате", "stub via interception") },
    spoofed: { cls: "bad", text: () => t("подменённый адрес", "spoofed address") },
    differs: { cls: "warn", text: () => t("отличается, не проверить", "differs, unverified") },
    no_answer: { cls: "", text: () => t("нет ответа", "no answer") },
  };
  const reasonText = (r: string) => {
    if (r === "nowhere") return t("ответил адрес, где DNS-сервера нет", "an address with no DNS server answered");
    const [kind, a, b] = r.split(":");
    if (kind === "same") return t(`у ${a} и ${b} один и тот же исходящий адрес`, `${a} and ${b} share one egress address`);
    if (kind === "isp") return t(`${a} ходит с адреса резолвера провайдера`, `${a} uses the ISP resolver's address`);
    return r;
  };
</script>

<div class="dc">
  <section class="card block">
    <div class="label"><SearchCheck size={11} /> {t("подмена DNS провайдером", "DNS tampering by the ISP")}</div>
    <p class="muted text">
      {t(
        "Проверяет два вида подмены. Заглушки: DNS провайдера отдаёт на заблокированные домены 127.0.0.1 или чужие адреса. Перехват: запросы к 8.8.8.8, 1.1.1.1 и 9.9.9.9 по дороге забирает и отвечает сервер провайдера — тогда смена DNS в настройках не помогает. Эталон — зашифрованный запрос через DoT. Отличающиеся адреса проверяются сертификатом сайта.",
        "Checks two kinds of tampering. Stubs: the ISP's DNS answers blocked domains with 127.0.0.1 or foreign addresses. Interception: queries to 8.8.8.8, 1.1.1.1 and 9.9.9.9 are taken over on the way and answered by the ISP's server — then changing DNS in settings does not help. The reference is an encrypted DoT query. Differing addresses are verified by the site's certificate.",
      )}
    </p>
    <div class="row">
      <input class="input" bind:value={domains} disabled={busy} placeholder="rutracker.org www.instagram.com" />
      <button class="btn primary" disabled={busy} onclick={run}>
        {#if busy}<span class="spin"><Loader size={13} /></span>{:else}<SearchCheck size={13} />{/if}
        {busy ? t("Проверяю…", "Checking…") : t("Проверить", "Check")}
      </button>
    </div>
  </section>

  {#if report}
    {@const bad = report.intercepted || report.stubs > 0}
    <section class="card verdict" class:bad>
      <div class="vt">
        {#if report.intercepted}
          {t("Провайдер перехватывает DNS", "The ISP intercepts DNS")}
        {:else if report.stubs}
          {t(`DNS провайдера подменяет ответы: ${report.stubs}`, `The ISP's DNS tampers with answers: ${report.stubs}`)}
        {:else}
          {t("Подмены не найдено", "No tampering found")}
        {/if}
      </div>
      <div class="vx">
        {#if report.intercepted}
          {t("Обычный DNS к любым серверам ненадёжен — нужен зашифрованный: локальный резолвер с DoT или DoH в Windows 11.", "Plain DNS to any server is unreliable — use encrypted DNS: the local resolver with DoT or Windows 11 DoH.")}
        {:else if report.stubs}
          {t("Перехвата нет, поэтому поможет просто сменить DNS (например, на Cloudflare или Google), а надёжнее — зашифрованный DNS.", "There is no interception, so switching DNS (e.g. to Cloudflare or Google) helps; encrypted DNS is more reliable.")}
        {:else}
          {t("Если сайты не открываются, дело не в DNS — проверьте их во «Почему не открывается».", "If sites do not open, DNS is not the cause — check them in \"Why it does not open\".")}
        {/if}
      </div>
      {#if bad}
        <div class="go"><button class="btn sm" onclick={() => go("dns")}>{t("К DNS", "Go to DNS")}</button></div>
      {/if}
      {#if report.trusted_error}<div class="vx warnline">{report.trusted_error}</div>{/if}
    </section>

    <section class="card block">
      <div class="label">{t("перехват запросов", "query interception")}</div>
      <div class="grid mono">
        <span class="k">{t("резолвер провайдера", "ISP resolver")}</span>
        <span>{report.system_egress ?? "—"}</span>
        <span class="chip"></span>
        {#each report.resolvers as r (r.server)}
          <span class="k">{r.name} · {r.server}</span>
          <span>{r.answered ? `${t("выход", "egress")} ${r.egress ?? "?"} · ${r.ms} ms` : t("нет ответа", "no answer")}</span>
          <span class="chip" class:sage={r.answered && !report.intercepted} class:red={report.intercepted && r.answered}>{r.answered ? (report.intercepted ? t("подозр.", "suspect") : "ok") : "—"}</span>
        {/each}
        <span class="k">{t("адрес без DNS-сервера", "address with no DNS")}</span>
        <span>{report.nowhere_answered ? t("ответил — перехват", "answered — intercepted") : t("молчит, как и должен", "silent, as expected")}</span>
        <span class="chip" class:sage={!report.nowhere_answered} class:red={report.nowhere_answered}>{report.nowhere_answered ? "!" : "ok"}</span>
      </div>
      {#each report.intercept_reasons as r (r)}
        <div class="reason mono">• {reasonText(r)}</div>
      {/each}
    </section>

    <section class="card block">
      <div class="label">{t("ответы по доменам", "answers per domain")}</div>
      <div class="dhead mono faint">
        <span>{t("домен", "domain")}</span><span>{t("DNS провайдера", "ISP DNS")}</span><span>8.8.8.8</span><span>DoT</span><span></span>
      </div>
      {#each report.domains as d (d.domain)}
        {@const v = verdicts[d.verdict]}
        <div class="drow mono" title={d.cert_check ?? ""}>
          <span class="dn">{d.domain}</span>
          <span class="ips" class:hl={d.verdict === "stub_system" || d.verdict === "spoofed"}>{d.system.join(", ") || "—"}</span>
          <span class="ips" class:hl={d.verdict === "stub_intercepted"}>{d.public.join(", ") || "—"}</span>
          <span class="ips">{d.trusted.join(", ") || "—"}</span>
          <span class="chip {v.cls}">{v.text()}</span>
        </div>
      {/each}
    </section>
  {/if}
</div>

<style>
  .dc {
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
  .label {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .text {
    margin: 0;
    font-size: 12px;
    line-height: 1.5;
  }
  .row {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 8px;
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
    gap: 6px;
    border-left: 3px solid var(--ok);
  }
  .verdict.bad {
    border-left-color: var(--danger);
  }
  .vt {
    font-weight: 700;
    font-size: 14px;
  }
  .vx {
    font-size: 12.5px;
    line-height: 1.5;
  }
  .warnline {
    color: var(--warn);
  }
  .go {
    display: flex;
  }
  .grid {
    display: grid;
    grid-template-columns: minmax(180px, auto) 1fr auto;
    gap: 6px 14px;
    align-items: center;
    font-size: 12px;
  }
  .k {
    color: var(--muted);
  }
  .reason {
    font-size: 12px;
    color: var(--danger-text);
  }
  .dhead,
  .drow {
    display: grid;
    grid-template-columns: minmax(140px, 0.9fr) 1fr 1fr 1fr 150px;
    gap: 10px;
    font-size: 11.5px;
    align-items: center;
  }
  .drow {
    padding: 5px 0;
    border-top: 1px solid var(--border-soft);
  }
  .ips {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--muted);
    user-select: text;
  }
  .ips.hl {
    color: var(--danger-text);
  }
  .dn {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .chip.ok {
    color: var(--ok);
    border-color: rgba(63, 185, 120, 0.4);
    background: var(--ok-soft);
  }
  .chip.warn {
    color: var(--warn);
    border-color: rgba(210, 153, 34, 0.4);
    background: var(--warn-soft);
  }
  .chip.bad {
    color: var(--danger-text);
    border-color: var(--danger-line);
    background: var(--danger-soft);
  }
  .chip:empty {
    visibility: hidden;
  }
</style>
