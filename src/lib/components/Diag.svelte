<script lang="ts">
  import { api, type DiagReport, type Probe, type Verdict } from "$lib/api";
  import { toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import { Search, Loader } from "@lucide/svelte";
  import Segmented from "./Segmented.svelte";
  import SniScan from "./SniScan.svelte";
  import DnsCheck from "./DnsCheck.svelte";

  let { go }: { go: (tab: string) => void } = $props();

  let mode = $state<"site" | "dns" | "sni">("site");
  let domain = $state("");
  let busy = $state(false);
  let report = $state<DiagReport | null>(null);

  async function run() {
    if (!domain.trim() || busy) return;
    busy = true;
    report = null;
    try {
      report = await api.diagRun(domain);
    } catch (e) {
      toast(String(e));
    } finally {
      busy = false;
    }
  }

  const verdicts: Record<Verdict, { cls: string; title: () => string; text: () => string; tabs: [string, () => string][] }> = {
    ok: {
      cls: "ok",
      title: () => t("Открывается", "Reachable"),
      text: () => t("TLS-соединение с сайтом устанавливается. Если сайт всё равно не работает, дело не в блокировке соединения.", "A TLS connection to the site succeeds. If it still does not work, the cause is not connection blocking."),
      tabs: [],
    },
    dns: {
      cls: "warn",
      title: () => t("Подмена DNS", "DNS spoofing"),
      text: () => t("Системный DNS отдаёт неправильный адрес, а настоящий адрес из DoH работает. Поможет смена DNS или DoH.", "The system DNS returns a wrong address while the real one from DoH works. Changing DNS or using DoH helps."),
      tabs: [["dns", () => t("к DNS", "go to DNS")]],
    },
    dpi: {
      cls: "warn",
      title: () => t("Блокировка DPI по имени сайта", "DPI blocking by site name"),
      text: () => t("TCP подключается, но TLS-рукопожатие обрывается или висит. Поможет zapret2 или прокси-обходчик.", "TCP connects but the TLS handshake is reset or hangs. zapret2 or the bypass proxy helps."),
      tabs: [["home", () => "zapret2"], ["proxy", () => t("прокси", "proxy")]],
    },
    ip: {
      cls: "bad",
      title: () => t("Блокировка по IP", "IP blocking"),
      text: () => t("Ни к одному адресу сайта не подключиться. Обход DPI и смена DNS тут не помогут — нужен VPN.", "No address of the site accepts connections. DPI bypass and DNS will not help — a VPN is needed."),
      tabs: [],
    },
    dest_net: {
      cls: "bad",
      title: () => t("Ограничение по сети назначения", "Destination-network restriction"),
      text: () =>
        t(
          "Режут адрес, а не имя сайта: TLS к нему обрывается с любым именем (а это имя на постороннем адресе проходит), либо передача замирает после ~16–33 КБ без сброса. Так с 2025 года ограничивают зарубежные хостинги по сети назначения (Hetzner, OVH, DigitalOcean, Vultr, Scaleway и др.). Нарезка zapret2 и прокси не поможет — нужен VPN с UDP-транспортом или сервер в другой сети.",
          "The address is cut, not the site name: TLS to it fails with any name (while this name passes on another address), or the transfer stalls after ~16–33 KB without a reset. Since 2025 foreign hostings are restricted this way by destination network (Hetzner, OVH, DigitalOcean, Vultr, Scaleway, etc.). zapret2 and proxy splitting won't help — a VPN over UDP or a server in another network will.",
        ),
      tabs: [],
    },
    no_domain: {
      cls: "bad",
      title: () => t("Домен не найден", "Domain not found"),
      text: () => t("Имя не разрешается ни системным DNS, ни через DoH. Проверьте написание.", "Neither the system DNS nor DoH resolves the name. Check the spelling."),
      tabs: [],
    },
    unknown: {
      cls: "",
      title: () => t("Не удалось определить", "Inconclusive"),
      text: () => t("Результаты противоречивы. Посмотрите подробности ниже.", "Results are inconsistent. See the details below."),
      tabs: [],
    },
  };

  const probeText = (p: Probe) =>
    ({
      ok: "ok",
      tcp_fail: t("нет TCP", "no TCP"),
      tls_reset: t("TLS сброшен", "TLS reset"),
      tls_timeout: t("TLS таймаут", "TLS timeout"),
      tls_cert: t("чужой сертификат", "wrong certificate"),
      tls_error: t("ошибка TLS", "TLS error"),
    })[p];
  const probeCls = (p: Probe) => (p === "ok" ? "ok" : p === "tcp_fail" ? "bad" : "warn");
  const srcText = (s: string) => (s === "both" ? t("оба", "both") : s === "system" ? t("система", "system") : "doh");
</script>

<div class="diag fade-in">
  <Segmented
    value={mode}
    onchange={(m) => (mode = m)}
    options={[
      { value: "site", label: t("Почему не открывается", "Why it does not open") },
      { value: "dns", label: t("Подмена DNS", "DNS tampering") },
      { value: "sni", label: t("Сканер SNI", "SNI scanner") },
    ]} />
  {#if mode === "sni"}
    <SniScan />
  {:else if mode === "dns"}
    <DnsCheck {go} />
  {:else}
  <section class="card block">
    <div class="label">{t("почему не открывается сайт", "why a site does not open")}</div>
    <div class="row">
      <input
        class="input"
        placeholder="youtube.com"
        bind:value={domain}
        onkeydown={(e) => e.key === "Enter" && run()} />
      <button class="btn primary" disabled={busy || !domain.trim()} onclick={run}>
        {#if busy}<span class="spin"><Loader size={13} /></span>{:else}<Search size={13} />{/if}
        {t("Проверить", "Check")}
      </button>
    </div>
    <div class="hint faint mono">
      {t("Сравнивает системный DNS с DoH и пробует TCP и TLS к каждому адресу. Если zapret2 включён, он влияет на результат.", "Compares the system DNS with DoH and tries TCP and TLS to each address. A running zapret2 affects the result.")}
    </div>
  </section>

  {#if report}
    {@const v = verdicts[report.verdict]}
    <section class="card verdict {v.cls}">
      <div class="vt">{v.title()}</div>
      <div class="vx">{v.text()}</div>
      {#if report.system_bogus && report.verdict !== "dns"}
        <div class="vx muted">{t("Кроме того, системный DNS отдаёт заглушку — стоит сменить и DNS.", "Also, the system DNS returns a stub address — change DNS as well.")}</div>
      {/if}
      {#if report.verdict === "dpi" && report.stage}
        <div class="vx">
          {#if report.stage === "request"}
            {t("Режут по вашему запросу (имя сайта в ClientHello): сервер ничего не успел ответить. Нарезка запроса — прокси или zapret2 — как раз против этого.", "Your request is cut (site name in ClientHello): the server never replied. Splitting the request — proxy or zapret2 — targets exactly this.")}
          {:else}
            {t("Режут по ответу сервера (сертификат): сервер ответил, потом соединение оборвали. Нарезка запроса тут обычно не помогает.", "The server's reply is cut (certificate): the server answered, then the connection was killed. Splitting the request usually doesn't help here.")}
          {/if}
        </div>
      {/if}
      {#if report.extra}
        {@const x = report.extra}
        <ul class="facts">
          {#if x.split_ok !== null}
            <li class:good={x.split_ok}>{x.split_ok ? t("С нарезкой ClientHello открывается — подойдёт прокси.", "Opens with a split ClientHello — the proxy will do.") : t("С нарезкой ClientHello тоже не открывается.", "Doesn't open with a split ClientHello either.")}</li>
          {/if}
          {#if x.small_buf_ok !== null}
            <li class:good={x.small_buf_ok}>{x.small_buf_ok ? t("С маленьким буфером приёма открывается — включите его в настройках прокси.", "Opens with a small receive buffer — enable it in the proxy settings.") : t("Маленький буфер приёма не помог.", "A small receive buffer didn't help.")}</li>
          {/if}
          {#if x.ip_clean !== null}
            <li>{x.ip_clean ? t(`Адрес ${x.ip} с другим именем отвечает — режут именно имя сайта.`, `Address ${x.ip} answers with another name — it's the site name that is cut.`) : t(`Адрес ${x.ip} режется и с другим именем — частичная блокировка по IP.`, `Address ${x.ip} is cut with another name too — partial IP block.`)}</li>
          {/if}
          {#if x.name_anywhere !== null}
            <li>{x.name_anywhere ? t("Имя сайта режется и на постороннем адресе (1.1.1.1) — DPI ищет его везде.", "The name is cut on an unrelated address (1.1.1.1) too — DPI looks for it everywhere.") : t("На постороннем адресе (1.1.1.1) имя проходит — DPI следит только за адресами сайта.", "On an unrelated address (1.1.1.1) the name passes — DPI watches only the site's addresses.")}</li>
          {/if}
        </ul>
      {/if}
      {#if report.checks.some((c) => c.unstable)}
        <div class="vx muted">{t("Повторы проверки дали разный результат — у провайдера балансировка или несколько DPI. Засчитан худший.", "Repeated checks disagreed — the ISP balances traffic or runs several DPIs. The worst result is shown.")}</div>
      {/if}
      {#if v.tabs.length}
        <div class="go">
          {#each v.tabs as [id, label] (id)}
            <button class="btn sm" onclick={() => go(id)}>{label()}</button>
          {/each}
        </div>
      {/if}
    </section>

    <section class="card block">
      <div class="label">dns</div>
      <div class="kv mono">
        <span class="k">{t("система", "system")}</span>
        <span class="v">
          {#if report.system.length}{report.system.join(", ")}{:else}<span class="faint">{report.system_error ?? "—"}</span>{/if}
          {#if report.system_bogus}<span class="chip red">{t("заглушка", "stub")}</span>{/if}
        </span>
      </div>
      <div class="kv mono">
        <span class="k">doh</span>
        <span class="v">{#if report.doh.length}{report.doh.join(", ")}{:else}<span class="faint">{report.doh_error ?? "—"}</span>{/if}</span>
      </div>
    </section>

    {#if report.checks.length}
      <section class="card block">
        <div class="label">{t("соединения :443", "connections :443")}</div>
        {#each report.checks as c (c.ip)}
          <div class="chk mono" title={c.detail ?? ""}>
            <span class="ip">{c.ip}</span>
            <span class="src faint">{srcText(c.source)}</span>
            <span class="chip {probeCls(c.result)}">{probeText(c.result)}{c.ms !== null ? ` · ${c.ms} ms` : ""}</span>
            {#if c.stage}<span class="faint">{c.stage === "request" ? t("на запросе", "on request") : t("на ответе", "on reply")}</span>{/if}
            {#if c.unstable}<span class="chip">{t("нестабильно", "unstable")}</span>{/if}
          </div>
        {/each}
      </section>
    {/if}
  {/if}
  {/if}
</div>

<style>
  .diag {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .facts {
    margin: 0;
    padding-left: 18px;
    display: flex;
    flex-direction: column;
    gap: 3px;
    font-size: 12.5px;
  }
  .facts li.good {
    color: var(--green, #4ade80);
  }
  .block {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .row {
    display: flex;
    gap: 8px;
  }
  .hint {
    font-size: 11px;
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
    border-left: 3px solid var(--border-strong);
  }
  .verdict.ok {
    border-left-color: var(--ok);
  }
  .verdict.warn {
    border-left-color: var(--warn);
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
    color: var(--text);
  }
  .vx.muted {
    color: var(--muted);
  }
  .go {
    display: flex;
    gap: 6px;
    margin-top: 2px;
  }
  .kv {
    display: grid;
    grid-template-columns: 64px 1fr;
    gap: 8px;
    font-size: 12px;
  }
  .k {
    color: var(--faint);
  }
  .v {
    word-break: break-all;
    user-select: text;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
  }
  .chk {
    display: grid;
    grid-template-columns: 1fr auto auto;
    gap: 10px;
    align-items: center;
    font-size: 12px;
    padding-top: 6px;
    border-top: 1px solid var(--border-soft);
  }
  .ip {
    overflow: hidden;
    text-overflow: ellipsis;
    user-select: text;
  }
  .src {
    font-size: 11px;
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
</style>
