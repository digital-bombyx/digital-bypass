<script lang="ts">
  import { type ProxyConfig } from "$lib/api";
  import { app, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import Switch from "./Switch.svelte";
  import { proxyWorkerCode, newWorkerKey } from "$lib/proxyWorker";
  import { Cloud, Copy, RefreshCw } from "@lucide/svelte";

  let { cfg, change, via }: { cfg: ProxyConfig; change: (p: Partial<ProxyConfig>) => void; via: number } = $props();

  let host = $state("");
  let key = $state("");
  let domains = $state("");
  let showHow = $state(false);
  $effect(() => {
    host = cfg.worker.host;
    key = cfg.worker.key;
    domains = cfg.rules.worker.join("\n");
  });

  const fromLines = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "")).filter(Boolean);
  const dirty = $derived(host !== cfg.worker.host || key !== cfg.worker.key || domains !== cfg.rules.worker.join("\n"));
  const ready = $derived(!!cfg.worker.host.trim() && !!cfg.worker.key.trim());

  function save() {
    change({ worker: { ...cfg.worker, host: host.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, ""), key: key.trim() }, rules: { ...cfg.rules, worker: fromLines(domains) } });
  }
  function gen() {
    key = newWorkerKey();
  }
  const code = $derived(proxyWorkerCode(key));
  const copy = () => navigator.clipboard?.writeText(code).then(() => toast(t("Код Worker'а скопирован — ключ уже вписан", "Worker code copied — the key is filled in"), "ok"));
</script>

<section class="card block">
  <div class="row">
    <div>
      <div class="label"><Cloud size={11} /> {t("через свой Cloudflare Worker", "through your Cloudflare Worker")}</div>
      <div class="hint faint mono">
        {t(
          "для сайтов, заблокированных по IP или с геоограничениями (Instagram, Facebook, Spotify, ИИ-сервисы): трафик к ним идёт через ваш Worker",
          "for sites blocked by IP or geo-restricted (Instagram, Facebook, Spotify, AI services): their traffic goes through your Worker",
        )}
      </div>
    </div>
    {#if ready}<span class="chip sage">{t("настроен", "set up")}{via ? ` · ${via}` : ""}</span>{:else}<span class="chip">{t("не настроен", "not set up")}</span>{/if}
  </div>
  <div class="grid">
    <label class="mono">
      <span class="k">{t("адрес Worker'а", "Worker address")}</span>
      <input class="input" spellcheck="false" placeholder="name.account.workers.dev" bind:value={host} disabled={app.busy} />
    </label>
    <label class="mono">
      <span class="k">{t("ключ", "key")}</span>
      <span class="keyrow">
        <input class="input" spellcheck="false" placeholder={t("тот же, что в коде Worker'а", "the same as in the Worker code")} bind:value={key} disabled={app.busy} />
        <button class="btn sm ghost" title={t("Новый ключ", "New key")} onclick={gen} disabled={app.busy}><RefreshCw size={12} /></button>
      </span>
    </label>
  </div>
  <label class="mono">
    <span class="k">{t("домены через Worker", "domains through the Worker")}</span>
    <textarea class="textarea" rows="4" spellcheck="false" placeholder="instagram.com&#10;cdninstagram.com&#10;facebook.com" bind:value={domains} disabled={app.busy}></textarea>
  </label>
  <div class="row">
    <div class="opt">
      <Switch checked={cfg.worker.fragment} disabled={app.busy} onchange={(v) => change({ worker: { ...cfg.worker, fragment: v } })} />
      <span class="hint mono">{t("нарезать ClientHello к Cloudflare (если workers.dev режут по имени)", "split the ClientHello to Cloudflare (if workers.dev is cut by name)")}</span>
    </div>
    <button class="btn sm" disabled={app.busy || !dirty} onclick={save}>{t("Сохранить", "Save")}</button>
  </div>
  <details class="how" bind:open={showHow}>
    <summary class="mono">{t("Как сделать свой Worker (бесплатно)", "How to make your own Worker (free)")}</summary>
    <ol class="text">
      <li>{t("Нажмите ↻ рядом с ключом — он сразу впишется в код ниже.", "Press ↻ next to the key — it goes straight into the code below.")}</li>
      <li>{t("dash.cloudflare.com → Compute → Workers & Pages → Create application → Start with Hello World! → Deploy.", "dash.cloudflare.com → Compute → Workers & Pages → Create application → Start with Hello World! → Deploy.")}</li>
      <li>{t("Edit code → вставьте код ниже → Deploy. Домен Worker'а (…workers.dev) — в поле «адрес Worker'а», затем «Сохранить».", "Edit code → paste the code below → Deploy. Put the Worker domain (…workers.dev) into “Worker address”, then Save.")}</li>
      <li>{t("Сайты, которые сами стоят за Cloudflare, через Worker не откроются (Cloudflare не подключается к своим адресам) — но они обычно и не заблокированы по IP.", "Sites that are themselves behind Cloudflare won't open through the Worker (Cloudflare does not connect to its own addresses) — but they are rarely IP-blocked anyway.")}</li>
      <li>{t("Бесплатный тариф — 100 000 запросов в день; каждое соединение — один запрос.", "The free plan gives 100,000 requests a day; each connection is one request.")}</li>
    </ol>
    <div class="code-head">
      <span class="k mono">worker.js</span>
      <button class="btn sm" onclick={copy}><Copy size={12} /> {t("Скопировать код", "Copy code")}</button>
    </div>
    <pre class="code mono">{code}</pre>
  </details>
</section>

<style>
  .block {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
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
    font-size: 11px;
    margin-top: 3px;
  }
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .k {
    font-size: 11px;
    color: var(--muted);
  }
  .keyrow {
    display: flex;
    gap: 6px;
  }
  .keyrow .input {
    flex: 1;
  }
  .opt {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .how summary {
    cursor: pointer;
    font-size: 12px;
    color: var(--muted);
  }
  .text {
    font-size: 12px;
    color: var(--muted);
    padding-left: 18px;
  }
  .code-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .code {
    max-height: 220px;
    overflow: auto;
    font-size: 11px;
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: 6px;
    padding: 8px 10px;
    white-space: pre;
    user-select: text;
  }
</style>
