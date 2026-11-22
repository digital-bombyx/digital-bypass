<script lang="ts">
  import { onMount } from "svelte";
  import { api, on, type NetStatus, type NetRules } from "$lib/api";
  import { app, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import Switch from "./Switch.svelte";
  import Segmented from "./Segmented.svelte";

  let st = $state<NetStatus | null>(null);
  let text = $state("");

  async function load() {
    try {
      st = await api.netStatus();
      text = st.rules.networks.join("\n");
    } catch (e) {
      toast(String(e));
    }
  }
  async function save(patch: Partial<NetRules>) {
    if (!st) return;
    try {
      st = await api.netSet({ ...st.rules, ...patch });
      text = st.rules.networks.join("\n");
    } catch (e) {
      toast(String(e));
    }
  }
  const lines = (s: string) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  function add(name: string) {
    if (!st || st.rules.networks.some((n) => n.toLowerCase() === name.toLowerCase())) return;
    save({ networks: [...st.rules.networks, name] });
  }

  onMount(() => {
    load();
    const un = on("net-changed", load);
    return () => {
      un.then((f) => f());
    };
  });
</script>

{#if st}
  <section class="card blk">
    <div class="line">
      <div>
        <div class="t">{t("Включение по сети", "Per-network switching")}</div>
        <div class="hint faint mono">{t("при смене сети останавливать или возвращать обход; ручное включение не мешает", "stop or resume the bypass when the network changes; manual switching still works")}</div>
      </div>
      <Switch checked={st.rules.enabled} disabled={app.busy} onchange={(v) => save({ enabled: v })} />
    </div>
    {#if st.rules.enabled}
      <div class="line">
        <Segmented
          small
          value={st.rules.mode}
          onchange={(m: "only" | "except") => save({ mode: m })}
          options={[
            { value: "except", label: t("Везде, кроме", "Everywhere except") },
            { value: "only", label: t("Только в этих", "Only in these") },
          ]} />
        <div class="mods">
          <label class="mono"><input type="checkbox" checked={st.rules.zapret} onchange={(e) => save({ zapret: e.currentTarget.checked })} /> zapret2</label>
          <label class="mono"><input type="checkbox" checked={st.rules.proxy} onchange={(e) => save({ proxy: e.currentTarget.checked })} /> {t("Прокси", "Proxy")}</label>
        </div>
      </div>
      <textarea class="input mono" rows="3" bind:value={text} onblur={() => save({ networks: lines(text) })}
        placeholder={t("имя сети в строке, напр. HomeWiFi", "one network name per line, e.g. HomeWiFi")}></textarea>
      <div class="hint faint mono now">
        {t("сейчас", "now")}:
        {#each st.current as n (n)}
          <button class="btn sm ghost" title={t("Добавить в список", "Add to the list")} onclick={() => add(n)}>+ {n}</button>
        {:else}
          {t("нет подключения", "not connected")}
        {/each}
        · {st.allowed ? t("обход разрешён", "bypass allowed") : t("обход выключен правилом", "bypass off by rule")}
      </div>
    {/if}
  </section>
{/if}

<style>
  .blk {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .line {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
  }
  .t {
    font-size: 13px;
  }
  .hint {
    font-size: 11px;
    margin-top: 4px;
  }
  .mods {
    display: flex;
    gap: 14px;
    font-size: 12px;
  }
  .mods label {
    display: flex;
    align-items: center;
    gap: 5px;
  }
  textarea {
    resize: vertical;
    font-size: 12px;
  }
  .now {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
</style>
