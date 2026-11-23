<script lang="ts">
  import { api } from "$lib/api";
  import { app, act, toast } from "$lib/state.svelte";
  import Switch from "./Switch.svelte";
  import Segmented from "./Segmented.svelte";
  import NetRules from "./NetRules.svelte";
  import McpCard from "./McpCard.svelte";
  import { t, i18n, type Lang } from "$lib/i18n.svelte";
  import { FolderOpen, Power } from "@lucide/svelte";

  const ov = $derived(app.ov!);
  // Поле — только для своей папки; встроенная выбирается кнопкой.
  let dir = $state(app.ov?.dir_source === "bundled" ? "" : (app.ov?.dir ?? ""));
  const sourceLabel = $derived(
    ov.dir_source === "bundled" ? t("встроенная", "bundled") : ov.dir_source === "custom" ? t("своя папка", "custom folder") : t("найдена на диске", "found on disk"),
  );
  let timeout = $state(app.ov?.test_timeout ?? 4);
  let parallel = $state(app.ov?.test_parallel ?? 16);

  async function saveDir() {
    await act(() => api.setZapretDir(dir), t("Папка сохранена", "Folder saved"));
  }
  async function saveTest() {
    await act(() => api.setTestParams(Number(timeout), Number(parallel)), t("Сохранено", "Saved"));
  }
</script>

<div class="settings fade-in">
  <section class="card blk">
    <div class="head">
      <div class="label">zapret-discord-youtube</div>
      <span class="chip" class:sage={ov.dir_source === "bundled"} class:amber={ov.dir_source !== "bundled"}>{sourceLabel}</span>
    </div>
    <div class="hint faint mono">
      {ov.dir ? `${t("сборка", "build")} ${ov.version ?? "?"} · ${ov.strategies.length} ${t("стратегий", "strategies")}` : t("сборка не найдена", "build not found")}
      {#if ov.bundled_version}· {t("встроена", "bundled")} {ov.bundled_version}{/if}
    </div>
    <div class="dirrow">
      <input class="input" bind:value={dir} placeholder={t("своя папка, напр. D:\\zapret-discord-youtube", "custom folder, e.g. D:\\zapret-discord-youtube")} />
      <button class="btn sm" disabled={!dir.trim() || dir === ov.dir} onclick={saveDir}>ok</button>
      <button class="btn sm ghost" disabled={!ov.dir} title={t("Открыть папку", "Open folder")}
        onclick={() => ov.dir && api.openPath(ov.dir).catch((e) => toast(String(e)))}><FolderOpen size={13} /></button>
    </div>
    {#if ov.dir_source !== "bundled" && ov.bundled_version}
      <button class="btn sm ghost back" disabled={app.busy}
        onclick={() => act(() => api.setZapretDir("").then(() => (dir = "")), t("Используется встроенная сборка", "Using the bundled build"))}
        >← {t("Вернуться к встроенной", "Back to bundled")}</button>
    {/if}
    {#if ov.bundle_error}
      <div class="berr mono">{ov.bundle_error}</div>
    {/if}
  </section>

  <section class="card blk">
    <div class="line">
      <div>
        <div class="t">{t("Язык", "Language")}</div>
        <div class="hint faint mono">{t("интерфейс и меню трея", "interface and tray menu")}</div>
      </div>
      <Segmented
        small
        value={i18n.lang}
        onchange={(l: Lang) => {
          i18n.lang = l;
          api.setLanguage(l);
        }}
        options={[
          { value: "ru", label: "Русский" },
          { value: "en", label: "English" },
        ]} />
    </div>
    <div class="line">
      <div>
        <div class="t">{t("Запускать вместе с Windows", "Start with Windows")}</div>
        <div class="hint faint mono">{t("задача планировщика, GUI стартует в трее и включает обход, если он был включён", "scheduled task; the GUI starts in the tray and re-enables the bypass if it was on")}</div>
      </div>
      <Switch checked={ov.autostart} disabled={app.busy || !ov.admin} onchange={(v) => act(() => api.setAutostart(v))} />
    </div>
    <div class="line">
      <div>
        <div class="t">{t("Крестик сворачивает в трей", "Close button hides to tray")}</div>
        <div class="hint faint mono">{t("окно выгружается из памяти, обход работает дальше; иначе крестик завершает приложение", "the window is unloaded from memory, the bypass keeps running; otherwise closing quits the app")}</div>
      </div>
      <Switch checked={ov.close_to_tray} disabled={app.busy} onchange={(v) => act(() => api.setCloseToTray(v))} />
    </div>
    <div class="line">
      <div>
        <div class="t">{t("Служба zapret", "zapret service")}</div>
        <div class="hint faint mono">
          {ov.status.service_installed ? t("установлена", "installed") : t("не установлена", "not installed")} · {t("режим «служба» переключается на главной", "service mode is switched on the main tab")}
        </div>
      </div>
      {#if ov.status.service_installed}
        <button class="btn sm danger" disabled={app.busy || !ov.admin} onclick={() => act(() => api.disable(), t("Служба удалена", "Service removed"))}
          >{t("Удалить", "Remove")}</button>
      {/if}
    </div>
  </section>

  <NetRules />

  <McpCard />

  <section class="card blk">
    <div class="label">{t("тесты", "tests")}</div>
    <div class="grid">
      <label class="mono">{t("таймаут, с", "timeout, s")} <input class="input" type="number" min="2" max="30" bind:value={timeout} /></label>
      <label class="mono">{t("потоков", "threads")} <input class="input" type="number" min="1" max="32" bind:value={parallel} /></label>
      <button class="btn sm" onclick={saveTest}>ok</button>
    </div>
  </section>

  <button class="btn ghost quit" onclick={() => api.quit()}><Power size={13} /> {t("Выйти из приложения", "Quit the app")}</button>
  <!-- Сведения об авторстве (GPL-3.0, NOTICE: дополнительное условие 7b). Не удалять в форках. -->
  <div class="foot faint mono">
    digital-bypass by digital-bombyx · GPL-3.0<br />
    <span class="url">github.com/digital-bombyx/digital-bypass</span>
  </div>
</div>

<style>
  .settings {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .blk {
    padding: 12px 14px;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .back {
    margin-top: 6px;
  }
  .berr {
    margin-top: 8px;
    font-size: 11px;
    color: var(--danger-text);
    white-space: pre-wrap;
  }
  .dirrow {
    display: flex;
    gap: 6px;
    margin-top: 8px;
  }
  .hint {
    font-size: 11px;
    margin-top: 4px;
  }
  .line {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    padding: 8px 0;
  }
  .line + .line {
    border-top: 1px solid var(--border-soft);
  }
  .t {
    font-size: 13px;
  }
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr auto;
    gap: 8px;
    align-items: end;
    margin-top: 8px;
  }
  .grid label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 11px;
    color: var(--muted);
  }
  .quit {
    align-self: center;
  }
  .foot .url {
    user-select: text;
  }
  .foot {
    line-height: 1.6;
    text-align: center;
    font-size: 10.5px;
  }
</style>
