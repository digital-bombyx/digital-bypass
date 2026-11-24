<script lang="ts">
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { X, Minus, Square } from "@lucide/svelte";
  import { isTauri } from "$lib/api";
  import { t } from "$lib/i18n.svelte";

  let { path }: { path: string } = $props();
  const noop = async () => {};
  const win = isTauri ? getCurrentWindow() : { close: noop, minimize: noop, toggleMaximize: noop };
</script>

<header class="bar" data-tauri-drag-region>
  <div class="brand mono" data-tauri-drag-region>
    <span class="mark" aria-hidden="true"></span>digital-bypass<span class="path">/{path}</span>
  </div>
  <div class="ctl">
    <button title={t("Свернуть", "Minimize")} onclick={() => win.minimize()}><Minus size={14} /></button>
    <button title={t("Развернуть", "Maximize")} onclick={() => win.toggleMaximize()}><Square size={11} /></button>
    <button class="close" title={t("Закрыть", "Close")} onclick={() => win.close()}><X size={15} /></button>
  </div>
</header>

<style>
  .bar {
    height: 36px;
    flex: none;
    display: grid;
    grid-template-columns: 1fr auto;
    column-gap: 12px;
    align-items: center;
    padding-left: 12px;
    border-bottom: 1px solid var(--border-soft);
    background: var(--bg);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    font-weight: 700;
    color: var(--text);
    white-space: nowrap;
    overflow: hidden;
    pointer-events: none;
  }
  .mark {
    width: 9px;
    height: 9px;
    flex: none;
    background: var(--accent);
  }
  .path {
    margin-left: -6px;
    font-weight: 400;
    color: var(--faint);
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ctl {
    display: flex;
    align-self: stretch;
  }
  .ctl button {
    width: 40px;
    height: 100%;
    border: 0;
    padding: 0;
    display: grid;
    place-items: center;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    transition: background 0.1s, color 0.1s;
  }
  .ctl button:hover {
    background: var(--panel-2);
    color: var(--text);
  }
  .ctl button.close:hover {
    background: #c42b1c;
    color: #fff;
  }
</style>
