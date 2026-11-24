<script lang="ts">
  import { Power } from "@lucide/svelte";
  import { t } from "$lib/i18n.svelte";

  /** Большой круглый тумблер модуля (zapret2, прокси, Telegram). */
  let { on, disabled = false, onclick }: { on: boolean; disabled?: boolean; onclick: () => void } = $props();
</script>

<button class="power" class:on {disabled} {onclick} aria-label={on ? t("Выключить", "Turn off") : t("Включить", "Turn on")}>
  <svg viewBox="0 0 120 120" class="dial">
    <circle cx="60" cy="60" r="46" class="track" />
  </svg>
  <span class="core"><Power size={30} strokeWidth={2.2} /></span>
</button>

<style>
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
  .dial .track {
    fill: none;
    stroke: var(--border);
    stroke-width: 3;
    transition: stroke 0.2s;
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
</style>
