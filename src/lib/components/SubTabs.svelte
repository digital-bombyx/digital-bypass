<script lang="ts" generics="T extends string">
  import { untrack } from "svelte";
  /** Подвкладки сверху вкладки. Выбранная запоминается в этом браузере (`key`). */
  type Tab = { id: T; label: string; badge?: string | number | null; title?: string };
  let { tabs, value = $bindable(), key }: { tabs: Tab[]; value: T; key: string } = $props();

  // Восстановить последнюю подвкладку (если такая ещё есть) — один раз при создании.
  untrack(() => {
    try {
      const v = localStorage.getItem(`sub.${key}`) as T | null;
      if (v && tabs.some((x) => x.id === v)) value = v;
    } catch {}
  });
  $effect(() => {
    try {
      localStorage.setItem(`sub.${key}`, value);
    } catch {}
  });
</script>

<div class="subtabs mono" role="tablist">
  {#each tabs as tb (tb.id)}
    <button role="tab" aria-selected={value === tb.id} class:active={value === tb.id} title={tb.title} onclick={() => (value = tb.id)}>
      {tb.label}
      {#if tb.badge}<span class="badge">{tb.badge}</span>{/if}
    </button>
  {/each}
</div>

<style>
  .subtabs {
    display: flex;
    gap: 2px;
    border-bottom: 1px solid var(--border-soft);
    overflow-x: auto;
    scrollbar-width: none;
  }
  button {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 14px 9px;
    font-size: 12.5px;
    color: var(--muted);
    background: transparent;
    border: 0;
    cursor: pointer;
    white-space: nowrap;
  }
  button:hover {
    color: var(--text);
  }
  button.active {
    color: var(--text);
  }
  button.active::after {
    content: "";
    position: absolute;
    left: 10px;
    right: 10px;
    bottom: -1px;
    height: 2px;
    border-radius: 2px;
    background: var(--accent);
  }
  .badge {
    font-size: 10.5px;
    padding: 0 6px;
    border-radius: 8px;
    color: var(--accent);
    border: 1px solid var(--border);
  }
</style>
