<script lang="ts" generics="T extends string">
  type Props = {
    options: { value: T; label: string }[];
    value: T;
    onchange: (v: T) => void;
    disabled?: boolean;
    small?: boolean;
  };
  let { options, value, onchange, disabled = false, small = false }: Props = $props();
</script>

<div class="seg" class:small class:disabled>
  {#each options as o (o.value)}
    <button
      class:active={o.value === value}
      {disabled}
      onclick={() => o.value !== value && onchange(o.value)}>{o.label}</button>
  {/each}
</div>

<style>
  .seg {
    display: flex;
    gap: 2px;
    padding: 3px;
    border-radius: var(--radius-sm);
    background: var(--bg);
    border: 1px solid var(--border);
  }
  .seg button {
    flex: 1;
    height: 26px;
    padding: 0 10px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 12px;
    cursor: pointer;
    transition: background 0.18s, color 0.18s, box-shadow 0.18s;
    white-space: nowrap;
  }
  .seg button:hover:not(:disabled):not(.active) {
    color: var(--text);
  }
  .seg button.active {
    background: var(--panel-3);
    color: var(--text);
  }
  .small button {
    height: 22px;
    font-size: 11px;
    padding: 0 8px;
  }
  .disabled {
    opacity: 0.5;
  }
</style>
