<script lang="ts">
  let { checked, onchange, disabled = false }: { checked: boolean; onchange: (v: boolean) => void; disabled?: boolean } =
    $props();
</script>

<button class="sw" class:on={checked} {disabled} role="switch" aria-checked={checked} aria-label="toggle" onclick={() => onchange(!checked)}>
  <span></span>
</button>

<style>
  .sw {
    position: relative;
    width: 38px;
    height: 22px;
    flex: none;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg);
    cursor: pointer;
    transition: background 0.2s, border-color 0.2s;
  }
  .sw span {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 2px;
    background: var(--faint);
    transition: transform 0.12s linear, background 0.12s;
  }
  .sw.on {
    background: var(--accent-soft);
    border-color: var(--accent);
  }
  .sw.on span {
    transform: translateX(16px);
    background: var(--amber);
  }
  .sw:disabled {
    opacity: 0.45;
    cursor: default;
  }
</style>
