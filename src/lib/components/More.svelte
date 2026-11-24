<script lang="ts">
  /** Свёрнутый блок «Дополнительно». Изменённое внутри не прячется: на заголовке —
   *  сколько настроек отличаются от стандартных (`active`).
   *  Раскрыт ли — запоминается в этом браузере (`key`). */
  import { untrack, type Snippet } from "svelte";
  import { t } from "$lib/i18n.svelte";
  import { ChevronRight, ChevronDown } from "@lucide/svelte";

  let { key, active = 0, title, children }: { key: string; active?: number; title?: string; children: Snippet } = $props();

  let open = $state(
    untrack(() => {
      try {
        return localStorage.getItem(`more.${key}`) === "1";
      } catch {
        return false;
      }
    }),
  );
  function toggle() {
    open = !open;
    try {
      localStorage.setItem(`more.${key}`, open ? "1" : "0");
    } catch {}
  }
</script>

<section class="card more" class:open>
  <button class="head mono" onclick={toggle} aria-expanded={open}>
    <span class="chev">{#if open}<ChevronDown size={14} />{:else}<ChevronRight size={14} />{/if}</span>
    <span class="label">{title ?? t("дополнительно", "advanced")}</span>
    <!-- Считаются настройки, отличные от стандартных (в том числе выключенное, что по умолчанию включено). -->
    {#if active > 0}<span class="badge" title={t("Столько настроек здесь отличаются от стандартных", "This many settings here differ from the defaults")}
        >{t(`изменено: ${active}`, `${active} changed`)}</span
      >{/if}
  </button>
  {#if open}<div class="body">{@render children()}</div>{/if}
</section>

<style>
  .more {
    padding: 0;
  }
  .head {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 11px 14px;
    background: transparent;
    border: 0;
    color: var(--muted);
    cursor: pointer;
    text-align: left;
  }
  .head:hover {
    color: var(--text);
  }
  .chev {
    display: inline-flex;
  }
  .badge {
    margin-left: auto;
    font-size: 10.5px;
    padding: 1px 7px;
    border-radius: 8px;
    color: var(--accent);
    border: 1px solid var(--border);
  }
  .body {
    padding: 0 14px 6px;
    border-top: 1px solid var(--border-soft);
  }
</style>
