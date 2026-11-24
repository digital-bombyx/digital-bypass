<script lang="ts">
  /** Вкладка Zapret2: подвкладки Bypass / Tests / Lists / Add-ons. */
  import SubTabs from "./SubTabs.svelte";
  import Home from "./Home.svelte";
  import Tests from "./Tests.svelte";
  import Lists from "./Lists.svelte";
  import Addons from "./Addons.svelte";
  import { app } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";

  type Sub = "bypass" | "tests" | "lists" | "addons";
  let { sub = $bindable("bypass") }: { sub?: Sub } = $props();

  const ov = $derived(app.ov!);
  const addonsOn = $derived([ov.addons.wireguard, ov.addons.lean_udp, ov.addons.hide_windivert].filter(Boolean).length);
</script>

<div class="z fade-in">
  <SubTabs
    key="zapret2"
    bind:value={sub}
    tabs={[
      { id: "bypass", label: "Bypass", title: t("Включение, стратегия, режим", "On/off, strategy, mode") },
      { id: "tests", label: "Tests", badge: ov.testing ? "…" : null, title: t("Тест стратегий и автоподбор", "Strategy test and auto-tune") },
      { id: "lists", label: "Lists", title: t("Списки доменов и исключений", "Domain and exclusion lists") },
      { id: "addons", label: "Add-ons", badge: addonsOn || null, title: t("WireGuard, экономный UDP, скрытие WinDivert", "WireGuard, lean UDP, hidden WinDivert") },
    ]} />
  {#if sub === "bypass"}<Home />
  {:else if sub === "tests"}<Tests />
  {:else if sub === "lists"}<Lists />
  {:else}<Addons />{/if}
</div>

<style>
  .z {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
</style>
