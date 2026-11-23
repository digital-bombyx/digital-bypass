<script lang="ts">
  import { api, type Addons } from "$lib/api";
  import { app, act } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import Switch from "./Switch.svelte";
  import { Puzzle } from "@lucide/svelte";

  const ov = $derived(app.ov!);
  const set = (patch: Partial<Addons>) => act(() => api.setAddons({ ...ov.addons, ...patch }), t("Сохранено", "Saved"));
</script>

<section class="card opts">
  <div class="label head"><Puzzle size={11} /> {t("дополнения", "add-ons")}</div>
  <div class="opt">
    <div>
      <div class="t">{t("Разблокировать WireGuard", "Unblock WireGuard")}</div>
      <div class="hint faint mono">
        {t(
          "фейк перед рукопожатием WireGuard/AmneziaWG на любых портах — для своего VPN-сервера, если ТСПУ рвёт туннель",
          "a fake before the WireGuard/AmneziaWG handshake on any port — for your own VPN server if TSPU breaks the tunnel",
        )}
      </div>
    </div>
    <Switch checked={ov.addons.wireguard} disabled={app.busy || ov.testing} onchange={(v) => set({ wireguard: v })} />
  </div>
  <div class="opt">
    <div>
      <div class="t">{t("Экономный перехват UDP", "Lean UDP capture")}</div>
      <div class="hint faint mono">
        {t(
          "QUIC и голос Discord отбираются фильтрами в драйвере: в winws2 идут только нужные пакеты (QUIC Initial, STUN, поиск адреса Discord), а не весь поток — меньше нагрузка на процессор при видео и звонках",
          "QUIC and Discord voice are picked by in-driver filters: only the needed packets (QUIC Initial, STUN, Discord IP discovery) reach winws2, not the whole stream — less CPU during video and calls",
        )}
      </div>
    </div>
    <Switch checked={ov.addons.lean_udp} disabled={app.busy || ov.testing} onchange={(v) => set({ lean_udp: v })} />
  </div>
  <div class="opt">
    <div>
      <div class="t">{t("Скрыть WinDivert от игр", "Hide WinDivert from games")}</div>
      <div class="hint faint mono">
        {t(
          "драйвер ставится под именем «Monkey» — помогает с античитами, которые ищут службу или файл WinDivert, но не с теми, что проверяют устройство драйвера",
          "the driver is installed as “Monkey” — helps with anti-cheats that look for the WinDivert service or file, not with those that check the driver device",
        )}
        {#if ov.windivert_hidden}· <span class="on">{t("сейчас скрыт", "hidden now")}</span>{/if}
      </div>
    </div>
    <Switch checked={ov.addons.hide_windivert} disabled={app.busy || ov.testing || !ov.admin} onchange={(v) => set({ hide_windivert: v })} />
  </div>
</section>

<style>
  .opts {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .opt {
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
    margin-top: 3px;
  }
  .on {
    color: var(--sage);
  }
</style>
