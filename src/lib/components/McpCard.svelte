<script lang="ts">
  import { onMount } from "svelte";
  import { api, type McpStatus } from "$lib/api";
  import { app, toast } from "$lib/state.svelte";
  import { t } from "$lib/i18n.svelte";
  import Switch from "./Switch.svelte";
  import Segmented from "./Segmented.svelte";
  import { Bot, Copy, RefreshCw, Eye, EyeOff } from "@lucide/svelte";

  let st = $state<McpStatus | null>(null);
  let port = $state(8899);
  let client = $state<"code" | "json" | "desktop">("code");
  let showToken = $state(false);

  onMount(async () => {
    try {
      st = await api.mcpStatus();
      port = st.settings.port;
    } catch (e) {
      toast(String(e));
    }
  });

  async function set(patch: { enabled?: boolean; allow_changes?: boolean; port?: number }) {
    if (!st) return;
    try {
      st = await api.mcpSet(patch.enabled ?? st.settings.enabled, patch.allow_changes ?? st.settings.allow_changes, Number(patch.port ?? port));
      if (st.error) toast(st.error);
    } catch (e) {
      toast(String(e));
    }
  }
  async function regen() {
    if (!confirm(t("Создать новый токен? Подключённым ассистентам придётся обновить настройки.", "Create a new token? Connected assistants will need updated settings."))) return;
    st = await api.mcpRegenToken();
  }

  const snippet = $derived.by(() => {
    if (!st) return "";
    const tok = st.settings.token;
    if (client === "code") return `claude mcp add --transport http digital-bypass ${st.url} --header "Authorization: Bearer ${tok}"`;
    if (client === "json")
      return JSON.stringify({ mcpServers: { "digital-bypass": { url: st.url, headers: { Authorization: `Bearer ${tok}` } } } }, null, 2);
    return JSON.stringify(
      {
        mcpServers: {
          "digital-bypass": {
            command: "npx",
            args: ["-y", "mcp-remote", st.url, "--header", "Authorization:${AUTH_HEADER}"],
            env: { AUTH_HEADER: `Bearer ${tok}` },
          },
        },
      },
      null,
      2,
    );
  });
  const shown = $derived(showToken || !st ? snippet : snippet.replaceAll(st.settings.token, "••••••••"));
  const copy = () => navigator.clipboard?.writeText(snippet).then(() => toast(t("Скопировано", "Copied"), "ok"));
</script>

{#if st}
  <section class="card blk">
    <div class="line">
      <div>
        <div class="t"><Bot size={13} /> {t("MCP для ИИ-ассистентов", "MCP for AI assistants")}</div>
        <div class="hint faint mono">
          {t(
            "Claude, Cursor и др. смогут проверить, почему не открывается сайт, подобрать стратегию zapret2, прочитать журналы",
            "Claude, Cursor and others can check why a site won't open, find a zapret2 strategy, read the logs",
          )}
        </div>
      </div>
      <Switch checked={st.settings.enabled} disabled={app.busy} onchange={(v) => set({ enabled: v })} />
    </div>
    {#if st.settings.enabled}
      <div class="line">
        <div>
          <div class="t">{t("Разрешить изменения", "Allow changes")}</div>
          <div class="hint faint mono">
            {t(
              "включать и выключать zapret2 и прокси, выбирать стратегию, править списки и настройки прокси; без этого — только проверки и чтение",
              "turn zapret2 and the proxy on/off, pick a strategy, edit lists and proxy settings; without it — checks and reading only",
            )}
          </div>
        </div>
        <Switch checked={st.settings.allow_changes} disabled={app.busy} onchange={(v) => set({ allow_changes: v })} />
      </div>
      {#if st.settings.allow_changes}
        <div class="line">
          <div>
            <div class="t">{t("Откатывать неподтверждённое", "Roll back unconfirmed changes")}</div>
            <div class="hint faint mono">
              {t(
                "изменение от ИИ — пробное: если за 2 минуты он не подтвердил, что всё работает, приложение вернёт как было. Защищает от случая, когда ИИ сломал сеть и сам потерял связь",
                "an AI change is a trial: if it does not confirm within 2 minutes that everything works, the app restores the previous state. Protects against the AI breaking the network and losing its own connection",
              )}
            </div>
          </div>
          <Switch checked={st.settings.rollback} disabled={app.busy} onchange={async (v) => (st = await api.mcpSetRollback(v))} />
        </div>
      {/if}
      <div class="row mono">
        <span class="faint">{t("адрес", "address")}</span>
        <span class="url">{st.url}</span>
        <span class="chip" class:sage={st.running} class:red={!st.running}>{st.running ? t("работает", "running") : t("не запущен", "not running")}</span>
        <span class="grow"></span>
        <label class="faint">{t("порт", "port")} <input class="input port" type="number" min="1024" max="65535" bind:value={port} onchange={() => set({ port })} /></label>
      </div>
      <div class="row mono">
        <span class="faint">{t("токен", "token")}</span>
        <span class="url">{showToken ? st.settings.token : "••••••••••••"}</span>
        <button class="btn sm ghost" onclick={() => (showToken = !showToken)}>{#if showToken}<EyeOff size={12} />{:else}<Eye size={12} />{/if}</button>
        <button class="btn sm ghost" title={t("Новый токен", "New token")} onclick={regen}><RefreshCw size={12} /></button>
      </div>
      <Segmented
        small
        value={client}
        onchange={(v: "code" | "json" | "desktop") => (client = v)}
        options={[
          { value: "code", label: "Claude Code" },
          { value: "json", label: "Cursor / VS Code" },
          { value: "desktop", label: "Claude Desktop" },
        ]} />
      <div class="snip">
        <pre class="mono">{shown}</pre>
        <button class="btn sm" onclick={copy}><Copy size={12} /> {t("Копировать", "Copy")}</button>
      </div>
      <div class="hint faint mono">
        {client === "desktop"
          ? t("Claude Desktop подключает только локальные программы — мост mcp-remote (нужен Node.js). Файл: %APPDATA%\\Claude\\claude_desktop_config.json", "Claude Desktop only runs local programs — the mcp-remote bridge (needs Node.js). File: %APPDATA%\\Claude\\claude_desktop_config.json")
          : client === "json"
            ? t("Cursor: ~/.cursor/mcp.json; VS Code: .vscode/mcp.json (ключ servers вместо mcpServers)", "Cursor: ~/.cursor/mcp.json; VS Code: .vscode/mcp.json (key servers instead of mcpServers)")
            : t("Выполните в терминале; затем спросите: «почему не грузится Discord?»", "Run in a terminal; then ask: “why won't Discord load?”")}
      </div>
      <div class="hint faint mono">{t("Сервер слушает только этот ПК (127.0.0.1); токен не передавайте другим.", "The server listens on this PC only (127.0.0.1); don't share the token.")}</div>
    {/if}
  </section>
{/if}

<style>
  .blk {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .line {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
  }
  .t {
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .hint {
    font-size: 11px;
    margin-top: 3px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
  }
  .url {
    user-select: text;
  }
  .grow {
    flex: 1;
  }
  .port {
    width: 80px;
    margin-left: 4px;
  }
  .snip {
    position: relative;
  }
  .snip pre {
    margin: 0;
    padding: 10px 120px 10px 12px;
    background: var(--bg);
    border: 1px solid var(--border-soft);
    border-radius: 8px;
    font-size: 11.5px;
    white-space: pre-wrap;
    word-break: break-all;
    user-select: text;
  }
  .snip .btn {
    position: absolute;
    top: 6px;
    right: 6px;
  }
</style>
