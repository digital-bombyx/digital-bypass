import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { mockInvoke } from "./mock";

/** В обычном браузере (npm run dev без Tauri) — мок для проверки вёрстки. */
export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
const invoke = <T>(cmd: string, args?: Record<string, unknown>): Promise<T> =>
  isTauri ? tauriInvoke<T>(cmd, args) : (mockInvoke(cmd, args) as Promise<T>);

export type Status = {
  running: boolean;
  mode: "off" | "process" | "service" | "external";
  strategy: string | null;
  service_installed: boolean;
  last_error: string | null;
};

export type StrategyInfo = { file: string; name: string; blocks: string[]; methods: string[] };
export type GameFilter = { mode: "disabled" | "all" | "tcp" | "udp"; tcp: string; udp: string };

export type Overview = {
  admin: boolean;
  dir: string | null;
  version: string | null;
  strategies: StrategyInfo[];
  selected: string | null;
  status: Status;
  game_filter: GameFilter;
  ipset: "loaded" | "none" | "any";
  ipset_has_backup: boolean;
  mode: "process" | "service";
  autostart: boolean;
  close_to_tray: boolean;
  test_timeout: number;
  test_parallel: number;
  testing: boolean;
  dir_source: "bundled" | "custom" | "found";
  bundled_version: string | null;
  bundle_error: string | null;
  language: "ru" | "en";
};

export type TargetResult = {
  key: string;
  kind: "url" | "ping" | "dpi";
  checks: [string, string][];
  ping_ms: number | null;
  ping_tried: boolean;
  detail: string | null;
};

export type StrategyResult = {
  file: string;
  started: boolean;
  error: string | null;
  targets: TargetResult[];
  ok: number;
  fail: number;
  unsup: number;
  blocked: number;
  ping_ok: number;
  ping_fail: number;
};

export type TestRun = {
  id: number;
  kind: "standard" | "dpi";
  total: number;
  index: number;
  current: string | null;
  results: StrategyResult[];
  best: string | null;
  finished: boolean;
  cancelled: boolean;
  message: string | null;
};

export type HostEntry = { ip: string; host: string };
export type HostEntryState = HostEntry & { in_block: boolean; manual: boolean };
export type HostsStatus = {
  source: string;
  groups: { name: string; entries: HostEntryState[] }[];
  custom: HostEntryState[];
  block_present: boolean;
  outdated: boolean;
  hosts_path: string;
};

export type DnsAdapter = {
  index: number;
  ipv6_index: number;
  guid: string;
  name: string;
  description: string;
  up: boolean;
  gateway: boolean;
  internet: boolean;
  metric: number;
  kind: "ethernet" | "wifi" | "other";
  addresses: string[];
  dns_v4: string[];
  dns_v6: string[];
  static_v4: boolean;
  static_v6: boolean;
  doh: string[];
};
export type DohTemplate = { server: string; template: string; autoupgrade: boolean; fallback: boolean };
export type DnsInfo = { adapters: DnsAdapter[]; doh_supported: boolean; templates: DohTemplate[] };
export type DnsPreset = {
  id: string;
  name: string;
  note_ru: string;
  note_en: string;
  v4: string[];
  v6: string[];
  doh: string | null;
};
export type DnsApplyReq = {
  index: number;
  v4: string[] | null;
  v6: string[] | null;
  doh_template: string | null;
  doh_fallback: boolean;
};

export type StubConfig = {
  guid: string;
  name: string;
  template: string;
  bootstrap: string[];
  fallback: string | null;
  ipv6: boolean;
  addr: string;
  prev_v4: string[] | null;
  prev_v6: string[] | null;
};
export type StubStatus = {
  running: boolean;
  config: StubConfig | null;
  stats: { queries: number; cached: number; errors: number; last_error: string | null; ipv6: boolean; addr: string; template: string } | null;
};

export type ProxyConfig = { port: number; method: "split" | "disorder"; doh: boolean; system: boolean };
export type ProxyStatus = {
  config: ProxyConfig;
  enabled: boolean;
  stats: { running: boolean; port: number; active: number; total: number; failed: number; system: boolean; last_error: string | null };
};

export type Probe = "ok" | "tcp_fail" | "tls_reset" | "tls_timeout" | "tls_cert" | "tls_error";
export type Verdict = "ok" | "dns" | "dpi" | "ip" | "no_domain" | "unknown";
export type DiagReport = {
  domain: string;
  system: string[];
  system_error: string | null;
  doh: string[];
  doh_error: string | null;
  system_bogus: boolean;
  checks: { ip: string; source: "system" | "doh" | "both"; result: Probe; ms: number | null; detail: string | null }[];
  verdict: Verdict;
};

export type ListPreset = { id: string; name: string; domains: string[]; builtin: number };

export const api = {
  overview: () => invoke<Overview>("overview"),
  status: () => invoke<Status>("status"),
  logTail: () => invoke<string[]>("log_tail"),
  setZapretDir: (path: string) => invoke<Overview>("set_zapret_dir", { path }),
  selectStrategy: (file: string) => invoke<void>("select_strategy", { file }),
  enable: () => invoke<void>("enable"),
  disable: () => invoke<void>("disable"),
  setMode: (mode: string) => invoke<void>("set_mode", { mode }),
  setGameFilter: (gf: GameFilter) => invoke<void>("set_game_filter", { gf }),
  setIpset: (mode: string) => invoke<void>("set_ipset", { mode }),
  strategyCommand: (file: string) => invoke<string[]>("strategy_command", { file }),
  listRead: (kind: string) => invoke<string>("list_read", { kind }),
  listWrite: (kind: string, content: string) => invoke<{ warnings: string[] }>("list_write", { kind, content }),
  testTargets: () => invoke<[string, string][]>("test_targets"),
  testStart: (kind: string, files: string[]) => invoke<void>("test_start", { kind, files }),
  testCancel: () => invoke<void>("test_cancel"),
  testLast: () => invoke<TestRun | null>("test_last"),
  testHistory: () => invoke<TestRun[]>("test_history"),
  setTestParams: (timeout: number, parallel: number) => invoke<void>("set_test_params", { timeout, parallel }),
  hostsStatus: () => invoke<HostsStatus>("hosts_status"),
  hostsApply: (entries: HostEntry[], custom: HostEntry[]) => invoke<void>("hosts_apply", { entries, custom }),
  hostsRemove: () => invoke<void>("hosts_remove"),
  hostsUpdate: () => invoke<number>("hosts_update"),
  dnsInfo: () => invoke<DnsInfo>("dns_info"),
  dnsPresets: () => invoke<DnsPreset[]>("dns_presets"),
  dnsApply: (req: DnsApplyReq) => invoke<DnsInfo>("dns_apply", { req }),
  dnsReset: (index: number, v4: boolean, v6: boolean) => invoke<DnsInfo>("dns_reset", { index, v4, v6 }),
  dnsFlush: () => invoke<void>("dns_flush"),
  dnsStubStatus: () => invoke<StubStatus>("dns_stub_status"),
  dnsStubEnable: (index: number, template: string, bootstrap: string[], fallback: boolean) =>
    invoke<StubStatus>("dns_stub_enable", { index, template, bootstrap, fallback }),
  dnsStubDisable: () => invoke<StubStatus>("dns_stub_disable"),
  proxyStatus: () => invoke<ProxyStatus>("proxy_status"),
  proxyStart: (config: ProxyConfig) => invoke<ProxyStatus>("proxy_start", { config }),
  proxyStop: () => invoke<ProxyStatus>("proxy_stop"),
  diagRun: (domain: string) => invoke<DiagReport>("diag_run", { domain }),
  listPresets: () => invoke<ListPreset[]>("list_presets"),
  listAddPresets: (ids: string[]) => invoke<number>("list_add_presets", { ids }),
  setAutostart: (enabled: boolean) => invoke<boolean>("set_autostart", { enabled }),
  setCloseToTray: (enabled: boolean) => invoke<void>("set_close_to_tray", { enabled }),
  setLanguage: (lang: string) => invoke<void>("set_language", { lang }),
  openPath: (path: string) => invoke<void>("open_path", { path }),
  quit: () => invoke<void>("quit_app"),
};

export function on<T>(event: string, cb: (payload: T) => void): Promise<UnlistenFn> {
  if (!isTauri) return Promise.resolve(() => {});
  return listen<T>(event, (e) => cb(e.payload));
}

export const strategyName = (file: string | null | undefined) => (file ?? "").replace(/\.bat$/i, "");
