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
  /** Имя сервера DNS over TLS (порт 853). */
  dot: string | null;
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

export type ProxyRules = { scope: "all" | "listed"; zapret_lists: boolean; bypass: string[]; skip: string[]; block: string[] };
export type ProxyConfig = {
  port: number;
  split: "sni" | "first-byte" | "chunk" | "random" | "custom" | "none";
  positions: string;
  unit: "records" | "tcp" | "mixed";
  chunk: number;
  disorder: boolean;
  oob: boolean;
  auto: boolean;
  auto_chain: ProxyVariant[];
  auto_timeout: number;
  log: boolean;
  ipv6: boolean;
  rules: ProxyRules;
  doh: boolean;
  system: boolean;
  lan: boolean;
  user: string;
  pass: string;
  rcvbuf: number;
};
export type ProxyStatus = {
  config: ProxyConfig;
  enabled: boolean;
  stats: { running: boolean; port: number; active: number; total: number; failed: number; system: boolean; lan: boolean; auth: boolean; bypassed: number; passed: number; blocked: number; dns_cached: number; bypass_domains: number; auto_retries: number; auto_sites: number; last_error: string | null };
};

export type ProxyVariant = { split: ProxyConfig["split"]; unit: ProxyConfig["unit"]; disorder: boolean; oob: boolean };
export type ProxyVariantResult = {
  variant: ProxyVariant;
  ok: number;
  total: number;
  avg_ms: number | null;
  targets: { host: string; ok: boolean; code: number | null; ms: number | null; error: string | null }[];
};

export type ProxyLogEntry = {
  ts: number;
  host: string;
  port: number;
  action: "bypass" | "pass" | "block";
  method: string | null;
  tries: number;
  ms: number | null;
  ok: boolean;
  error: string | null;
};

export type DnsDomainVerdict = "ok" | "cdn" | "stub_system" | "stub_intercepted" | "spoofed" | "differs" | "no_answer";
export type DnsCheckReport = {
  nowhere_answered: boolean;
  resolvers: { name: string; server: string; answered: boolean; egress: string | null; ms: number | null }[];
  system_egress: string | null;
  trusted_ok: boolean;
  trusted_error: string | null;
  intercepted: boolean;
  intercept_reasons: string[];
  domains: { domain: string; system: string[]; public: string[]; trusted: string[]; verdict: DnsDomainVerdict; cert_check: string | null }[];
  stubs: number;
};

export type TgConfig = {
  port: number;
  secret: string;
  dc_ip: string[];
  fragment: boolean;
  cf_proxy: boolean;
  cf_domains: string[];
  cf_workers: string[];
  sni: string;
  enabled: boolean;
};
export type TgStatus = {
  config: TgConfig;
  stats: {
    running: boolean;
    active: number;
    total: number;
    ws: number;
    cf: number;
    worker: number;
    fronted: number;
    tcp: number;
    bad: number;
    failed: number;
    bytes_up: number;
    bytes_down: number;
    last_error: string | null;
  };
  link: string;
  default_cf: string[];
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
  checks: {
    ip: string;
    source: "system" | "doh" | "both";
    result: Probe;
    ms: number | null;
    detail: string | null;
    stage: Stage | null;
    unstable: boolean;
  }[];
  verdict: Verdict;
  stage: Stage | null;
  extra: {
    ip: string;
    split_ok: boolean | null;
    small_buf_ok: boolean | null;
    ip_clean: boolean | null;
    name_anywhere: boolean | null;
  } | null;
};
export type Stage = "request" | "response";

export type EvolveCand = {
  name: string;
  parent: string;
  changes: string[];
  ok: number;
  fail: number;
  score: number;
  complexity: number;
  unstable: boolean;
  error: string | null;
  seed: boolean;
};
export type EvolveRun = {
  kind: string;
  round: number;
  rounds: number;
  done: number;
  planned: number;
  current: string | null;
  hall: EvolveCand[];
  tried: EvolveCand[];
  finished: boolean;
  cancelled: boolean;
  message: string | null;
  saved: string[];
  baseline: number;
  ceiling: number | null;
};

export type McpStatus = {
  settings: { enabled: boolean; port: number; token: string; allow_changes: boolean };
  running: boolean;
  url: string;
  error: string | null;
};

export type NetRules = { enabled: boolean; mode: "only" | "except"; networks: string[]; zapret: boolean; proxy: boolean };
export type NetStatus = { rules: NetRules; current: string[]; allowed: boolean; paused: boolean };

export type SniOutcome = "pass" | "reset" | "timeout" | "no_tcp";
export type SniReport = {
  target: string;
  items: { sni: string; outcome: SniOutcome; ms: number | null; detail: string | null }[];
  passed: number;
  blocked: number;
  whitelist_suspected: boolean;
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
  evolveStart: (kind: string, seeds: string[], rounds: number) => invoke<void>("evolve_start", { kind, seeds, rounds }),
  evolveLast: () => invoke<EvolveRun | null>("evolve_last"),
  evolveSave: (name: string) => invoke<string>("evolve_save", { name }),
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
  proxySetConfig: (config: ProxyConfig) => invoke<ProxyStatus>("proxy_set_config", { config }),
  proxyTestTargets: () => invoke<string[]>("proxy_test_targets"),
  proxyTest: (targets: string, timeout: number) =>
    invoke<{ results: ProxyVariantResult[]; best: ProxyVariant | null; cancelled: boolean }>("proxy_test", { targets, timeout }),
  proxyTestCancel: () => invoke<void>("proxy_test_cancel"),
  proxyLog: () => invoke<ProxyLogEntry[]>("proxy_log"),
  proxyLogClear: () => invoke<void>("proxy_log_clear"),
  diagRun: (domain: string) => invoke<DiagReport>("diag_run", { domain }),
  dnsCheck: (domains: string) => invoke<DnsCheckReport>("dns_check", { domains }),
  dnsCheckDefaults: () => invoke<string[]>("dns_check_defaults"),
  lanAddresses: () => invoke<string[]>("lan_addresses"),
  tgStatus: () => invoke<TgStatus>("tg_status"),
  mcpStatus: () => invoke<McpStatus>("mcp_status"),
  mcpSet: (enabled: boolean, allowChanges: boolean, port: number) => invoke<McpStatus>("mcp_set", { enabled, allowChanges, port }),
  mcpRegenToken: () => invoke<McpStatus>("mcp_regen_token"),
  netStatus: () => invoke<NetStatus>("net_status"),
  netSet: (rules: NetRules) => invoke<NetStatus>("net_set", { rules }),
  tgStart: (config: TgConfig) => invoke<TgStatus>("tg_start", { config }),
  tgStop: () => invoke<TgStatus>("tg_stop"),
  tgSetConfig: (config: TgConfig) => invoke<TgStatus>("tg_set_config", { config }),
  tgRegenSecret: () => invoke<TgStatus>("tg_regen_secret"),
  tgOpenLink: () => invoke<void>("tg_open_link"),
  sniDefaults: () => invoke<{ target: string; snis: string[] }>("sni_defaults"),
  sniScan: (target: string, snis: string, timeout: number) => invoke<SniReport>("sni_scan", { target, snis, timeout }),
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
