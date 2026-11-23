// Мок бэкенда для `npm run dev` в обычном браузере (без Tauri): только вёрстка.
const names = [
  "general (ALT)", ...Array.from({ length: 12 }, (_, i) => `general (ALT${i + 2})`), "general (EXP)",
  "general (FAKE TLS AUTO ALT)", "general (FAKE TLS AUTO ALT2)", "general (FAKE TLS AUTO ALT3)", "general (FAKE TLS AUTO)",
  "general (SIMPLE FAKE ALT)", "general (SIMPLE FAKE ALT2)", "general (SIMPLE FAKE)", "general",
];
const blocks = ["Domain Bypass Quic", "Discord Voice", "Discord Media", "Youtube", "Domain Bypass TLS", "IP Bypass TLS"];
const state: any = {
  admin: true,
  dir: "D:\\zapret-discord-youtube",
  version: "1.10.4",
  strategies: names.map((n, i) => ({ file: `${n}.bat`, name: n, blocks, methods: i % 2 ? ["fake", "multisplit"] : ["fake", "fakedsplit", "multisplit"] })),
  selected: "general (ALT).bat",
  status: { running: true, mode: "process", strategy: "general (ALT).bat", service_installed: false, last_error: null },
  game_filter: { mode: "disabled", tcp: "1024-65535", udp: "1024-65535" },
  ipset: "loaded",
  ipset_has_backup: false,
  mode: "process",
  addons: { wireguard: false, lean_udp: false, hide_windivert: false },
  windivert_hidden: false,
  autostart: false,
  close_to_tray: true,
  test_timeout: 4,
  test_parallel: 16,
  testing: false,
  dir_source: "bundled",
  bundled_version: "1.10.4 @ aa56e97",
  bundle_error: null,
  language: "ru",
};
const targets = ["DiscordMain", "DiscordGateway", "YouTubeWeb", "GoogleMain", "CloudflareWeb"];
const mkRes = (file: string, ok: number) => ({
  file,
  started: true,
  error: null,
  targets: targets.map((k, i) => ({
    key: k,
    kind: "url",
    checks: [["HTTP", i < ok ? "OK" : "ERROR"], ["TLS1.2", "OK"], ["TLS1.3", i % 2 ? "UNSUP" : "OK"]],
    ping_ms: 20 + i * 7,
    ping_tried: true,
    detail: null,
  })),
  ok: ok * 2 + 3,
  fail: 5 - ok,
  unsup: 2,
  blocked: 0,
  ping_ok: 5,
  ping_fail: 0,
});
const run = {
  id: 1795340000,
  kind: "standard",
  total: 3,
  index: 3,
  current: null,
  results: [mkRes("general.bat", 2), mkRes("general (ALT).bat", 5), { ...mkRes("general (ALT2).bat", 0), started: false, error: "winws2 сразу завершился", targets: [] }],
  best: "general (ALT).bat",
  finished: true,
  cancelled: false,
  message: null,
};

const dnsPresets = [
  { id: "cloudflare", name: "Cloudflare", note_ru: "без фильтрации, быстрый", note_en: "no filtering, fast", v4: ["1.1.1.1", "1.0.0.1"], v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"], doh: "https://cloudflare-dns.com/dns-query", dot: "cloudflare-dns.com" },
  { id: "google", name: "Google", note_ru: "без фильтрации", note_en: "no filtering", v4: ["8.8.8.8", "8.8.4.4"], v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"], doh: "https://dns.google/dns-query", dot: "dns.google" },
  { id: "quad9", name: "Quad9", note_ru: "блокирует вредоносные домены, DNSSEC", note_en: "blocks malware domains, DNSSEC", v4: ["9.9.9.9", "149.112.112.112"], v6: ["2620:fe::fe", "2620:fe::9"], doh: "https://dns.quad9.net/dns-query", dot: "dns.quad9.net" },
  { id: "adguard", name: "AdGuard", note_ru: "режет рекламу и трекеры", note_en: "blocks ads and trackers", v4: ["94.140.14.14", "94.140.15.15"], v6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"], doh: "https://dns.adguard-dns.com/dns-query", dot: "dns.adguard-dns.com" },
  { id: "yandex", name: "Яндекс", note_ru: "базовый, доступен при белых списках", note_en: "basic, reachable under whitelists", v4: ["77.88.8.8", "77.88.8.1"], v6: ["2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"], doh: "https://common.dot.dns.yandex.net/dns-query", dot: "common.dot.dns.yandex.net" },
  { id: "mullvad", name: "Mullvad", note_ru: "без логов и фильтрации", note_en: "no logs, no filtering", v4: ["194.242.2.2"], v6: ["2a07:e340::2"], doh: "https://dns.mullvad.net/dns-query", dot: "dns.mullvad.net" },
];
const dns: any = {
  doh_supported: true,
  templates: [{ server: "1.1.1.1", template: "https://cloudflare-dns.com/dns-query", autoupgrade: true, fallback: false }],
  adapters: [
    { index: 12, ipv6_index: 12, guid: "{A1}", name: "Ethernet", description: "Realtek PCIe GbE Family Controller", up: true, gateway: true, internet: true, metric: 25, kind: "ethernet", addresses: ["192.168.1.34"], dns_v4: ["1.1.1.1", "1.0.0.1"], dns_v6: [], static_v4: true, static_v6: false, doh: ["1.1.1.1"] },
    { index: 18, ipv6_index: 18, guid: "{B2}", name: "Wi-Fi", description: "Intel(R) Wi-Fi 6 AX201 160MHz", up: true, gateway: false, internet: false, metric: 35, kind: "wifi", addresses: ["10.0.0.12", "2a00:1370:8000::12"], dns_v4: ["192.168.1.1"], dns_v6: ["2a00:1370:8000::1"], static_v4: false, static_v6: false, doh: [] },
    { index: 22, ipv6_index: 22, guid: "{C3}", name: "vEthernet (WSL)", description: "Hyper-V Virtual Ethernet Adapter", up: false, gateway: false, internet: false, metric: 5000, kind: "other", addresses: [], dns_v4: [], dns_v6: [], static_v4: false, static_v6: false, doh: [] },
  ],
};

const stub: any = { running: false, config: null, stats: null };
const proxy: any = {
  config: {
    port: 8881, split: "sni", unit: "records", chunk: 4, positions: "", disorder: true, oob: false, ipv6: false,
    auto: true, auto_timeout: 4, log: true,
    auto_chain: [
      { split: "chunk", unit: "records", disorder: true, oob: false },
      { split: "sni", unit: "records", disorder: true, oob: false },
      { split: "chunk", unit: "tcp", disorder: true, oob: false },
      { split: "sni", unit: "records", disorder: false, oob: true },
    ],
    rules: { scope: "all", zapret_lists: true, bypass: [], skip: ["sberbank.ru"], block: [], worker: [] },
    worker: { host: "", key: "", fragment: true },
    doh: true, system: true, lan: false, user: "", pass: "", rcvbuf: 0,
  },
  enabled: false,
  stats: { running: false, port: 8881, active: 0, total: 0, failed: 0, system: false, lan: false, auth: false, bypassed: 0, passed: 0, blocked: 0, dns_cached: 0, bypass_domains: 0, auto_retries: 0, auto_sites: 0, last_error: null },
};
const listPresets = [
  { id: "telegram", name: "Telegram", domains: ["telegram.org", "t.me", "telegram.me"], builtin: 0 },
  { id: "meta", name: "Instagram / Facebook / WhatsApp", domains: ["instagram.com", "facebook.com", "whatsapp.com"], builtin: 0 },
  { id: "twitter", name: "X / Twitter", domains: ["x.com", "twitter.com", "twimg.com", "t.co"], builtin: 0 },
  { id: "roblox", name: "Roblox", domains: ["roblox.com", "rbxcdn.com", "rbx.com"], builtin: 0 },
  { id: "soundcloud", name: "SoundCloud", domains: ["soundcloud.com", "soundcloud.cloud", "sndcdn.com"], builtin: 0 },
];
const diagSample = (domain: string) => ({
  domain,
  system: ["127.0.0.1"],
  system_error: null,
  doh: ["157.240.205.174", "2a03:2880:f15c:83:face:b00c:0:3603"],
  doh_error: null,
  system_bogus: true,
  checks: [
    { ip: "127.0.0.1", source: "system", result: "tcp_fail", ms: null, detail: "bogus", stage: null, unstable: false },
    { ip: "157.240.205.174", source: "doh", result: "tls_timeout", ms: null, detail: "os error 10060", stage: "response", unstable: true },
  ],
  verdict: "dpi",
  stage: "response",
  freeze: null,
  via_proxy: { port: 8881, result: "ok", ms: 412, detail: null },
  extra: { ip: "157.240.205.174", split_ok: false, small_buf_ok: true, ip_clean: true, name_anywhere: false, sni_pass: null },
});

const tg: any = {
  config: {
    port: 1443,
    secret: "3f1c0a9b7e5d4c2b1a0f9e8d7c6b5a49",
    dc_ip: ["2:149.154.167.220", "4:149.154.167.220"],
    fragment: true,
    cf_proxy: true,
    cf_domains: [],
    cf_workers: [],
    sni: "",
    enabled: false,
  },
  stats: { running: false, active: 0, total: 0, ws: 0, cf: 0, worker: 0, fronted: 0, tcp: 0, bad: 0, failed: 0, bytes_up: 0, bytes_down: 0, last_error: null },
  link: "tg://proxy?server=127.0.0.1&port=1443&secret=dd3f1c0a9b7e5d4c2b1a0f9e8d7c6b5a49",
  default_cf: Array.from({ length: 20 }, (_, i) => `cf${i}.co.uk`),
};

const mcp: any = {
  settings: { enabled: false, port: 8899, token: "3b1f0c9e7a5d4c2b1a0f9e8d7c6b5a49e1d2c3b4", allow_changes: false },
  running: false,
  url: "http://127.0.0.1:8899/mcp",
  error: null,
};

const net: any = {
  rules: { enabled: false, mode: "except", networks: [], zapret: true, proxy: true },
  current: ["HomeWiFi"],
  allowed: true,
  paused: false,
};

export async function mockInvoke(cmd: string, args: any = {}): Promise<any> {
  await new Promise((r) => setTimeout(r, 120));
  // Как настоящий invoke: аргументы сериализуются (реактивные прокси Svelte не клонируются).
  args = JSON.parse(JSON.stringify(args ?? {}));
  switch (cmd) {
    case "set_addons":
      state.addons = args.addons;
      state.windivert_hidden = args.addons.hide_windivert;
      return;
    case "rotate_build":
      if (!state.strategies.some((s: any) => s.file === "general (AUTO ROTATE).bat"))
        state.strategies.push({ file: "general (AUTO ROTATE).bat", name: "general (AUTO ROTATE)", blocks: [], methods: ["circular", "fake", "multisplit"] });
      return "general (AUTO ROTATE).bat";
    case "overview":
      return structuredClone(state);
    case "enable":
      state.status = { ...state.status, running: true, mode: state.mode, strategy: state.selected };
      return;
    case "disable":
      state.status = { ...state.status, running: false, mode: "off", strategy: null };
      return;
    case "select_strategy":
      state.selected = args.file;
      if (state.status.running) state.status.strategy = args.file;
      return;
    case "set_mode":
      state.mode = args.mode;
      return;
    case "set_game_filter":
      state.game_filter = args.gf;
      return;
    case "set_ipset":
      state.ipset = args.mode;
      return;
    case "list_read":
      return "# Never leave this file empty\ndomain.example.abc\n";
    case "list_write":
      return { warnings: [] };
    case "test_last":
      return run;
    case "test_history":
      return [run];
    case "log_tail":
      return ["winws2 started", "lua init ok"];
    case "hosts_status":
      return {
        source: state.language === "en" ? "build (.service\\hosts)" : "сборка (.service\\hosts)",
        // Группы и размеры как в настоящем .service\hosts.
        groups: ([["discord.com", 8], ["discordapp.net", 8], ["github.com", 1], ["githubusercontent.com", 36], ["t.me", 1], ["telegram.dog", 1], ["telegram.me", 1], ["telegram.org", 21], ["telegram.space", 1], ["telesco.pe", 8], ["tg.dev", 2]] as [string, number][]).map(
          ([g, n]) => ({ name: g, entries: Array.from({ length: n }, (_, i) => ({ ip: "140.82.121.3", host: i ? `h${i}.${g}` : g, in_block: true, manual: false })) }),
        ),
        custom: [],
        block_present: true,
        outdated: false,
        hosts_path: "C:\\Windows\\System32\\drivers\\etc\\hosts",
      };
    case "dns_info":
      return structuredClone(dns);
    case "dns_presets":
      return dnsPresets;
    case "dns_apply": {
      const a = dns.adapters.find((x: any) => x.index === args.req.index);
      if (args.req.v4) Object.assign(a, { dns_v4: args.req.v4, static_v4: true });
      if (args.req.v6) Object.assign(a, { dns_v6: args.req.v6, static_v6: true });
      a.doh = args.req.doh_template ? [...(args.req.v4 ?? []), ...(args.req.v6 ?? [])] : [];
      return structuredClone(dns);
    }
    case "dns_reset": {
      const a = dns.adapters.find((x: any) => x.index === args.index);
      if (args.v4) Object.assign(a, { dns_v4: ["192.168.1.1"], static_v4: false });
      if (args.v6) Object.assign(a, { dns_v6: [], static_v6: false });
      a.doh = [];
      return structuredClone(dns);
    }
    case "dns_flush":
      return;
    case "dns_stub_status":
      return structuredClone(stub);
    case "dns_stub_enable":
      Object.assign(stub, {
        running: true,
        config: { guid: "{A1}", name: "Ethernet", template: args.template, bootstrap: args.bootstrap, fallback: args.fallback ? args.bootstrap[0] : null, ipv6: true, addr: "127.0.0.53", prev_v4: null, prev_v6: null },
        stats: { queries: 0, cached: 0, errors: 0, last_error: null, ipv6: true, addr: "127.0.0.53", template: args.template },
      });
      return structuredClone(stub);
    case "dns_stub_disable":
      Object.assign(stub, { running: false, config: null, stats: null });
      return structuredClone(stub);
    case "proxy_status":
      return structuredClone(proxy);
    case "proxy_start":
      proxy.config = args.config;
      proxy.enabled = true;
      proxy.stats = { running: true, port: args.config.port, active: 3, total: 41, failed: 1, system: args.config.system, lan: args.config.lan, auth: !!args.config.user, bypassed: 30, passed: 9, blocked: 2, dns_cached: 17, bypass_domains: 1840, auto_retries: 3, auto_sites: 2, last_error: null };
      return structuredClone(proxy);
    case "proxy_test_targets":
      return ["www.youtube.com", "x.com", "discord.com", "www.instagram.com"];
    case "proxy_test": {
      await new Promise((r) => setTimeout(r, 900));
      const hosts = ["www.youtube.com", "x.com", "discord.com", "www.instagram.com"];
      const mk = (split: string, unit: string, disorder: boolean, ok: number, ms: number | null, oob = false) => ({
        variant: { split, unit, disorder, oob },
        ok,
        total: 4,
        avg_ms: ms,
        targets: hosts.map((h, i) => ({ host: h, ok: i < ok, code: i < ok ? 200 : null, ms: i < ok ? ms : null, error: i < ok ? null : "tls reset" })),
      });
      const results = [mk("none", "records", false, 0, null), mk("sni", "records", true, 2, 1360), mk("chunk", "records", true, 4, 1566), mk("chunk", "tcp", true, 3, 1264), mk("random", "tcp", true, 1, 857), mk("sni", "tcp", false, 3, 1039, true)];
      return { results, best: results[2].variant, cancelled: false };
    }
    case "proxy_log": {
      const now = Date.now();
      return [
        { ts: now - 1000, host: "www.instagram.com", port: 443, action: "bypass", method: null, tries: 0, ms: null, ok: false, error: "connection timed out" },
        { ts: now - 3000, host: "discord.com", port: 443, action: "bypass", method: "chunk/records+disorder", tries: 1, ms: 202, ok: true, error: null },
        { ts: now - 5000, host: "online.sberbank.ru", port: 443, action: "pass", method: null, tries: 0, ms: 95, ok: true, error: null },
        { ts: now - 9000, host: "www.youtube.com", port: 443, action: "bypass", method: "chunk/records+disorder", tries: 2, ms: 4660, ok: true, error: null },
        { ts: now - 9500, host: "ads.example.com", port: 443, action: "block", method: null, tries: 0, ms: null, ok: false, error: null },
      ];
    }
    case "proxy_log_clear":
      return;
    case "proxy_test_cancel":
      return;
    case "proxy_set_config":
      proxy.config = args.config;
      return structuredClone(proxy);
    case "proxy_stop":
      proxy.enabled = false;
      proxy.stats = { ...proxy.stats, running: false, active: 0 };
      return structuredClone(proxy);
    case "diag_run":
      await new Promise((r) => setTimeout(r, 700));
      return diagSample(args.domain);
    case "dns_check_defaults":
      return ["rutracker.org", "www.linkedin.com", "www.instagram.com", "www.facebook.com", "x.com", "discord.com"];
    case "dns_check":
      await new Promise((r) => setTimeout(r, 800));
      return {
        nowhere_answered: false,
        resolvers: [
          { name: "Google", server: "8.8.8.8", answered: true, egress: "172.217.33.215", ms: 82 },
          { name: "Cloudflare", server: "1.1.1.1", answered: true, egress: "172.69.50.56", ms: 69 },
          { name: "Quad9", server: "9.9.9.9", answered: true, egress: "103.194.167.233", ms: 120 },
        ],
        system_egress: "178.185.173.115",
        trusted_ok: true,
        trusted_error: null,
        intercepted: false,
        intercept_reasons: [],
        stubs: 2,
        domains: [
          { domain: "rutracker.org", system: ["172.67.182.196", "104.21.32.39"], public: ["172.67.182.196", "104.21.32.39"], trusted: ["104.21.32.39", "172.67.182.196"], verdict: "ok", cert_check: null },
          { domain: "www.linkedin.com", system: ["130.211.32.14"], public: ["104.18.41.41"], trusted: ["104.18.41.41"], verdict: "cdn", cert_check: "130.211.32.14: ok" },
          { domain: "www.instagram.com", system: ["127.0.0.1"], public: ["31.13.72.174"], trusted: ["31.13.72.174"], verdict: "stub_system", cert_check: null },
          { domain: "www.facebook.com", system: ["127.0.0.1"], public: ["57.144.248.1"], trusted: ["31.13.72.36"], verdict: "stub_system", cert_check: null },
          { domain: "nnmclub.to", system: ["172.67.144.20"], public: ["188.114.97.3"], trusted: ["172.67.144.20"], verdict: "differs", cert_check: "188.114.97.3: TcpFail" },
        ],
      };
    case "evolve_last":
      return {
        kind: "standard", round: 2, rounds: 3, done: 17, planned: 40, current: "AUTO 2.9",
        hall: [
          { name: "AUTO 1.3", parent: "general (ALT3).bat", changes: ["multisplit: seqovl=681 → 568", "fake: −tcp_ts=-600000"], ok: 21, fail: 3, score: 20.6, complexity: 8, unstable: false, error: null, seed: false },
          { name: "general (ALT3)", parent: "general (ALT3).bat", changes: [], ok: 19, fail: 5, score: 18.5, complexity: 9, unstable: true, error: null, seed: true },
          { name: "AUTO 2.4", parent: "general (ALT3).bat", changes: ["multisplit → multidisorder"], ok: 18, fail: 6, score: 17.6, complexity: 8, unstable: false, error: null, seed: false },
        ],
        tried: [], finished: false, cancelled: false, message: null, saved: [], baseline: 19, ceiling: 24,
      };
    case "evolve_start":
    case "evolve_save":
      return "general (AUTO 1).bat";
    case "mcp_status":
      return structuredClone(mcp);
    case "mcp_set":
      mcp.settings = { ...mcp.settings, enabled: args.enabled, allow_changes: args.allowChanges, port: args.port };
      mcp.running = args.enabled;
      mcp.url = `http://127.0.0.1:${args.port}/mcp`;
      return structuredClone(mcp);
    case "mcp_regen_token":
      mcp.settings.token = "9f2c" + Math.random().toString(16).slice(2, 14);
      return structuredClone(mcp);
    case "net_status":
      return structuredClone(net);
    case "net_set":
      net.rules = JSON.parse(JSON.stringify(args.rules));
      net.allowed = !args.rules.enabled || !args.rules.networks.length || (args.rules.mode === "only") === args.rules.networks.includes("HomeWiFi");
      return structuredClone(net);
    case "tg_status":
      return structuredClone(tg);
    case "tg_start":
      tg.config = { ...args.config, enabled: true };
      tg.stats = { ...tg.stats, running: true, active: 3, total: 12, ws: 0, cf: 12, worker: 0, tcp: 0, bytes_up: 182000, bytes_down: 5400000, last_error: "DC2 kws2.web.telegram.org: connection timed out" };
      return structuredClone(tg);
    case "tg_stop":
      tg.config.enabled = false;
      tg.stats = { ...tg.stats, running: false, active: 0 };
      return structuredClone(tg);
    case "tg_set_config":
      tg.config = args.config;
      return structuredClone(tg);
    case "tg_regen_secret":
      return structuredClone(tg);
    case "tg_open_link":
      return;
    case "lan_addresses":
      return ["192.168.0.3"];
    case "sni_defaults":
      return { target: "104.16.132.229:443", snis: ["ya.ru", "vk.com", "gosuslugi.ru", "www.google.com", "www.youtube.com", "discord.com", "github.com", "x.com"] };
    case "sni_scan":
      await new Promise((r) => setTimeout(r, 600));
      return {
        target: args.target,
        items: [
          { sni: "ya.ru", outcome: "pass", ms: 171, detail: null },
          { sni: "vk.com", outcome: "pass", ms: 162, detail: null },
          { sni: "www.google.com", outcome: "pass", ms: 139, detail: null },
          { sni: "www.youtube.com", outcome: "reset", ms: null, detail: "os error 10054" },
          { sni: "discord.com", outcome: "timeout", ms: null, detail: "os error 10060" },
          { sni: "github.com", outcome: "pass", ms: 136, detail: null },
        ],
        passed: 4,
        blocked: 2,
        whitelist_suspected: false,
      };
    case "list_presets":
      return listPresets;
    case "list_add_presets":
      return 7;
    case "set_autostart":
      state.autostart = args.enabled;
      return args.enabled;
    case "set_language":
      state.language = args.lang;
      return;
    case "set_close_to_tray":
      state.close_to_tray = args.enabled;
      return;
    default:
      return null;
  }
}
