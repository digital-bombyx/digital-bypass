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
  { id: "cloudflare", name: "Cloudflare", note_ru: "без фильтрации, быстрый", note_en: "no filtering, fast", v4: ["1.1.1.1", "1.0.0.1"], v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"], doh: "https://cloudflare-dns.com/dns-query" },
  { id: "google", name: "Google", note_ru: "без фильтрации", note_en: "no filtering", v4: ["8.8.8.8", "8.8.4.4"], v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"], doh: "https://dns.google/dns-query" },
  { id: "quad9", name: "Quad9", note_ru: "блокирует вредоносные домены, DNSSEC", note_en: "blocks malware domains, DNSSEC", v4: ["9.9.9.9", "149.112.112.112"], v6: ["2620:fe::fe", "2620:fe::9"], doh: "https://dns.quad9.net/dns-query" },
  { id: "adguard", name: "AdGuard", note_ru: "режет рекламу и трекеры", note_en: "blocks ads and trackers", v4: ["94.140.14.14", "94.140.15.15"], v6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"], doh: "https://dns.adguard-dns.com/dns-query" },
  { id: "yandex", name: "Яндекс", note_ru: "базовый, доступен при белых списках", note_en: "basic, reachable under whitelists", v4: ["77.88.8.8", "77.88.8.1"], v6: ["2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"], doh: "https://common.dot.dns.yandex.net/dns-query" },
  { id: "mullvad", name: "Mullvad", note_ru: "без логов и фильтрации", note_en: "no logs, no filtering", v4: ["194.242.2.2"], v6: ["2a07:e340::2"], doh: "https://dns.mullvad.net/dns-query" },
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

export async function mockInvoke(cmd: string, args: any = {}): Promise<any> {
  await new Promise((r) => setTimeout(r, 120));
  switch (cmd) {
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
