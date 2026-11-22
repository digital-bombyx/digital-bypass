<div align="center">

<img src="src-tauri/icons/128x128.png" width="96" alt="digital-bypass" />

# digital-bypass

**A network unblocking multitool for Windows**

One-click zapret2 (winws2 + Lua), a bypass proxy without admin rights, DNS switching and DoH, a "why won't it open" check, hosts.

[Русский](README.md) · **English**

![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-58a6ff?style=flat-square&labelColor=0f1216)
![Rust](https://img.shields.io/badge/Rust-Tauri%202-58a6ff?style=flat-square&labelColor=0f1216)
![Svelte](https://img.shields.io/badge/Svelte-5-58a6ff?style=flat-square&labelColor=0f1216)
![License](https://img.shields.io/badge/license-GPL--3.0-58a6ff?style=flat-square&labelColor=0f1216)

</div>

> Based on [Zapret2-RustGUI](https://github.com/digital-bombyx/Zapret2-RustGUI): its features became the `zapret2` module of this multitool.

## Modules

### zapret2

- **Bundled zapret-discord-youtube.** Ships inside the installer, your lists and settings survive updates. A custom folder is supported.
- **One-click bypass.** `winws2.exe` runs directly, without a console: as a process (while the app is open) or as the `zapret` service, compatible with `service.bat`.
- **Strategies as-is.** Arguments are read straight from `general*.bat`.
- **Strategy tests** modelled on `utils\test zapret.ps1`: HTTP / TLS 1.2 / TLS 1.3 + ping and the "16-20 KB" DPI test, best pick and history.
- **Game Filter, IPSet, user lists** — the same files `service.bat` writes.
- **Domain sets**: Telegram, Instagram/Facebook/WhatsApp, X, Roblox, SoundCloud are added to the list in one click (YouTube and Discord are already in the built-in lists).

### DNS

Sometimes changing DNS is enough to get around light blocking.

- Pick a network adapter. The one carrying internet traffic is preselected.
- Current IPv4 and IPv6 DNS: manual or DHCP, and whether DoH is on.
- Presets: Cloudflare, Cloudflare Security, Google, Quad9, AdGuard, AdGuard Unfiltered, Yandex, Yandex Safe, OpenDNS, Mullvad, or your own addresses.
- **DNS-over-HTTPS** (Windows 11): the template is registered with `netsh dns add encryption`, and encryption is enabled on the adapter for the chosen servers. Optional fallback to plain DNS.
- Revert to automatic DNS (DHCP) and flush the DNS cache.
- **Local resolver** — encrypted DNS on Windows 10 too: the app answers DNS queries on `127.0.0.x:53` and forwards them over DoT (DNS over TLS, works for every preset except OpenDNS) or DoH. While it runs the ISP cannot see or spoof DNS; on exit the previous DNS is restored. An optional plain DNS fallback keeps the internet working when the app is closed.

### Bypass proxy

DPI bypass **without admin rights and without a driver** — for work PCs and when antivirus blocks WinDivert.

- A local proxy splits the TLS ClientHello: at the site name, the first byte, fixed-size chunks, a random point or custom positions (ByeDPI syntax, e.g. `0+sm 1:3:5 -10`); parts go as separate TLS records or TCP segments. `disorder` sends the first part with TTL=1.
- **Auto mode**: if a site resets or stays silent after the ClientHello, the proxy reconnects with fallback methods and remembers the one that works for that site. **OOB** adds an urgent byte after the first part that DPI sees but the server does not. Ideas from [ByeDPI](https://github.com/hufrea/byedpi).
- **Connection log** (optional): site, action, method, attempts and outcome.
- **Method finder**: every split variant is tried on a temporary proxy against chosen sites, the best is applied in one click — like the zapret2 strategy tests.
- **Per-domain rules**: split everything or only listed domains (including the zapret2 lists), "do not split" for banks and fragile sites, blocking.
- Site addresses are resolved via DoH (Cloudflare and Google in parallel, cached), so DNS spoofing does not matter. Connections race several site addresses and take the first that answers.
- The proxy is set in Windows settings and removed when turned off.
- HTTP and SOCKS5 on one port.
- **Local network sharing**: a phone on the same Wi-Fi uses the PC as its proxy. Only local network addresses are allowed, and the firewall rule is added automatically (with admin rights). An optional user and password are asked from network devices but not from the PC itself.
- HTTPS through the proxy only: UDP, QUIC and Discord voice still need zapret2.

### Check

Enter a domain: the app compares the system DNS with DoH, tries TCP and TLS to each address and tells what is wrong — DNS spoofing, DPI by site name or IP blocking — and which module helps.

**DNS tampering**: finds ISP stubs (127.0.0.1 and foreign addresses for blocked domains) and interception of queries to 8.8.8.8, 1.1.1.1, 9.9.9.9 — then changing DNS does not help and encrypted DNS is needed. The reference is DoT; differing addresses are verified by the site's certificate (with a split ClientHello so DPI does not interfere).

The **SNI scanner** sends a TLS hello with different site names to one address and shows which names DPI lets through. It helps to tell whether whitelists are on and to pick a name for VLESS Reality or a fake SNI for strategies. The idea comes from [sni-spoofing-rust](https://github.com/therealaleph/sni-spoofing-rust).

### hosts

Entries from `.service\hosts` go into the system hosts file as a separate block that one button removes. Custom entries, GitHub updates, a backup before writing.

### General

Tray with quick zapret2 and bypass proxy toggles, strategy switch and DoH resolver state, autostart with admin rights, Russian and English UI.

## Install

1. Download `digital-bypass_x.y.z_x64-setup.exe` from [Releases](https://github.com/digital-bombyx/digital-bypass/releases/latest). A `.sha256` file is attached.
2. Run it. The app asks for administrator rights: WinDivert, services, hosts and DNS changes need them.

> [!NOTE]
> The app ships `winws2.exe` and the WinDivert driver. Some antivirus products flag files like these. You can verify them against the checksums of the [zapret2 release](https://github.com/bol-van/zapret2/releases).

## Build from source

Requires Node.js, Rust (MSVC) and a git clone of [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube):

```powershell
npm install
$env:ZAPRET_SRC = "D:\zapret-discord-youtube"   # this is the default
npm run tauri build
```

## Credits

- **[bol-van](https://github.com/bol-van)** — [zapret](https://github.com/bol-van/zapret) and [zapret2](https://github.com/bol-van/zapret2).
- **[Flowseal](https://github.com/Flowseal)** and the [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) contributors.
- Authors of [PR #18202](https://github.com/Flowseal/zapret-discord-youtube/pull/18202) — the zapret2 port.
- **[basil00/WinDivert](https://github.com/basil00/WinDivert)**, **[hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers)**.

## License

[GPL-3.0](LICENSE) with additional terms under section 7 ([NOTICE](NOTICE)):

- every copy and derivative keeps the NOTICE file and the copyright;
- if the program shows author information in its UI (an About or settings screen), it must include "Based on digital-bypass by digital-bombyx" with a link to the repository;
- modified versions must be marked as different from the original (another name or a version suffix).

Forks and derivative works stay open under GPL-3.0.
