<div align="center">

<img src="src-tauri/icons/128x128.png" width="96" alt="digital-bypass" />

# digital-bypass

**A network unblocking multitool for Windows**

One-click zapret2 (winws2 + Lua), DNS switching with DoH, hosts. One installer, no console windows.

[Русский](README.md) · **English**

![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-58a6ff?style=flat-square&labelColor=0f1216)
![Rust](https://img.shields.io/badge/Rust-Tauri%202-58a6ff?style=flat-square&labelColor=0f1216)
![Svelte](https://img.shields.io/badge/Svelte-5-58a6ff?style=flat-square&labelColor=0f1216)

</div>

> Based on [Zapret2-RustGUI](https://github.com/digital-bombyx/Zapret2-RustGUI): its features became the `zapret2` module of this multitool.

## Modules

### zapret2

- **Bundled zapret-discord-youtube.** Ships inside the installer, your lists and settings survive updates. A custom folder is supported.
- **One-click bypass.** `winws2.exe` runs directly, without a console: as a process (while the app is open) or as the `zapret` service, compatible with `service.bat`.
- **Strategies as-is.** Arguments are read straight from `general*.bat`.
- **Strategy tests** modelled on `utils\test zapret.ps1`: HTTP / TLS 1.2 / TLS 1.3 + ping and the "16-20 KB" DPI test, best pick and history.
- **Game Filter, IPSet, user lists** — the same files `service.bat` writes.

### DNS

Sometimes changing DNS is enough to get around light blocking.

- Pick a network adapter. The one carrying internet traffic is preselected.
- Current IPv4 and IPv6 DNS: manual or DHCP, and whether DoH is on.
- Presets: Cloudflare, Cloudflare Security, Google, Quad9, AdGuard, AdGuard Unfiltered, Yandex, Yandex Safe, OpenDNS, Mullvad, or your own addresses.
- **DNS-over-HTTPS** (Windows 11): the template is registered with `netsh dns add encryption`, and encryption is enabled on the adapter for the chosen servers. Optional fallback to plain DNS.
- Revert to automatic DNS (DHCP) and flush the DNS cache.

### hosts

Entries from `.service\hosts` go into the system hosts file as a separate block that one button removes. Custom entries, GitHub updates, a backup before writing.

### General

Tray with a quick zapret2 toggle and strategy switch, autostart with admin rights, Russian and English UI.

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
