# Changelog

Все заметные изменения проекта. Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии — [SemVer](https://semver.org/lang/ru/).

Раздел версии целиком попадает в описание релиза на GitHub, поэтому пишите его для пользователей. Неизданные изменения копите в `[Unreleased]`, а перед тегом `vX.Y.Z` переименуйте его в `[X.Y.Z] - дата`.

## [Unreleased]

### Что нового

- **digital-bypass** — мультитул на основе Zapret2-RustGUI 0.1.1. Всё, что умел Zapret2-RustGUI, стало модулем `zapret2`.
- **Модуль DNS.** Выбор адаптера, пресеты (Cloudflare, Google, Quad9, AdGuard, Яндекс, OpenDNS, Mullvad) и свои адреса, IPv4 и IPv6, возврат к DHCP, показ текущих DNS, сброс кэша. DNS-over-HTTPS на Windows 11 через `netsh dns add encryption`.
- **Строгая тёмная тема.** Графитовый фон, один холодный акцент, вкладки с подчёркиванием, стандартные кнопки окна.
- Вкладки DNS и настроек работают и без папки zapret.

### What's new

- **digital-bypass** — a multitool based on Zapret2-RustGUI 0.1.1. Everything Zapret2-RustGUI did is now the `zapret2` module.
- **DNS module.** Adapter picker, presets (Cloudflare, Google, Quad9, AdGuard, Yandex, OpenDNS, Mullvad) and custom addresses, IPv4 and IPv6, revert to DHCP, current DNS view, cache flush. DNS-over-HTTPS on Windows 11 via `netsh dns add encryption`.
- **Strict dark theme.** Graphite background, a single cool accent, underlined tabs, standard window buttons.
- DNS and Settings tabs work without a zapret folder.

[Unreleased]: https://github.com/digital-bombyx/digital-bypass/commits/main
