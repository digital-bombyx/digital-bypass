# Changelog

Все заметные изменения проекта. Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии — [SemVer](https://semver.org/lang/ru/).

Раздел версии целиком попадает в описание релиза на GitHub, поэтому пишите его для пользователей. Неизданные изменения копите в `[Unreleased]`, а перед тегом `vX.Y.Z` переименуйте его в `[X.Y.Z] - дата`.

## [Unreleased]

### Что нового

- **digital-bypass** — мультитул на основе Zapret2-RustGUI 0.1.1. Всё, что умел Zapret2-RustGUI, стало модулем `zapret2`.
- **Модуль DNS.** Выбор адаптера, пресеты (Cloudflare, Google, Quad9, AdGuard, Яндекс, OpenDNS, Mullvad) и свои адреса, IPv4 и IPv6, возврат к DHCP, показ текущих DNS, сброс кэша. DNS-over-HTTPS на Windows 11 через `netsh dns add encryption`.
- **Строгая тёмная тема.** Графитовый фон, один холодный акцент, стандартные кнопки окна.
- **Широкое окно** 1040×680 с навигацией слева по модулям (в узком окне — вкладки сверху). Размер, положение и развёрнутость окна запоминаются.
- Вкладки DNS и настроек работают и без папки zapret.
- **Прокси-обходчик** без прав администратора и драйвера: нарезка TLS ClientHello (split / disorder), DoH для адресов сайтов, системный прокси Windows с откатом.
- **Локальный DoH-резолвер**: шифрованный DNS и на Windows 10, с резервным обычным DNS и возвратом прежних настроек при выходе.
- **Проверка домена**: системный DNS против DoH, TCP и TLS по адресам, вердикт «подмена DNS / DPI / блокировка по IP» и подсказка модуля.
- **Наборы доменов** для списка обхода: Telegram, Instagram/Facebook/WhatsApp, X, Roblox. Домены, которые уже есть во встроенных списках (YouTube, Discord), не дублируются.
- **Трей**: переключатель прокси-обходчика, состояние DoH-резолвера, в подсказке — все включённые модули.

### What's new

- **digital-bypass** — a multitool based on Zapret2-RustGUI 0.1.1. Everything Zapret2-RustGUI did is now the `zapret2` module.
- **DNS module.** Adapter picker, presets (Cloudflare, Google, Quad9, AdGuard, Yandex, OpenDNS, Mullvad) and custom addresses, IPv4 and IPv6, revert to DHCP, current DNS view, cache flush. DNS-over-HTTPS on Windows 11 via `netsh dns add encryption`.
- **Strict dark theme.** Graphite background, a single cool accent, standard window buttons.
- **Wide window** 1040×680 with module navigation on the left (top tabs when narrow). Window size, position and maximized state are remembered.
- DNS and Settings tabs work without a zapret folder.
- **Bypass proxy** without admin rights or a driver: TLS ClientHello splitting (split / disorder), DoH for site addresses, Windows system proxy with restore.
- **Local DoH resolver**: encrypted DNS on Windows 10 too, with a plain DNS fallback and restore on exit.
- **Domain check**: system DNS vs DoH, TCP and TLS per address, a "DNS spoofing / DPI / IP block" verdict and the module to use.
- **Domain sets** for the bypass list: Telegram, Instagram/Facebook/WhatsApp, X, Roblox. Domains already in the built-in lists (YouTube, Discord) are not duplicated.
- **Tray**: bypass proxy toggle, DoH resolver state, all active modules in the tooltip.

[Unreleased]: https://github.com/digital-bombyx/digital-bypass/commits/main
