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
- **Наборы доменов** для списка обхода: Telegram, Instagram/Facebook/WhatsApp, X, Roblox, SoundCloud. Домены, которые уже есть во встроенных списках (YouTube, Discord), не дублируются.
- **Трей**: переключатель прокси-обходчика, состояние DoH-резолвера, в подсказке — все включённые модули.
- **Прокси**: SOCKS5 на том же порту, раздача в локальную сеть с правилом брандмауэра и логином/паролем для устройств из сети.
- **Сканер SNI** во вкладке «проверка»: какие имена сайтов DPI пропускает к заданному адресу, признак белых списков.
- **Лицензия GPL-3.0** с дополнительными условиями (NOTICE): сохранение авторства и пометка изменённых версий. Zapret2-RustGUI остаётся под MIT.
- **Прокси, способы нарезки** (по мотивам SpoofDPI): по SNI, первый байт, куски, случайная точка; TLS-записи или TCP-сегменты; disorder отдельным переключателем. Правила по доменам: «только списки» (включая списки zapret2), «не резать», «блокировать». DoH с кэшем и параллельным опросом серверов, подключение сразу к нескольким адресам сайта, режим только IPv4.

### What's new

- **digital-bypass** — a multitool based on Zapret2-RustGUI 0.1.1. Everything Zapret2-RustGUI did is now the `zapret2` module.
- **DNS module.** Adapter picker, presets (Cloudflare, Google, Quad9, AdGuard, Yandex, OpenDNS, Mullvad) and custom addresses, IPv4 and IPv6, revert to DHCP, current DNS view, cache flush. DNS-over-HTTPS on Windows 11 via `netsh dns add encryption`.
- **Strict dark theme.** Graphite background, a single cool accent, standard window buttons.
- **Wide window** 1040×680 with module navigation on the left (top tabs when narrow). Window size, position and maximized state are remembered.
- DNS and Settings tabs work without a zapret folder.
- **Bypass proxy** without admin rights or a driver: TLS ClientHello splitting (split / disorder), DoH for site addresses, Windows system proxy with restore.
- **Local DoH resolver**: encrypted DNS on Windows 10 too, with a plain DNS fallback and restore on exit.
- **Domain check**: system DNS vs DoH, TCP and TLS per address, a "DNS spoofing / DPI / IP block" verdict and the module to use.
- **Domain sets** for the bypass list: Telegram, Instagram/Facebook/WhatsApp, X, Roblox, SoundCloud. Domains already in the built-in lists (YouTube, Discord) are not duplicated.
- **Tray**: bypass proxy toggle, DoH resolver state, all active modules in the tooltip.
- **Proxy**: SOCKS5 on the same port, local network sharing with a firewall rule and a user/password for network devices.
- **SNI scanner** in the Check tab: which site names DPI lets through to a given address, with a whitelist hint.
- **GPL-3.0 license** with additional terms (NOTICE): author attribution and marking of modified versions. Zapret2-RustGUI stays under MIT.
- **Proxy split methods** (inspired by SpoofDPI): at SNI, first byte, chunks, random point; TLS records or TCP segments; disorder as a separate switch. Per-domain rules: listed only (including the zapret2 lists), do not split, block. Cached DoH with parallel servers, racing connections to several site addresses, IPv4-only mode.

[Unreleased]: https://github.com/digital-bombyx/digital-bypass/commits/main
