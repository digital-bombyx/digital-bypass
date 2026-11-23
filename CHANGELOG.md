# Changelog

Все заметные изменения проекта. Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии — [SemVer](https://semver.org/lang/ru/).

Раздел версии целиком попадает в описание релиза на GitHub, поэтому пишите его для пользователей. Неизданные изменения копите в `[Unreleased]`, а перед тегом `vX.Y.Z` переименуйте его в `[X.Y.Z] - дата`.

## [Unreleased]

### Что нового

- **Прокси: маршрут через свой Cloudflare Worker** — домены из списка (сайты, заблокированные по IP или с геоограничениями: Instagram, Facebook, Spotify, ИИ-сервисы) идут через ваш Worker по WebSocket, а он открывает TCP к сайту. TLS браузера с сайтом сквозной. Нарезка ClientHello к Cloudflare — как в Telegram-модуле. Код Worker с ключом и инструкция — в приложении. Идея — ws-proxy из [kinlay0/zapret2-discord-youtube-strats](https://github.com/kinlay0/zapret2-discord-youtube-strats).

- **Ещё 38 стратегий zapret2** из коллекции [kinlay0/zapret2-discord-youtube-strats](https://github.com/kinlay0/zapret2-discord-youtube-strats): ALT14–16, CIRCULAR, DOUBLE/SINGLE FAKE, EXP1–10, HOSTFAKESPLIT TS, LEGACY, SYNDATA и др. В списке — с префиксом «K-», имена фейков приведены к сборке Flowseal, два новых фейка добавлены. Обновление коллекции — `scripts/import-kinlay-strats.py`.

- **Дополнения к zapret2** (из официальной сборки bol-van для Windows):
  - **Авто-стратегия** — кнопка в результатах теста собирает `general (AUTO ROTATE).bat`: основа — лучшая стратегия, а в TCP-профилях действия 2–4 следующих становятся запасными. winws2 сам переключает их для каждого сайта при сбоях (RST от DPI, ретрансмиссии) — оркестратор `circular` из `zapret-auto.lua`.
  - **Разблокировать WireGuard** — фейк перед рукопожатием WireGuard/AmneziaWG на любых портах.
  - **Экономный перехват UDP** — QUIC и голос Discord отбираются фильтрами в драйвере WinDivert: в winws2 идут только нужные пакеты, а не весь поток.
  - **Скрыть WinDivert от игр** — драйвер под именем «Monkey» для античитов, ищущих WinDivert по имени.

- **DoH-резолвер убирает ECH**: на запросы HTTPS-записей (где сайты за Cloudflare публикуют ключ ECH) отдаётся пустой ответ. Иначе Chrome шлёт ClientHello с именем `cloudflare-ech.com`, а такие ТСПУ отбрасывает с ноября 2024; без ключа браузер шлёт обычный ClientHello, который обходится нарезкой. Действует, когда браузер берёт DNS у системы (не свой встроенный DoH). Идея — из [B4](https://github.com/DanielLavrushin/b4).
- **Проверка сайта через прокси**: если прокси-обходчик включён, сайт проверяется и через него — видно, исправляет прокси сайт или ломает его.
- **Ограничение по сети назначения: поиск SNI** — адрес хостинга проверяется со списком имён сканера SNI; если какое-то проходит, VLESS+Reality с таким SNI на этом хостинге может работать.
- **Автоподбор: подтверждение победителя** — перед сохранением ещё три прогона, каждый должен быть выше планки, иначе очередь следующего кандидата (как в Discovery у B4).

- **Проверка: ограничение по сети назначения** — новый вердикт для зарубежных хостингов (Hetzner, OVH, DigitalOcean, Vultr и др.): TLS к адресу обрывается с любым именем сайта, или передача замирает после ~16–33 КБ без сброса (проверка отправкой 64 КБ). Нарезка тут не помогает, раньше это ошибочно называлось «DPI по имени». По обзорам [tspu-docs](https://github.com/DanielLavrushin/tspu-docs).
- **Тест стратегий**: лучшая стратегия перепроверяется в конце (блокировка после срабатывания держится 40–420 с, порядок проверки может влиять); по умолчанию 8 потоков вместо 16 (у части провайдеров лимит ~12 TLS-соединений).

- **MCP для ИИ-ассистентов**: HTTP-сервер на 127.0.0.1 с токеном, 12 инструментов — проверка сайта с советом, подбор стратегии zapret2 под конкретный сайт, статус, журналы, проверка DNS, управление zapret2 и прокси, правка списков (изменения — по отдельному разрешению). Готовые настройки для Claude Code, Cursor / VS Code и Claude Desktop.
- **Прокси: TLS-записи с разными версиями** (первая 1.2, остальные 1.0), в подборе способа 37 вариантов.

- **Тест стратегий: потолок** — сколько проверок не прошли ни с одной стратегией (обычно блокировка по IP); автоподбор сохраняет кандидата, только если он обошёл засев и в своей перепроверке, и в обычном тесте.

- **Автоподбор стратегии zapret2** (эксперимент, по мотивам Geneva): мутации TCP-части лучших стратегий, двойная проверка тестером, штраф за сложность, сохранение лучшего как `general (AUTO N).bat`. Упрощённый локальный поиск, не полный генетический алгоритм.

- **Проверка: тип блокировки** (по методике blockcheck из zapret): режут запрос или ответ сервера, помогает ли нарезка, частичная блокировка по IP, режется ли имя на постороннем адресе; две попытки на адрес, расхождение показывается.
- **Прокси: маленький буфер приёма** (эксперимент) — против DPI, который режет по сертификату в ответе.
- **Включение по сети**: zapret2 и прокси только в выбранных сетях или везде, кроме них; при смене сети останавливаются и возвращаются сами.

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
- **Подбор способа для прокси**: 17 вариантов нарезки на временных прокси, сайты на выбор, лучший — одной кнопкой.
- Подбор стратегии zapret2 перенесён на вкладку zapret2, отдельной вкладки «Тесты» больше нет.
- **Прокси, автоматический режим** (по мотивам ByeDPI): при сбросе или молчании после ClientHello — переподключение запасными способами, рабочий запоминается для сайта на 6 часов. Запасные способы задаются подбором. **OOB** как ещё одна техника; подбор проверяет 33 варианта.
- **Свои позиции разреза** для прокси в синтаксисе ByeDPI: `смещение[:повторы:шаг][+s|e|m|n]`.
- Текст ярче, мелкие подписи на полпикселя крупнее.
- **DoT для локального резолвера**: DNS поверх TLS (порт 853), по умолчанию. Наш DoH работает по HTTP/1.1, и Quad9, Яндекс, AdGuard Unfiltered и Mullvad по нему не отвечали; по DoT отвечают все пресеты, кроме OpenDNS.
- **Журнал соединений прокси** (включается в настройках): сайт, действие, способ, число попыток автоматического режима, время или ошибка.
- **Проверка DNS на подмену** во вкладке «Проверка»: заглушки провайдера, перехват запросов к публичным DNS (адрес без DNS-сервера, `whoami.akamai.net`), эталон через DoT, проверка отличающихся адресов сертификатом.
- **Telegram-прокси** (порт tg-ws-proxy от Flowseal): MTProto → WebSocket к Telegram, запасные пути через свой Cloudflare Worker, CF-прокси и TCP; нарезка ClientHello; подключение в Telegram одной кнопкой; код Worker'а в приложении; переключатель в трее.
- **Telegram: подмена SNI** для прямого WebSocket (как в tg-ws-proxy): в TLS — другое имя, Host настоящий; сертификат проверяется по цепочке без сверки имени; при неудаче — повтор с настоящим именем.

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
- **Proxy method finder**: 17 split variants on temporary proxies, sites of your choice, the best applied in one click.
- The zapret2 strategy test moved to the zapret2 tab; the separate Tests tab is gone.
- **Proxy auto mode** (inspired by ByeDPI): on a reset or silence after the ClientHello the proxy reconnects with fallback methods and remembers the working one per site for 6 hours; the finder sets the fallbacks. **OOB** as another technique; the finder tries 33 variants.
- **Custom cut positions** for the proxy in ByeDPI syntax: `offset[:repeats:skip][+s|e|m|n]`.
- Brighter text; small labels half a pixel larger.
- **DoT for the local resolver**: DNS over TLS (port 853), the default. Our DoH speaks HTTP/1.1, and Quad9, Yandex, AdGuard Unfiltered and Mullvad did not answer it; over DoT every preset except OpenDNS works.
- **Proxy connection log** (opt-in): site, action, method, auto-mode attempts, time or error.
- **DNS tampering check** in the Check tab: ISP stubs, interception of queries to public DNS (no-DNS address, `whoami.akamai.net`), DoT reference, certificate check of differing addresses.
- **Telegram proxy** (a port of Flowseal's tg-ws-proxy): MTProto → WebSocket to Telegram, fallbacks through your own Cloudflare Worker, a CF proxy and TCP; split ClientHello; one-click Telegram setup; Worker code built in; tray toggle.
- **Telegram: SNI override** for the direct WebSocket (as in tg-ws-proxy): another name in TLS, the real Host; the certificate chain is verified without the name check; on failure — retry with the real name.

[Unreleased]: https://github.com/digital-bombyx/digital-bypass/commits/main
