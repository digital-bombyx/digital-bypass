<div align="center">

<img src="src-tauri/icons/128x128.png" width="96" alt="digital-bypass" />

# digital-bypass

**Мультитул для обхода блокировок на Windows**

zapret2 (winws2 + Lua) в один клик, прокси-обходчик без прав администратора, смена DNS и DoH, проверка «почему не открывается», hosts.

**Русский** · [English](README.en.md)

![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-58a6ff?style=flat-square&labelColor=0f1216)
![Rust](https://img.shields.io/badge/Rust-Tauri%202-58a6ff?style=flat-square&labelColor=0f1216)
![Svelte](https://img.shields.io/badge/Svelte-5-58a6ff?style=flat-square&labelColor=0f1216)
![License](https://img.shields.io/badge/license-GPL--3.0-58a6ff?style=flat-square&labelColor=0f1216)

</div>

> Основан на [Zapret2-RustGUI](https://github.com/digital-bombyx/Zapret2-RustGUI): его функции стали модулем `zapret2` этого мультитула.

## Модули

### zapret2

- **Встроенный zapret-discord-youtube.** Сборка лежит внутри установщика, при обновлении ваши списки и настройки остаются. Можно указать свою папку.
- **Включение в один клик.** `winws2.exe` запускается напрямую, без консоли: процессом (пока открыто приложение) или службой `zapret`, совместимой с `service.bat`.
- **Стратегии без переделок.** Аргументы берутся прямо из `general*.bat`.
- **Тесты стратегий** по образцу `utils\test zapret.ps1`: HTTP / TLS 1.2 / TLS 1.3 + ping и DPI-тест «16-20 КБ», выбор лучшей, история.
- **Game Filter, IPSet, пользовательские списки** — те же файлы, что пишет `service.bat`.
- **Наборы доменов**: Telegram, Instagram/Facebook/WhatsApp, X, Roblox, SoundCloud добавляются в список одним кликом (YouTube и Discord уже есть во встроенных списках).

### DNS

Иногда лёгкие блокировки обходятся одной сменой DNS.

- Выбор сетевого адаптера. Адаптер, через который идёт интернет, выбирается сам.
- Текущие DNS для IPv4 и IPv6: заданы вручную или получены по DHCP, включён ли DoH.
- Пресеты: Cloudflare, Cloudflare Security, Google, Quad9, AdGuard, AdGuard Unfiltered, Яндекс, Яндекс Безопасный, OpenDNS, Mullvad. Или свои адреса.
- **DNS-over-HTTPS** (Windows 11): шаблон регистрируется через `netsh dns add encryption`, на адаптере включается шифрование для выбранных серверов. Откат на обычный DNS — по желанию.
- Возврат к автоматическому DNS (DHCP) и сброс кэша DNS.
- **Локальный резолвер** — шифрованный DNS и на Windows 10: приложение само отвечает на DNS-запросы на `127.0.0.x:53` и пересылает их по DoT (DNS поверх TLS, работает у всех пресетов, кроме OpenDNS) или DoH. Пока оно работает, провайдер не видит и не подменяет DNS; при выходе прежний DNS возвращается. Есть резервный обычный DNS на случай, если приложение закрыто.

### Прокси-обходчик

Обход DPI **без прав администратора и без драйвера** — для рабочих ПК и случаев, когда антивирус не даёт WinDivert.

- Локальный прокси режет TLS ClientHello: по имени сайта, первый байт, куски заданного размера, в случайной точке или по своим позициям (синтаксис ByeDPI, например `0+sm 1:3:5 -10`); части — отдельными TLS-записями или TCP-сегментами. `disorder` отправляет первую часть с TTL=1.
- **Автоматический режим**: если сайт сбросил соединение или молчит после ClientHello, прокси переподключается запасными способами и запоминает рабочий для этого сайта. **OOB** — к первой части добавляется «срочный» байт, который видит DPI, но не сервер. Идеи — из [ByeDPI](https://github.com/hufrea/byedpi).
- **Подбор способа**: каждый вариант нарезки проверяется на временном прокси по выбранным сайтам, лучший применяется одной кнопкой — как тесты стратегий zapret2.
- **Правила по доменам**: резать всё или только домены из списков (в том числе списков zapret2), «не резать» для банков и капризных сайтов, блокировка.
- Адреса сайтов разрешаются через DoH (Cloudflare и Google параллельно, с кэшем) — подмена DNS не мешает. Подключение идёт сразу к нескольким адресам сайта, побеждает первый ответивший.
- Прокси прописывается в настройки Windows и снимается при выключении.
- HTTP и SOCKS5 на одном порту.
- **Раздача в локальную сеть**: телефон в той же Wi-Fi указывает ПК как прокси. Пускаются только адреса локальной сети, правило брандмауэра добавляется само (с правами администратора). Можно задать логин и пароль — их спрашивают у устройств из сети, но не у самого ПК.
- Только HTTPS через прокси: UDP, QUIC и голос Discord по-прежнему требуют zapret2.

### Проверка

Введите домен — приложение сравнит системный DNS с DoH, попробует TCP и TLS к каждому адресу и скажет, в чём дело: подмена DNS, DPI по имени сайта или блокировка по IP. И подскажет, какой модуль поможет.

**Сканер SNI** отправляет к одному адресу TLS-приветствие с разными именами сайтов и показывает, какие имена DPI пропускает. Помогает понять, включены ли белые списки, и подобрать имя для VLESS Reality или поддельный SNI для стратегий. Идея — из [sni-spoofing-rust](https://github.com/therealaleph/sni-spoofing-rust).

### hosts

Записи из `.service\hosts` добавляются в системный hosts отдельным блоком, который снимается одной кнопкой. Свои записи, обновление с GitHub, бэкап перед записью.

### Общее

Трей с быстрым включением zapret2 и прокси-обходчика, сменой стратегии и состоянием DoH-резолвера, автозапуск с правами администратора, русский и английский интерфейс.

## Установка

1. Скачайте `digital-bypass_x.y.z_x64-setup.exe` со страницы [Releases](https://github.com/digital-bombyx/digital-bypass/releases/latest) и установите. Рядом лежит `.sha256`.
2. Запустите. Приложение попросит права администратора: они нужны WinDivert, службам, hosts и смене DNS.

> [!NOTE]
> Внутри лежат `winws2.exe` и драйвер WinDivert. Некоторые антивирусы помечают такие файлы как угрозу. Проверить их можно по контрольным суммам релиза [zapret2](https://github.com/bol-van/zapret2/releases).

## Сборка из исходников

Нужны Node.js, Rust (MSVC) и git-клон [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube):

```powershell
npm install
$env:ZAPRET_SRC = "D:\zapret-discord-youtube"   # по умолчанию именно этот путь
npm run tauri build
```

Перед сборкой `scripts/sync-zapret.mjs` берёт чистую копию сборки из git и кладёт её в ресурсы установщика. Установщик появится в `src-tauri\target\release\bundle\nsis\`.

Релизы собирает GitHub Actions ([`release.yml`](.github/workflows/release.yml)) при пуше тега `vX.Y.Z`, описание берётся из [CHANGELOG.md](CHANGELOG.md).

## Благодарности

- **[bol-van](https://github.com/bol-van)** — [zapret](https://github.com/bol-van/zapret) и [zapret2](https://github.com/bol-van/zapret2): движок `winws` / `winws2` и Lua-библиотеки.
- **[Flowseal](https://github.com/Flowseal)** и контрибьюторы [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) — сборка, стратегии, списки и скрипты.
- Авторы [PR #18202](https://github.com/Flowseal/zapret-discord-youtube/pull/18202) — перевод сборки на zapret2.
- **[basil00/WinDivert](https://github.com/basil00/WinDivert)** — драйвер перехвата пакетов.
- **[hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers)** — цели для DPI-теста «16-20 КБ».

Бинарники и Lua-скрипты встроенной сборки распространяются под лицензиями их авторов (см. `LICENSE.txt` в папке сборки).

## Лицензия

[GPL-3.0](LICENSE) с дополнительными условиями по пункту 7 ([NOTICE](NOTICE)):

- в любой копии и производной версии сохраняются файл NOTICE и копирайт;
- если программа показывает сведения об авторах в интерфейсе («О программе», настройки), там должна быть строка «Based on digital-bypass by digital-bombyx» со ссылкой на репозиторий;
- изменённые версии помечаются как отличные от оригинала (другое название или суффикс версии).

Форки и производные работы остаются открытыми под GPL-3.0.

<div align="center"><sub><a href="https://github.com/digital-bombyx">digital-bombyx</a></sub></div>
