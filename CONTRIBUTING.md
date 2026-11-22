# Как помочь проекту

Спасибо, что хотите помочь digital-bypass! Ниже — короткие правила, чтобы ваш вклад было легко принять.

*English version below.*

## Сообщить об ошибке

Откройте [issue](https://github.com/digital-bombyx/digital-bypass/issues) и укажите:

- версию приложения и Windows;
- какую сборку zapret используете: встроенную или свою папку (видно в «Настройках»);
- шаги, чтобы воспроизвести проблему, что ожидали и что получили;
- текст ошибки и лог winws2 (кнопка «лог» на главной), если он есть.

> Если перестала работать стратегия обхода, проблема скорее всего в самой стратегии, а не в GUI. О таком пишите в [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube).

## Предложить идею

Опишите в issue, какую задачу решает идея и как вы видите её в интерфейсе. Скриншот или набросок очень помогают.

## Pull request

1. Сделайте форк и ветку от `main`: `feature/…` или `fix/…`.
2. Один PR — одна логическая задача. Большие изменения лучше сначала обсудить в issue.
3. Перед отправкой проверьте:
   ```powershell
   npm run check                       # svelte-check без ошибок
   cd src-tauri; cargo test            # тесты Rust
   npm run tauri build                 # сборка проходит
   ```
4. Опишите в PR, что изменилось и как вы это проверили. Для изменений интерфейса приложите скриншоты.
5. Если изменение заметно пользователю, добавьте строку в раздел `[Unreleased]` файла [CHANGELOG.md](CHANGELOG.md).

### Принципы проекта

- **Bat-файлы стратегий не меняем.** GUI читает `general*.bat` из сборки как есть.
- **Совместимость с `service.bat`.** Состояние (Game Filter, IPSet, пользовательские списки, служба `zapret`) хранится в тех же файлах и местах, что использует сборка.
- **Лёгкость.** Перед добавлением новой зависимости подумайте, нельзя ли без неё.
- **Два языка.** Любой новый текст в интерфейсе пишите через `t("по-русски", "in English")` во фронтенде и через `tr!(…)` в Rust.
- **Палитра.** Используйте токены из `src/app.css`, без новых «случайных» цветов.

### Стиль кода

- Rust: `cargo fmt`, без новых предупреждений `cargo clippy`.
- Svelte/TypeScript: Svelte 5 runes, строгая типизация, `npm run check` без ошибок.
- Комментарии пишите по делу и объясняйте в них «почему», а не «что».

## Поведение

Будьте вежливы и уважительны. Конструктивная критика приветствуется, переход на личности — нет.

## Лицензия

Отправляя вклад, вы соглашаетесь, что он распространяется под [лицензией GPL-3.0](LICENSE) проекта с дополнительными условиями из [NOTICE](NOTICE).

---

# Contributing (English)

Thanks for helping digital-bypass!

- **Bugs:** open an [issue](https://github.com/digital-bombyx/digital-bypass/issues) with:
  - the app and Windows versions;
  - which zapret build you use: bundled or a custom folder;
  - steps to reproduce, what you expected and what happened;
  - the error text and the winws2 log, if any.

  If a bypass strategy itself stopped working, report it to [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) instead.
- **Ideas:** describe the problem the idea solves and how you see it in the UI.
- **Pull requests:**
  - branch from `main` as `feature/…` or `fix/…`;
  - keep one logical change per PR;
  - make sure `npm run check`, `cargo test` (in `src-tauri`) and `npm run tauri build` pass;
  - add screenshots for UI changes;
  - add a line to `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- **Project principles:**
  - never edit the strategy `.bat` files;
  - stay compatible with `service.bat`;
  - keep the app lightweight;
  - write every UI string in both languages: `t("ru", "en")` / `tr!(…)`;
  - use the palette tokens from `src/app.css`.
- **Conduct:** be kind and respectful.
- **License:** contributions are released under the project's [GPL-3.0 license](LICENSE) with the additional terms in [NOTICE](NOTICE).
