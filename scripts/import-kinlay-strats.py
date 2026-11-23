"""Импорт стратегий kinlay0/zapret2-discord-youtube-strats в src-tauri/addons.

Запуск: py scripts/import-kinlay-strats.py <папка с распакованным репозиторием>

- Каждая стратегия получает префикс «K-»: general (ALT14).bat -> general (K-ALT14).bat
  (не пересекаются с одноимёнными у Flowseal, видно источник).
- Имена фейков приводятся к именам из blobs.lua сборки Flowseal.
- Фейки, которых у Flowseal нет, регистрирует addons/blobs-extra.lua; стратегиям,
  которые их используют, добавляется --lua-init этого файла.
- Список для встраивания в exe пишется в src-tauri/src/addons_strats.rs.
После импорта: cargo test kinlay_strategies_parse — проверит, что все фейки известны.
"""
import pathlib, re, shutil, sys

SRC = pathlib.Path(sys.argv[1])
ROOT = pathlib.Path(__file__).resolve().parent.parent / 'src-tauri'
ADD = ROOT / 'addons'
DST = ADD / 'strats'

# Их имя фейка -> имя в blobs.lua сборки Flowseal.
MAP = {
    'active_discord': 'ACTIVE_DISCORD',
    'active_game': 'ACTIVE_GAME',
    'tls_mail': 'tls_sochi_park',
    'tls_steamchat': 'tls_steam_chat',
    'quic_steamchat': 'quic_steam_chat',
    'quic_steam': 'quic_steamcomm',
}
# Фейки, которых у Flowseal нет: имя -> файл в bin/.
EXTRA = {'tls_firpo': 'tls_clienthello_firpo_ru.bin', 'tls_retext': 'tls_clienthello_retext_ai.bin'}

if DST.exists():
    shutil.rmtree(DST)
DST.mkdir(parents=True)

files = []
for f in sorted(SRC.glob('general*.bat')):
    text = f.read_bytes().decode('utf-8')
    for a, b in MAP.items():
        text = re.sub(r'(?<==)' + re.escape(a) + r'\b', b, text)
    if any(re.search(r'(?<==)' + n + r'\b', text) for n in EXTRA):
        text = text.replace('--lua-init=@"%LUA%blobs.lua" ^', '--lua-init=@"%LUA%blobs.lua" ^\r\n--lua-init=@"%LUA%blobs-extra.lua" ^', 1)
        assert 'blobs-extra.lua' in text, f.name
    name = re.sub(r'^general \((.*)\)\.bat$', r'general (K-\1).bat', f.name)
    assert name != f.name, f.name
    note = ':: digital-bypass: from kinlay0/zapret2-discord-youtube-strats (MIT), blob names mapped to the Flowseal build\r\n'
    i = text.find('\n')
    text = text[: i + 1] + note + text[i + 1 :]
    (DST / name).write_bytes(text.encode('utf-8'))
    files.append(name)

src_blobs = (SRC / 'lua' / 'blobs.lua').read_bytes().decode('utf-8')
start = src_blobs.index('local blobs = {')
end = src_blobs.index('}', start)
entries = '\n'.join(f'\t{k} = "{v}",' for k, v in EXTRA.items())
(ADD / 'blobs-extra.lua').write_bytes((src_blobs[:start] + 'local blobs = {\n' + entries + '\n' + src_blobs[end:]).encode('utf-8'))
for v in EXTRA.values():
    shutil.copy(SRC / 'bin' / v, ADD / v)
shutil.copy(SRC / 'LICENSE', DST / 'LICENSE')

lines = [
    '//! Стратегии коллекции kinlay0/zapret2-discord-youtube-strats (MIT),',
    '//! импортированы scripts/import-kinlay-strats.py: префикс «K-», имена фейков — как в сборке Flowseal.',
    '//! Файл сгенерирован, не править руками.',
    '',
    'pub const STRATS: &[(&str, &str)] = &[',
]
lines += [f'    ("{f}", include_str!("../addons/strats/{f}")),' for f in files]
lines.append('];')
(ROOT / 'src' / 'addons_strats.rs').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('imported', len(files), 'strategies')
