// Описание релиза: раздел версии из CHANGELOG.md + служебный подвал
// (встроенная сборка zapret, SHA256 установщика, предупреждение про антивирусы).
//
//   node scripts/release-notes.mjs <версия> <выходной файл> [--sha <hash>] [--file <имя exe>] [--zapret <версия>] [--tor <версия>] [--xray <версия>]
//
// Если раздела нет или он пустой — ошибка: релиз без описания изменений не выпускаем.
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const [version, out, ...rest] = process.argv.slice(2);
if (!version || !out) {
  console.error("usage: release-notes.mjs <version> <out> [--sha H] [--file F] [--zapret V] [--tor V] [--xray V]");
  process.exit(2);
}
const opt = {};
for (let i = 0; i < rest.length; i += 2) opt[rest[i].replace(/^--/, "")] = rest[i + 1];

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const lines = readFileSync(join(root, "CHANGELOG.md"), "utf8").replace(/\r\n/g, "\n").split("\n");
const ver = version.replace(/^v/, "");
const esc = ver.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const start = lines.findIndex((l) => new RegExp(`^## \\[${esc}\\]`).test(l));
if (start < 0) {
  console.error(`[release-notes] в CHANGELOG.md нет раздела "## [${ver}]"`);
  process.exit(1);
}
let end = lines.findIndex((l, i) => i > start && (/^## \[/.test(l) || /^\[[^\]]+\]: /.test(l)));
if (end < 0) end = lines.length;
const body = lines.slice(start + 1, end).join("\n").trim();
if (!body) {
  console.error(`[release-notes] раздел "## [${ver}]" пустой`);
  process.exit(1);
}

const footer = ["", "---", ""];
if (opt.zapret) {
  footer.push(
    `Встроенная сборка / bundled build: zapret-discord-youtube ${opt.zapret} + [PR #18202](https://github.com/Flowseal/zapret-discord-youtube/pull/18202) (zapret2).`,
    "",
  );
}
if (opt.tor) {
  footer.push(
    `Tor: Tor Expert Bundle ${opt.tor} ([sha256sums](https://dist.torproject.org/torbrowser/${opt.tor}/sha256sums-signed-build.txt), сумма архива сверяется при сборке / archive sum checked at build time).`,
    "",
  );
}
if (opt.xray) {
  footer.push(
    `Xray-core ${opt.xray} ([.dgst](https://github.com/XTLS/Xray-core/releases/download/v${opt.xray}/Xray-windows-64.zip.dgst), сумма архива сверяется при сборке / archive sum checked at build time).`,
    "",
  );
}
if (opt.sha) {
  footer.push(`**SHA256** \`${opt.file ?? "setup.exe"}\`:`, "```", opt.sha, "```", "");
}
footer.push(
  "> Антивирусы иногда помечают `winws2.exe` / WinDivert / `tor.exe` / `xray.exe` внутри установщика. Суммы бинарников можно сверить с [релизом zapret2](https://github.com/bol-van/zapret2/releases) и списком Tor выше.",
);

writeFileSync(out, `${body}\n${footer.join("\n")}\n`);
console.log(`[release-notes] ${ver}: ${body.split("\n").length} строк → ${out}`);
