// Скачивает Xray-core для Windows с GitHub XTLS, сверяет SHA-256 и кладёт в
// src-tauri/xray: xray.exe, geoip.dat, geosite.dat (теги ru, category-ru,
// category-ads-all и др.) и LICENSE (MPL-2.0). wintun.dll не берём — режима TUN пока нет.
//
// Хэш закреплён по официальному Xray-windows-64.zip.dgst релиза. Новая версия —
// поменять XRAY_VERSION и XRAY_SHA256 (строка SHA2-256 из .dgst).
import { execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const XRAY_VERSION = "26.11.9";
const XRAY_SHA256 = "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d";
const URL = `https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-windows-64.zip`;

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dest = join(root, "src-tauri", "xray");
const stamp = join(dest, "bundle.json");

if (existsSync(stamp)) {
  try {
    if (JSON.parse(readFileSync(stamp, "utf8")).version === XRAY_VERSION) {
      console.log(`[sync-xray] xray ${XRAY_VERSION} уже на месте`);
      process.exit(0);
    }
  } catch {}
}

// Локальная копия архива (без сети): XRAY_ZIP=путь\к\Xray-windows-64.zip.
let data;
if (process.env.XRAY_ZIP) {
  data = readFileSync(process.env.XRAY_ZIP);
} else {
  console.log(`[sync-xray] скачиваю ${URL}`);
  const r = await fetch(URL);
  if (!r.ok) {
    console.error(`[sync-xray] ${r.status} ${r.statusText}`);
    process.exit(1);
  }
  data = Buffer.from(await r.arrayBuffer());
}
const sha = createHash("sha256").update(data).digest("hex");
if (sha !== XRAY_SHA256) {
  console.error(`[sync-xray] SHA-256 не совпал: ${sha}, ожидался ${XRAY_SHA256}`);
  process.exit(1);
}

const tmp = mkdtempSync(join(tmpdir(), "xray-sync-"));
try {
  writeFileSync(join(tmp, "x.zip"), data);
  // Системный tar.exe (Windows 10+) умеет zip.
  const tar = join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe");
  execSync(`"${tar}" -xf "${join(tmp, "x.zip")}" -C "${tmp}"`, { stdio: "inherit" });
  rmSync(dest, { recursive: true, force: true });
  mkdirSync(dest, { recursive: true });
  for (const f of ["xray.exe", "geoip.dat", "geosite.dat", "LICENSE"]) cpSync(join(tmp, f), join(dest, f));
  writeFileSync(stamp, JSON.stringify({ version: XRAY_VERSION, sha256: XRAY_SHA256, source: URL }, null, 2));
  console.log(`[sync-xray] xray ${XRAY_VERSION} → ${dest}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
