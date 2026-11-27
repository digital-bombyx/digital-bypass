// Скачивает Tor Expert Bundle с dist.torproject.org, сверяет SHA-256 и кладёт
// в src-tauri/tor только нужное: tor.exe, lyrebird.exe (obfs4, webtunnel,
// snowflake, meek), pt_config.json (встроенные мосты) и тексты лицензий.
// conjure-client, tor-gencert и geoip не берём.
//
// Хэш закреплён: его можно сверить с официальным списком
// https://dist.torproject.org/torbrowser/<версия>/sha256sums-signed-build.txt
// Новая версия — поменять TOR_VERSION и TOR_SHA256.
import { execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const TOR_VERSION = "16.0.1";
const TOR_SHA256 = "9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b";
const FILE = `tor-expert-bundle-windows-x86_64-${TOR_VERSION}.tar.gz`;
// На dist.torproject.org лежит только текущая версия; прошлые переезжают в
// archive.torproject.org. Пробуем по очереди, SHA-256 сверяется в любом случае.
const URLS = [
  `https://dist.torproject.org/torbrowser/${TOR_VERSION}/${FILE}`,
  `https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_VERSION}/${FILE}`,
];
let URL = URLS[0];

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dest = join(root, "src-tauri", "tor");
const stamp = join(dest, "bundle.json");

if (existsSync(stamp)) {
  try {
    if (JSON.parse(readFileSync(stamp, "utf8")).version === TOR_VERSION) {
      console.log(`[sync-tor] tor ${TOR_VERSION} уже на месте`);
      process.exit(0);
    }
  } catch {}
}

// Локальная копия архива (без сети): TOR_TARBALL=путь\к\архиву.
let data;
if (process.env.TOR_TARBALL) {
  data = readFileSync(process.env.TOR_TARBALL);
} else {
  for (const u of URLS) {
    console.log(`[sync-tor] скачиваю ${u}`);
    try {
      const r = await fetch(u);
      if (r.ok) {
        URL = u;
        data = Buffer.from(await r.arrayBuffer());
        break;
      }
      console.error(`[sync-tor] ${r.status} ${r.statusText}`);
    } catch (e) {
      console.error(`[sync-tor] ${e.cause?.code ?? e.message}`);
    }
  }
  if (!data) {
    console.error(`[sync-tor] архив ${FILE} не скачался ни из одного источника; без сети или если Tor режут — скачайте его вручную и задайте TOR_TARBALL=путь`);
    process.exit(1);
  }
}
const sha = createHash("sha256").update(data).digest("hex");
if (sha !== TOR_SHA256) {
  console.error(`[sync-tor] SHA-256 не совпал: ${sha}, ожидался ${TOR_SHA256}`);
  process.exit(1);
}

const tmp = mkdtempSync(join(tmpdir(), "tor-sync-"));
try {
  writeFileSync(join(tmp, FILE), data);
  // Системный tar.exe (Windows 10+); путь явный, как в sync-zapret.
  const tar = join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe");
  execSync(`"${tar}" -xzf "${join(tmp, FILE)}" -C "${tmp}"`, { stdio: "inherit" });

  rmSync(dest, { recursive: true, force: true });
  mkdirSync(join(dest, "pluggable_transports"), { recursive: true });
  mkdirSync(join(dest, "docs"), { recursive: true });
  cpSync(join(tmp, "tor", "tor.exe"), join(dest, "tor.exe"));
  for (const f of ["lyrebird.exe", "pt_config.json"]) {
    cpSync(join(tmp, "tor", "pluggable_transports", f), join(dest, "pluggable_transports", f));
  }
  for (const f of ["tor.txt", "lyrebird.txt", "libevent.txt", "openssl.txt", "zlib.txt"]) {
    cpSync(join(tmp, "docs", f), join(dest, "docs", f));
  }
  writeFileSync(stamp, JSON.stringify({ version: TOR_VERSION, sha256: TOR_SHA256, source: URL }, null, 2));
  console.log(`[sync-tor] tor ${TOR_VERSION} → ${dest}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
