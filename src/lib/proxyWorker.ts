// Код Cloudflare Worker для маршрута «через свой Worker» в прокси-обходчике.
// Worker принимает WebSocket на /tunnel?h=<хост>&p=<порт>&k=<ключ>, открывает
// TCP к сайту (cloudflare:sockets) и пересылает байты. TLS браузера с сайтом
// остаётся сквозным: Worker видит только зашифрованный поток.
// Ограничение Cloudflare: к адресам самого Cloudflare connect() не подключается.
export function proxyWorkerCode(key: string): string {
  return `// digital-bypass: туннель WebSocket -> TCP для прокси-обходчика
import { connect } from "cloudflare:sockets";

const KEY = ${JSON.stringify(key || "CHANGE_ME")};

export default {
  async fetch(request) {
    if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
      return new Response("digital-bypass worker", { status: 426 });
    }
    const url = new URL(request.url);
    if (url.pathname !== "/tunnel" || url.searchParams.get("k") !== KEY) {
      return new Response("Forbidden", { status: 403 });
    }
    const hostname = url.searchParams.get("h") || "";
    const port = parseInt(url.searchParams.get("p") || "443", 10);
    if (!hostname || !(port > 0 && port < 65536)) {
      return new Response("Bad request", { status: 400 });
    }
    let socket;
    try {
      socket = connect({ hostname, port });
      await socket.opened;
    } catch (e) {
      return new Response("connect failed: " + e, { status: 502 });
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    const writer = socket.writable.getWriter();
    server.addEventListener("message", async (ev) => {
      try {
        const d = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : new TextEncoder().encode(ev.data);
        await writer.write(d);
      } catch {
        try { server.close(1011, "tcp write failed"); } catch {}
      }
    });
    server.addEventListener("close", () => {
      try { writer.close(); } catch {}
      try { socket.close(); } catch {}
    });
    (async () => {
      const reader = socket.readable.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value) server.send(value);
        }
      } catch {
      } finally {
        try { server.close(); } catch {}
        try { socket.close(); } catch {}
      }
    })();
    return new Response(null, { status: 101, webSocket: client });
  },
};
`;
}

/** Случайный ключ доступа к Worker. */
export function newWorkerKey(): string {
  const b = new Uint8Array(18);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
