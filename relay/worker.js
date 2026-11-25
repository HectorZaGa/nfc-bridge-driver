const MAX_WS_PAYLOAD_BYTES = 64 * 1024;
const CHANNEL_RE = /^[A-Za-z0-9_-]{8,64}$/;

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export class RelayRoom {
  constructor(state) {
    this.state = state;
    this.sockets = { pc: null, mobile: null };
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }

    const url = new URL(request.url);
    const role = url.searchParams.get("role") === "pc" ? "pc" : "mobile";

    if (role === "pc") {
      const auth = request.headers.get("Authorization") || "";
      const rawSecret = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
      if (rawSecret.length < 16 || rawSecret.length > 256) {
        return new Response("Missing host authorization", { status: 401 });
      }
      const presentedHash = await sha256Hex(rawSecret);
      const storedHash = await this.state.storage.get("host_secret_hash");
      if (!storedHash) {
        await this.state.storage.put("host_secret_hash", presentedHash);
      } else if (!constantTimeEqual(storedHash, presentedHash)) {
        return new Response("Invalid host secret", { status: 403 });
      }
    } else if (!this.sockets.pc || this.sockets.pc.readyState !== 1) {
      return new Response("PC offline", { status: 409 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    const prev = this.sockets[role];
    if (prev) {
      try {
        prev.close(1000, "replaced");
      } catch (_) {}
    }
    this.sockets[role] = server;

    const peerRole = role === "pc" ? "mobile" : "pc";

    server.addEventListener("message", (evt) => {
      const byteLen =
        typeof evt.data === "string"
          ? evt.data.length
          : evt.data?.byteLength ?? 0;
      if (byteLen > MAX_WS_PAYLOAD_BYTES) {
        try {
          server.close(1009, "payload_too_large");
        } catch (_) {}
        return;
      }

      const peer = this.sockets[peerRole];
      if (peer && peer.readyState === 1) {
        try {
          peer.send(evt.data);
        } catch (_) {}
      }
    });

    const cleanup = () => {
      if (this.sockets[role] === server) {
        this.sockets[role] = null;
      }
    };

    server.addEventListener("close", cleanup);
    server.addEventListener("error", cleanup);

    return new Response(null, { status: 101, webSocket: client });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json(
        { status: "ok", service: "nfc-bridge-relay" },
        { headers: { "X-Content-Type-Options": "nosniff" } }
      );
    }

    if (url.pathname.startsWith("/ws/")) {
      const channelId = url.pathname.slice(4).split("/")[0]?.trim() || "";
      if (!CHANNEL_RE.test(channelId)) {
        return new Response("Invalid channel", { status: 400 });
      }
      const id = env.RELAY_ROOM.idFromName(channelId);
      const stub = env.RELAY_ROOM.get(id);
      return stub.fetch(request);
    }

    if (url.pathname === "/connect" || url.pathname === "/pair") {
      const deepLink = buildDeepLink(url);
      return new Response(renderLandingHtml(deepLink), {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY",
          "Referrer-Policy": "no-referrer",
          "Content-Security-Policy":
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'",
        },
      });
    }

    return new Response("NFC Bridge Cloud Relay", {
      status: 200,
      headers: { "X-Content-Type-Options": "nosniff" },
    });
  },
};

function buildDeepLink(url) {
  const relayWs = `wss://${url.host}`;
  const out = new URLSearchParams();
  const channel = (url.searchParams.get("channel") || "").trim();
  const name = (url.searchParams.get("name") || "PC Windows").trim().slice(0, 64);
  const pair = (url.searchParams.get("pair") || "").trim().slice(0, 64);
  if (CHANNEL_RE.test(channel)) out.set("channel", channel);
  if (name) out.set("name", name);
  out.set("transport", "relay");
  // Siempre forzar nuestro propio host para impedir redirección a servidores maliciosos
  out.set("relay", relayWs);
  if (pair) out.set("pair", pair);
  return `nfcbridge://relay?${out.toString()}`;
}

function escapeHtml(s) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeJsonForScript(val) {
  return JSON.stringify(val)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026");
}

function renderLandingHtml(deepLink) {
  const safe = escapeHtml(deepLink);
  const safeJs = escapeJsonForScript(deepLink);
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NFC Bridge — Vincular PC</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#121212;color:#f3f0ef;font-family:system-ui,-apple-system,sans-serif;padding:24px}.card{max-width:420px;width:100%;background:#1e1e1e;border:1px solid #313030;border-radius:16px;padding:24px;text-align:center}a.btn{display:inline-block;margin-top:16px;padding:12px 20px;border-radius:10px;background:#3b82f6;color:#fff;text-decoration:none;font-weight:600}p{color:#adabaa;font-size:14px;line-height:1.5}</style></head><body><div class="card"><h2>NFC Bridge Lite</h2><p>Abriendo enlace directo de vinculación con tu PC...</p><a class="btn" href="${safe}">Abrir en NFC Bridge</a></div><script>window.location.href=${safeJs};</script></body></html>`;
}
