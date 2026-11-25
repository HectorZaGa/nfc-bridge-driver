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
    if (typeof this.state.setWebSocketAutoResponse === "function") {
      this.state.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    }
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
    } else {
      const pcs = this.state.getWebSockets("pc");
      if (!pcs || pcs.length === 0) {
        return new Response("PC offline", { status: 409 });
      }
    }

    for (const existing of this.state.getWebSockets(role)) {
      try {
        existing.close(1000, "replaced");
      } catch (_) {}
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server, [role]);

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    const byteLen =
      typeof message === "string"
        ? message.length
        : message?.byteLength ?? 0;
    if (byteLen > MAX_WS_PAYLOAD_BYTES) {
      try {
        ws.close(1009, "payload_too_large");
      } catch (_) {}
      return;
    }

    const tags = this.state.getTags(ws);
    const role = tags[0] === "pc" ? "pc" : "mobile";
    const peerRole = role === "pc" ? "mobile" : "pc";
    for (const peer of this.state.getWebSockets(peerRole)) {
      try {
        peer.send(message);
      } catch (_) {}
    }
  }

  async webSocketClose(ws, code, reason) {
    try {
      ws.close(code || 1000, reason || "closed");
    } catch (_) {}
  }

  async webSocketError(ws) {
    try {
      ws.close(1011, "error");
    } catch (_) {}
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
  const encrypted = (url.searchParams.get("d") || "").trim();
  if (encrypted) {
    return `nfcbridge://relay?d=${encodeURIComponent(encrypted)}&relay=${encodeURIComponent(relayWs)}`;
  }

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
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeJsonForScript(s) {
  return JSON.stringify(s)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026");
}

function renderLandingHtml(deepLink) {
  const safeHref = escapeHtml(deepLink);
  const safeJsHref = escapeJsonForScript(deepLink);
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Conectar NFC Bridge</title><style>body{background:#121212;color:#f3f0ef;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;box-sizing:border-box}.card{max-width:420px;width:100%;background:#1e1e1e;border:1px solid #313030;border-radius:16px;padding:24px;text-align:center}a.btn{display:block;margin-top:16px;padding:12px 18px;border-radius:10px;background:#3b82f6;color:#fff;text-decoration:none;font-weight:600}p{color:#adabaa;font-size:14px;line-height:1.4}</style></head><body><div class="card"><h2>NFC Bridge</h2><p>Pulsa el botón para abrir NFC Bridge Lite y enlazar este teléfono de forma segura.</p><a class="btn" href="${safeHref}">Abrir en NFC Bridge Lite</a><p style="margin-top:14px;font-size:12px">Si no se abre automáticamente, copia este enlace y pégalo en la opción Enlace remoto de la app.</p></div><script>setTimeout(function(){window.location.href=${safeJsHref};},150);</script></body></html>`;
}
