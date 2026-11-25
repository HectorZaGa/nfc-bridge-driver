# NFC Bridge Cloud Relay (Cloudflare Workers + Durable Objects)

Relay WebSocket ultraligero para conectar **NFC Bridge Driver (Windows)** con **NFC Bridge Lite (Android)** cuando no comparten red local (por ejemplo, celular en 4G/5G y PC en casa), sin instalar apps de terceros.

## Endpoints

- `GET /ws/<channel_id>?role=pc|mobile`: túnel WebSocket binario bidireccional por canal.
- `GET /connect?channel=<channel_id>&name=<PC>&pair=<pair_token>`: Link único compartible que abre `nfcbridge://relay?...` en Android.
- `GET /health`: verificación de estado JSON.

## Despliegue rápido (Plan gratuito de Cloudflare Workers)

```bash
cd relay
npx wrangler deploy
```

Luego copia la URL resultante (por ejemplo `https://nfc-bridge-relay.<tu-subdominio>.workers.dev`) en el campo **Relay URL** de **NFC Bridge Sync** en Windows.
