# NFC Bridge Driver (Windows)

Controlador en segundo plano y servicio de baja latencia para Windows desarrollado en **Rust**.
Actúa como receptor universal para los dispositivos móviles (**NFC Bridge Lite** y **NFC Bridge Tools**) y expone un canal IPC para las aplicaciones de escritorio (**NFC Bridge Sync** y **NFC Bridge Tools Desktop**).

---

## 🚀 Características Principales

- **Ultra Baja Latencia (< 1 ms):** Desarrollado en Rust nativo sobre Tokio con `TCP_NODELAY`, sin recolección de basura (Garbage Collector) ni sobrecarga de runtime.
- **Servidor TCP (Puerto `45362`):** Escucha las conexiones del móvil sobre Wi-Fi o túnel USB (`adb reverse tcp:45362 tcp:45362`).
- **Canal IPC Local (Named Pipe):** Expone la tubería `\\.\pipe\nfc_bridge_driver` para que las aplicaciones de escritorio reciban eventos en tiempo real en formato JSON y envíen comandos.
- **Protocolo Binario v1:** Validación por trama con CRC-16 CCITT, soporte de desfragmentación automática y resincronización de flujo.
- **Modo Consola / Servicio Windows:** Puede ejecutarse interactivamente desde consola para depuración o instalarse como Windows Service silencioso.

---

## 📁 Estructura del Código

```text
nfc-bridge-driver/
├── Cargo.toml                  # Configuración y dependencias (Tokio, Bytes, Serde, Tracing)
├── src/
│   ├── lib.rs                  # Módulos exportados
│   ├── main.rs                 # Punto de entrada interactivo / logging
│   ├── protocol/               # Codecs binarios v1 compatibles con Android
│   │   ├── constants.rs        # Magic 0x4E, 0x42, versión 0x01, puertos
│   │   ├── crc.rs              # Cálculo CRC-16 CCITT (0x1021, 0xFFFF)
│   │   ├── message_type.rs     # Opcodes (HELLO, HEARTBEAT, TAG_ATTACH, etc.)
│   │   ├── frame.rs            # Estructuras NfcBridgeFrame y TagInfo
│   │   └── codec.rs            # Serialización y StreamFrameDecoder
│   ├── network/                # Servidor TCP asíncrono
│   │   └── tcp_server.rs       # Acepta conexiones del móvil y procesa tramas
│   └── ipc/                    # Servidor IPC de Windows
│       ├── events.rs           # Modelos de eventos y comandos JSON
│       └── named_pipe_server.rs # Servidor \\.\pipe\nfc_bridge_driver
└── tests/
    └── integration_test.rs     # Pruebas de compatibilidad cruzada del protocolo
```

---

## 🛠️ Compilación y Ejecución

### Ejecutar pruebas unitarias:
```bash
cargo test
```

### Ejecutar en modo desarrollo:
```bash
cargo run
```

### Compilar binario de producción optimizado:
```bash
cargo build --release
```
El ejecutable resultante se genera en `target/release/nfc-bridge-driver.exe`.
