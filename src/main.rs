use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::info;
use tracing_subscriber::EnvFilter;

use nfc_bridge_driver::emulator::{CcidHandler, UsbIpServer, USBIP_DEFAULT_PORT};
use nfc_bridge_driver::ipc::{IpcEvent, NamedPipeIpcServer};
use nfc_bridge_driver::network::BridgeTcpServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configuración de Logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,nfc_bridge_driver=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("============================================================");
    info!("        NFC BRIDGE DRIVER (Windows Background Service)      ");
    info!("============================================================");

    // 1. Instanciar el motor de emulación CCID compartido
    let ccid_handler = Arc::new(Mutex::new(CcidHandler::new()));

    // Canal broadcast interno para eventos IPC (Sync / Tools Desktop)
    let (event_tx, _) = broadcast::channel::<IpcEvent>(128);

    // 2. Iniciar Servidor IPC (Named Pipe de Windows: \\.\pipe\nfc_bridge_driver)
    let ipc_server = Arc::new(NamedPipeIpcServer::new(event_tx.clone()));
    tokio::spawn(async move {
        ipc_server.run().await;
    });

    // 3. Iniciar Servidor TCP (Puerto 45362 para el teléfono Android)
    let tcp_server = Arc::new(BridgeTcpServer::new(event_tx, Arc::clone(&ccid_handler)));
    let tcp_server_for_run = Arc::clone(&tcp_server);
    tokio::spawn(async move {
        if let Err(e) = tcp_server_for_run.run().await {
            tracing::error!("Error crítico en el servidor TCP: {}", e);
        }
    });

    // 4. Iniciar Servidor USB/IP (Puerto 3240 para emulación USB CCID ACR122U)
    let usbip_server = UsbIpServer::new(USBIP_DEFAULT_PORT, Arc::clone(&ccid_handler));
    let tcp_server_for_usbip = Arc::clone(&tcp_server);
    tokio::spawn(async move {
        let transceive_cb = move |req: Vec<u8>| {
            let tcp = Arc::clone(&tcp_server_for_usbip);
            async move {
                tcp.transceive(req).await
            }
        };

        if let Err(e) = usbip_server.start(transceive_cb).await {
            tracing::error!("Error crítico en el servidor USB/IP: {}", e);
        }
    });

    info!("Driver activo: TCP (45362), USB/IP (3240), IPC (\\\\.\\pipe\\nfc_bridge_driver).");
    info!("Presiona Ctrl+C para detener el servicio.");

    tokio::signal::ctrl_c().await?;
    info!("Señal de apagado recibida. Cerrando NFC Bridge Driver...");

    Ok(())
}
