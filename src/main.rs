use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;
use tracing_subscriber::EnvFilter;

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

    // Canal broadcast interno para eventos IPC (Sync / Tools Desktop)
    let (event_tx, _) = broadcast::channel::<IpcEvent>(128);

    // 1. Iniciar Servidor IPC (Named Pipe de Windows)
    let ipc_server = Arc::new(NamedPipeIpcServer::new(event_tx.clone()));
    tokio::spawn(async move {
        ipc_server.run().await;
    });

    // 2. Iniciar Servidor TCP (Puerto 45362 para el teléfono Android)
    let tcp_server = Arc::new(BridgeTcpServer::new(event_tx));
    tokio::spawn(async move {
        if let Err(e) = tcp_server.run().await {
            tracing::error!("Error crítico en el servidor TCP: {}", e);
        }
    });

    info!("Driver activo y listo.");
    info!("Presiona Ctrl+C para detener el servicio.");

    tokio::signal::ctrl_c().await?;
    info!("Señal de apagado recibida. Cerrando NFC Bridge Driver...");

    Ok(())
}
