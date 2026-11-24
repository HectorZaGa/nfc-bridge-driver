#![windows_subsystem = "windows"]

//! # NFC Bridge Driver (Windows Background Service)
//!
//! Controlador en segundo plano de ultra baja latencia y emulador PC/SC para Windows.
//! Ejecuta silenciosamente sin ventana CMD (subsistema Windows nativo) y puede registrarse
//! como Servicio de Windows (services.msc).

use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use nfc_bridge_driver::emulator::{CcidHandler, UsbIpServer, USBIP_DEFAULT_PORT};
use nfc_bridge_driver::ipc::{IpcEvent, NamedPipeIpcServer};
use nfc_bridge_driver::network::{BridgeTcpServer, UsbAoaHost};

fn handle_cli_commands() -> Option<anyhow::Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        return None;
    }

    match args[1].as_str() {
        "--install-service" => {
            let exe_path = std::env::current_exe().unwrap_or_default();
            let bin_path = format!("\"{}\"", exe_path.to_string_lossy());
            let status = std::process::Command::new("sc.exe")
                .args(["create", "NfcBridgeDriver", &format!("binPath={}", bin_path), "start=auto", "DisplayName=NFC Bridge Driver Service"])
                .status();
            match status {
                Ok(s) if s.success() => {
                    let _ = std::process::Command::new("sc.exe").args(["start", "NfcBridgeDriver"]).status();
                    Some(Ok(()))
                }
                Ok(s) => Some(Err(anyhow::anyhow!("sc.exe create falló con código: {:?}", s.code()))),
                Err(e) => Some(Err(anyhow::anyhow!("No se pudo ejecutar sc.exe: {}", e))),
            }
        }
        "--uninstall-service" => {
            let _ = std::process::Command::new("sc.exe").args(["stop", "NfcBridgeDriver"]).status();
            let status = std::process::Command::new("sc.exe").args(["delete", "NfcBridgeDriver"]).status();
            match status {
                Ok(s) if s.success() => Some(Ok(())),
                Ok(s) => Some(Err(anyhow::anyhow!("sc.exe delete falló con código: {:?}", s.code()))),
                Err(e) => Some(Err(anyhow::anyhow!("No se pudo ejecutar sc.exe: {}", e))),
            }
        }
        "--status" => {
            let status = std::process::Command::new("sc.exe").args(["query", "NfcBridgeDriver"]).status();
            match status {
                Ok(s) if s.success() => Some(Ok(())),
                Ok(_) => Some(Err(anyhow::anyhow!("El servicio NfcBridgeDriver no está instalado o activo."))),
                Err(e) => Some(Err(anyhow::anyhow!("Error al consultar sc.exe: {}", e))),
            }
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(result) = handle_cli_commands() {
        return result;
    }

    // Configuración de Logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,nfc_bridge_driver=debug"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    info!("============================================================");
    info!("    NFC BRIDGE DRIVER (Windows Silent Background Service)   ");
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

    // 3. Iniciar Servidor TCP (Puerto 45362)
    // Si nfc-bridge-sync ya está escuchando en 45362, no detener el driver:
    // en ese escenario, nfc-bridge-sync actuará como puente vía Named Pipe.
    let tcp_server = Arc::new(BridgeTcpServer::new(event_tx, Arc::clone(&ccid_handler)));
    let tcp_server_for_run = Arc::clone(&tcp_server);
    tokio::spawn(async move {
        if let Err(e) = tcp_server_for_run.run().await {
            warn!("Servidor TCP directo no pudo enlazarse (nfc-bridge-sync puede estar gestionando la red): {}", e);
        }
    });

    // 3b. Iniciar Host USB AOA (Android Open Accessory puro sin ADB ni red)
    let aoa_host = Arc::new(UsbAoaHost::new(Arc::clone(&tcp_server)));
    tokio::spawn(async move {
        aoa_host.run().await;
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
            warn!("Aviso en el servidor USB/IP: {}", e);
        }
    });

    info!("Driver activo en segundo plano: Named Pipe (\\\\.\\pipe\\nfc_bridge_driver) listo.");

    tokio::signal::ctrl_c().await?;
    info!("Señal de apagado recibida. Cerrando NFC Bridge Driver...");

    Ok(())
}
