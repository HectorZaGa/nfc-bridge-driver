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

#[cfg(all(windows, target_arch = "x86_64"))]
const EMBEDDED_USBDK_MSI: &[u8] = include_bytes!("../assets/UsbDk_1.0.22_x64.msi");

fn run_hidden_command(program: &str, args: &[&str]) -> std::io::Result<std::process::ExitStatus> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.status()
}

fn is_usbdk_installed() -> bool {
    run_hidden_command("sc.exe", &["query", "UsbDk"])
        .map(|s| s.success())
        .unwrap_or(false)
}

fn install_embedded_usbdk(quiet: bool) -> anyhow::Result<()> {
    if is_usbdk_installed() {
        return Ok(());
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let temp_msi = std::env::temp_dir().join(format!(
            "nfc-bridge-usbdk-{}.msi",
            std::process::id()
        ));
        std::fs::write(&temp_msi, EMBEDDED_USBDK_MSI)?;

        let mode_arg = if quiet { "/qn" } else { "/passive" };
        let temp_str = temp_msi.to_string_lossy().to_string();
        let status = std::process::Command::new("msiexec.exe")
            .args(["/i", &temp_str, mode_arg, "/norestart"])
            .status();

        let _ = std::fs::remove_file(&temp_msi);

        let status = status?;
        let code = status.code().unwrap_or(-1);
        if status.success() || code == 3010 {
            return Ok(());
        }
        anyhow::bail!("Instalación de UsbDk falló con código msiexec: {}", code);
    }

    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = quiet;
        anyhow::bail!("UsbDk embebido solo disponible para arquitectura Windows x64");
    }
}

fn handle_cli_commands() -> Option<anyhow::Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        return None;
    }

    match args[1].as_str() {
        "--install-service" => {
            if let Err(e) = install_embedded_usbdk(true) {
                return Some(Err(anyhow::anyhow!("No se pudo instalar UsbDk embebido: {}", e)));
            }

            let exe_path = std::env::current_exe().unwrap_or_default();
            let bin_path = format!("\"{}\"", exe_path.to_string_lossy());
            let bin_arg = format!("binPath={}", bin_path);

            let service_exists = run_hidden_command("sc.exe", &["query", "NfcBridgeDriver"])
                .map(|s| s.success())
                .unwrap_or(false);

            let status = if service_exists {
                let _ = run_hidden_command("sc.exe", &["stop", "NfcBridgeDriver"]);
                run_hidden_command(
                    "sc.exe",
                    &[
                        "config",
                        "NfcBridgeDriver",
                        &bin_arg,
                        "start=auto",
                        "DisplayName=NFC Bridge Driver Service",
                    ],
                )
            } else {
                run_hidden_command(
                    "sc.exe",
                    &[
                        "create",
                        "NfcBridgeDriver",
                        &bin_arg,
                        "start=auto",
                        "DisplayName=NFC Bridge Driver Service",
                    ],
                )
            };

            match status {
                Ok(s) if s.success() => {
                    let _ = run_hidden_command("sc.exe", &["start", "NfcBridgeDriver"]);
                    Some(Ok(()))
                }
                Ok(s) => Some(Err(anyhow::anyhow!(
                    "sc.exe {} falló con código: {:?}",
                    if service_exists { "config" } else { "create" },
                    s.code()
                ))),
                Err(e) => Some(Err(anyhow::anyhow!("No se pudo ejecutar sc.exe: {}", e))),
            }
        }
        "--install-usbdk" => Some(install_embedded_usbdk(false)),
        "--uninstall-service" => {
            let _ = run_hidden_command("sc.exe", &["stop", "NfcBridgeDriver"]);
            let status = run_hidden_command("sc.exe", &["delete", "NfcBridgeDriver"]);
            match status {
                Ok(s) if s.success() => Some(Ok(())),
                Ok(s) => Some(Err(anyhow::anyhow!("sc.exe delete falló con código: {:?}", s.code()))),
                Err(e) => Some(Err(anyhow::anyhow!("No se pudo ejecutar sc.exe: {}", e))),
            }
        }
        "--status" => {
            let status = run_hidden_command("sc.exe", &["query", "NfcBridgeDriver"]);
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

    // 2. Instanciar coordinador de red/transporte (TCP + UDP Discovery + USB AOA)
    let tcp_server = Arc::new(BridgeTcpServer::new(event_tx.clone(), Arc::clone(&ccid_handler)));

    // 3. Iniciar Servidor IPC (Named Pipe de Windows: \\.\pipe\nfc_bridge_driver)
    let ipc_server = Arc::new(NamedPipeIpcServer::with_coordinator(
        event_tx,
        Arc::clone(&tcp_server),
    ));
    tokio::spawn(async move {
        ipc_server.run().await;
    });

    // 4. Iniciar Servidor TCP + Responder UDP Discovery (Puerto 45362)
    let tcp_server_for_run = Arc::clone(&tcp_server);
    tokio::spawn(async move {
        if let Err(e) = tcp_server_for_run.run().await {
            tracing::error!("Error crítico al iniciar servidor TCP/UDP del driver en 45362: {}", e);
        }
    });

    // 5. Iniciar Host USB AOA (Android Open Accessory puro sin ADB ni red)
    let aoa_host = Arc::new(UsbAoaHost::new(Arc::clone(&tcp_server)));
    tokio::spawn(async move {
        aoa_host.run().await;
    });

    // 6. Iniciar Servidor USB/IP (Puerto 3240 para emulación USB CCID ACR122U)
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
