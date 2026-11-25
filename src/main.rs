#![windows_subsystem = "windows"]

//! # NFC Bridge Driver (Windows Background Service)
//!
//! Controlador en segundo plano de ultra baja latencia y emulador PC/SC para Windows.
//! Ejecuta silenciosamente sin ventana CMD (subsistema Windows nativo) y puede registrarse
//! como Servicio de Windows (services.msc).

use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, Notify};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use nfc_bridge_driver::emulator::{CcidHandler, UsbIpServer, USBIP_DEFAULT_PORT};
use nfc_bridge_driver::ipc::{IpcEvent, NamedPipeIpcServer};
use nfc_bridge_driver::network::{
    BluetoothRfcommServer, BridgeTcpServer, UsbAoaHost, WifiDirectServer,
};

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

fn handle_cli_commands() -> Option<anyhow::Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        return None;
    }

    match args[1].as_str() {
        "--service" => {
            #[cfg(windows)]
            {
                return Some(
                    windows_svc::run()
                        .map_err(|e| anyhow::anyhow!("Error en servicio NfcBridgeDriver: {}", e)),
                );
            }
            #[cfg(not(windows))]
            {
                None
            }
        }
        "--install-service" => {
            let exe_path = std::env::current_exe().unwrap_or_default();
            let bin_path = format!("\"{}\" --service", exe_path.to_string_lossy());
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
                    let start_status = run_hidden_command("sc.exe", &["start", "NfcBridgeDriver"]);
                    match start_status {
                        Ok(st) if st.success() => Some(Ok(())),
                        Ok(st) => Some(Err(anyhow::anyhow!(
                            "sc.exe start NfcBridgeDriver falló con código: {:?}",
                            st.code()
                        ))),
                        Err(e) => Some(Err(anyhow::anyhow!("No se pudo iniciar el servicio: {}", e))),
                    }
                }
                Ok(s) => Some(Err(anyhow::anyhow!(
                    "sc.exe {} falló con código: {:?}",
                    if service_exists { "config" } else { "create" },
                    s.code()
                ))),
                Err(e) => Some(Err(anyhow::anyhow!("No se pudo ejecutar sc.exe: {}", e))),
            }
        }
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

fn init_logging(to_programdata_file: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,nfc_bridge_driver=debug"));

    if to_programdata_file {
        let log_dir = std::path::PathBuf::from(
            std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()),
        )
        .join("NFC Bridge");
        if std::fs::create_dir_all(&log_dir).is_ok() {
            let log_path = log_dir.join("driver.log");
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(log_path)
            {
                let _ = tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_target(false)
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(file))
                    .try_init();
                return;
            }
        }
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn run_driver(shutdown: Option<Arc<Notify>>, log_to_file: bool) -> anyhow::Result<()> {
    init_logging(log_to_file);

    info!("============================================================");
    info!("    NFC BRIDGE DRIVER (Windows Silent Background Service)   ");
    info!("============================================================");

    // 1. Instanciar el motor de emulación CCID compartido
    let ccid_handler = Arc::new(Mutex::new(CcidHandler::new()));

    // Canal broadcast interno para eventos IPC (Sync / Tools Desktop)
    let (event_tx, _) = broadcast::channel::<IpcEvent>(128);

    // 2. Instanciar coordinador de red/transporte (TCP + UDP Discovery + USB AOA)
    let tcp_server = Arc::new(BridgeTcpServer::new(event_tx.clone(), Arc::clone(&ccid_handler)));
    let wfd_server = Arc::new(WifiDirectServer::new(event_tx.clone()));

    // 3. Iniciar Servidor IPC (Named Pipe de Windows: \\.\pipe\nfc_bridge_driver)
    let ipc_server = Arc::new(NamedPipeIpcServer::with_transports(
        event_tx,
        Arc::clone(&tcp_server),
        Arc::clone(&wfd_server),
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

    // 6. Iniciar Servidor Bluetooth RFCOMM SPP nativo de Windows
    let bt_server = Arc::new(BluetoothRfcommServer::new(Arc::clone(&tcp_server)));
    tokio::spawn(async move {
        bt_server.run().await;
    });

    // 7. Iniciar Servidor Wi-Fi Direct (P2P nativo + Legacy SoftAP automático)
    let wfd_server_for_run = Arc::clone(&wfd_server);
    tokio::spawn(async move {
        wfd_server_for_run.run().await;
    });

    // 6. Iniciar Servidor USB/IP (Puerto 3240 para emulación USB CCID ACR122U)
    let usbip_server = UsbIpServer::new(USBIP_DEFAULT_PORT, Arc::clone(&ccid_handler));
    let tcp_server_for_usbip = Arc::clone(&tcp_server);
    tokio::spawn(async move {
        let transceive_cb = move |req: Vec<u8>| {
            let tcp = Arc::clone(&tcp_server_for_usbip);
            async move { tcp.transceive(req).await }
        };

        if let Err(e) = usbip_server.start(transceive_cb).await {
            warn!("Aviso en el servidor USB/IP: {}", e);
        }
    });

    info!("Driver activo en segundo plano: Named Pipe (\\\\.\\pipe\\nfc_bridge_driver) listo.");

    if let Some(notify) = shutdown {
        notify.notified().await;
    } else {
        tokio::signal::ctrl_c().await?;
    }

    info!("Señal de apagado recibida. Cerrando NFC Bridge Driver...");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    if let Some(result) = handle_cli_commands() {
        return result;
    }

    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(run_driver(None, false));
    rt.shutdown_timeout(std::time::Duration::from_millis(250));
    result
}

#[cfg(windows)]
mod windows_svc {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_NAME: &str = "NfcBridgeDriver";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> windows_service::Result<()> {
        let shutdown = Arc::new(Notify::new());
        let shutdown_signal = Arc::clone(&shutdown);

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    shutdown_signal.notify_waiters();
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let _ = rt.block_on(super::run_driver(Some(shutdown), true));
            rt.shutdown_timeout(Duration::from_millis(250));
        }

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        Ok(())
    }
}
