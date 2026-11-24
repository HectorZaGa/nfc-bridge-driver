//! Servidor IPC por Named Pipe de Windows (\\.\pipe\nfc_bridge_driver).

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use super::events::{IpcCommand, IpcEvent};
use crate::network::BridgeTcpServer;
use crate::protocol::constants::NAMED_PIPE_NAME;

pub struct NamedPipeIpcServer {
    event_sender: broadcast::Sender<IpcEvent>,
    coordinator: Option<Arc<BridgeTcpServer>>,
}

impl NamedPipeIpcServer {
    pub fn new(event_sender: broadcast::Sender<IpcEvent>) -> Self {
        Self {
            event_sender,
            coordinator: None,
        }
    }

    pub fn with_coordinator(
        event_sender: broadcast::Sender<IpcEvent>,
        coordinator: Arc<BridgeTcpServer>,
    ) -> Self {
        Self {
            event_sender,
            coordinator: Some(coordinator),
        }
    }

    /// Inicia el bucle que acepta clientes locales de Windows (Sync / Tools).
    pub async fn run(self: Arc<Self>) {
        info!("Iniciando servidor IPC Named Pipe en {}", NAMED_PIPE_NAME);

        let mut first = true;
        loop {
            let server = match ServerOptions::new()
                .first_pipe_instance(first)
                .create(NAMED_PIPE_NAME)
            {
                Ok(s) => {
                    first = false;
                    s
                }
                Err(e) => {
                    error!("Error al crear Named Pipe {}: {}", NAMED_PIPE_NAME, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            if let Err(e) = server.connect().await {
                warn!("Fallo al conectar cliente a Named Pipe: {}", e);
                continue;
            }

            info!("Cliente IPC (Sync / Tools) conectado a Named Pipe");
            let this = Arc::clone(&self);
            let mut event_rx = this.event_sender.subscribe();

            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(server);
                let mut lines = BufReader::new(reader).lines();

                // Enviar estado inicial al conectarse Sync/Tools
                if let Some(ref coord) = this.coordinator {
                    let initial_status = coord.get_status_event().await;
                    if let Ok(json) = serde_json::to_string(&initial_status) {
                        let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                }

                loop {
                    tokio::select! {
                        Ok(event) = event_rx.recv() => {
                            if let Ok(json) = serde_json::to_string(&event) {
                                if writer.write_all(format!("{}\n", json).as_bytes()).await.is_err() {
                                    break;
                                }
                                let _ = writer.flush().await;
                            }
                        }
                        line_result = lines.next_line() => {
                            match line_result {
                                Ok(Some(line)) => {
                                    if let Ok(cmd) = serde_json::from_str::<IpcCommand>(&line) {
                                        info!("Comando IPC recibido: {:?}", cmd);
                                        if let Some(ref coord) = this.coordinator {
                                            match cmd {
                                                IpcCommand::GetStatus => {
                                                    let status = coord.get_status_event().await;
                                                    if let Ok(json) = serde_json::to_string(&status) {
                                                        if writer.write_all(format!("{}\n", json).as_bytes()).await.is_err() {
                                                            break;
                                                        }
                                                        let _ = writer.flush().await;
                                                    }
                                                }
                                                IpcCommand::SetPaused { paused } => {
                                                    coord.set_paused(paused).await;
                                                }
                                                IpcCommand::DisconnectDevice => {
                                                    coord.disconnect_active().await;
                                                }
                                                IpcCommand::SetUsbPriority { .. } => {}
                                            }
                                        }
                                    }
                                }
                                _ => break,
                            }
                        }
                    }
                }
                info!("Cliente IPC desconectado");
            });
        }
    }
}
