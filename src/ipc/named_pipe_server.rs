//! Servidor IPC por Named Pipe de Windows (\\.\pipe\nfc_bridge_driver).

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use super::events::{IpcCommand, IpcEvent};
use crate::protocol::constants::NAMED_PIPE_NAME;

pub struct NamedPipeIpcServer {
    event_sender: broadcast::Sender<IpcEvent>,
}

impl NamedPipeIpcServer {
    pub fn new(event_sender: broadcast::Sender<IpcEvent>) -> Self {
        Self { event_sender }
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

            // Esperar a que un cliente local (Sync o Tools Desktop) se conecte
            if let Err(e) = server.connect().await {
                warn!("Fallo al conectar cliente a Named Pipe: {}", e);
                continue;
            }

            info!("Cliente IPC conectado a Named Pipe");
            let this = Arc::clone(&self);
            let mut event_rx = this.event_sender.subscribe();

            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(server);
                let mut lines = BufReader::new(reader).lines();

                loop {
                    tokio::select! {
                        // Enviar eventos hacia el cliente
                        Ok(event) = event_rx.recv() => {
                            if let Ok(json) = serde_json::to_string(&event) {
                                if writer.write_all(format!("{}\n", json).as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                        }
                        // Recibir comandos desde el cliente
                        line_result = lines.next_line() => {
                            match line_result {
                                Ok(Some(line)) => {
                                    if let Ok(cmd) = serde_json::from_str::<IpcCommand>(&line) {
                                        info!("Comando IPC recibido: {:?}", cmd);
                                    }
                                }
                                _ => break, // Cliente desconectado
                            }
                        }
                    }
                }
                info!("Cliente IPC desconectado");
            });
        }
    }
}
