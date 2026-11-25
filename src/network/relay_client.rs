//! Cliente WebSocket saliente para conectar el Driver con el Cloud Relay (`nfc-bridge-relay`).
//!
//! Cuando existe una URL de Relay configurada (`relay_config.json` o `NFC_BRIDGE_RELAY_URL`),
//! mantiene una conexión saliente persistente hacia `wss://<relay>/ws/<channel>?role=pc` y
//! redirige las tramas binarias directamente a `BridgeTcpServer::handle_stream`.
//! Si no hay Relay configurado, permanece dormido sin consumo de red ni CPU.

use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, info, warn};

use crate::network::pairing_manager::to_ws_base;
use crate::network::{BridgeTcpServer, PairingManager};

pub struct RelayClient {
    coordinator: Arc<BridgeTcpServer>,
    pairing: Arc<PairingManager>,
    is_connected: Arc<AtomicBool>,
    config_changed: Arc<Notify>,
}

impl RelayClient {
    pub fn new(coordinator: Arc<BridgeTcpServer>, pairing: Arc<PairingManager>) -> Self {
        Self {
            coordinator,
            pairing,
            is_connected: Arc::new(AtomicBool::new(false)),
            config_changed: Arc::new(Notify::new()),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Relaxed)
    }

    pub fn notify_config_changed(&self) {
        self.config_changed.notify_waiters();
    }

    pub async fn run(self: Arc<Self>) {
        info!("Monitor de enlace Cloud Relay iniciado.");
        let mut backoff_secs = 3u64;

        loop {
            let Some(raw_url) = self.pairing.get_relay_url() else {
                self.is_connected.store(false, Ordering::Relaxed);
                self.config_changed.notified().await;
                backoff_secs = 3;
                continue;
            };

            let ws_base = to_ws_base(&raw_url);
            let channel = self.pairing.get_relay_channel();
            let ws_url = format!("{}/ws/{}?role=pc", ws_base, channel);

            info!("Conectando canal Cloud Relay ({})...", ws_base);

            let connect_res = tokio::select! {
                _ = self.config_changed.notified() => {
                    backoff_secs = 3;
                    continue;
                }
                res = connect_async(&ws_url) => res,
            };

            match connect_res {
                Ok((ws_stream, _)) => {
                    backoff_secs = 3;
                    self.is_connected.store(true, Ordering::Relaxed);
                    info!("Túnel Cloud Relay activo (canal={})", channel);

                    let (mut ws_write, mut ws_read) = ws_stream.split();
                    let (bridge_io, driver_io) = tokio::io::duplex(64 * 1024);
                    let (mut bridge_r, mut bridge_w) = tokio::io::split(bridge_io);
                    let (driver_r, driver_w) = tokio::io::split(driver_io);

                    let coord = Arc::clone(&self.coordinator);
                    let stream_task = tokio::spawn(async move {
                        coord
                            .handle_stream(driver_r, driver_w, "Cloud Relay".to_string())
                            .await;
                    });

                    let mut out_buf = [0u8; 8192];
                    loop {
                        tokio::select! {
                            _ = self.config_changed.notified() => {
                                let _ = ws_write.close().await;
                                break;
                            }
                            ws_msg = ws_read.next() => {
                                match ws_msg {
                                    Some(Ok(Message::Binary(bytes))) => {
                                        if bridge_w.write_all(&bytes).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(Ok(Message::Ping(p))) => {
                                        if ws_write.send(Message::Pong(p)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(Ok(Message::Close(_))) | None => break,
                                    Some(Ok(_)) => {}
                                    Some(Err(e)) => {
                                        debug!("Error WS Cloud Relay: {}", e);
                                        break;
                                    }
                                }
                            }
                            read_res = bridge_r.read(&mut out_buf) => {
                                match read_res {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if ws_write.send(Message::Binary(out_buf[..n].to_vec().into())).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    drop(bridge_w);
                    let _ = stream_task.await;
                    self.is_connected.store(false, Ordering::Relaxed);
                    info!("Túnel Cloud Relay desconectado; reconectando...");
                }
                Err(e) => {
                    self.is_connected.store(false, Ordering::Relaxed);
                    warn!(
                        "No se pudo conectar al Cloud Relay ({}): {}. Reintento en {} s...",
                        ws_base, e, backoff_secs
                    );
                }
            }

            tokio::select! {
                _ = self.config_changed.notified() => {
                    backoff_secs = 3;
                }
                _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {
                    backoff_secs = (backoff_secs * 2).min(20);
                }
            }
        }
    }
}
