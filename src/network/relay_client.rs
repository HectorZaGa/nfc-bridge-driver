//! Cliente WebSocket saliente para conectar el Driver con el Cloud Relay (`nfc-bridge-relay`).
//!
//! Cuando existe una URL de Relay configurada (`relay_config.json` o `NFC_BRIDGE_RELAY_URL`),
//! mantiene una conexión saliente persistente hacia `wss://<relay>/ws/<channel>?role=pc` y
//! redirige las tramas binarias directamente a `BridgeTcpServer::handle_stream`.
//! Si no hay Relay configurado, permanece dormido sin consumo de red ni CPU.

use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};
use tracing::{debug, info, warn};

use crate::network::pairing_manager::{has_outbound_network, to_ws_base};
use crate::network::{BridgeTcpServer, PairingManager};

pub struct RelayClient {
    coordinator: Arc<BridgeTcpServer>,
    pairing: Arc<PairingManager>,
    is_connected: Arc<AtomicBool>,
    config_changed: Arc<Notify>,
    snapshot_notify: Arc<Notify>,
}

static INIT_TLS_PROVIDER: Once = Once::new();

fn ensure_rustls_crypto_provider() {
    INIT_TLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn is_local_relay_url(ws_base: &str) -> bool {
    let lower = ws_base.to_ascii_lowercase();
    lower.contains("://127.0.0.1") || lower.contains("://localhost") || lower.contains("://[::1]")
}

fn has_route_for_relay(ws_base: &str) -> bool {
    is_local_relay_url(ws_base) || has_outbound_network()
}

#[cfg(windows)]
fn register_windows_network_notifier(net_notify: Arc<Notify>) {
    use core::ffi::c_void;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::IpHelper::{
        NotifyIpInterfaceChange, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    unsafe extern "system" fn on_ip_change(
        ctx: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _notif: MIB_NOTIFICATION_TYPE,
    ) {
        if !ctx.is_null() {
            let notify = &*(ctx as *const Notify);
            notify.notify_waiters();
        }
    }

    let raw_ctx = Arc::into_raw(net_notify) as *const c_void;
    let mut handle = HANDLE::default();
    let err = unsafe { NotifyIpInterfaceChange(AF_UNSPEC, Some(on_ip_change), Some(raw_ctx), false, &mut handle) };
    if err.0 != 0 {
        unsafe {
            drop(Arc::from_raw(raw_ctx as *const Notify));
        }
        warn!("NotifyIpInterfaceChange falló (código {}): usando sondeo de respaldo.", err.0);
    } else {
        let _ = handle;
    }
}

#[cfg(not(windows))]
fn register_windows_network_notifier(_net_notify: Arc<Notify>) {}

impl RelayClient {
    pub fn new(coordinator: Arc<BridgeTcpServer>, pairing: Arc<PairingManager>) -> Self {
        Self::with_snapshot_notify(coordinator, pairing, Arc::new(Notify::new()))
    }

    pub fn with_snapshot_notify(
        coordinator: Arc<BridgeTcpServer>,
        pairing: Arc<PairingManager>,
        snapshot_notify: Arc<Notify>,
    ) -> Self {
        Self {
            coordinator,
            pairing,
            is_connected: Arc::new(AtomicBool::new(false)),
            config_changed: Arc::new(Notify::new()),
            snapshot_notify,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Relaxed)
    }

    fn set_connected(&self, val: bool) {
        if self.is_connected.swap(val, Ordering::Relaxed) != val {
            self.snapshot_notify.notify_waiters();
        }
    }

    pub fn notify_config_changed(&self) {
        self.config_changed.notify_waiters();
    }

    pub async fn run(self: Arc<Self>) {
        ensure_rustls_crypto_provider();
        info!("Monitor de enlace Cloud Relay iniciado.");
        let net_changed = Arc::new(Notify::new());
        register_windows_network_notifier(Arc::clone(&net_changed));
        let mut backoff_secs = 2u64;

        loop {
            let Some(raw_url) = self.pairing.get_relay_url() else {
                self.set_connected(false);
                self.config_changed.notified().await;
                backoff_secs = 2;
                continue;
            };

            let ws_base = to_ws_base(&raw_url);
            if !has_route_for_relay(&ws_base) {
                self.set_connected(false);
                self.snapshot_notify.notify_waiters();
                tokio::select! {
                    _ = self.config_changed.notified() => {
                        backoff_secs = 2;
                    }
                    _ = net_changed.notified() => {
                        self.snapshot_notify.notify_waiters();
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        backoff_secs = 1;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                }
                continue;
            }

            let channel = self.pairing.get_relay_channel();
            let host_secret = self.pairing.get_relay_host_secret();
            let ws_url = format!("{}/ws/{}?role=pc", ws_base, channel);

            info!("Conectando canal Cloud Relay ({})...", ws_base);

            let Ok(mut ws_req) = ws_url.into_client_request() else {
                warn!("URL de Cloud Relay inválida: {}", ws_base);
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            };
            if let Ok(header_val) = format!("Bearer {}", host_secret).parse() {
                ws_req.headers_mut().insert("Authorization", header_val);
            }

            let connect_res = tokio::select! {
                _ = self.config_changed.notified() => {
                    backoff_secs = 2;
                    continue;
                }
                _ = net_changed.notified() => {
                    if !has_route_for_relay(&ws_base) {
                        self.set_connected(false);
                        self.snapshot_notify.notify_waiters();
                    }
                    backoff_secs = 1;
                    continue;
                }
                res = connect_async(ws_req) => res,
            };

            match connect_res {
                Ok((ws_stream, _)) => {
                    backoff_secs = 2;
                    self.set_connected(true);
                    info!("Túnel Cloud Relay activo (canal={})", channel);

                    let (mut ws_write, mut ws_read) = ws_stream.split();
                    let mut ping_interval = tokio::time::interval(Duration::from_secs(8));
                    ping_interval.tick().await;
                    let mut last_ws_rx = Instant::now();

                    let spawn_session = |coord: &Arc<BridgeTcpServer>| {
                        let (bridge_io, driver_io) = tokio::io::duplex(64 * 1024);
                        let (bridge_r, bridge_w) = tokio::io::split(bridge_io);
                        let (driver_r, driver_w) = tokio::io::split(driver_io);
                        let c = Arc::clone(coord);
                        let task = tokio::spawn(async move {
                            c.handle_stream(driver_r, driver_w, "Cloud Relay".to_string())
                                .await;
                        });
                        (bridge_r, bridge_w, task)
                    };

                    let (mut bridge_r, mut bridge_w, mut stream_task) =
                        spawn_session(&self.coordinator);

                    let mut out_buf = [0u8; 8192];
                    loop {
                        tokio::select! {
                            _ = self.config_changed.notified() => {
                                let _ = ws_write.close().await;
                                break;
                            }
                            _ = net_changed.notified() => {
                                if !has_route_for_relay(&ws_base) {
                                    warn!("Red desconectada; cerrando túnel Cloud Relay al instante.");
                                    let _ = ws_write.close().await;
                                    break;
                                }
                                let _ = ws_write.send(Message::Ping(b"net".to_vec().into())).await;
                            }
                            _ = ping_interval.tick() => {
                                if !has_route_for_relay(&ws_base) || last_ws_rx.elapsed() > Duration::from_secs(24) {
                                    warn!("Sin respuesta o ruta de red en Cloud Relay; desconectando...");
                                    let _ = ws_write.close().await;
                                    break;
                                }
                                if ws_write.send(Message::Ping(b"hb".to_vec().into())).await.is_err() {
                                    break;
                                }
                            }
                            ws_msg = ws_read.next() => {
                                match ws_msg {
                                    Some(Ok(Message::Binary(bytes))) => {
                                        last_ws_rx = Instant::now();
                                        if bridge_w.write_all(&bytes).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(Ok(Message::Ping(p))) => {
                                        last_ws_rx = Instant::now();
                                        if ws_write.send(Message::Pong(p)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(Ok(Message::Pong(_))) => {
                                        last_ws_rx = Instant::now();
                                    }
                                    Some(Ok(Message::Close(_))) | None => break,
                                    Some(Ok(_)) => {
                                        last_ws_rx = Instant::now();
                                    }
                                    Some(Err(e)) => {
                                        debug!("Error WS Cloud Relay: {}", e);
                                        break;
                                    }
                                }
                            }
                            read_res = bridge_r.read(&mut out_buf) => {
                                match read_res {
                                    Ok(0) | Err(_) => {
                                        // Sesión del móvil terminó cleanly; rearmar pipe manteniendo el túnel PC abierto
                                        let _ = stream_task.await;
                                        let next = spawn_session(&self.coordinator);
                                        bridge_r = next.0;
                                        bridge_w = next.1;
                                        stream_task = next.2;
                                    }
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
                    self.set_connected(false);
                    info!("Túnel Cloud Relay desconectado; reconectando...");
                }
                Err(e) => {
                    self.set_connected(false);
                    warn!(
                        "No se pudo conectar al Cloud Relay ({}): {}. Reintento en {} s...",
                        ws_base, e, backoff_secs
                    );
                }
            }

            tokio::select! {
                _ = self.config_changed.notified() => {
                    backoff_secs = 2;
                }
                _ = net_changed.notified() => {
                    self.snapshot_notify.notify_waiters();
                    tokio::time::sleep(Duration::from_millis(120)).await;
                    backoff_secs = 1;
                }
                _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {
                    backoff_secs = (backoff_secs * 2).min(15);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_rustls_crypto_provider;
    use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};

    #[tokio::test]
    async fn test_wss_connector_does_not_panic() {
        ensure_rustls_crypto_provider();
        let req = "wss://127.0.0.1:1/ws/nb-testsec01?role=pc"
            .into_client_request()
            .unwrap();
        let res = connect_async(req).await;
        assert!(res.is_err());
    }
}
