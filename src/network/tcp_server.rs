//! Servidor TCP / UDP Discovery de ultra baja latencia para comunicación con NFC Bridge Android.
//!
//! Es el núcleo de transporte en Windows: gestiona las conexiones entrantes (TCP, USB AOA, etc.),
//! responde al auto-descubrimiento UDP en la red local y sincroniza el estado en vivo hacia
//! el lector virtual CCID y las aplicaciones de escritorio vía IPC Named Pipe.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, Notify};
use tracing::{debug, error, info, warn};

use crate::emulator::CcidHandler;
use crate::ipc::events::IpcEvent;
use crate::network::pairing_manager::{HelloAuthOutcome, PairingManager};
use crate::protocol::codec::{FrameCodec, StreamFrameDecoder};
use crate::protocol::constants::DEFAULT_TCP_PORT;
use crate::protocol::crc::compute_crc16;
use crate::protocol::frame::NfcBridgeFrame;
use crate::protocol::message_type::MessageType;

#[derive(Debug, Clone, Default)]
pub struct DriverRuntimeStatus {
    pub connected: bool,
    pub device_name: Option<String>,
    pub endpoint: Option<String>,
    pub latency_ms: u64,
    pub paused: bool,
    pub tag_present: bool,
    pub tag_uid: Option<String>,
}

pub struct BridgeTcpServer {
    event_tx: broadcast::Sender<IpcEvent>,
    ccid_handler: Arc<Mutex<CcidHandler>>,
    pairing: Arc<PairingManager>,
    sequence_counter: AtomicU16,
    active_client_tx: Arc<Mutex<Option<mpsc::Sender<NfcBridgeFrame>>>>,
    pending_transceive: Arc<Mutex<Option<(u16, oneshot::Sender<Vec<u8>>)>>>,
    runtime_status: Arc<Mutex<DriverRuntimeStatus>>,
    is_paused: AtomicBool,
    disconnect_notify: Arc<Notify>,
}

impl BridgeTcpServer {
    pub fn new(event_tx: broadcast::Sender<IpcEvent>, ccid_handler: Arc<Mutex<CcidHandler>>) -> Self {
        let pc_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "NFC Bridge PC".to_string());
        Self::with_pairing(event_tx, ccid_handler, Arc::new(PairingManager::new(pc_name)))
    }

    pub fn with_pairing(
        event_tx: broadcast::Sender<IpcEvent>,
        ccid_handler: Arc<Mutex<CcidHandler>>,
        pairing: Arc<PairingManager>,
    ) -> Self {
        Self {
            event_tx,
            ccid_handler,
            pairing,
            sequence_counter: AtomicU16::new(1),
            active_client_tx: Arc::new(Mutex::new(None)),
            pending_transceive: Arc::new(Mutex::new(None)),
            runtime_status: Arc::new(Mutex::new(DriverRuntimeStatus::default())),
            is_paused: AtomicBool::new(false),
            disconnect_notify: Arc::new(Notify::new()),
        }
    }

    pub async fn get_status_event(&self) -> IpcEvent {
        let st = self.runtime_status.lock().await;
        IpcEvent::Status {
            connected: st.connected,
            device_name: st.device_name.clone(),
            latency_ms: st.latency_ms,
            paused: self.is_paused.load(Ordering::Relaxed),
            tag_present: st.tag_present,
            tag_uid: st.tag_uid.clone(),
        }
    }

    pub async fn set_paused(&self, paused: bool) {
        self.is_paused.store(paused, Ordering::Relaxed);
        {
            let mut st = self.runtime_status.lock().await;
            st.paused = paused;
            if paused {
                st.tag_present = false;
                st.tag_uid = None;
            }
        }
        if paused {
            let mut handler = self.ccid_handler.lock().await;
            handler.set_tag(None);
        }
        let status_evt = self.get_status_event().await;
        let _ = self.event_tx.send(status_evt);
    }

    pub async fn disconnect_active(&self) {
        self.disconnect_notify.notify_waiters();
    }

    async fn update_connected_device_name(&self, device_name: Option<String>) {
        let Some(name) = device_name else {
            return;
        };
        let endpoint = {
            let mut st = self.runtime_status.lock().await;
            st.device_name = Some(name.clone());
            st.endpoint.clone().unwrap_or_default()
        };
        let _ = self.event_tx.send(IpcEvent::DeviceConnected {
            device_name: name,
            endpoint,
        });
    }

    /// Inicia el listener TCP y el responder UDP de auto-descubrimiento en el puerto 45362.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", DEFAULT_TCP_PORT);
        let listener = TcpListener::bind(&addr).await?;
        info!("Driver TCP escuchando en {} (Esperando teléfono Android)", addr);

        // Iniciar responder UDP en el mismo puerto 45362 para auto-descubrimiento en red Wi-Fi / LAN
        let pc_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "NFC Bridge PC".to_string());
        tokio::spawn(async move {
            if let Err(e) = Self::run_udp_discovery_responder(DEFAULT_TCP_PORT, pc_name).await {
                warn!("UDP discovery responder en driver finalizó con error: {}", e);
            }
        });

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    info!("Dispositivo Android conectado vía TCP desde: {}", peer_addr);
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        server.handle_client(socket, peer_addr.to_string()).await;
                    });
                }
                Err(e) => {
                    error!("Error al aceptar conexión TCP: {}", e);
                }
            }
        }
    }

    async fn run_udp_discovery_responder(port: u16, pc_name: String) -> anyhow::Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let socket = UdpSocket::bind(addr).await?;
        info!("Driver UDP auto-descubrimiento activo en {}", addr);

        let mut buf = [0u8; 1024];
        let mut last_logged: HashMap<String, Instant> = HashMap::new();

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    let msg = String::from_utf8_lossy(&buf[..len]);
                    if msg.contains("NFC_BRIDGE_DISCOVERY") {
                        let pc_id = format!(
                            "{:04X}{:04X}",
                            compute_crc16(pc_name.as_bytes()),
                            compute_crc16(&port.to_le_bytes())
                        );
                        let response = format!(
                            r#"{{"id":"{}","name":"{}","port":{},"model":"WINDOWS","status":"ready"}}"#,
                            pc_id, pc_name, port
                        );
                        if let Err(e) = socket.send_to(response.as_bytes(), peer_addr).await {
                            warn!("Error respondiendo descubrimiento UDP a {}: {}", peer_addr, e);
                        } else {
                            let peer_ip = peer_addr.ip().to_string();
                            let now = Instant::now();
                            let should_log = last_logged
                                .get(&peer_ip)
                                .map(|prev| now.duration_since(*prev) >= Duration::from_secs(3))
                                .unwrap_or(true);
                            if should_log {
                                last_logged.insert(peer_ip, now);
                                info!("Descubrimiento Wi-Fi respondido a {} (PC: '{}')", peer_addr, pc_name);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Error recibiendo datagrama UDP: {}", e);
                }
            }
        }
    }

    /// Envía un comando transceive crudo / APDU al teléfono Android conectado y espera la respuesta.
    pub async fn transceive(&self, payload: Vec<u8>) -> Option<Vec<u8>> {
        if self.is_paused.load(Ordering::Relaxed) {
            return None;
        }

        let client_tx = {
            let guard = self.active_client_tx.lock().await;
            guard.clone()
        }?;

        let seq = self.sequence_counter.fetch_add(1, Ordering::SeqCst);
        let (resp_tx, resp_rx) = oneshot::channel();

        {
            let mut pending = self.pending_transceive.lock().await;
            *pending = Some((seq, resp_tx));
        }

        let frame = NfcBridgeFrame::new(MessageType::TransceiveReq, seq, payload);
        if let Err(e) = client_tx.send(frame).await {
            warn!("Fallo al encolar TRANSCEIVE_REQ para el móvil: {}", e);
            let mut pending = self.pending_transceive.lock().await;
            *pending = None;
            return None;
        }

        match tokio::time::timeout(Duration::from_secs(2), resp_rx).await {
            Ok(Ok(response_bytes)) => Some(response_bytes),
            Ok(Err(_)) => {
                debug!("Canal oneshot cancelado antes de recibir respuesta");
                None
            }
            Err(_) => {
                warn!("Timeout esperando respuesta TRANSCEIVE_RESP del móvil (seq={})", seq);
                let mut pending = self.pending_transceive.lock().await;
                *pending = None;
                None
            }
        }
    }

    async fn handle_client(&self, socket: TcpStream, peer_endpoint: String) {
        if let Err(e) = socket.set_nodelay(true) {
            warn!("No se pudo configurar TCP_NODELAY: {}", e);
        }

        let (reader, writer) = socket.into_split();
        self.handle_stream(reader, writer, peer_endpoint).await;
    }

    /// Maneja cualquier flujo bidireccional de tramas BAP v1 (TCP, USB AOA, Bluetooth, etc.).
    pub async fn handle_stream<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        peer_endpoint: String,
    ) where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (out_tx, mut out_rx) = mpsc::channel::<NfcBridgeFrame>(128);

        {
            let mut active = self.active_client_tx.lock().await;
            *active = Some(out_tx.clone());
        }
        {
            let mut st = self.runtime_status.lock().await;
            st.connected = true;
            st.device_name = Some("Android Phone".to_string());
            st.endpoint = Some(peer_endpoint.clone());
        }

        let _ = self.event_tx.send(IpcEvent::DeviceConnected {
            device_name: "Android Phone".to_string(),
            endpoint: peer_endpoint.clone(),
        });

        let write_task = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                let encoded = FrameCodec::encode(&frame);
                if let Err(e) = writer.write_all(&encoded).await {
                    debug!("Error escribiendo hacia móvil: {}", e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    debug!("Error en flush hacia móvil: {}", e);
                    break;
                }
            }
        });

        let hb_tx = out_tx.clone();
        let hb_event_tx = self.event_tx.clone();
        let hb_status = Arc::clone(&self.runtime_status);
        let hb_active = Arc::new(AtomicBool::new(true));
        let hb_flag = Arc::clone(&hb_active);

        let heartbeat_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            while hb_flag.load(Ordering::Relaxed) {
                interval.tick().await;
                let start_time = Instant::now();
                let ping_frame = NfcBridgeFrame::new(MessageType::Heartbeat, 100, vec![]);

                if hb_tx.send(ping_frame).await.is_ok() {
                    let rtt_ms = start_time.elapsed().as_millis() as u64;
                    let latency = rtt_ms.max(1);
                    {
                        let mut st = hb_status.lock().await;
                        st.latency_ms = latency;
                    }
                    let _ = hb_event_tx.send(IpcEvent::LatencyUpdated { latency_ms: latency });
                } else {
                    break;
                }
            }
        });

        let mut decoder = StreamFrameDecoder::new();
        let mut buffer = [0u8; 4096];

        loop {
            tokio::select! {
                _ = self.disconnect_notify.notified() => {
                    info!("Desconexión solicitada vía IPC para {}", peer_endpoint);
                    break;
                }
                read_res = reader.read(&mut buffer) => {
                    match read_res {
                        Ok(0) => {
                            info!("Dispositivo Android desconectado ({})", peer_endpoint);
                            break;
                        }
                        Ok(n) => {
                            let frames = decoder.feed(&buffer[..n]);
                            for frame in frames {
                                self.process_frame(frame, &out_tx).await;
                            }
                        }
                        Err(e) => {
                            warn!("Error de lectura en enlace con móvil ({}): {}", peer_endpoint, e);
                            break;
                        }
                    }
                }
            }
        }

        hb_active.store(false, Ordering::Relaxed);
        heartbeat_task.abort();
        write_task.abort();

        {
            let mut active = self.active_client_tx.lock().await;
            *active = None;
        }
        {
            let mut st = self.runtime_status.lock().await;
            st.connected = false;
            st.device_name = None;
            st.endpoint = None;
            st.tag_present = false;
            st.tag_uid = None;
        }
        {
            let mut handler = self.ccid_handler.lock().await;
            handler.set_tag(None);
        }

        let _ = self.event_tx.send(IpcEvent::DeviceDisconnected);
    }

    async fn process_frame(
        &self,
        frame: NfcBridgeFrame,
        out_tx: &mpsc::Sender<NfcBridgeFrame>,
    ) {
        match frame.message_type {
            MessageType::HelloSyn => {
                let pc_name = self.pairing.pc_name().to_string();
                let outcome = self.pairing.validate_hello_payload(&frame.payload);
                match outcome {
                    HelloAuthOutcome::Rejected { reason } => {
                        warn!("Handshake HELLO_SYN rechazado ({})", reason);
                        let payload = serde_json::json!({
                            "pc_name": pc_name,
                            "status": "rejected",
                            "reason": reason
                        })
                        .to_string();
                        let ack_frame = NfcBridgeFrame::new(
                            MessageType::HelloAck,
                            frame.sequence_id,
                            payload.into_bytes(),
                        );
                        let _ = out_tx.send(ack_frame).await;
                        let notify = Arc::clone(&self.disconnect_notify);
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(80)).await;
                            notify.notify_waiters();
                        });
                    }
                    HelloAuthOutcome::Paired {
                        device_name,
                        new_device_token,
                    } => {
                        info!("Handshake HELLO_SYN emparejado con QR/Link (nuevo device_token emitido)");
                        self.update_connected_device_name(device_name).await;
                        let payload = serde_json::json!({
                            "pc_name": pc_name,
                            "status": "ready",
                            "device_token": new_device_token
                        })
                        .to_string();
                        let ack_frame = NfcBridgeFrame::new(
                            MessageType::HelloAck,
                            frame.sequence_id,
                            payload.into_bytes(),
                        );
                        let _ = out_tx.send(ack_frame).await;
                    }
                    HelloAuthOutcome::Trusted { device_name }
                    | HelloAuthOutcome::LegacyAllowed { device_name } => {
                        info!("Handshake HELLO_SYN recibido del móvil. Respondiendo HELLO_ACK...");
                        self.update_connected_device_name(device_name).await;
                        let payload = serde_json::json!({
                            "pc_name": pc_name,
                            "status": "ready"
                        })
                        .to_string();
                        let ack_frame = NfcBridgeFrame::new(
                            MessageType::HelloAck,
                            frame.sequence_id,
                            payload.into_bytes(),
                        );
                        let _ = out_tx.send(ack_frame).await;
                    }
                }
            }
            MessageType::TagAttached => {
                if self.is_paused.load(Ordering::Relaxed) {
                    return;
                }
                if let Some(tag) = FrameCodec::decode_tag_attached(&frame.payload) {
                    let uid_hex = tag.uid_hex();
                    let is_ntag215 = tag.is_mifare_ultralight();
                    info!("ETIQUETA NFC DETECTADA: UID={} (NTAG215={})", uid_hex, is_ntag215);

                    {
                        let mut st = self.runtime_status.lock().await;
                        st.tag_present = true;
                        st.tag_uid = Some(uid_hex.clone());
                    }
                    {
                        let mut handler = self.ccid_handler.lock().await;
                        handler.set_tag(Some(tag.clone()));
                    }

                    let mut techs = Vec::new();
                    if tag.is_nfc_a() { techs.push("NfcA".to_string()); }
                    if tag.is_iso_dep() { techs.push("IsoDep".to_string()); }
                    if tag.is_mifare_ultralight() { techs.push("MifareUltralight".to_string()); }

                    let _ = self.event_tx.send(IpcEvent::TagAttached {
                        uid: uid_hex,
                        technologies: techs,
                        is_ntag215,
                    });
                }
            }
            MessageType::TagDetached => {
                info!("ETIQUETA NFC RETIRADA del campo");
                {
                    let mut st = self.runtime_status.lock().await;
                    st.tag_present = false;
                    st.tag_uid = None;
                }
                {
                    let mut handler = self.ccid_handler.lock().await;
                    handler.set_tag(None);
                }
                let _ = self.event_tx.send(IpcEvent::TagDetached);
            }
            MessageType::TransceiveResp => {
                debug!("TRANSCEIVE_RESP recibido del móvil para seq={}", frame.sequence_id);
                let mut pending = self.pending_transceive.lock().await;
                if let Some((expected_seq, _)) = &*pending {
                    if *expected_seq == frame.sequence_id {
                        if let Some((_, sender)) = pending.take() {
                            let _ = sender.send(frame.payload);
                        }
                    }
                }
            }
            MessageType::Heartbeat => {
                let ack = NfcBridgeFrame::new(MessageType::HeartbeatAck, frame.sequence_id, vec![]);
                let _ = out_tx.send(ack).await;
            }
            MessageType::HeartbeatAck => {}
            _ => {
                info!("Trama recibida: tipo={:?}, seq={}", frame.message_type, frame.sequence_id);
            }
        }
    }
}
