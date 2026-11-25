//! Servidor TCP / UDP Discovery de ultra baja latencia para comunicación con NFC Bridge Android.
//!
//! Es el núcleo de transporte en Windows: gestiona las conexiones entrantes (TCP, USB AOA, etc.),
//! responde al auto-descubrimiento UDP en la red local y sincroniza el estado en vivo hacia
//! el lector virtual CCID y las aplicaciones de escritorio vía IPC Named Pipe.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, Notify};
use tracing::{debug, error, info, warn};

use crate::emulator::CcidHandler;
use crate::ipc::events::IpcEvent;
use crate::network::pairing_manager::{parse_hello_paused, HelloAuthOutcome, PairingManager};
use crate::network::tls_cert;
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
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    tcp_enabled: Arc<AtomicBool>,
    wfd_accept_allowed: Arc<AtomicBool>,
    wfd_host_ip: Arc<StdMutex<Option<String>>>,
    usb_auto_connect: AtomicBool,
    usb_active: AtomicBool,
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
        let tls_acceptor = match tls_cert::load_or_create_default() {
            Ok(id) => {
                pairing.set_tcp_cert_sha256(Some(id.cert_sha256_hex));
                Some(id.acceptor)
            }
            Err(e) => {
                warn!("No se pudo inicializar certificado TLS local: {}", e);
                None
            }
        };
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
            tls_acceptor,
            tcp_enabled: Arc::new(AtomicBool::new(true)),
            wfd_accept_allowed: Arc::new(AtomicBool::new(false)),
            wfd_host_ip: Arc::new(StdMutex::new(None)),
            usb_auto_connect: AtomicBool::new(true),
            usb_active: AtomicBool::new(false),
        }
    }

    pub fn is_tcp_enabled(&self) -> bool {
        self.tcp_enabled.load(Ordering::Relaxed)
    }

    pub fn is_usb_connected(&self) -> bool {
        self.usb_active.load(Ordering::Relaxed)
    }

    pub fn is_usb_auto_connect(&self) -> bool {
        self.usb_auto_connect.load(Ordering::Relaxed)
    }

    pub async fn set_usb_auto_connect(&self, enabled: bool) {
        self.usb_auto_connect.store(enabled, Ordering::Relaxed);
        self.send_usb_priority_hint(enabled).await;
    }

    pub async fn send_usb_priority_hint(&self, auto_usb_priority: bool) {
        let client_tx = {
            let guard = self.active_client_tx.lock().await;
            guard.clone()
        };
        if let Some(tx) = client_tx {
            let seq = self.sequence_counter.fetch_add(1, Ordering::SeqCst);
            let payload = serde_json::json!({ "auto_usb_priority": auto_usb_priority }).to_string();
            let frame = NfcBridgeFrame::new(MessageType::UsbPriorityHint, seq, payload.into_bytes());
            let _ = tx.send(frame).await;
        }
    }

    pub fn set_wfd_accept_allowed(&self, allowed: bool, wfd_ip: Option<String>) {
        self.wfd_accept_allowed.store(allowed, Ordering::Relaxed);
        if let Ok(mut guard) = self.wfd_host_ip.lock() {
            *guard = wfd_ip;
        }
    }

    pub async fn set_tcp_enabled(&self, enabled: bool) {
        self.tcp_enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.disconnect_if_tcp_lan().await;
        }
    }

    pub async fn disconnect_if_endpoint_starts_with(&self, prefix: &str) {
        let matches = {
            let st = self.runtime_status.lock().await;
            st.connected
                && st
                    .endpoint
                    .as_deref()
                    .map(|ep| ep.starts_with(prefix))
                    .unwrap_or(false)
        };
        if matches {
            self.disconnect_active().await;
        }
    }

    pub async fn disconnect_if_tcp_lan(&self) {
        let matches = {
            let st = self.runtime_status.lock().await;
            st.connected
                && st
                    .endpoint
                    .as_deref()
                    .map(|ep| {
                        !ep.starts_with("USB-AOA")
                            && !ep.starts_with("Bluetooth")
                            && ep != "Cloud Relay"
                            && !is_wfd_endpoint_str(ep, &self.wfd_host_ip)
                    })
                    .unwrap_or(false)
        };
        if matches {
            self.disconnect_active().await;
        }
    }

    pub async fn disconnect_if_wfd(&self) {
        let matches = {
            let st = self.runtime_status.lock().await;
            st.connected
                && st
                    .endpoint
                    .as_deref()
                    .map(|ep| is_wfd_endpoint_str(ep, &self.wfd_host_ip))
                    .unwrap_or(false)
        };
        if matches {
            self.disconnect_active().await;
        }
    }

    fn should_accept_tcp_socket(&self, socket: &TcpStream, peer_addr: SocketAddr) -> bool {
        if self.tcp_enabled.load(Ordering::Relaxed) {
            return true;
        }
        if !self.wfd_accept_allowed.load(Ordering::Relaxed) {
            return false;
        }
        let peer_ip = peer_addr.ip().to_string();
        if peer_ip.starts_with("192.168.137.") || peer_ip.starts_with("192.168.49.") {
            return true;
        }
        if let Ok(local) = socket.local_addr() {
            let local_ip = local.ip().to_string();
            if let Ok(guard) = self.wfd_host_ip.lock() {
                if guard.as_deref() == Some(local_ip.as_str()) {
                    return true;
                }
            }
        }
        false
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

    async fn apply_pause_state(&self, paused: bool) {
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

    pub async fn set_paused(&self, paused: bool) {
        self.apply_pause_state(paused).await;
        let client_tx = {
            let guard = self.active_client_tx.lock().await;
            guard.clone()
        };
        if let Some(tx) = client_tx {
            let seq = self.sequence_counter.fetch_add(1, Ordering::SeqCst);
            let payload = serde_json::json!({ "paused": paused }).to_string();
            let frame = NfcBridgeFrame::new(MessageType::DeviceState, seq, payload.into_bytes());
            let _ = tx.send(frame).await;
        }
    }

    pub async fn disconnect_active(&self) {
        let client_tx = {
            let guard = self.active_client_tx.lock().await;
            guard.clone()
        };
        if let Some(tx) = client_tx {
            let seq = self.sequence_counter.fetch_add(1, Ordering::SeqCst);
            let payload = br#"{"reason":"manual_disconnect"}"#.to_vec();
            let frame = NfcBridgeFrame::new(MessageType::Disconnect, seq, payload);
            let _ = tx.send(frame).await;
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        self.disconnect_notify.notify_waiters();
    }

    /// Inicia el listener TCP y el responder UDP de auto-descubrimiento en el puerto 45362.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", DEFAULT_TCP_PORT);
        let listener = TcpListener::bind(&addr).await?;
        let cert_fp = self.pairing.get_tcp_cert_sha256();
        info!(
            "Driver TCP{} escuchando en {} (Esperando teléfono Android)",
            if self.tls_acceptor.is_some() { "+TLS" } else { "" },
            addr
        );

        // Iniciar responder UDP en el mismo puerto 45362 para auto-descubrimiento en red Wi-Fi / LAN
        let pc_name = self.pairing.pc_name().to_string();
        let tcp_enabled_udp = Arc::clone(&self.tcp_enabled);
        tokio::spawn(async move {
            if let Err(e) = Self::run_udp_discovery_responder(
                DEFAULT_TCP_PORT,
                pc_name,
                cert_fp,
                tcp_enabled_udp,
            )
            .await
            {
                warn!("UDP discovery responder en driver finalizó con error: {}", e);
            }
        });

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    if !self.should_accept_tcp_socket(&socket, peer_addr) {
                        debug!(
                            "Conexión TCP rechazada desde {} (Red Local TCP desactivada)",
                            peer_addr
                        );
                        drop(socket);
                        continue;
                    }
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

    async fn run_udp_discovery_responder(
        port: u16,
        pc_name: String,
        cert_sha256: Option<String>,
        tcp_enabled: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let socket = UdpSocket::bind(addr).await?;
        info!("Driver UDP auto-descubrimiento activo en {}", addr);

        let mut buf = [0u8; 1024];
        let mut last_logged: HashMap<String, Instant> = HashMap::new();

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    if !tcp_enabled.load(Ordering::Relaxed) {
                        continue;
                    }
                    let msg = String::from_utf8_lossy(&buf[..len]);
                    if msg.contains("NFC_BRIDGE_DISCOVERY") {
                        let pc_id = format!(
                            "{:04X}{:04X}",
                            compute_crc16(pc_name.as_bytes()),
                            compute_crc16(&port.to_le_bytes())
                        );
                        let mut resp_json = serde_json::json!({
                            "id": pc_id,
                            "name": pc_name,
                            "port": port,
                            "model": "WINDOWS",
                            "status": "ready"
                        });
                        if let (Some(ref c), Some(obj)) = (&cert_sha256, resp_json.as_object_mut()) {
                            obj.insert("cert".to_string(), serde_json::Value::String(c.clone()));
                        }
                        let response = resp_json.to_string();
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

        if let Some(ref acceptor) = self.tls_acceptor {
            match tokio::time::timeout(Duration::from_secs(6), acceptor.accept(socket)).await {
                Ok(Ok(tls_stream)) => {
                    let (reader, writer) = tokio::io::split(tls_stream);
                    self.handle_stream(reader, writer, peer_endpoint).await;
                }
                Ok(Err(e)) => {
                    warn!("Handshake TLS rechazado desde {}: {}", peer_endpoint, e);
                }
                Err(_) => {
                    warn!("Timeout en handshake TLS desde {}", peer_endpoint);
                }
            }
            return;
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
        let session_cancel = Arc::new(Notify::new());
        let require_token = peer_endpoint == "Cloud Relay";
        let mut authenticated = false;

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
                        if st.connected {
                            st.latency_ms = latency;
                        }
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
                _ = self.disconnect_notify.notified(), if authenticated => {
                    info!("Desconexión solicitada vía IPC para {}", peer_endpoint);
                    break;
                }
                _ = session_cancel.notified() => {
                    info!("Sesión cerrada tras rechazo o fin de enlace ({})", peer_endpoint);
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
                                let just_authed = self
                                    .process_frame(
                                        frame,
                                        &out_tx,
                                        authenticated,
                                        require_token,
                                        &peer_endpoint,
                                        &session_cancel,
                                    )
                                    .await;
                                if just_authed && !authenticated {
                                    authenticated = true;
                                    {
                                        let mut active = self.active_client_tx.lock().await;
                                        *active = Some(out_tx.clone());
                                    }
                                }
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

        if authenticated {
            self.is_paused.store(false, Ordering::Relaxed);
            self.usb_active.store(false, Ordering::Relaxed);
            {
                let mut active = self.active_client_tx.lock().await;
                *active = None;
            }
            {
                let mut st = self.runtime_status.lock().await;
                st.connected = false;
                st.device_name = None;
                st.endpoint = None;
                st.paused = false;
                st.tag_present = false;
                st.tag_uid = None;
            }
            {
                let mut handler = self.ccid_handler.lock().await;
                handler.set_tag(None);
            }

            let _ = self.event_tx.send(IpcEvent::DeviceDisconnected);
            let status_evt = self.get_status_event().await;
            let _ = self.event_tx.send(status_evt);
        }
    }

    async fn process_frame(
        &self,
        frame: NfcBridgeFrame,
        out_tx: &mpsc::Sender<NfcBridgeFrame>,
        authenticated: bool,
        require_token: bool,
        peer_endpoint: &str,
        session_cancel: &Arc<Notify>,
    ) -> bool {
        match frame.message_type {
            MessageType::HelloSyn => {
                let pc_name = self.pairing.pc_name().to_string();
                let phone_paused = parse_hello_paused(&frame.payload);
                let outcome = self
                    .pairing
                    .validate_hello_payload_for_transport(&frame.payload, require_token);
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
                        let cancel = Arc::clone(session_cancel);
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(80)).await;
                            cancel.notify_waiters();
                        });
                        false
                    }
                    HelloAuthOutcome::Paired {
                        device_name,
                        new_device_token,
                    } => {
                        info!("Handshake HELLO_SYN emparejado con QR/Link (nuevo device_token emitido)");
                        self.accept_hello_session(
                            device_name,
                            Some(new_device_token),
                            phone_paused,
                            &pc_name,
                            peer_endpoint,
                            frame.sequence_id,
                            out_tx,
                        )
                        .await;
                        true
                    }
                    HelloAuthOutcome::Trusted { device_name }
                    | HelloAuthOutcome::LegacyAllowed { device_name } => {
                        info!("Handshake HELLO_SYN recibido del móvil. Respondiendo HELLO_ACK...");
                        self.accept_hello_session(
                            device_name,
                            None,
                            phone_paused,
                            &pc_name,
                            peer_endpoint,
                            frame.sequence_id,
                            out_tx,
                        )
                        .await;
                        true
                    }
                }
            }
            MessageType::TagAttached => {
                if !authenticated || self.is_paused.load(Ordering::Relaxed) {
                    return false;
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
                false
            }
            MessageType::TagDetached => {
                if !authenticated {
                    return false;
                }
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
                false
            }
            MessageType::TransceiveResp => {
                if !authenticated {
                    return false;
                }
                debug!("TRANSCEIVE_RESP recibido del móvil para seq={}", frame.sequence_id);
                let mut pending = self.pending_transceive.lock().await;
                if let Some((expected_seq, _)) = &*pending {
                    if *expected_seq == frame.sequence_id {
                        if let Some((_, sender)) = pending.take() {
                            let _ = sender.send(frame.payload);
                        }
                    }
                }
                false
            }
            MessageType::Heartbeat => {
                let ack = NfcBridgeFrame::new(MessageType::HeartbeatAck, frame.sequence_id, vec![]);
                let _ = out_tx.send(ack).await;
                false
            }
            MessageType::HeartbeatAck => false,
            MessageType::DeviceState => {
                if !authenticated {
                    return false;
                }
                if let Some(remote_paused) = parse_device_state_paused(&frame.payload) {
                    info!("Estado de pausa recibido desde el móvil: paused={}", remote_paused);
                    self.apply_pause_state(remote_paused).await;
                }
                false
            }
            MessageType::Disconnect => {
                if authenticated {
                    info!("Móvil solicitó desconexión limpia ({})", peer_endpoint);
                    session_cancel.notify_waiters();
                }
                false
            }
            _ => {
                info!("Trama recibida: tipo={:?}, seq={}", frame.message_type, frame.sequence_id);
                false
            }
        }
    }

    async fn accept_hello_session(
        &self,
        device_name: Option<String>,
        new_device_token: Option<String>,
        phone_paused: bool,
        pc_name: &str,
        peer_endpoint: &str,
        sequence_id: u16,
        out_tx: &mpsc::Sender<NfcBridgeFrame>,
    ) {
        let name = device_name.unwrap_or_else(|| "Android Phone".to_string());
        self.usb_active
            .store(peer_endpoint.starts_with("USB-AOA"), Ordering::Relaxed);
        {
            let mut st = self.runtime_status.lock().await;
            st.connected = true;
            st.device_name = Some(name.clone());
            st.endpoint = Some(peer_endpoint.to_string());
        }
        self.apply_pause_state(phone_paused).await;
        let _ = self.event_tx.send(IpcEvent::DeviceConnected {
            device_name: name,
            endpoint: peer_endpoint.to_string(),
        });
        let mut ack_obj = serde_json::json!({
            "pc_name": pc_name,
            "status": "ready",
            "paused": phone_paused
        });
        if let (Some(tok), Some(map)) = (new_device_token, ack_obj.as_object_mut()) {
            map.insert("device_token".to_string(), serde_json::Value::String(tok));
        }
        let ack_frame = NfcBridgeFrame::new(
            MessageType::HelloAck,
            sequence_id,
            ack_obj.to_string().into_bytes(),
        );
        let _ = out_tx.send(ack_frame).await;

        let hint_seq = self.sequence_counter.fetch_add(1, Ordering::SeqCst);
        let hint_payload = serde_json::json!({
            "auto_usb_priority": self.usb_auto_connect.load(Ordering::Relaxed)
        })
        .to_string();
        let hint_frame = NfcBridgeFrame::new(
            MessageType::UsbPriorityHint,
            hint_seq,
            hint_payload.into_bytes(),
        );
        let _ = out_tx.send(hint_frame).await;
    }
}

fn is_wfd_endpoint_str(endpoint: &str, wfd_host_ip: &StdMutex<Option<String>>) -> bool {
    if endpoint.starts_with("192.168.137.") || endpoint.starts_with("192.168.49.") {
        return true;
    }
    if let (Some(ip), Ok(guard)) = (endpoint.split(':').next(), wfd_host_ip.lock()) {
        if let Some(host_ip) = guard.as_deref() {
            if let (Some(prefix), Some(peer_prefix)) = (
                host_ip.rsplit_once('.').map(|(p, _)| p),
                ip.rsplit_once('.').map(|(p, _)| p),
            ) {
                return prefix == peer_prefix;
            }
        }
    }
    false
}

fn parse_device_state_paused(payload: &[u8]) -> Option<bool> {
    if payload.len() == 1 && (payload[0] == 0 || payload[0] == 1) {
        return Some(payload[0] == 1);
    }
    #[derive(serde::Deserialize)]
    struct DeviceStateJson {
        paused: Option<bool>,
    }
    serde_json::from_slice::<DeviceStateJson>(payload)
        .ok()
        .and_then(|s| s.paused)
}
