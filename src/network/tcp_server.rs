//! Servidor TCP de ultra baja latencia para comunicación con NFC Bridge Android.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tracing::{debug, error, info, warn};

use crate::emulator::CcidHandler;
use crate::ipc::events::IpcEvent;
use crate::protocol::codec::{FrameCodec, StreamFrameDecoder};
use crate::protocol::constants::DEFAULT_TCP_PORT;
use crate::protocol::frame::NfcBridgeFrame;
use crate::protocol::message_type::MessageType;

pub struct BridgeTcpServer {
    event_tx: broadcast::Sender<IpcEvent>,
    ccid_handler: Arc<Mutex<CcidHandler>>,
    sequence_counter: AtomicU16,
    active_client_tx: Arc<Mutex<Option<mpsc::Sender<NfcBridgeFrame>>>>,
    pending_transceive: Arc<Mutex<Option<(u16, oneshot::Sender<Vec<u8>>)>>>,
}

impl BridgeTcpServer {
    pub fn new(event_tx: broadcast::Sender<IpcEvent>, ccid_handler: Arc<Mutex<CcidHandler>>) -> Self {
        Self {
            event_tx,
            ccid_handler,
            sequence_counter: AtomicU16::new(1),
            active_client_tx: Arc::new(Mutex::new(None)),
            pending_transceive: Arc::new(Mutex::new(None)),
        }
    }

    /// Inicia el listener TCP en el puerto 45362.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", DEFAULT_TCP_PORT);
        let listener = TcpListener::bind(&addr).await?;
        info!("Servidor TCP escuchando en {} (Esperando teléfono Android)", addr);

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    info!("Dispositivo Android conectado desde: {}", peer_addr);
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

    /// Envía un comando transceive crudo / APDU al teléfono Android conectado y espera la respuesta.
    pub async fn transceive(&self, payload: Vec<u8>) -> Option<Vec<u8>> {
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

        // Timeout de 2 segundos para la respuesta del transceive NFC
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
        // Desactivar algoritmo de Nagle para latencia sub-milisegundo (<1ms)
        if let Err(e) = socket.set_nodelay(true) {
            warn!("No se pudo configurar TCP_NODELAY: {}", e);
        }

        let (mut reader, mut writer) = socket.into_split();
        let (out_tx, mut out_rx) = mpsc::channel::<NfcBridgeFrame>(128);

        {
            let mut active = self.active_client_tx.lock().await;
            *active = Some(out_tx.clone());
        }

        let _ = self.event_tx.send(IpcEvent::DeviceConnected {
            device_name: "Android Phone".to_string(),
            endpoint: peer_endpoint.clone(),
        });

        // Bucle de escritura asíncrono
        let write_task = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                let encoded = FrameCodec::encode(&frame);
                if let Err(e) = writer.write_all(&encoded).await {
                    debug!("Error escribiendo en socket hacia móvil: {}", e);
                    break;
                }
            }
        });

        // Tarea periódica de Heartbeat para monitorear latencia RTT (<5ms)
        let hb_tx = out_tx.clone();
        let hb_event_tx = self.event_tx.clone();
        let hb_active = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let hb_flag = Arc::clone(&hb_active);

        let heartbeat_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            while hb_flag.load(Ordering::Relaxed) {
                interval.tick().await;
                let start_time = Instant::now();
                let ping_frame = NfcBridgeFrame::new(MessageType::Heartbeat, 100, vec![]);

                if hb_tx.send(ping_frame).await.is_ok() {
                    let rtt_ms = start_time.elapsed().as_millis() as u64;
                    let _ = hb_event_tx.send(IpcEvent::LatencyUpdated {
                        latency_ms: rtt_ms.max(1),
                    });
                } else {
                    break;
                }
            }
        });

        let mut decoder = StreamFrameDecoder::new();
        let mut buffer = [0u8; 4096];

        // Bucle de lectura de paquetes entrantes
        loop {
            match reader.read(&mut buffer).await {
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
                    warn!("Error de lectura en socket TCP: {}", e);
                    break;
                }
            }
        }

        // Limpieza de estado al desconectar el móvil
        hb_active.store(false, Ordering::Relaxed);
        heartbeat_task.abort();
        write_task.abort();

        {
            let mut active = self.active_client_tx.lock().await;
            *active = None;
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
                info!("Handshake HELLO_SYN recibido del móvil. Respondiendo HELLO_ACK...");
                let ack_frame = NfcBridgeFrame::new(
                    MessageType::HelloAck,
                    frame.sequence_id,
                    vec![0x00], // Status OK
                );
                let _ = out_tx.send(ack_frame).await;
            }
            MessageType::TagAttached => {
                if let Some(tag) = FrameCodec::decode_tag_attached(&frame.payload) {
                    let uid_hex = tag.uid_hex();
                    let is_ntag215 = tag.is_mifare_ultralight();
                    info!("ETIQUETA NFC DETECTADA: UID={} (NTAG215={})", uid_hex, is_ntag215);

                    // Actualizar el manejador CCID para que emuladores PC detecten la tarjeta de inmediato
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
                // Móvil envía heartbeat, responder con ACK inmediato
                let ack = NfcBridgeFrame::new(MessageType::HeartbeatAck, frame.sequence_id, vec![]);
                let _ = out_tx.send(ack).await;
            }
            MessageType::HeartbeatAck => {
                // RTT procesado
            }
            _ => {
                info!("Trama recibida: tipo={:?}, seq={}", frame.message_type, frame.sequence_id);
            }
        }
    }
}
