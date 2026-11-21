//! Servidor TCP de ultra baja latencia para comunicación con NFC Bridge Android.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

use crate::ipc::events::IpcEvent;
use crate::protocol::codec::{FrameCodec, StreamFrameDecoder};
use crate::protocol::constants::DEFAULT_TCP_PORT;
use crate::protocol::frame::NfcBridgeFrame;
use crate::protocol::message_type::MessageType;

pub struct BridgeTcpServer {
    event_tx: broadcast::Sender<IpcEvent>,
    #[allow(dead_code)]
    sequence_counter: AtomicU16,
}

impl BridgeTcpServer {
    pub fn new(event_tx: broadcast::Sender<IpcEvent>) -> Self {
        Self {
            event_tx,
            sequence_counter: AtomicU16::new(1),
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

    async fn handle_client(&self, socket: TcpStream, peer_endpoint: String) {
        // Desactivar algoritmo de Nagle para latencia sub-milisegundo
        if let Err(e) = socket.set_nodelay(true) {
            warn!("No se pudo configurar TCP_NODELAY: {}", e);
        }

        let (mut reader, writer) = socket.into_split();
        let writer = Arc::new(Mutex::new(writer));

        let _ = self.event_tx.send(IpcEvent::DeviceConnected {
            device_name: "Android Phone".to_string(),
            endpoint: peer_endpoint.clone(),
        });

        let mut decoder = StreamFrameDecoder::new();
        let mut buffer = [0u8; 4096];

        // Tarea periódica de Heartbeat para monitorear latencia RTT
        let hb_writer = Arc::clone(&writer);
        let hb_event_tx = self.event_tx.clone();
        let hb_active = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let hb_flag = Arc::clone(&hb_active);

        let heartbeat_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
            while hb_flag.load(Ordering::Relaxed) {
                interval.tick().await;
                let start_time = Instant::now();
                let ping_frame = NfcBridgeFrame::new(MessageType::Heartbeat, 100, vec![]);
                let bytes = FrameCodec::encode(&ping_frame);

                let mut w = hb_writer.lock().await;
                if w.write_all(&bytes).await.is_ok() {
                    let rtt_ms = start_time.elapsed().as_millis() as u64;
                    let _ = hb_event_tx.send(IpcEvent::LatencyUpdated {
                        latency_ms: rtt_ms.max(1),
                    });
                } else {
                    break;
                }
            }
        });

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
                        self.process_frame(frame, &writer).await;
                    }
                }
                Err(e) => {
                    warn!("Error de lectura en socket TCP: {}", e);
                    break;
                }
            }
        }

        hb_active.store(false, Ordering::Relaxed);
        heartbeat_task.abort();
        let _ = self.event_tx.send(IpcEvent::DeviceDisconnected);
    }

    async fn process_frame(
        &self,
        frame: NfcBridgeFrame,
        writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    ) {
        match frame.message_type {
            MessageType::HelloSyn => {
                info!("Handshake HELLO_SYN recibido del móvil. Respondiendo HELLO_ACK...");
                let ack_frame = NfcBridgeFrame::new(
                    MessageType::HelloAck,
                    frame.sequence_id,
                    vec![0x00], // Status OK
                );
                let bytes = FrameCodec::encode(&ack_frame);
                let mut w = writer.lock().await;
                let _ = w.write_all(&bytes).await;
            }
            MessageType::TagAttached => {
                if let Some(tag) = FrameCodec::decode_tag_attached(&frame.payload) {
                    let uid_hex = tag.uid_hex();
                    let is_ntag215 = tag.is_mifare_ultralight();
                    info!("ETIQUETA NFC DETECTADA: UID={} (NTAG215={})", uid_hex, is_ntag215);

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
                let _ = self.event_tx.send(IpcEvent::TagDetached);
            }
            MessageType::Heartbeat => {
                // Móvil envía heartbeat, responder con ACK inmediato
                let ack = NfcBridgeFrame::new(MessageType::HeartbeatAck, frame.sequence_id, vec![]);
                let bytes = FrameCodec::encode(&ack);
                let mut w = writer.lock().await;
                let _ = w.write_all(&bytes).await;
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
