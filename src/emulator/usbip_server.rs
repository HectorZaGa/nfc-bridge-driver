//! Servidor USB/IP para exportar el lector virtual ACS ACR122U CCID a Windows / Linux.
//!
//! Permite que controladores USB/IP de Windows (como usbip-win2 o usbip CLI) reconozcan
//! el emulador como hardware USB nativo (VID: 0x072F, PID: 0x2200), habilitando a
//! Ryujinx, Yuzu forks, Cemu y el subsistema WinSCard acceder a las tarjetas NFC
//! leídas por el dispositivo Android.

use std::sync::Arc;
use std::collections::VecDeque;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, warn, error, debug};

use super::acr122u_descriptors::*;
use super::ccid_handler::CcidHandler;

pub const USBIP_DEFAULT_PORT: u16 = 3240;
pub const USBIP_VERSION: u16 = 0x0111;

// Códigos de operación de gestión (Big-Endian)
pub const OP_REQ_DEVLIST: u16 = 0x8005;
pub const OP_REP_DEVLIST: u16 = 0x0005;
pub const OP_REQ_IMPORT: u16 = 0x8003;
pub const OP_REP_IMPORT: u16 = 0x0003;

// Comandos URB durante la conexión adjunta (Big-Endian)
pub const USBIP_CMD_SUBMIT: u32 = 0x00000001;
pub const USBIP_CMD_UNLINK: u32 = 0x00000002;
pub const USBIP_RET_SUBMIT: u32 = 0x00000003;
pub const USBIP_RET_UNLINK: u32 = 0x00000004;

pub const USBIP_DIR_OUT: u32 = 0;
pub const USBIP_DIR_IN: u32 = 1;

/// Identificadores de bus y ruta para el emulador virtual
pub const VIRTUAL_BUSID: &str = "1-1";
pub const VIRTUAL_PATH: &str = "/sys/devices/virtual/nfc_bridge/usb1/1-1";

pub struct UsbIpServer {
    bind_port: u16,
    ccid_handler: Arc<Mutex<CcidHandler>>,
}

impl UsbIpServer {
    pub fn new(bind_port: u16, ccid_handler: Arc<Mutex<CcidHandler>>) -> Self {
        Self {
            bind_port,
            ccid_handler,
        }
    }

    /// Inicia el bucle de escucha del servidor USB/IP en 127.0.0.1:port (solo loopback local)
    pub async fn start<F, Fut>(&self, transceive_callback: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        let addr = format!("127.0.0.1:{}", self.bind_port);
        let listener = TcpListener::bind(&addr).await?;
        info!("USB/IP Server escuchando en {} (ACR122U USB CCID Emulator)", addr);

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    info!("Nueva conexión USB/IP desde {}", peer_addr);
                    let handler_clone = Arc::clone(&self.ccid_handler);
                    let transceive_fn = transceive_callback.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(socket, handler_clone, transceive_fn).await {
                            debug!("Conexión USB/IP con {} cerrada: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error aceptando conexión USB/IP: {}", e);
                }
            }
        }
    }

    /// Maneja el ciclo de vida completo de un cliente USB/IP (Fase OP -> Fase URB)
    async fn handle_client<F, Fut>(
        mut socket: TcpStream,
        ccid_handler: Arc<Mutex<CcidHandler>>,
        transceive_fn: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        socket.set_nodelay(true)?;

        // 1. Fase de Handshake y Negociación OP
        loop {
            let mut op_header = [0u8; 8];
            if let Err(_) = socket.read_exact(&mut op_header).await {
                return Ok(()); // Desconexión limpia
            }

            let version = u16::from_be_bytes([op_header[0], op_header[1]]);
            let command = u16::from_be_bytes([op_header[2], op_header[3]]);
            let _status = u32::from_be_bytes([op_header[4], op_header[5], op_header[6], op_header[7]]);

            debug!("USB/IP Recibido OP command=0x{:04X}, version=0x{:04X}", command, version);

            match command {
                OP_REQ_DEVLIST => {
                    debug!("Enviando respuesta OP_REP_DEVLIST...");
                    let rep = Self::build_rep_devlist();
                    socket.write_all(&rep).await?;
                    socket.flush().await?;
                }
                OP_REQ_IMPORT => {
                    // Leer los 32 bytes de busid solicitado
                    let mut busid_buf = [0u8; 32];
                    socket.read_exact(&mut busid_buf).await?;
                    let req_busid = String::from_utf8_lossy(&busid_buf);
                    let req_busid = req_busid.trim_matches(char::from(0));

                    debug!("USB/IP Solicitud IMPORT para busid: '{}'", req_busid);

                    if req_busid == VIRTUAL_BUSID {
                        let rep = Self::build_rep_import(0); // Status 0 = Exitoso
                        socket.write_all(&rep).await?;
                        socket.flush().await?;
                        info!("Dispositivo ACR122U USB adjuntado exitosamente a cliente USB/IP. Entrando en modo URB.");
                        break; // Salir de la fase OP y pasar a la fase URB
                    } else {
                        warn!("Busid desconocido: '{}'", req_busid);
                        let rep = Self::build_rep_import(1); // Error
                        socket.write_all(&rep).await?;
                        socket.flush().await?;
                        return Ok(());
                    }
                }
                _ => {
                    warn!("Comando OP desconocido o no soportado: 0x{:04X}", command);
                    return Ok(());
                }
            }
        }

        // 2. Fase de Tráfico URB (USBIP_CMD_SUBMIT / USBIP_CMD_UNLINK)
        Self::handle_urb_loop(socket, ccid_handler, transceive_fn).await
    }

    /// Construye el paquete de respuesta OP_REP_DEVLIST (320 bytes totales)
    pub fn build_rep_devlist() -> Vec<u8> {
        let mut buf = Vec::with_capacity(320);

        // Header (8 bytes)
        buf.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        buf.extend_from_slice(&OP_REP_DEVLIST.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // Status = 0

        // ndev = 1 (4 bytes)
        buf.extend_from_slice(&1u32.to_be_bytes());

        // Device info (308 bytes)
        Self::append_device_info(&mut buf);

        // Interface info para cada interfaz (1 interfaz = 4 bytes)
        buf.push(0x0B); // bInterfaceClass = SmartCard (0x0B)
        buf.push(0x00); // bInterfaceSubClass = 0
        buf.push(0x00); // bInterfaceProtocol = 0
        buf.push(0x00); // padding

        buf
    }

    /// Construye el paquete de respuesta OP_REP_IMPORT (316 bytes totales si status == 0)
    pub fn build_rep_import(status: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(316);

        // Header (8 bytes)
        buf.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        buf.extend_from_slice(&OP_REP_IMPORT.to_be_bytes());
        buf.extend_from_slice(&status.to_be_bytes());

        if status == 0 {
            // Device info (308 bytes)
            Self::append_device_info(&mut buf);
        }

        buf
    }

    fn append_device_info(buf: &mut Vec<u8>) {
        // path (256 bytes)
        let mut path_bytes = [0u8; 256];
        let p_slice = VIRTUAL_PATH.as_bytes();
        path_bytes[..p_slice.len()].copy_from_slice(p_slice);
        buf.extend_from_slice(&path_bytes);

        // busid (32 bytes)
        let mut busid_bytes = [0u8; 32];
        let b_slice = VIRTUAL_BUSID.as_bytes();
        busid_bytes[..b_slice.len()].copy_from_slice(b_slice);
        buf.extend_from_slice(&busid_bytes);

        buf.extend_from_slice(&1u32.to_be_bytes());          // busnum = 1
        buf.extend_from_slice(&2u32.to_be_bytes());          // devnum = 2
        buf.extend_from_slice(&2u32.to_be_bytes());          // speed = 2 (USB_SPEED_FULL)
        buf.extend_from_slice(&VENDOR_ID_ACS.to_be_bytes()); // idVendor = 0x072F
        buf.extend_from_slice(&PRODUCT_ID_ACR122U.to_be_bytes()); // idProduct = 0x2200
        buf.extend_from_slice(&DEVICE_RELEASE_NUMBER.to_be_bytes()); // bcdDevice = 0x0100
        buf.push(0x00); // bDeviceClass = 0
        buf.push(0x00); // bDeviceSubClass = 0
        buf.push(0x00); // bDeviceProtocol = 0
        buf.push(0x01); // bConfigurationValue = 1
        buf.push(0x01); // bNumConfigurations = 1
        buf.push(0x01); // bNumInterfaces = 1
    }

    /// Ciclo de despacho y procesamiento de URBs
    async fn handle_urb_loop<F, Fut>(
        mut socket: TcpStream,
        ccid_handler: Arc<Mutex<CcidHandler>>,
        transceive_fn: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        // Cola de respuestas CCID pendientes listas para ser leídas por Bulk-IN (EP 2)
        let mut pending_bulk_in_responses: VecDeque<Vec<u8>> = VecDeque::new();
        let mut current_config = 1u8;

        loop {
            let mut header_buf = [0u8; 48];
            if let Err(_) = socket.read_exact(&mut header_buf).await {
                info!("Cliente USB/IP desconectado.");
                return Ok(());
            }

            let command = u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
            let seqnum = u32::from_be_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);
            let devid = u32::from_be_bytes([header_buf[8], header_buf[9], header_buf[10], header_buf[11]]);
            let direction = u32::from_be_bytes([header_buf[12], header_buf[13], header_buf[14], header_buf[15]]);
            let ep = u32::from_be_bytes([header_buf[16], header_buf[17], header_buf[18], header_buf[19]]);
            let transfer_flags = u32::from_be_bytes([header_buf[20], header_buf[21], header_buf[22], header_buf[23]]);
            let transfer_buffer_length = u32::from_be_bytes([header_buf[24], header_buf[25], header_buf[26], header_buf[27]]);
            let _start_frame = u32::from_be_bytes([header_buf[28], header_buf[29], header_buf[30], header_buf[31]]);
            let _number_of_packets = u32::from_be_bytes([header_buf[32], header_buf[33], header_buf[34], header_buf[35]]);
            let _interval = u32::from_be_bytes([header_buf[36], header_buf[37], header_buf[38], header_buf[39]]);
            let setup = [
                header_buf[40], header_buf[41], header_buf[42], header_buf[43],
                header_buf[44], header_buf[45], header_buf[46], header_buf[47],
            ];

            match command {
                USBIP_CMD_SUBMIT => {
                    let mut out_data = Vec::new();
                    if direction == USBIP_DIR_OUT && transfer_buffer_length > 0 {
                        out_data.resize(transfer_buffer_length as usize, 0);
                        socket.read_exact(&mut out_data).await?;
                    }

                    // Procesar la solicitud según el Endpoint
                    let (status, in_data) = match ep {
                        0 => {
                            // Endpoint 0: Control Transfers
                            Self::handle_control_transfer(
                                &setup,
                                direction,
                                transfer_buffer_length,
                                &out_data,
                                &mut current_config,
                            )
                        }
                        1 => {
                            // Endpoint 1: Bulk-OUT (Comandos CCID de la PC al Lector)
                            debug!("URB Bulk-OUT (EP 1): {} bytes recibidos", out_data.len());
                            let mut handler = ccid_handler.lock().await;
                            let transceive_cb = transceive_fn.clone();
                            let resp = handler.process_ccid_command(&out_data, move |req| transceive_cb(req)).await;

                            if !resp.is_empty() {
                                pending_bulk_in_responses.push_back(resp);
                            }

                            // Confirmar recepción OUT
                            (0, Vec::new())
                        }
                        2 => {
                            // Endpoint 2: Bulk-IN (Respuestas CCID del Lector a la PC)
                            if let Some(resp) = pending_bulk_in_responses.pop_front() {
                                debug!("URB Bulk-IN (EP 2): Enviando respuesta CCID de {} bytes", resp.len());
                                (0, resp)
                            } else {
                                // No hay respuesta pendiente inmediata: devolver buffer vacío
                                (0, Vec::new())
                            }
                        }
                        3 => {
                            // Endpoint 3: Interrupt-IN (Notificación de estado de ranura/tarjeta)
                            let handler = ccid_handler.lock().await;
                            let slot_status = if handler.is_tag_present() {
                                0x03 // Tarjeta presente y con cambio de estado
                            } else {
                                0x00 // No hay tarjeta
                            };
                            let notify = vec![0x50, slot_status];
                            (0, notify)
                        }
                        _ => {
                            warn!("URB en Endpoint desconocido: {}", ep);
                            (0, Vec::new())
                        }
                    };

                    // Enviar respuesta USBIP_RET_SUBMIT
                    let actual_length = in_data.len() as u32;
                    let ret_header = Self::build_ret_submit(
                        seqnum,
                        devid,
                        direction,
                        ep,
                        status,
                        actual_length,
                    );

                    socket.write_all(&ret_header).await?;
                    if direction == USBIP_DIR_IN && actual_length > 0 {
                        socket.write_all(&in_data).await?;
                    }
                    socket.flush().await?;
                }
                USBIP_CMD_UNLINK => {
                    let unlink_seqnum = transfer_flags; // En USB/IP CMD_UNLINK, el target suele ir aquí
                    debug!("URB UNLINK para seqnum: {}", unlink_seqnum);

                    let ret_unlink = Self::build_ret_unlink(seqnum, devid, direction, ep, 0);
                    socket.write_all(&ret_unlink).await?;
                    socket.flush().await?;
                }
                _ => {
                    warn!("Comando URB no reconocido: 0x{:08X}", command);
                }
            }
        }
    }

    /// Maneja transferencias de Control en el Endpoint 0 (USB Standard / Class Requests)
    fn handle_control_transfer(
        setup: &[u8; 8],
        _direction: u32,
        _requested_length: u32,
        _out_data: &[u8],
        current_config: &mut u8,
    ) -> (u32, Vec<u8>) {
        let bm_request_type = setup[0];
        let b_request = setup[1];
        let w_value = u16::from_le_bytes([setup[2], setup[3]]);
        let w_index = u16::from_le_bytes([setup[4], setup[5]]);
        let w_length = u16::from_le_bytes([setup[6], setup[7]]) as usize;

        let req_type = (bm_request_type >> 5) & 0x03; // 0 = Standard, 1 = Class, 2 = Vendor

        debug!(
            "EP0 Control: Type=0x{:02X}, Req=0x{:02X}, Val=0x{:04X}, Idx=0x{:04X}, Len={}",
            bm_request_type, b_request, w_value, w_index, w_length
        );

        match req_type {
            0 => {
                // USB Standard Requests
                match b_request {
                    0x06 => {
                        // GET_DESCRIPTOR
                        let desc_type = (w_value >> 8) as u8;
                        let desc_index = (w_value & 0xFF) as u8;

                        if let Some(desc) = get_descriptor(desc_type, desc_index) {
                            let send_len = desc.len().min(w_length);
                            (0, desc[..send_len].to_vec())
                        } else {
                            warn!("Descriptor no encontrado: type=0x{:02X}, index={}", desc_type, desc_index);
                            (0xFFFFFFE0, Vec::new()) // -EPIPE (Stall)
                        }
                    }
                    0x08 => {
                        // GET_CONFIGURATION
                        (0, vec![*current_config])
                    }
                    0x09 => {
                        // SET_CONFIGURATION
                        *current_config = (w_value & 0xFF) as u8;
                        info!("USB Dispositivo configurado con Config = {}", *current_config);
                        (0, Vec::new())
                    }
                    0x00 => {
                        // GET_STATUS
                        (0, vec![0x00, 0x00])
                    }
                    0x01 | 0x03 => {
                        // CLEAR_FEATURE / SET_FEATURE
                        (0, Vec::new())
                    }
                    0x0A => {
                        // GET_INTERFACE
                        (0, vec![0x00])
                    }
                    0x0B => {
                        // SET_INTERFACE
                        (0, Vec::new())
                    }
                    _ => {
                        debug!("Standard Request no manejada: 0x{:02X}", b_request);
                        (0, Vec::new())
                    }
                }
            }
            1 => {
                // CCID Class-Specific Requests en EP 0 (ABORT, GET_CLOCK_FREQUENCIES, etc.)
                debug!("CCID Class Request en EP0: bRequest=0x{:02X}", b_request);
                (0, Vec::new())
            }
            _ => {
                (0, Vec::new())
            }
        }
    }

    /// Construye la cabecera USBIP_RET_SUBMIT (48 bytes)
    fn build_ret_submit(
        seqnum: u32,
        devid: u32,
        direction: u32,
        ep: u32,
        status: u32,
        actual_length: u32,
    ) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0..4].copy_from_slice(&USBIP_RET_SUBMIT.to_be_bytes());
        buf[4..8].copy_from_slice(&seqnum.to_be_bytes());
        buf[8..12].copy_from_slice(&devid.to_be_bytes());
        buf[12..16].copy_from_slice(&direction.to_be_bytes());
        buf[16..20].copy_from_slice(&ep.to_be_bytes());
        buf[20..24].copy_from_slice(&status.to_be_bytes());
        buf[24..28].copy_from_slice(&actual_length.to_be_bytes());
        // start_frame (0), number_of_packets (0), error_count (0), setup (8 bytes) ya son 0
        buf
    }

    /// Construye la cabecera USBIP_RET_UNLINK (48 bytes)
    fn build_ret_unlink(
        seqnum: u32,
        devid: u32,
        direction: u32,
        ep: u32,
        status: u32,
    ) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0..4].copy_from_slice(&USBIP_RET_UNLINK.to_be_bytes());
        buf[4..8].copy_from_slice(&seqnum.to_be_bytes());
        buf[8..12].copy_from_slice(&devid.to_be_bytes());
        buf[12..16].copy_from_slice(&direction.to_be_bytes());
        buf[16..20].copy_from_slice(&ep.to_be_bytes());
        buf[20..24].copy_from_slice(&status.to_be_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_rep_devlist_structure() {
        let devlist = UsbIpServer::build_rep_devlist();
        assert_eq!(devlist.len(), 328); // 8 header + 4 ndev + 312 devinfo + 4 iface

        let version = u16::from_be_bytes([devlist[0], devlist[1]]);
        let op = u16::from_be_bytes([devlist[2], devlist[3]]);
        let status = u32::from_be_bytes([devlist[4], devlist[5], devlist[6], devlist[7]]);
        let ndev = u32::from_be_bytes([devlist[8], devlist[9], devlist[10], devlist[11]]);

        assert_eq!(version, USBIP_VERSION);
        assert_eq!(op, OP_REP_DEVLIST);
        assert_eq!(status, 0);
        assert_eq!(ndev, 1);
    }

    #[test]
    fn test_build_rep_import_success() {
        let rep = UsbIpServer::build_rep_import(0);
        assert_eq!(rep.len(), 320); // 8 header + 312 devinfo

        let op = u16::from_be_bytes([rep[2], rep[3]]);
        let status = u32::from_be_bytes([rep[4], rep[5], rep[6], rep[7]]);
        assert_eq!(op, OP_REP_IMPORT);
        assert_eq!(status, 0);
    }

    #[test]
    fn test_ret_submit_format() {
        let ret = UsbIpServer::build_ret_submit(42, 1, USBIP_DIR_IN, 2, 0, 16);
        assert_eq!(ret.len(), 48);

        let cmd = u32::from_be_bytes([ret[0], ret[1], ret[2], ret[3]]);
        let seq = u32::from_be_bytes([ret[4], ret[5], ret[6], ret[7]]);
        let dir = u32::from_be_bytes([ret[12], ret[13], ret[14], ret[15]]);
        let ep = u32::from_be_bytes([ret[16], ret[17], ret[18], ret[19]]);
        let status = u32::from_be_bytes([ret[20], ret[21], ret[22], ret[23]]);
        let actual_len = u32::from_be_bytes([ret[24], ret[25], ret[26], ret[27]]);

        assert_eq!(cmd, USBIP_RET_SUBMIT);
        assert_eq!(seq, 42);
        assert_eq!(dir, USBIP_DIR_IN);
        assert_eq!(ep, 2);
        assert_eq!(status, 0);
        assert_eq!(actual_len, 16);
    }
}
