//! # USB AOA (Android Open Accessory) Host
//!
//! Implementa comunicación USB directa sin TCP/IP y sin Depuración USB (ADB):
//! 1. Detecta dispositivos Android enchufados por USB (requiere interfaz WinUSB para control AOA).
//! 2. Envía el handshake estándar AOA (51 GetProtocol, 52 SendString, 53 Start) para conmutar
//!    el dispositivo al modo Accesorio (VID 0x18D1, PID 0x2D00..0x2D05).
//! 3. Abre los endpoints USB Bulk IN / OUT y puentea tramas BAP v1 directamente hacia `BridgeTcpServer`
//!    (`CcidHandler` + `NamedPipeIpcServer`).

use std::sync::Arc;
use std::time::Duration;
use nusb::descriptors::TransferType;
use nusb::transfer::{Bulk, ControlIn, ControlOut, ControlType, Direction, In, Out, Recipient};
use tracing::{debug, info, warn};

use crate::network::BridgeTcpServer;

const AOA_VENDOR_ID: u16 = 0x18D1;
const AOA_PIDS: [u16; 6] = [0x2D00, 0x2D01, 0x2D02, 0x2D03, 0x2D04, 0x2D05];

const AOA_GET_PROTOCOL: u8 = 51;
const AOA_SEND_STRING: u8 = 52;
const AOA_START: u8 = 53;

const AOA_MANUFACTURER: &[u8] = b"NFC Bridge\0";
const AOA_MODEL: &[u8] = b"NFC Bridge Host\0";
const AOA_DESCRIPTION: &[u8] = b"NFC Bridge Virtual NFC Reader\0";
const AOA_VERSION: &[u8] = b"1.0\0";
const AOA_URI: &[u8] = b"https://github.com/HectorZaGa/nfc-bridge-android\0";
const AOA_SERIAL: &[u8] = b"NFC-BRIDGE-HOST-01\0";

/// VIDs conocidos de fabricantes Android para intentar conmutación AOA segura.
const KNOWN_ANDROID_VIDS: [u16; 14] = [
    0x18D1, // Google
    0x2717, // Xiaomi / POCO / Redmi
    0x04E8, // Samsung
    0x22D9, // OPPO / Realme / OnePlus
    0x2A70, // OnePlus
    0x2D95, // Vivo
    0x22B8, // Motorola
    0x12D1, // Huawei / Honor
    0x0FCE, // Sony
    0x1004, // LG
    0x0B05, // ASUS
    0x2970, // Nothing
    0x05C6, // Qualcomm Android
    0x0E8D, // MediaTek Android
];

pub struct UsbAoaHost {
    coordinator: Arc<BridgeTcpServer>,
}

impl UsbAoaHost {
    pub fn new(coordinator: Arc<BridgeTcpServer>) -> Self {
        Self { coordinator }
    }

    pub async fn run(self: Arc<Self>) {
        info!("Monitor USB AOA (Android Open Accessory) iniciado.");

        loop {
            if let Err(e) = self.scan_and_connect().await {
                debug!("Ciclo de escaneo USB AOA: {}", e);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn scan_and_connect(&self) -> anyhow::Result<()> {
        let devices: Vec<nusb::DeviceInfo> = nusb::list_devices().await?.collect();

        // 1. Priorizar dispositivos que YA están en modo Android Open Accessory (0x18D1 : 0x2D00..0x2D05)
        for dev_info in &devices {
            if dev_info.vendor_id() == AOA_VENDOR_ID && AOA_PIDS.contains(&dev_info.product_id()) {
                info!(
                    "Dispositivo Android en modo AOA detectado ({:04X}:{:04X}). Abriendo canal USB...",
                    dev_info.vendor_id(),
                    dev_info.product_id()
                );
                match self.connect_aoa_device(dev_info).await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        warn!("No se pudo abrir interfaz USB AOA ({:04X}:{:04X}): {}", dev_info.vendor_id(), dev_info.product_id(), e);
                    }
                }
            }
        }

        // 2. Si ningún dispositivo está en modo AOA, intentar negociación AOA en teléfonos Android compatibles
        for dev_info in &devices {
            let vid = dev_info.vendor_id();
            let pid = dev_info.product_id();
            if vid == AOA_VENDOR_ID && AOA_PIDS.contains(&pid) {
                continue;
            }
            if KNOWN_ANDROID_VIDS.contains(&vid) {
                if let Ok(true) = self.try_switch_to_aoa(dev_info).await {
                    info!(
                        "Solicitud AOA enviada al teléfono ({:04X}:{:04X}). Esperando re-enumeración USB...",
                        vid, pid
                    );
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    async fn try_switch_to_aoa(&self, dev_info: &nusb::DeviceInfo) -> anyhow::Result<bool> {
        let device = dev_info.open().await?;
        let interface = device.claim_interface(0).await?;

        let proto_bytes = interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request: AOA_GET_PROTOCOL,
                    value: 0,
                    index: 0,
                    length: 2,
                },
                Duration::from_millis(500),
            )
            .await?;

        if proto_bytes.len() < 2 {
            return Ok(false);
        }
        let version = u16::from_le_bytes([proto_bytes[0], proto_bytes[1]]);
        if version < 1 {
            return Ok(false);
        }

        info!("Teléfono soporta AOA v{}. Enviando descriptores NFC Bridge...", version);

        let strings: [(u16, &[u8]); 6] = [
            (0, AOA_MANUFACTURER),
            (1, AOA_MODEL),
            (2, AOA_DESCRIPTION),
            (3, AOA_VERSION),
            (4, AOA_URI),
            (5, AOA_SERIAL),
        ];

        for (idx, data) in strings {
            interface
                .control_out(
                    ControlOut {
                        control_type: ControlType::Vendor,
                        recipient: Recipient::Device,
                        request: AOA_SEND_STRING,
                        value: 0,
                        index: idx,
                        data,
                    },
                    Duration::from_millis(500),
                )
                .await?;
        }

        interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request: AOA_START,
                    value: 0,
                    index: 0,
                    data: &[],
                },
                Duration::from_millis(500),
            )
            .await?;

        Ok(true)
    }

    async fn connect_aoa_device(&self, dev_info: &nusb::DeviceInfo) -> anyhow::Result<()> {
        let device = dev_info.open().await?;
        let interface = device.claim_interface(0).await?;

        let desc = interface
            .descriptor()
            .ok_or_else(|| anyhow::anyhow!("Interfaz USB AOA sin descriptor"))?;

        let mut ep_in_addr = None;
        let mut ep_out_addr = None;

        for ep in desc.endpoints() {
            if ep.transfer_type() == TransferType::Bulk {
                match ep.direction() {
                    Direction::In if ep_in_addr.is_none() => ep_in_addr = Some(ep.address()),
                    Direction::Out if ep_out_addr.is_none() => ep_out_addr = Some(ep.address()),
                    _ => {}
                }
            }
        }

        let in_addr = ep_in_addr.ok_or_else(|| anyhow::anyhow!("No se encontró endpoint Bulk IN en AOA"))?;
        let out_addr = ep_out_addr.ok_or_else(|| anyhow::anyhow!("No se encontró endpoint Bulk OUT en AOA"))?;

        let ep_in = interface.endpoint::<Bulk, In>(in_addr)?;
        let ep_out = interface.endpoint::<Bulk, Out>(out_addr)?;

        let reader = ep_in.reader(4096);
        let writer = ep_out.writer(4096);

        info!(
            "Canal USB AOA enlazado (IN=0x{:02X}, OUT=0x{:02X}). Esperando tramas BAP v1...",
            in_addr, out_addr
        );

        self.coordinator
            .handle_stream(reader, writer, format!("USB-AOA ({:04X}:{:04X})", dev_info.vendor_id(), dev_info.product_id()))
            .await;

        Ok(())
    }
}
