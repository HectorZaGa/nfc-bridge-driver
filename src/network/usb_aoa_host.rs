//! # USB AOA (Android Open Accessory) Host con UsbDk
//!
//! Implementa comunicación USB directa sin TCP/IP y sin Depuración USB (ADB):
//! 1. Prioriza el backend `UsbDk` en Windows (`rusb::UsbOption::use_usbdk()`), lo que permite
//!    negociar AOA incluso cuando Windows monta el teléfono con `WUDFWpdMtp` (MTP) o sin
//!    driver específico, sin romper ni desinstalar el driver MTP del usuario.
//! 2. Recuerda cada dispositivo `(bus, address, vid, pid)` ya intentado mientras siga
//!    conectado para NO interrumpir transferencias MTP repetidamente cada 2 segundos.
//! 3. Cuando el dispositivo conmuta a modo Accesorio (`0x18D1:0x2D00..0x2D05`), abre los
//!    endpoints USB Bulk IN/OUT y puentea tramas BAP v1 hacia `BridgeTcpServer`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusb::{Context, Device, Direction, Recipient, RequestType, TransferType, UsbContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

type UsbDeviceKey = (u8, u8, u16, u16);

struct UsbBackend {
    ctx: Context,
    using_usbdk: bool,
}

pub struct UsbAoaHost {
    coordinator: Arc<BridgeTcpServer>,
}

impl UsbAoaHost {
    pub fn new(coordinator: Arc<BridgeTcpServer>) -> Self {
        Self { coordinator }
    }

    fn init_usb_backend(warn_if_missing_usbdk: bool) -> anyhow::Result<UsbBackend> {
        #[cfg(windows)]
        {
            if let Ok(usbdk_ctx) = Context::with_options(&[rusb::UsbOption::use_usbdk()]) {
                if usbdk_ctx.devices().is_ok() {
                    info!("Backend USB AOA activo con UsbDk (MTP/Charging compatible sin ADB).");
                    return Ok(UsbBackend {
                        ctx: usbdk_ctx,
                        using_usbdk: true,
                    });
                }
            }
            if warn_if_missing_usbdk {
                warn!(
                    "UsbDk no está instalado o activo en Windows; usando backend WinUSB estándar. \
                     Para USB AOA puro con dispositivos MTP/Xiaomi/Samsung instala UsbDk (`daynix.UsbDk`)."
                );
            }
        }

        let ctx = Context::new()?;
        Ok(UsbBackend {
            ctx,
            using_usbdk: false,
        })
    }

    pub async fn run(self: Arc<Self>) {
        info!("Monitor USB AOA (Android Open Accessory) iniciado.");

        let mut backend: Option<UsbBackend> = None;
        let mut warn_missing = true;
        let mut last_usbdk_retry = Instant::now();
        let mut attempted_devices: HashSet<UsbDeviceKey> = HashSet::new();

        loop {
            let need_usbdk_upgrade = backend
                .as_ref()
                .map(|b| !b.using_usbdk && last_usbdk_retry.elapsed() >= Duration::from_secs(10))
                .unwrap_or(true);

            if need_usbdk_upgrade {
                match Self::init_usb_backend(warn_missing) {
                    Ok(new_backend) => {
                        if new_backend.using_usbdk
                            && backend.as_ref().map(|b| !b.using_usbdk).unwrap_or(false)
                        {
                            // Al pasar a UsbDk en caliente, reintentar dispositivos ya conectados.
                            attempted_devices.clear();
                        }
                        warn_missing = false;
                        last_usbdk_retry = Instant::now();
                        backend = Some(new_backend);
                    }
                    Err(e) => {
                        debug!("Error inicializando contexto libusb: {}", e);
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                }
            }

            if let Some(ref b) = backend {
                if let Err(e) = self.scan_and_connect(&b.ctx, &mut attempted_devices).await {
                    debug!("Ciclo de escaneo USB AOA: {}", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn scan_and_connect(
        &self,
        ctx: &Context,
        attempted_devices: &mut HashSet<UsbDeviceKey>,
    ) -> anyhow::Result<()> {
        let (present_keys, aoa_candidates, android_candidates) = {
            let device_list = ctx.devices()?;
            let mut present_keys: HashSet<UsbDeviceKey> = HashSet::new();
            let mut aoa_candidates: Vec<(Device<Context>, u16, u16)> = Vec::new();
            let mut android_candidates: Vec<(Device<Context>, UsbDeviceKey)> = Vec::new();

            for dev in device_list.iter() {
                let Ok(desc) = dev.device_descriptor() else {
                    continue;
                };
                let vid = desc.vendor_id();
                let pid = desc.product_id();
                let key: UsbDeviceKey = (dev.bus_number(), dev.address(), vid, pid);
                present_keys.insert(key);

                if vid == AOA_VENDOR_ID && AOA_PIDS.contains(&pid) {
                    aoa_candidates.push((dev, vid, pid));
                } else if KNOWN_ANDROID_VIDS.contains(&vid) {
                    android_candidates.push((dev, key));
                }
            }

            (present_keys, aoa_candidates, android_candidates)
        };

        // Limpiar del historial dispositivos desconectados o que cambiaron de modo USB
        attempted_devices.retain(|k| present_keys.contains(k));

        // 1. Priorizar dispositivos que YA están en modo Android Open Accessory (0x18D1:0x2D00..0x2D05)
        for (dev, vid, pid) in aoa_candidates {
            info!(
                "Dispositivo Android en modo AOA detectado ({:04X}:{:04X}). Abriendo canal USB...",
                vid, pid
            );
            match self.connect_aoa_device(dev, vid, pid).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        "No se pudo abrir interfaz USB AOA ({:04X}:{:04X}): {}",
                        vid, pid, e
                    );
                }
            }
        }

        // 2. Intentar negociación AOA una vez por conexión física/modo en Android compatibles
        for (dev, key) in android_candidates {
            if attempted_devices.contains(&key) {
                continue;
            }
            attempted_devices.insert(key);

            let vid = key.2;
            let pid = key.3;
            match tokio::task::spawn_blocking(move || Self::try_switch_to_aoa(&dev)).await {
                Ok(Ok(true)) => {
                    info!(
                        "Solicitud AOA enviada al teléfono ({:04X}:{:04X}). Esperando re-enumeración USB...",
                        vid, pid
                    );
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    return Ok(());
                }
                Ok(Ok(false)) => {
                    debug!("Dispositivo {:04X}:{:04X} no reportó soporte AOA.", vid, pid);
                }
                Ok(Err(e)) => {
                    debug!("Sondeo AOA omitido en {:04X}:{:04X}: {}", vid, pid, e);
                }
                Err(e) => {
                    debug!("Error en tarea bloqueante AOA ({:04X}:{:04X}): {}", vid, pid, e);
                }
            }
        }

        Ok(())
    }

    fn try_switch_to_aoa(dev: &Device<Context>) -> anyhow::Result<bool> {
        let handle = dev.open()?;
        let _ = handle.claim_interface(0);

        let req_in = rusb::request_type(Direction::In, RequestType::Vendor, Recipient::Device);
        let req_out = rusb::request_type(Direction::Out, RequestType::Vendor, Recipient::Device);

        let mut proto_bytes = [0u8; 2];
        let n = handle.read_control(
            req_in,
            AOA_GET_PROTOCOL,
            0,
            0,
            &mut proto_bytes,
            Duration::from_millis(500),
        )?;

        if n < 2 {
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
            handle.write_control(
                req_out,
                AOA_SEND_STRING,
                0,
                idx,
                data,
                Duration::from_millis(500),
            )?;
        }

        handle.write_control(
            req_out,
            AOA_START,
            0,
            0,
            &[],
            Duration::from_millis(500),
        )?;

        Ok(true)
    }

    async fn connect_aoa_device(
        &self,
        dev: Device<Context>,
        vid: u16,
        pid: u16,
    ) -> anyhow::Result<()> {
        let config_desc = dev.active_config_descriptor()?;

        let mut found = None;
        for iface in config_desc.interfaces() {
            for desc in iface.descriptors() {
                let mut ep_in_addr = None;
                let mut ep_out_addr = None;
                for ep in desc.endpoint_descriptors() {
                    if ep.transfer_type() == TransferType::Bulk {
                        match ep.direction() {
                            Direction::In if ep_in_addr.is_none() => ep_in_addr = Some(ep.address()),
                            Direction::Out if ep_out_addr.is_none() => {
                                ep_out_addr = Some(ep.address())
                            }
                            _ => {}
                        }
                    }
                }
                if let (Some(in_addr), Some(out_addr)) = (ep_in_addr, ep_out_addr) {
                    found = Some((iface.number(), in_addr, out_addr));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }

        let (iface_num, in_addr, out_addr) = found
            .ok_or_else(|| anyhow::anyhow!("No se encontraron endpoints Bulk IN/OUT en AOA"))?;

        let handle = Arc::new(dev.open()?);
        handle.claim_interface(iface_num)?;

        info!(
            "Canal USB AOA enlazado (iface={}, IN=0x{:02X}, OUT=0x{:02X}). Esperando tramas BAP v1...",
            iface_num, in_addr, out_addr
        );

        let (bridge_stream, usb_stream) = tokio::io::duplex(16 * 1024);
        let (bridge_reader, bridge_writer) = tokio::io::split(bridge_stream);
        let (mut usb_read_half, mut usb_write_half) = tokio::io::split(usb_stream);

        let running = Arc::new(AtomicBool::new(true));
        let rt_handle = tokio::runtime::Handle::current();

        let handle_in = Arc::clone(&handle);
        let running_in = Arc::clone(&running);
        let rt_in = rt_handle.clone();
        let in_task = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            while running_in.load(Ordering::Relaxed) {
                match handle_in.read_bulk(in_addr, &mut buf, Duration::from_millis(250)) {
                    Ok(0) => continue,
                    Ok(n) => {
                        if rt_in
                            .block_on(usb_write_half.write_all(&buf[..n]))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(rusb::Error::Timeout) => continue,
                    Err(e) => {
                        debug!("USB AOA Bulk IN cerrado: {}", e);
                        break;
                    }
                }
            }
            running_in.store(false, Ordering::Relaxed);
            let _ = rt_in.block_on(usb_write_half.shutdown());
        });

        let handle_out = Arc::clone(&handle);
        let running_out = Arc::clone(&running);
        let rt_out = rt_handle;
        let out_task = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            while running_out.load(Ordering::Relaxed) {
                let n = match rt_out.block_on(usb_read_half.read(&mut buf)) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };

                let mut offset = 0;
                while offset < n && running_out.load(Ordering::Relaxed) {
                    match handle_out.write_bulk(out_addr, &buf[offset..n], Duration::from_secs(2)) {
                        Ok(0) => break,
                        Ok(written) => offset += written,
                        Err(e) => {
                            debug!("USB AOA Bulk OUT cerrado: {}", e);
                            running_out.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
            running_out.store(false, Ordering::Relaxed);
        });

        self.coordinator
            .handle_stream(
                bridge_reader,
                bridge_writer,
                format!("USB-AOA ({:04X}:{:04X})", vid, pid),
            )
            .await;

        running.store(false, Ordering::Relaxed);
        let _ = out_task.await;
        let _ = in_task.await;
        let _ = handle.release_interface(iface_num);

        Ok(())
    }
}
