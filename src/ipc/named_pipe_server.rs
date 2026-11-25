//! Servidor IPC por Named Pipe de Windows (\\.\pipe\nfc_bridge_driver).

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use super::events::{IpcCommand, IpcEvent};
use crate::network::pairing_manager::detect_lan_ipv4;
use crate::network::{
    get_local_bluetooth_info, BluetoothRfcommServer, BridgeTcpServer, PairingManager, RelayClient,
    UsbAoaHost, WifiDirectServer,
};
use crate::protocol::constants::{DEFAULT_TCP_PORT, NAMED_PIPE_NAME};

pub struct NamedPipeIpcServer {
    event_sender: broadcast::Sender<IpcEvent>,
    coordinator: Option<Arc<BridgeTcpServer>>,
    wifi_direct: Option<Arc<WifiDirectServer>>,
    pairing: Option<Arc<PairingManager>>,
    relay_client: Option<Arc<RelayClient>>,
    usb_aoa: Option<Arc<UsbAoaHost>>,
    bluetooth: Option<Arc<BluetoothRfcommServer>>,
}

#[cfg(windows)]
fn create_pipe_instance(
    first: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    // Permite control total a SYSTEM/Administrators y Lectura+Escritura IPC a usuarios autenticados (Sync/Tools sin UAC).
    let sddl: Vec<u16> = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)\0"
        .encode_utf16()
        .collect();
    const SDDL_REVISION_1: u32 = 1;

    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    };

    if ok != 0 && !sd.is_null() {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let result = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .create_with_security_attributes_raw(
                    NAMED_PIPE_NAME,
                    (&mut sa as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
                )
        };
        unsafe {
            LocalFree(sd as HLOCAL);
        }
        return result;
    }

    ServerOptions::new()
        .first_pipe_instance(first)
        .create(NAMED_PIPE_NAME)
}

impl NamedPipeIpcServer {
    pub fn new(event_sender: broadcast::Sender<IpcEvent>) -> Self {
        Self {
            event_sender,
            coordinator: None,
            wifi_direct: None,
            pairing: None,
            relay_client: None,
            usb_aoa: None,
            bluetooth: None,
        }
    }

    pub fn with_coordinator(
        event_sender: broadcast::Sender<IpcEvent>,
        coordinator: Arc<BridgeTcpServer>,
    ) -> Self {
        Self {
            event_sender,
            coordinator: Some(coordinator),
            wifi_direct: None,
            pairing: None,
            relay_client: None,
            usb_aoa: None,
            bluetooth: None,
        }
    }

    pub fn with_transports(
        event_sender: broadcast::Sender<IpcEvent>,
        coordinator: Arc<BridgeTcpServer>,
        wifi_direct: Arc<WifiDirectServer>,
        pairing: Arc<PairingManager>,
        relay_client: Arc<RelayClient>,
        usb_aoa: Arc<UsbAoaHost>,
        bluetooth: Arc<BluetoothRfcommServer>,
    ) -> Self {
        Self {
            event_sender,
            coordinator: Some(coordinator),
            wifi_direct: Some(wifi_direct),
            pairing: Some(pairing),
            relay_client: Some(relay_client),
            usb_aoa: Some(usb_aoa),
            bluetooth: Some(bluetooth),
        }
    }

    fn build_transport_snapshot(&self) -> Option<IpcEvent> {
        let pairing = self.pairing.as_ref()?;
        let bt_info = get_local_bluetooth_info();
        let wfd = self.wifi_direct.as_ref().map(|w| w.current_snapshot());
        let tcp_ip = detect_lan_ipv4();
        let relay_url = pairing.get_relay_url();
        let relay_channel = pairing.get_relay_channel();
        let relay_connected = self
            .relay_client
            .as_ref()
            .map(|r| r.is_connected())
            .unwrap_or(false);
        let tcp_enabled = self
            .coordinator
            .as_ref()
            .map(|c| c.is_tcp_enabled())
            .unwrap_or(true);
        let wfd_enabled = self
            .wifi_direct
            .as_ref()
            .map(|w| w.is_enabled())
            .unwrap_or(false);
        let bt_enabled = self
            .bluetooth
            .as_ref()
            .map(|b| b.is_enabled())
            .unwrap_or(true);
        let usb_enabled = self
            .usb_aoa
            .as_ref()
            .map(|u| u.is_enabled())
            .unwrap_or(true);
        let usb_auto_connect = self
            .usb_aoa
            .as_ref()
            .map(|u| u.is_auto_connect())
            .unwrap_or(true);
        let usb_connected = self
            .coordinator
            .as_ref()
            .map(|c| c.is_usb_connected())
            .unwrap_or(false);

        Some(IpcEvent::TransportSnapshot {
            pc_name: pairing.pc_name().to_string(),
            tcp_ip,
            tcp_port: DEFAULT_TCP_PORT,
            bt_available: bt_info.is_some(),
            bt_mac: bt_info.as_ref().map(|(m, _)| m.clone()),
            bt_name: bt_info.map(|(_, n)| n),
            relay_url,
            relay_channel,
            relay_connected,
            wfd_available: wfd.as_ref().map(|w| w.available && w.active).unwrap_or(false),
            wfd_ssid: wfd.as_ref().and_then(|w| w.ssid.clone()),
            wfd_passphrase: wfd.as_ref().and_then(|w| w.passphrase.clone()),
            wfd_ip: wfd.and_then(|w| w.ip),
            tcp_enabled,
            wfd_enabled,
            bt_enabled,
            usb_enabled,
            usb_auto_connect,
            usb_connected,
            driver_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            driver_build_id: Some(env!("NFC_BRIDGE_BUILD_ID").to_string()),
            trusted_devices: pairing.list_trusted_devices(),
        })
    }

    async fn ensure_method_enabled(&self, method: &str) -> bool {
        let mut enabled_any = false;
        match method {
            "tcp" => {
                if let Some(ref coord) = self.coordinator {
                    if !coord.is_tcp_enabled() {
                        coord.set_tcp_enabled(true).await;
                        enabled_any = true;
                    }
                }
            }
            "bluetooth" => {
                if let Some(ref bt) = self.bluetooth {
                    if !bt.is_enabled() {
                        bt.set_enabled(true);
                        enabled_any = true;
                        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
                    }
                }
            }
            "usb" => {
                if let Some(ref usb) = self.usb_aoa {
                    if !usb.is_enabled() {
                        usb.set_enabled(true);
                        enabled_any = true;
                    }
                }
            }
            "wifi_direct" => {
                if let Some(ref wfd) = self.wifi_direct {
                    if !wfd.is_enabled() {
                        wfd.set_enabled(true);
                        enabled_any = true;
                        for _ in 0..14 {
                            if wfd.current_snapshot().active {
                                break;
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    }
                    if let Some(ref coord) = self.coordinator {
                        coord.set_wfd_accept_allowed(true, wfd.current_snapshot().ip);
                    }
                }
            }
            _ => {}
        }
        enabled_any
    }

    /// Inicia el bucle que acepta clientes locales de Windows (Sync / Tools).
    pub async fn run(self: Arc<Self>) {
        info!("Iniciando servidor IPC Named Pipe en {}", NAMED_PIPE_NAME);

        let mut first = true;
        loop {
            let server = match create_pipe_instance(first) {
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

            if let Err(e) = server.connect().await {
                warn!("Fallo al conectar cliente a Named Pipe: {}", e);
                continue;
            }

            info!("Cliente IPC (Sync / Tools) conectado a Named Pipe");
            let this = Arc::clone(&self);
            let mut event_rx = this.event_sender.subscribe();

            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(server);
                let mut lines = BufReader::new(reader).lines();

                // Enviar estado inicial al conectarse Sync/Tools
                if let Some(ref coord) = this.coordinator {
                    let initial_status = coord.get_status_event().await;
                    if let Ok(json) = serde_json::to_string(&initial_status) {
                        let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                }
                if let Some(ref wfd) = this.wifi_direct {
                    let initial_wfd = wfd.get_status_event();
                    if let Ok(json) = serde_json::to_string(&initial_wfd) {
                        let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                }
                if let Some(snapshot) = this.build_transport_snapshot() {
                    if let Ok(json) = serde_json::to_string(&snapshot) {
                        let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                }

                loop {
                    tokio::select! {
                        Ok(event) = event_rx.recv() => {
                            if let Ok(json) = serde_json::to_string(&event) {
                                if writer.write_all(format!("{}\n", json).as_bytes()).await.is_err() {
                                    break;
                                }
                                let _ = writer.flush().await;
                            }
                        }
                        line_result = lines.next_line() => {
                            match line_result {
                                Ok(Some(line)) => {
                                    if let Ok(cmd) = serde_json::from_str::<IpcCommand>(&line) {
                                        info!("Comando IPC recibido: {:?}", cmd);
                                        match cmd {
                                            IpcCommand::GetWifiDirectInfo => {
                                                if let Some(ref wfd) = this.wifi_direct {
                                                    let wfd_evt = wfd.get_status_event();
                                                    if let Ok(json) = serde_json::to_string(&wfd_evt) {
                                                        if writer.write_all(format!("{}\n", json).as_bytes()).await.is_err() {
                                                            break;
                                                        }
                                                        let _ = writer.flush().await;
                                                    }
                                                }
                                            }
                                            IpcCommand::GetTransportSnapshot => {
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    if let Ok(json) = serde_json::to_string(&snapshot) {
                                                        if writer.write_all(format!("{}\n", json).as_bytes()).await.is_err() {
                                                            break;
                                                        }
                                                        let _ = writer.flush().await;
                                                    }
                                                }
                                            }
                                            IpcCommand::IssuePairingToken { method } => {
                                                let transport_auto_enabled = this.ensure_method_enabled(&method).await;
                                                if transport_auto_enabled {
                                                    if let Some(snapshot) = this.build_transport_snapshot() {
                                                        let _ = this.event_sender.send(snapshot);
                                                    }
                                                }

                                                if let Some(ref pairing) = this.pairing {
                                                    let (pair_token, expires_in_secs) =
                                                        pairing.issue_ephemeral_token_for_method(&method);
                                                    let bt_info = get_local_bluetooth_info();
                                                    let wfd = this.wifi_direct.as_ref().map(|w| w.current_snapshot());
                                                    let tcp_ip = detect_lan_ipv4();
                                                    let (uri, share_link) = pairing.build_qr_and_link(
                                                        &method,
                                                        &pair_token,
                                                        tcp_ip.as_deref(),
                                                        DEFAULT_TCP_PORT,
                                                        bt_info.as_ref().map(|(m, _)| m.as_str()),
                                                        wfd.as_ref().and_then(|w| w.ssid.as_deref()),
                                                        wfd.as_ref().and_then(|w| w.passphrase.as_deref()),
                                                        wfd.as_ref().and_then(|w| w.ip.as_deref()),
                                                    );
                                                    let evt = IpcEvent::PairingTokenIssued {
                                                        method,
                                                        pair_token,
                                                        expires_in_secs,
                                                        uri,
                                                        share_link,
                                                    };
                                                    if let Ok(json) = serde_json::to_string(&evt) {
                                                        if writer.write_all(format!("{}\n", json).as_bytes()).await.is_err() {
                                                            break;
                                                        }
                                                        let _ = writer.flush().await;
                                                    }
                                                }
                                            }
                                            IpcCommand::SetRelayUrl { url } => {
                                                if let Some(ref pairing) = this.pairing {
                                                    pairing.set_relay_url(url);
                                                }
                                                if let Some(ref relay) = this.relay_client {
                                                    relay.notify_config_changed();
                                                }
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    let _ = this.event_sender.send(snapshot);
                                                }
                                            }
                                            IpcCommand::SetTcpEnabled { enabled } => {
                                                if let Some(ref coord) = this.coordinator {
                                                    coord.set_tcp_enabled(enabled).await;
                                                }
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    let _ = this.event_sender.send(snapshot);
                                                }
                                            }
                                            IpcCommand::SetWifiDirectEnabled { enabled } => {
                                                if let Some(ref wfd) = this.wifi_direct {
                                                    wfd.set_enabled(enabled);
                                                    if enabled {
                                                        for _ in 0..12 {
                                                            if wfd.current_snapshot().active {
                                                                break;
                                                            }
                                                            tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;
                                                        }
                                                    }
                                                    if let Some(ref coord) = this.coordinator {
                                                        coord.set_wfd_accept_allowed(enabled, wfd.current_snapshot().ip);
                                                        if !enabled {
                                                            coord.disconnect_if_wfd().await;
                                                        }
                                                    }
                                                }
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    let _ = this.event_sender.send(snapshot);
                                                }
                                            }
                                            IpcCommand::SetBluetoothEnabled { enabled } => {
                                                if let Some(ref bt) = this.bluetooth {
                                                    bt.set_enabled(enabled);
                                                }
                                                if !enabled {
                                                    if let Some(ref coord) = this.coordinator {
                                                        coord.disconnect_if_endpoint_starts_with("Bluetooth").await;
                                                    }
                                                }
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    let _ = this.event_sender.send(snapshot);
                                                }
                                            }
                                            IpcCommand::SetUsbEnabled { enabled } => {
                                                if let Some(ref usb) = this.usb_aoa {
                                                    usb.set_enabled(enabled);
                                                }
                                                if !enabled {
                                                    if let Some(ref coord) = this.coordinator {
                                                        coord.disconnect_if_endpoint_starts_with("USB-AOA").await;
                                                    }
                                                }
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    let _ = this.event_sender.send(snapshot);
                                                }
                                            }
                                            IpcCommand::SetUsbPriority { enabled } => {
                                                if let Some(ref usb) = this.usb_aoa {
                                                    usb.set_auto_connect(enabled);
                                                    if enabled && !usb.is_enabled() {
                                                        usb.set_enabled(true);
                                                    }
                                                }
                                                if let Some(ref coord) = this.coordinator {
                                                    coord.set_usb_auto_connect(enabled).await;
                                                }
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    let _ = this.event_sender.send(snapshot);
                                                }
                                            }
                                            IpcCommand::RevokeTrustedDevice { device_id } => {
                                                let removed = this
                                                    .pairing
                                                    .as_ref()
                                                    .and_then(|p| p.revoke_trusted_device(&device_id));
                                                if let Some(removed_name) = removed {
                                                    if let Some(ref coord) = this.coordinator {
                                                        if let IpcEvent::Status {
                                                            connected: true,
                                                            device_name: active_name,
                                                            active_device_id,
                                                            ..
                                                        } = coord.get_status_event().await
                                                        {
                                                            if active_device_id.as_deref() == Some(device_id.as_str())
                                                                || active_name.as_deref() == Some(removed_name.as_str())
                                                            {
                                                                coord.disconnect_active().await;
                                                            }
                                                        }
                                                    }
                                                }
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    let _ = this.event_sender.send(snapshot);
                                                }
                                            }
                                            IpcCommand::RenameTrustedDevice { device_id, name } => {
                                                if let Some(clean_name) = this
                                                    .pairing
                                                    .as_ref()
                                                    .and_then(|p| p.rename_trusted_device(&device_id, &name))
                                                {
                                                    if let Some(ref coord) = this.coordinator {
                                                        coord.update_active_device_name(&device_id, &clean_name).await;
                                                    }
                                                }
                                                if let Some(snapshot) = this.build_transport_snapshot() {
                                                    let _ = this.event_sender.send(snapshot);
                                                }
                                            }
                                            IpcCommand::SelectTrustedDevice { device_id } => {
                                                let target = this
                                                    .pairing
                                                    .as_ref()
                                                    .and_then(|p| p.get_trusted_device(&device_id));
                                                let mut snapshot_dirty = false;
                                                if let (Some(target), Some(ref coord)) =
                                                    (target, this.coordinator.as_ref())
                                                {
                                                    let target_tr = target
                                                        .transport
                                                        .as_deref()
                                                        .unwrap_or("tcp")
                                                        .to_string();
                                                    if this.ensure_method_enabled(&target_tr).await {
                                                        snapshot_dirty = true;
                                                    }
                                                    if let IpcEvent::Status {
                                                        connected: true,
                                                        device_name: active_name,
                                                        mobile_id: active_mid,
                                                        active_device_id,
                                                        ..
                                                    } = coord.get_status_event().await
                                                    {
                                                        if active_device_id.as_deref()
                                                            != Some(device_id.as_str())
                                                        {
                                                            let same_phone =
                                                                match (&active_mid, &target.mobile_id)
                                                                {
                                                                    (Some(a), Some(b)) => {
                                                                        a.eq_ignore_ascii_case(b)
                                                                    }
                                                                    _ => {
                                                                        active_name.as_deref()
                                                                            == Some(
                                                                                target
                                                                                    .device_name
                                                                                    .as_str(),
                                                                            )
                                                                    }
                                                                };
                                                            if same_phone {
                                                                if let Some(ref pairing) =
                                                                    this.pairing
                                                                {
                                                                    let (pair_token, _) = pairing
                                                                        .issue_ephemeral_token_for_method(
                                                                            &target_tr,
                                                                        );
                                                                    let bt_info =
                                                                        get_local_bluetooth_info();
                                                                    let wfd = this
                                                                        .wifi_direct
                                                                        .as_ref()
                                                                        .map(|w| w.current_snapshot());
                                                                    let payload = serde_json::json!({
                                                                        "transport": target_tr,
                                                                        "pc_name": pairing.pc_name(),
                                                                        "tcp_ip": detect_lan_ipv4(),
                                                                        "tcp_port": DEFAULT_TCP_PORT,
                                                                        "cert": pairing.get_tcp_cert_sha256(),
                                                                        "bt_mac": bt_info.map(|(m, _)| m),
                                                                        "relay_url": pairing.get_relay_url(),
                                                                        "relay_channel": pairing.get_relay_channel(),
                                                                        "wfd_ip": wfd.as_ref().and_then(|w| w.ip.clone()),
                                                                        "wfd_ssid": wfd.as_ref().and_then(|w| w.ssid.clone()),
                                                                        "wfd_pass": wfd.as_ref().and_then(|w| w.passphrase.clone()),
                                                                        "pair_token": pair_token,
                                                                    })
                                                                    .to_string();
                                                                    info!(
                                                                        "Solicitando cambio de transporte del móvil activo hacia '{}' ({})",
                                                                        target_tr, device_id
                                                                    );
                                                                    coord
                                                                        .switch_active_transport(
                                                                            payload,
                                                                        )
                                                                        .await;
                                                                }
                                                            } else {
                                                                info!(
                                                                    "Desconectando perfil actual para priorizar el seleccionado ({})",
                                                                    device_id
                                                                );
                                                                coord.disconnect_active().await;
                                                            }
                                                        }
                                                    }
                                                }
                                                if snapshot_dirty {
                                                    if let Some(snapshot) =
                                                        this.build_transport_snapshot()
                                                    {
                                                        let _ = this.event_sender.send(snapshot);
                                                    }
                                                }
                                            }
                                            other_cmd => {
                                                if let Some(ref coord) = this.coordinator {
                                                    match other_cmd {
                                                        IpcCommand::GetStatus => {
                                                            let status = coord.get_status_event().await;
                                                            if let Ok(json) = serde_json::to_string(&status) {
                                                                if writer.write_all(format!("{}\n", json).as_bytes()).await.is_err() {
                                                                    break;
                                                                }
                                                                let _ = writer.flush().await;
                                                            }
                                                        }
                                                        IpcCommand::SetPaused { paused } => {
                                                            coord.set_paused(paused).await;
                                                        }
                                                        IpcCommand::DisconnectDevice => {
                                                            coord.disconnect_active().await;
                                                        }
                                                        IpcCommand::SetUsbPriority { .. }
                                                        | IpcCommand::SetUsbEnabled { .. }
                                                        | IpcCommand::SetTcpEnabled { .. }
                                                        | IpcCommand::SetWifiDirectEnabled { .. }
                                                        | IpcCommand::SetBluetoothEnabled { .. }
                                                        | IpcCommand::GetWifiDirectInfo
                                                        | IpcCommand::GetTransportSnapshot
                                                        | IpcCommand::IssuePairingToken { .. }
                                                        | IpcCommand::SetRelayUrl { .. }
                                                        | IpcCommand::RevokeTrustedDevice { .. }
                                                        | IpcCommand::RenameTrustedDevice { .. }
                                                        | IpcCommand::SelectTrustedDevice { .. } => {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => break,
                            }
                        }
                    }
                }
                info!("Cliente IPC desconectado");
            });
        }
    }
}
