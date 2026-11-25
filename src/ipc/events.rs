//! Eventos y Comandos IPC entre el Driver y las aplicaciones de escritorio (Sync / Tools).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedDeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub created_unix: u64,
}

/// Comandos que las aplicaciones de escritorio pueden enviar al Driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", content = "params")]
pub enum IpcCommand {
    GetStatus,
    GetWifiDirectInfo,
    GetTransportSnapshot,
    IssuePairingToken { method: String },
    SetRelayUrl { url: Option<String> },
    SetPaused { paused: bool },
    SetUsbPriority { enabled: bool },
    DisconnectDevice,
    RevokeTrustedDevice { device_id: String },
}

/// Eventos emitidos en tiempo real por el Driver hacia las aplicaciones de escritorio.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum IpcEvent {
    Status {
        connected: bool,
        device_name: Option<String>,
        latency_ms: u64,
        paused: bool,
        tag_present: bool,
        tag_uid: Option<String>,
    },
    WifiDirectStatus {
        available: bool,
        active: bool,
        pc_name: String,
        ssid: Option<String>,
        passphrase: Option<String>,
        ip: Option<String>,
        port: u16,
        reason: Option<String>,
    },
    TransportSnapshot {
        pc_name: String,
        tcp_ip: Option<String>,
        tcp_port: u16,
        bt_available: bool,
        bt_mac: Option<String>,
        bt_name: Option<String>,
        relay_url: Option<String>,
        relay_channel: String,
        relay_connected: bool,
        wfd_available: bool,
        wfd_ssid: Option<String>,
        wfd_passphrase: Option<String>,
        wfd_ip: Option<String>,
        #[serde(default)]
        driver_version: Option<String>,
        #[serde(default)]
        driver_build_id: Option<String>,
        #[serde(default)]
        trusted_devices: Vec<TrustedDeviceInfo>,
    },
    PairingTokenIssued {
        method: String,
        pair_token: String,
        expires_in_secs: u64,
        uri: String,
        share_link: Option<String>,
    },
    DeviceConnected {
        device_name: String,
        endpoint: String,
    },
    DeviceDisconnected,
    LatencyUpdated {
        latency_ms: u64,
    },
    TagAttached {
        uid: String,
        technologies: Vec<String>,
        is_ntag215: bool,
    },
    TagDetached,
    Error {
        message: String,
    },
}
