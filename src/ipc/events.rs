//! Eventos y Comandos IPC entre el Driver y las aplicaciones de escritorio (Sync / Tools).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedDeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub created_unix: u64,
    #[serde(default)]
    pub mobile_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

fn default_true() -> bool {
    true
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
    SetUsbEnabled { enabled: bool },
    SetTcpEnabled { enabled: bool },
    SetWifiDirectEnabled { enabled: bool },
    SetBluetoothEnabled { enabled: bool },
    DisconnectDevice,
    RevokeTrustedDevice { device_id: String },
    RenameTrustedDevice { device_id: String, name: String },
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
        #[serde(default)]
        transport: Option<String>,
        #[serde(default)]
        mobile_id: Option<String>,
        #[serde(default)]
        active_device_id: Option<String>,
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
        #[serde(default = "default_true")]
        tcp_enabled: bool,
        #[serde(default)]
        wfd_enabled: bool,
        #[serde(default = "default_true")]
        bt_enabled: bool,
        #[serde(default = "default_true")]
        usb_enabled: bool,
        #[serde(default = "default_true")]
        usb_auto_connect: bool,
        #[serde(default)]
        usb_connected: bool,
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
