//! Eventos y Comandos IPC entre el Driver y las aplicaciones de escritorio (Sync / Tools).

use serde::{Deserialize, Serialize};

/// Comandos que las aplicaciones de escritorio pueden enviar al Driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", content = "params")]
pub enum IpcCommand {
    GetStatus,
    SetPaused { paused: bool },
    SetUsbPriority { enabled: bool },
    DisconnectDevice,
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
