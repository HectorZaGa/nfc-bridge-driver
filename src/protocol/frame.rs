//! Estructuras de datos del protocolo binario.

use super::constants::PROTOCOL_VERSION;
use super::message_type::MessageType;

/// Información de una etiqueta NFC detectada por el móvil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagInfo {
    pub uid: Vec<u8>,
    pub technology_mask: u16,
    pub atqa: u16,
    pub sak: u8,
    pub historical_bytes: Vec<u8>,
}

impl TagInfo {
    pub fn uid_hex(&self) -> String {
        self.uid.iter().map(|b| format!("{:02X}", b)).collect()
    }

    pub fn is_nfc_a(&self) -> bool {
        (self.technology_mask & (1 << 0)) != 0
    }

    pub fn is_iso_dep(&self) -> bool {
        (self.technology_mask & (1 << 2)) != 0
    }

    pub fn is_mifare_ultralight(&self) -> bool {
        (self.technology_mask & (1 << 6)) != 0
    }
}

/// Trama inmutable del protocolo NFC-Bridge v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfcBridgeFrame {
    pub version: u8,
    pub message_type: MessageType,
    pub sequence_id: u16,
    pub payload: Vec<u8>,
}

impl NfcBridgeFrame {
    pub fn new(message_type: MessageType, sequence_id: u16, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            sequence_id,
            payload,
        }
    }
}
