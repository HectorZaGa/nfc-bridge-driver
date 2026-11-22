//! Constantes y Opcodes de la especificación USB CCID (Circuit Card Interface Device).

// Opcodes de Comandos PC -> Lector (Host to Reader)
pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
pub const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6C;
pub const PC_TO_RDR_RESET_PARAMETERS: u8 = 0x6D;
pub const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
pub const PC_TO_RDR_ESCAPE: u8 = 0x6B;

// Opcodes de Respuestas Lector -> PC (Reader to Host)
pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;
pub const RDR_TO_PC_ESCAPE: u8 = 0x83;

// Estados de la ranura de tarjeta (Slot Status - bmICCStatus)
pub const ICC_PRESENT_ACTIVE: u8 = 0x00;     // Tarjeta presente y con energía
pub const ICC_PRESENT_INACTIVE: u8 = 0x01;   // Tarjeta presente pero apagada
pub const ICC_NOT_PRESENT: u8 = 0x02;        // Sin tarjeta en el campo

// Estado de comando (bmCommandStatus)
pub const CMD_STATUS_SUCCESS: u8 = 0x00;
pub const CMD_STATUS_FAILED: u8 = 0x40;
pub const CMD_STATUS_TIME_EXTENSION: u8 = 0x80;

/// ATR (Answer To Reset) estándar del ACS ACR122U para tarjetas NFC Tipo 2 (ISO 14443-3A / NTAG215).
/// Reconocido instantáneamente por emuladores (Ryujinx, Yuzu, Cemu) y PC/SC de Windows.
pub const DEFAULT_NTAG215_ATR: &[u8] = &[
    0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x68,
];
