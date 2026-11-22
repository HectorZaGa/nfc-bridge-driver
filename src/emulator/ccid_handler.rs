//! Manejador de la máquina de estados USB CCID y traductor de pseudo-APDUs del ACR122U.

use super::ccid_constants::*;
use crate::protocol::frame::TagInfo;

pub struct CcidHandler {
    tag_present: bool,
    current_tag: Option<TagInfo>,
    slot_sequence: u8,
}

impl CcidHandler {
    pub fn new() -> Self {
        Self {
            tag_present: false,
            current_tag: None,
            slot_sequence: 0,
        }
    }

    /// Actualiza la presencia física de la tarjeta (disparado por TAG_ATTACHED / TAG_DETACHED).
    pub fn set_tag(&mut self, tag: Option<TagInfo>) {
        self.tag_present = tag.is_some();
        self.current_tag = tag;
    }

    pub fn is_tag_present(&self) -> bool {
        self.tag_present
    }

    /// Procesa un mensaje CCID entrante de la PC y retorna la respuesta CCID correspondiente.
    pub async fn process_ccid_command<F, Fut>(&mut self, request: &[u8], transceive_fn: F) -> Vec<u8>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Option<Vec<u8>>>,
    {
        if request.len() < 10 {
            return Vec::new(); // Mensaje CCID corrupto
        }

        let msg_type = request[0];
        let length = u32::from_le_bytes([request[1], request[2], request[3], request[4]]) as usize;
        let slot = request[5];
        let seq = request[6];
        self.slot_sequence = seq;

        let payload = if request.len() >= 10 + length {
            &request[10..10 + length]
        } else {
            &request[10..]
        };

        match msg_type {
            PC_TO_RDR_ICC_POWER_ON => {
                // Activar tarjeta y devolver ATR
                if self.tag_present {
                    self.build_data_block_response(seq, slot, CMD_STATUS_SUCCESS, ICC_PRESENT_ACTIVE, DEFAULT_NTAG215_ATR)
                } else {
                    self.build_slot_status_response(seq, slot, CMD_STATUS_FAILED, ICC_NOT_PRESENT)
                }
            }
            PC_TO_RDR_ICC_POWER_OFF => {
                let status = if self.tag_present { ICC_PRESENT_INACTIVE } else { ICC_NOT_PRESENT };
                self.build_slot_status_response(seq, slot, CMD_STATUS_SUCCESS, status)
            }
            PC_TO_RDR_GET_SLOT_STATUS => {
                let status = if self.tag_present { ICC_PRESENT_ACTIVE } else { ICC_NOT_PRESENT };
                self.build_slot_status_response(seq, slot, CMD_STATUS_SUCCESS, status)
            }
            PC_TO_RDR_GET_PARAMETERS => {
                // Devolver parámetros de protocolo T=1
                self.build_parameters_response(seq, slot)
            }
            PC_TO_RDR_XFR_BLOCK => {
                if !self.tag_present {
                    return self.build_data_block_response(seq, slot, CMD_STATUS_FAILED, ICC_NOT_PRESENT, &[0x6A, 0x82]);
                }

                // Interceptar pseudo-APDU del ACR122U: GET UID (FF CA 00 00 00)
                if payload.starts_with(&[0xFF, 0xCA, 0x00, 0x00]) {
                    if let Some(tag) = &self.current_tag {
                        let mut resp = tag.uid.clone();
                        resp.extend_from_slice(&[0x90, 0x00]); // SW1 SW2: Exitoso
                        return self.build_data_block_response(seq, slot, CMD_STATUS_SUCCESS, ICC_PRESENT_ACTIVE, &resp);
                    }
                }

                // Para cualquier otro comando APDU / comando crudo: despachar a través de la red al móvil
                let mobile_resp = transceive_fn(payload.to_vec()).await;
                match mobile_resp {
                    Some(mut data) => {
                        // Si la respuesta no contiene SW1 SW2 al final, adjuntar 0x90, 0x00
                        if data.len() < 2 {
                            data.extend_from_slice(&[0x90, 0x00]);
                        }
                        self.build_data_block_response(seq, slot, CMD_STATUS_SUCCESS, ICC_PRESENT_ACTIVE, &data)
                    }
                    None => {
                        self.build_data_block_response(seq, slot, CMD_STATUS_FAILED, ICC_PRESENT_ACTIVE, &[0x6F, 0x00])
                    }
                }
            }
            _ => {
                // Comando no soportado o de parámetros
                let status = if self.tag_present { ICC_PRESENT_ACTIVE } else { ICC_NOT_PRESENT };
                self.build_slot_status_response(seq, slot, CMD_STATUS_FAILED, status)
            }
        }
    }

    /// Construye una respuesta RDR_to_PC_DataBlock (0x80)
    fn build_data_block_response(&self, seq: u8, slot: u8, cmd_status: u8, icc_status: u8, data: &[u8]) -> Vec<u8> {
        let length = data.len() as u32;
        let mut resp = Vec::with_capacity(10 + data.len());

        resp.push(RDR_TO_PC_DATA_BLOCK);
        resp.extend_from_slice(&length.to_le_bytes());
        resp.push(slot);
        resp.push(seq);
        resp.push(cmd_status | icc_status); // bStatus
        resp.push(0x00);                    // bError
        resp.push(0x00);                    // bChainParameter
        resp.extend_from_slice(data);

        resp
    }

    /// Construye una respuesta RDR_to_PC_SlotStatus (0x81)
    fn build_slot_status_response(&self, seq: u8, slot: u8, cmd_status: u8, icc_status: u8) -> Vec<u8> {
        let mut resp = Vec::with_capacity(10);
        resp.push(RDR_TO_PC_SLOT_STATUS);
        resp.extend_from_slice(&0u32.to_le_bytes()); // Length = 0
        resp.push(slot);
        resp.push(seq);
        resp.push(cmd_status | icc_status);
        resp.push(0x00); // bError
        resp.push(0x00); // bClockStatus
        resp
    }

    /// Construye una respuesta RDR_to_PC_Parameters (0x82) para T=1
    fn build_parameters_response(&self, seq: u8, slot: u8) -> Vec<u8> {
        let mut resp = Vec::with_capacity(17);
        resp.push(RDR_TO_PC_PARAMETERS);
        resp.extend_from_slice(&7u32.to_le_bytes()); // Length = 7 bytes para T=1
        resp.push(slot);
        resp.push(seq);
        resp.push(CMD_STATUS_SUCCESS | ICC_PRESENT_ACTIVE);
        resp.push(0x00); // bError
        resp.push(0x01); // bProtocolNum = T=1

        // Parámetros T=1 estándar (bmFindexDindex, bmTCCKST1, bGuardTimeT1, bWaitingIntegerT1, bClockStop, bIFSC, bNadValue)
        resp.extend_from_slice(&[0x11, 0x10, 0x00, 0x4D, 0x00, 0xFE, 0x00]);
        resp
    }

    /// Genera el paquete para el Endpoint Interrupt-IN cuando cambia el estado de la tarjeta.
    pub fn build_interrupt_message(&self) -> [u8; 2] {
        let status = if self.tag_present { 0x03 } else { 0x02 }; // Bit 0: Slot 0 changed, Bit 1: Current state
        [0x50, status]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_slot_status_without_tag() {
        let mut handler = CcidHandler::new();
        let cmd = [PC_TO_RDR_GET_SLOT_STATUS, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let resp = handler.process_ccid_command(&cmd, |_| async { None }).await;

        assert_eq!(resp[0], RDR_TO_PC_SLOT_STATUS);
        assert_eq!(resp[7] & 0x03, ICC_NOT_PRESENT);
    }

    #[tokio::test]
    async fn test_icc_power_on_returns_atr() {
        let mut handler = CcidHandler::new();
        handler.set_tag(Some(TagInfo {
            uid: vec![0x04, 0x11, 0x22, 0x33],
            technology_mask: 1,
            atqa: 0x0044,
            sak: 0x00,
            historical_bytes: vec![],
        }));

        let cmd = [PC_TO_RDR_ICC_POWER_ON, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let resp = handler.process_ccid_command(&cmd, |_| async { None }).await;

        assert_eq!(resp[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(&resp[10..], DEFAULT_NTAG215_ATR);
    }

    #[tokio::test]
    async fn test_get_uid_pseudo_apdu() {
        let mut handler = CcidHandler::new();
        let expected_uid = vec![0x04, 0xAA, 0xBB, 0xCC];
        handler.set_tag(Some(TagInfo {
            uid: expected_uid.clone(),
            technology_mask: 1,
            atqa: 0x0044,
            sak: 0x00,
            historical_bytes: vec![],
        }));

        // APDU Get UID: FF CA 00 00 00
        let mut cmd = vec![PC_TO_RDR_XFR_BLOCK, 0x05, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
        cmd.extend_from_slice(&[0xFF, 0xCA, 0x00, 0x00, 0x00]);

        let resp = handler.process_ccid_command(&cmd, |_| async { None }).await;

        assert_eq!(resp[0], RDR_TO_PC_DATA_BLOCK);
        // Payload debe ser UID + 90 00
        let data = &resp[10..];
        assert_eq!(&data[0..4], &expected_uid[..]);
        assert_eq!(&data[4..6], &[0x90, 0x00]);
    }
}
