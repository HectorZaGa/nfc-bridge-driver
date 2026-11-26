//! Manejador de la máquina de estados USB CCID y traductor de pseudo-APDUs del ACR122U.

use super::ccid_constants::*;
use crate::protocol::frame::TagInfo;

pub struct CcidHandler {
    tag_present: bool,
    current_tag: Option<TagInfo>,
    slot_sequence: u8,
    read_only_mode: bool,
}

/// Determina si un comando APDU / raw NFC corresponde a una operación de escritura física.
pub fn is_write_apdu(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Pseudo-APDUs ACR122U de lectura/control que nunca escriben en tarjeta física
    if data.starts_with(&[0xFF, 0xCA])
        || data.starts_with(&[0xFF, 0xB0])
        || data.starts_with(&[0xFF, 0x00, 0x48])
        || data.starts_with(&[0xFF, 0x00, 0x40])
    {
        return false;
    }

    // ACR122U Direct Transmit: FF 00 00 00 Lc <raw>
    if data.starts_with(&[0xFF, 0x00, 0x00, 0x00]) && data.len() > 5 {
        return is_write_apdu(&data[5..]);
    }

    // ACR122U Update Binary: FF D6 ...
    if data.starts_with(&[0xFF, 0xD6]) {
        return true;
    }

    // Mifare Ultralight / NTAG WRITE (0xA2) y Mifare Classic / Compatibility WRITE (0xA0)
    let cmd = data[0];
    if cmd == 0xA2 || cmd == 0xA0 {
        return true;
    }

    // ISO 7816 INS estándar de modificación (solo cuando CLA != 0xFF o ya filtrado arriba)
    if data.len() >= 2 && data[0] != 0xFF {
        let ins = data[1];
        return matches!(ins, 0xD0 | 0xD2 | 0xD6 | 0xDA | 0xDB | 0xDC | 0x0E);
    }

    false
}

/// Construye un ATR PC/SC 2.0 Part 3 dinámico acorde a la tecnología física de la etiqueta.
pub fn build_atr_for_tag(tag: Option<&TagInfo>) -> Vec<u8> {
    let Some(t) = tag else {
        return DEFAULT_NTAG215_ATR.to_vec();
    };

    // ISO-DEP (ISO 14443-4) con historical bytes reales si están disponibles
    if t.is_iso_dep() && !t.historical_bytes.is_empty() && t.historical_bytes.len() <= 15 {
        let hist_len = t.historical_bytes.len() as u8;
        let mut atr = Vec::with_capacity(5 + t.historical_bytes.len());
        atr.push(0x3B);
        atr.push(0x80 | hist_len); // TD1 presente + K historical bytes
        atr.push(0x80);            // TD2 presente, protocolo T=0/indica TD2
        atr.push(0x01);            // T=1
        atr.extend_from_slice(&t.historical_bytes);
        let tck = atr[1..].iter().fold(0u8, |acc, &b| acc ^ b);
        atr.push(tck);
        return atr;
    }

    // PC/SC 2.0 Part 3 Storage Card ATR (AID A0 00 00 03 06)
    let (ss, card_name_hi, card_name_lo): (u8, u8, u8) = if t.is_mifare_ultralight() {
        (0x03, 0x00, 0x01)
    } else if t.is_mifare_classic() || t.sak == 0x08 || t.sak == 0x18 {
        if t.sak == 0x18 {
            (0x03, 0x00, 0x02) // MIFARE Classic 4K
        } else {
            (0x03, 0x00, 0x01) // MIFARE Classic 1K / storage compatible
        }
    } else if t.is_nfc_f() {
        (0x11, 0x00, 0x3B) // FeliCa (JIS X 6319-4)
    } else if t.is_nfc_v() {
        (0x0B, 0x00, 0x07) // ISO 15693
    } else if t.is_nfc_b() {
        (0x07, 0x00, 0x0B) // ISO 14443-B
    } else {
        return DEFAULT_NTAG215_ATR.to_vec();
    };

    let mut atr = vec![
        0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, ss,
        card_name_hi, card_name_lo, 0x00, 0x00, 0x00, 0x00,
    ];
    let tck = atr[1..].iter().fold(0u8, |acc, &b| acc ^ b);
    atr.push(tck);
    atr
}

impl Default for CcidHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl CcidHandler {
    pub fn new() -> Self {
        Self {
            tag_present: false,
            current_tag: None,
            slot_sequence: 0,
            read_only_mode: false,
        }
    }

    pub fn set_read_only(&mut self, enabled: bool) {
        self.read_only_mode = enabled;
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only_mode
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
            return Vec::new();
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
                if self.tag_present {
                    let atr = build_atr_for_tag(self.current_tag.as_ref());
                    self.build_data_block_response(seq, slot, CMD_STATUS_SUCCESS, ICC_PRESENT_ACTIVE, &atr)
                } else {
                    self.build_slot_status_response(seq, slot, CMD_STATUS_FAILED, ICC_NOT_PRESENT)
                }
            }
            PC_TO_RDR_ICC_POWER_OFF => {
                let status = if self.tag_present {
                    ICC_PRESENT_INACTIVE
                } else {
                    ICC_NOT_PRESENT
                };
                self.build_slot_status_response(seq, slot, CMD_STATUS_SUCCESS, status)
            }
            PC_TO_RDR_GET_SLOT_STATUS => {
                let status = if self.tag_present {
                    ICC_PRESENT_ACTIVE
                } else {
                    ICC_NOT_PRESENT
                };
                self.build_slot_status_response(seq, slot, CMD_STATUS_SUCCESS, status)
            }
            PC_TO_RDR_GET_PARAMETERS | PC_TO_RDR_SET_PARAMETERS | PC_TO_RDR_RESET_PARAMETERS => {
                self.build_parameters_response(seq, slot)
            }
            PC_TO_RDR_ESCAPE => {
                if payload.starts_with(&[0xFF, 0x00, 0x48, 0x00, 0x00]) {
                    self.build_escape_response(seq, slot, b"ACR122U214")
                } else {
                    self.build_escape_response(seq, slot, &[0x90, 0x00])
                }
            }
            PC_TO_RDR_XFR_BLOCK => {
                // Pseudo-APDUs de lector que funcionan incluso sin tarjeta o sin tocar el chip
                if payload.starts_with(&[0xFF, 0x00, 0x48, 0x00, 0x00]) {
                    return self.build_data_block_response(
                        seq,
                        slot,
                        CMD_STATUS_SUCCESS,
                        if self.tag_present { ICC_PRESENT_ACTIVE } else { ICC_NOT_PRESENT },
                        b"ACR122U214",
                    );
                }
                if payload.starts_with(&[0xFF, 0x00, 0x40]) {
                    return self.build_data_block_response(
                        seq,
                        slot,
                        CMD_STATUS_SUCCESS,
                        if self.tag_present { ICC_PRESENT_ACTIVE } else { ICC_NOT_PRESENT },
                        &[0x90, 0x00],
                    );
                }

                if !self.tag_present {
                    return self.build_data_block_response(
                        seq,
                        slot,
                        CMD_STATUS_FAILED,
                        ICC_NOT_PRESENT,
                        &[0x6A, 0x82],
                    );
                }

                // Pseudo-APDU GET DATA: FF CA 00 00 [Le] (UID) o FF CA 01 00 [Le] (ATS/hist)
                if payload.len() >= 4 && payload[0] == 0xFF && payload[1] == 0xCA && payload[3] == 0x00 {
                    if let Some(tag) = &self.current_tag {
                        let le = payload.get(4).copied().unwrap_or(0) as usize;
                        let source: &[u8] = match payload[2] {
                            0x00 => &tag.uid,
                            0x01 => &tag.historical_bytes,
                            _ => {
                                return self.build_data_block_response(
                                    seq,
                                    slot,
                                    CMD_STATUS_SUCCESS,
                                    ICC_PRESENT_ACTIVE,
                                    &[0x6A, 0x81],
                                );
                            }
                        };
                        let mut resp = if le > 0 && le < source.len() {
                            source[..le].to_vec()
                        } else {
                            source.to_vec()
                        };
                        resp.extend_from_slice(&[0x90, 0x00]);
                        return self.build_data_block_response(
                            seq,
                            slot,
                            CMD_STATUS_SUCCESS,
                            ICC_PRESENT_ACTIVE,
                            &resp,
                        );
                    }
                }

                // Bloqueo preventivo de escrituras en Modo Solo Lectura
                if self.read_only_mode && is_write_apdu(payload) {
                    return self.build_data_block_response(
                        seq,
                        slot,
                        CMD_STATUS_SUCCESS,
                        ICC_PRESENT_ACTIVE,
                        &[0x69, 0x82],
                    );
                }

                // Traducción pseudo-APDUs ACR122U sobre Mifare Ultralight / NTAG:
                // - FF B0 00 <page> <le> -> comando crudo READ [0x30, page]
                // - FF D6 00 <page> 04 <d0 d1 d2 d3> -> comando crudo WRITE [0xA2, page, d0..d3]
                // - FF 00 00 00 <lc> <raw...> -> Direct Transmit
                let is_ultralight = self
                    .current_tag
                    .as_ref()
                    .is_some_and(|t| t.is_mifare_ultralight());

                let (wire_cmd, read_binary_le, append_sw) =
                    if is_ultralight && payload.len() >= 5 && payload[0] == 0xFF && payload[1] == 0xB0 && payload[2] == 0x00 {
                        (vec![0x30, payload[3]], Some(payload[4] as usize), true)
                    } else if is_ultralight
                        && payload.len() >= 9
                        && payload[0] == 0xFF
                        && payload[1] == 0xD6
                        && payload[2] == 0x00
                        && payload[4] == 0x04
                    {
                        (
                            vec![0xA2, payload[3], payload[5], payload[6], payload[7], payload[8]],
                            None,
                            true,
                        )
                    } else if payload.starts_with(&[0xFF, 0x00, 0x00, 0x00]) && payload.len() > 5 {
                        let lc = payload[4] as usize;
                        let end = (5 + lc).min(payload.len());
                        (payload[5..end].to_vec(), None, true)
                    } else {
                        (payload.to_vec(), None, false)
                    };

                let mobile_resp = transceive_fn(wire_cmd).await;
                match mobile_resp {
                    Some(mut data) => {
                        if let Some(le) = read_binary_le {
                            if le > 0 && data.len() > le {
                                data.truncate(le);
                            }
                            data.extend_from_slice(&[0x90, 0x00]);
                        } else if append_sw || data.len() < 2 {
                            data.extend_from_slice(&[0x90, 0x00]);
                        }
                        self.build_data_block_response(seq, slot, CMD_STATUS_SUCCESS, ICC_PRESENT_ACTIVE, &data)
                    }
                    None => self.build_data_block_response(
                        seq,
                        slot,
                        CMD_STATUS_FAILED,
                        ICC_PRESENT_ACTIVE,
                        &[0x6F, 0x00],
                    ),
                }
            }
            _ => {
                let status = if self.tag_present {
                    ICC_PRESENT_ACTIVE
                } else {
                    ICC_NOT_PRESENT
                };
                self.build_slot_status_response(seq, slot, CMD_STATUS_FAILED, status)
            }
        }
    }

    fn build_data_block_response(
        &self,
        seq: u8,
        slot: u8,
        cmd_status: u8,
        icc_status: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let length = data.len() as u32;
        let mut resp = Vec::with_capacity(10 + data.len());

        resp.push(RDR_TO_PC_DATA_BLOCK);
        resp.extend_from_slice(&length.to_le_bytes());
        resp.push(slot);
        resp.push(seq);
        resp.push(cmd_status | icc_status);
        resp.push(0x00);
        resp.push(0x00);
        resp.extend_from_slice(data);

        resp
    }

    fn build_slot_status_response(
        &self,
        seq: u8,
        slot: u8,
        cmd_status: u8,
        icc_status: u8,
    ) -> Vec<u8> {
        let mut resp = Vec::with_capacity(10);
        resp.push(RDR_TO_PC_SLOT_STATUS);
        resp.extend_from_slice(&0u32.to_le_bytes());
        resp.push(slot);
        resp.push(seq);
        resp.push(cmd_status | icc_status);
        resp.push(0x00);
        resp.push(0x00);
        resp
    }

    fn build_parameters_response(&self, seq: u8, slot: u8) -> Vec<u8> {
        let icc_status = if self.tag_present {
            ICC_PRESENT_ACTIVE
        } else {
            ICC_NOT_PRESENT
        };
        let mut resp = Vec::with_capacity(17);
        resp.push(RDR_TO_PC_PARAMETERS);
        resp.extend_from_slice(&7u32.to_le_bytes());
        resp.push(slot);
        resp.push(seq);
        resp.push(CMD_STATUS_SUCCESS | icc_status);
        resp.push(0x00);
        resp.push(0x01); // T=1
        resp.extend_from_slice(&[0x11, 0x10, 0x00, 0x4D, 0x00, 0xFE, 0x00]);
        resp
    }

    fn build_escape_response(&self, seq: u8, slot: u8, data: &[u8]) -> Vec<u8> {
        let icc_status = if self.tag_present {
            ICC_PRESENT_ACTIVE
        } else {
            ICC_NOT_PRESENT
        };
        let mut resp = Vec::with_capacity(10 + data.len());
        resp.push(RDR_TO_PC_ESCAPE);
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.push(slot);
        resp.push(seq);
        resp.push(CMD_STATUS_SUCCESS | icc_status);
        resp.push(0x00);
        resp.push(0x00);
        resp.extend_from_slice(data);
        resp
    }

    pub fn build_interrupt_message(&self, changed: bool) -> [u8; 2] {
        let status = match (self.tag_present, changed) {
            (true, true) => 0x03,
            (true, false) => 0x02,
            (false, true) => 0x01,
            (false, false) => 0x00,
        };
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
            technology_mask: 1 | (1 << 6),
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
    async fn test_dynamic_atr_for_isodep_and_felica() {
        let mut handler = CcidHandler::new();
        handler.set_tag(Some(TagInfo {
            uid: vec![0x01, 0x02, 0x03, 0x04],
            technology_mask: 1 << 2, // IsoDep
            atqa: 0x0004,
            sak: 0x20,
            historical_bytes: vec![0x80, 0x73, 0xC8],
        }));
        let cmd = [PC_TO_RDR_ICC_POWER_ON, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let resp = handler.process_ccid_command(&cmd, |_| async { None }).await;
        assert_eq!(&resp[10..17], &[0x3B, 0x83, 0x80, 0x01, 0x80, 0x73, 0xC8]);

        handler.set_tag(Some(TagInfo {
            uid: vec![0x01, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A, 0x79, 0x88],
            technology_mask: 1 << 3, // NfcF
            atqa: 0,
            sak: 0,
            historical_bytes: vec![],
        }));
        let felica_resp = handler.process_ccid_command(&cmd, |_| async { None }).await;
        assert_eq!(felica_resp[10 + 12], 0x11);
        assert_eq!(felica_resp[10 + 14], 0x3B);
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
            historical_bytes: vec![0x59, 0x75],
        }));

        let mut cmd = vec![PC_TO_RDR_XFR_BLOCK, 0x05, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
        cmd.extend_from_slice(&[0xFF, 0xCA, 0x00, 0x00, 0x00]);
        let resp = handler.process_ccid_command(&cmd, |_| async { None }).await;
        assert_eq!(resp[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(&resp[10..16], &[0x04, 0xAA, 0xBB, 0xCC, 0x90, 0x00]);

        let mut ats_cmd = vec![PC_TO_RDR_XFR_BLOCK, 0x05, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00];
        ats_cmd.extend_from_slice(&[0xFF, 0xCA, 0x01, 0x00, 0x00]);
        let ats_resp = handler.process_ccid_command(&ats_cmd, |_| async { None }).await;
        assert_eq!(&ats_resp[10..14], &[0x59, 0x75, 0x90, 0x00]);
    }

    #[tokio::test]
    async fn test_read_only_blocks_writes_with_6982() {
        let mut handler = CcidHandler::new();
        handler.set_read_only(true);
        handler.set_tag(Some(TagInfo {
            uid: vec![0x04, 0x11, 0x22, 0x33],
            technology_mask: 1 | (1 << 6),
            atqa: 0x0044,
            sak: 0x00,
            historical_bytes: vec![],
        }));

        // FF D6 00 04 04 AA BB CC DD (Update Binary)
        let mut write_apdu = vec![PC_TO_RDR_XFR_BLOCK, 0x09, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00];
        write_apdu.extend_from_slice(&[0xFF, 0xD6, 0x00, 0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]);
        let resp = handler
            .process_ccid_command(&write_apdu, |_| async {
                panic!("transceive_fn no debe invocarse en Modo Solo Lectura")
            })
            .await;
        assert_eq!(&resp[10..], &[0x69, 0x82]);
    }

    #[tokio::test]
    async fn test_read_binary_and_firmware_pseudo_apdu() {
        let mut handler = CcidHandler::new();
        handler.set_tag(Some(TagInfo {
            uid: vec![0x04, 0x11, 0x22, 0x33],
            technology_mask: 1 | (1 << 6),
            atqa: 0x0044,
            sak: 0x00,
            historical_bytes: vec![],
        }));

        let mut read_apdu = vec![PC_TO_RDR_XFR_BLOCK, 0x05, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00];
        read_apdu.extend_from_slice(&[0xFF, 0xB0, 0x00, 0x04, 0x04]);
        let resp = handler
            .process_ccid_command(&read_apdu, |req| async move {
                assert_eq!(req, vec![0x30, 0x04]);
                Some(vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
            })
            .await;
        assert_eq!(&resp[10..], &[0x10, 0x20, 0x30, 0x40, 0x90, 0x00]);

        let mut fw_apdu = vec![PC_TO_RDR_XFR_BLOCK, 0x05, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00];
        fw_apdu.extend_from_slice(&[0xFF, 0x00, 0x48, 0x00, 0x00]);
        let fw_resp = handler.process_ccid_command(&fw_apdu, |_| async { None }).await;
        assert_eq!(&fw_resp[10..], b"ACR122U214");
    }
}
