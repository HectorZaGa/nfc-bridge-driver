//! Serializador, deserializador y decodificador de flujo con buffer para sockets.

use bytes::{Buf, BufMut, BytesMut};
use super::constants::{CRC_SIZE, HEADER_SIZE, MAGIC_BYTE_0, MAGIC_BYTE_1, OVERHEAD_SIZE};
use super::crc::compute_crc16;
use super::frame::{NfcBridgeFrame, TagInfo};
use super::message_type::{MessageType, TransceiveStatus};

pub struct FrameCodec;

impl FrameCodec {
    /// Codifica una trama a bytes listos para transmitir por TCP/NamedPipe.
    pub fn encode(frame: &NfcBridgeFrame) -> Vec<u8> {
        let payload_len = frame.payload.len();
        let total_size = HEADER_SIZE + payload_len + CRC_SIZE;
        let mut buf = BytesMut::with_capacity(total_size);

        // Header (8 bytes)
        buf.put_u8(MAGIC_BYTE_0);
        buf.put_u8(MAGIC_BYTE_1);
        buf.put_u8(frame.version);
        buf.put_u8(frame.message_type.as_u8());
        buf.put_u16(frame.sequence_id);
        buf.put_u16(payload_len as u16);

        // Payload
        if payload_len > 0 {
            buf.put_slice(&frame.payload);
        }

        // Checksum CRC-16
        let crc = compute_crc16(&buf);
        buf.put_u16(crc);

        buf.to_vec()
    }

    /// Intenta decodificar una trama a partir de un slice exacto.
    pub fn decode(bytes: &[u8]) -> Option<NfcBridgeFrame> {
        if bytes.len() < OVERHEAD_SIZE {
            return None;
        }

        // 1. Validar Magic Bytes
        if bytes[0] != MAGIC_BYTE_0 || bytes[1] != MAGIC_BYTE_1 {
            return None;
        }

        let version = bytes[2];
        let msg_type = MessageType::from_u8(bytes[3])?;
        let sequence_id = u16::from_be_bytes([bytes[4], bytes[5]]);
        let payload_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;

        let expected_total = HEADER_SIZE + payload_len + CRC_SIZE;
        if bytes.len() < expected_total {
            return None;
        }

        // 2. Validar CRC
        let data_slice = &bytes[0..(HEADER_SIZE + payload_len)];
        let calculated_crc = compute_crc16(data_slice);

        let crc_offset = HEADER_SIZE + payload_len;
        let actual_crc = u16::from_be_bytes([bytes[crc_offset], bytes[crc_offset + 1]]);

        if calculated_crc != actual_crc {
            return None; // Checksum corrupto
        }

        // 3. Extraer Payload
        let payload = if payload_len > 0 {
            bytes[HEADER_SIZE..(HEADER_SIZE + payload_len)].to_vec()
        } else {
            Vec::new()
        };

        Some(NfcBridgeFrame {
            version,
            message_type: msg_type,
            sequence_id,
            payload,
        })
    }

    /// Decodifica el payload de TAG_ATTACHED (0x10).
    pub fn decode_tag_attached(payload: &[u8]) -> Option<TagInfo> {
        if payload.len() < 7 {
            return None;
        }
        let uid_len = payload[0] as usize;
        if payload.len() < 1 + uid_len + 6 {
            return None;
        }

        let uid = payload[1..1 + uid_len].to_vec();
        let mut idx = 1 + uid_len;

        let tech_mask = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        idx += 2;

        let atqa = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        idx += 2;

        let sak = payload[idx];
        idx += 1;

        let hist_len = payload[idx] as usize;
        idx += 1;

        let historical_bytes = if hist_len > 0 && payload.len() >= idx + hist_len {
            payload[idx..idx + hist_len].to_vec()
        } else {
            Vec::new()
        };

        Some(TagInfo {
            uid,
            technology_mask: tech_mask,
            atqa,
            sak,
            historical_bytes,
        })
    }

    /// Codifica el payload para peticiones TRANSCEIVE_REQ (0x20): [TimeoutMs: 2B][Command: NB]
    pub fn encode_transceive_req(timeout_ms: u16, command: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + command.len());
        buf.extend_from_slice(&timeout_ms.to_be_bytes());
        buf.extend_from_slice(command);
        buf
    }

    /// Decodifica la respuesta TRANSCEIVE_RESP (0x21): [Status: 1B][Response: NB]
    pub fn decode_transceive_resp(payload: &[u8]) -> Option<(TransceiveStatus, Vec<u8>)> {
        if payload.is_empty() {
            return None;
        }
        let status = TransceiveStatus::from_u8(payload[0]);
        let data = payload[1..].to_vec();
        Some((status, data))
    }
}

/// Decodificador de flujo continuo para manejar paquetes fragmentados y concatenados de sockets TCP.
#[derive(Default)]
pub struct StreamFrameDecoder {
    buffer: BytesMut,
}

impl StreamFrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Alimenta bytes leídos del socket y emite todas las tramas completas recibidas.
    pub fn feed(&mut self, incoming: &[u8]) -> Vec<NfcBridgeFrame> {
        self.buffer.extend_from_slice(incoming);
        let mut frames = Vec::new();

        loop {
            if self.buffer.len() < HEADER_SIZE {
                break;
            }

            // Buscar Magic Bytes (0x4E, 0x42)
            if self.buffer[0] != MAGIC_BYTE_0 || self.buffer[1] != MAGIC_BYTE_1 {
                self.buffer.advance(1); // Resincronizar byte por byte
                continue;
            }

            // Leer longitud del payload
            let payload_len = u16::from_be_bytes([self.buffer[6], self.buffer[7]]) as usize;
            let total_frame_size = HEADER_SIZE + payload_len + CRC_SIZE;

            if self.buffer.len() < total_frame_size {
                // Trama incompleta, esperar más datos del socket
                break;
            }

            let frame_bytes = &self.buffer[..total_frame_size];
            if let Some(frame) = FrameCodec::decode(frame_bytes) {
                frames.push(frame);
                self.buffer.advance(total_frame_size);
            } else {
                // Trama corrupta, descartar el magic erróneo y continuar buscando
                self.buffer.advance(1);
            }
        }

        frames
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let frame = NfcBridgeFrame::new(MessageType::HelloSyn, 10, vec![0xAA, 0xBB]);
        let encoded = FrameCodec::encode(&frame);
        let decoded = FrameCodec::decode(&encoded).expect("Debe decodificar exitosamente");

        assert_eq!(decoded.message_type, MessageType::HelloSyn);
        assert_eq!(decoded.sequence_id, 10);
        assert_eq!(decoded.payload, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_stream_decoder_fragmentation() {
        let mut decoder = StreamFrameDecoder::new();

        let f1 = NfcBridgeFrame::new(MessageType::Heartbeat, 1, vec![]);
        let f2 = NfcBridgeFrame::new(MessageType::HeartbeatAck, 2, vec![]);

        let b1 = FrameCodec::encode(&f1);
        let b2 = FrameCodec::encode(&f2);
        let mut all = Vec::new();
        all.extend_from_slice(&b1);
        all.extend_from_slice(&b2);

        // Alimentar en pedazos
        let frames_part1 = decoder.feed(&all[..5]);
        assert_eq!(frames_part1.len(), 0);

        let frames_part2 = decoder.feed(&all[5..15]);
        assert_eq!(frames_part2.len(), 1);
        assert_eq!(frames_part2[0].message_type, MessageType::Heartbeat);

        let frames_part3 = decoder.feed(&all[15..]);
        assert_eq!(frames_part3.len(), 1);
        assert_eq!(frames_part3[0].message_type, MessageType::HeartbeatAck);
    }
}
