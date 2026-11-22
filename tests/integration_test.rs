use nfc_bridge_driver::protocol::codec::{FrameCodec, StreamFrameDecoder};
use nfc_bridge_driver::protocol::frame::{NfcBridgeFrame, TagInfo};
use nfc_bridge_driver::protocol::message_type::MessageType;

#[test]
fn test_protocol_cross_compatibility() {
    // 1. Simular trama TAG_ATTACHED enviada desde Android
    let tag_info = TagInfo {
        uid: vec![0x04, 0xA1, 0xB2, 0xC3],
        technology_mask: (1 << 0) | (1 << 6), // NfcA + MifareUltralight
        atqa: 0x0044,
        sak: 0x00,
        historical_bytes: vec![],
    };

    let mut payload = Vec::new();
    payload.push(tag_info.uid.len() as u8);
    payload.extend_from_slice(&tag_info.uid);
    payload.extend_from_slice(&tag_info.technology_mask.to_be_bytes());
    payload.extend_from_slice(&tag_info.atqa.to_be_bytes());
    payload.push(tag_info.sak);
    payload.push(0); // hist_len

    let frame = NfcBridgeFrame::new(MessageType::TagAttached, 42, payload);
    let wire_bytes = FrameCodec::encode(&frame);

    // 2. Simular recepción continua en el driver de Windows
    let mut decoder = StreamFrameDecoder::new();
    let decoded_frames = decoder.feed(&wire_bytes);

    assert_eq!(decoded_frames.len(), 1);
    let decoded = &decoded_frames[0];
    assert_eq!(decoded.message_type, MessageType::TagAttached);
    assert_eq!(decoded.sequence_id, 42);

    let parsed_tag = FrameCodec::decode_tag_attached(&decoded.payload)
        .expect("Debe decodificar el payload de la tarjeta");

    assert_eq!(parsed_tag.uid_hex(), "04A1B2C3");
    assert!(parsed_tag.is_nfc_a());
    assert!(parsed_tag.is_mifare_ultralight());
}

#[tokio::test]
async fn test_ccid_usbip_transceive_dispatch() {
    use nfc_bridge_driver::emulator::CcidHandler;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let mut handler = CcidHandler::new();
    let tag = TagInfo {
        uid: vec![0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        technology_mask: 1 | (1 << 6),
        atqa: 0x0044,
        sak: 0x00,
        historical_bytes: vec![],
    };
    handler.set_tag(Some(tag));
    let ccid_mutex = Arc::new(Mutex::new(handler));

    // Simular que el emulador envía APDU para leer bloque 4 (0x30, 0x04)
    let read_block_apdu = vec![
        0x6F, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x30, 0x04,
    ];

    let mut guard = ccid_mutex.lock().await;
    let resp = guard.process_ccid_command(&read_block_apdu, |req| async move {
        assert_eq!(req, vec![0x30, 0x04]);
        // Simular respuesta del teléfono: 16 bytes de datos + 90 00
        Some(vec![0xAA; 16])
    }).await;

    // Verificar que la respuesta CCID contiene los 16 bytes y el código exitoso
    assert!(resp.len() >= 10 + 16);
    assert_eq!(resp[0], 0x80); // RDR_to_PC_DataBlock
    assert_eq!(&resp[10..26], &[0xAA; 16]);
}
