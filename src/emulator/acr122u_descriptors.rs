//! Descriptores USB estándar para emulación del lector ACS ACR122U USB CCID.

pub const VENDOR_ID_ACS: u16 = 0x072F;
pub const PRODUCT_ID_ACR122U: u16 = 0x2200;
pub const DEVICE_RELEASE_NUMBER: u16 = 0x0100;

/// USB Device Descriptor (18 bytes)
pub const ACR122U_DEVICE_DESCRIPTOR: &[u8] = &[
    0x12,       // bLength = 18 bytes
    0x01,       // bDescriptorType = Device (0x01)
    0x00, 0x02, // bcdUSB = 2.00
    0x00,       // bDeviceClass = 0 (Defined at Interface level)
    0x00,       // bDeviceSubClass = 0
    0x00,       // bDeviceProtocol = 0
    0x40,       // bMaxPacketSize0 = 64 bytes
    0x2F, 0x07, // idVendor = 0x072F (ACS)
    0x00, 0x22, // idProduct = 0x2200 (ACR122U)
    0x00, 0x01, // bcdDevice = 1.00
    0x01,       // iManufacturer = String 1 ("ACS")
    0x02,       // iProduct = String 2 ("ACR122U USB Reader")
    0x00,       // iSerialNumber = 0
    0x01,       // bNumConfigurations = 1
];

/// USB Configuration Descriptor con Interface CCID y 3 Endpoints (Bulk IN, Bulk OUT, Interrupt IN)
pub const ACR122U_CONFIG_DESCRIPTOR: &[u8] = &[
    // --- Configuration Descriptor (9 bytes) ---
    0x09,       // bLength = 9
    0x02,       // bDescriptorType = Configuration (0x02)
    0x5D, 0x00, // wTotalLength = 93 bytes
    0x01,       // bNumInterfaces = 1
    0x01,       // bConfigurationValue = 1
    0x00,       // iConfiguration = 0
    0x80,       // bmAttributes = Bus powered
    0x32,       // bMaxPower = 100 mA (50 * 2)

    // --- Interface Descriptor (9 bytes) ---
    0x09,       // bLength = 9
    0x04,       // bDescriptorType = Interface (0x04)
    0x00,       // bInterfaceNumber = 0
    0x00,       // bAlternateSetting = 0
    0x03,       // bNumEndpoints = 3
    0x0B,       // bInterfaceClass = Smart Card (0x0B)
    0x00,       // bInterfaceSubClass = 0
    0x00,       // bInterfaceProtocol = 0 (Bulk)
    0x00,       // iInterface = 0

    // --- CCID Class Descriptor (54 bytes) ---
    0x36,       // bLength = 54
    0x21,       // bDescriptorType = Functional (0x21)
    0x10, 0x01, // bcdCCID = 1.10
    0x00,       // bMaxSlotIndex = 0 (1 slot)
    0x07,       // bVoltageSupport = 5.0V, 3.0V, 1.8V
    0x02, 0x00, 0x00, 0x00, // dwProtocols = T=1
    0xA0, 0x0F, 0x00, 0x00, // dwDefaultClock = 4.0 MHz (4000 kHz)
    0xA0, 0x0F, 0x00, 0x00, // dwMaximumClock = 4.0 MHz
    0x00,       // bNumClockSupported = 0
    0x00, 0x4B, 0x00, 0x00, // dwDataRate = 19200 bps
    0x00, 0x4B, 0x00, 0x00, // dwMaxDataRate = 19200 bps
    0x00,       // bNumDataRatesSupported = 0
    0x00, 0x01, 0x00, 0x00, // dwMaxIFSD = 256 bytes
    0x00, 0x00, 0x00, 0x00, // dwSynchProtocols = 0
    0x00, 0x00, 0x00, 0x00, // dwMechanical = 0
    0xBA, 0x00, 0x02, 0x00, // dwFeatures (Automatic parameter negotiation, short APDU)
    0x0F, 0x01, 0x00, 0x00, // dwMaxCCIDMessageLength = 271 bytes
    0x00,       // bClassGetResponse = 0
    0x00,       // bClassEnvelope = 0
    0x00, 0x00, // wLcdLayout = 0
    0x00,       // bPINSupport = 0
    0x01,       // bMaxCCIDBusySlots = 1

    // --- Endpoint 1: Bulk-OUT (PC -> Lector) (7 bytes) ---
    0x07,       // bLength = 7
    0x05,       // bDescriptorType = Endpoint (0x05)
    0x01,       // bEndpointAddress = EP 1 OUT
    0x02,       // bmAttributes = Bulk (0x02)
    0x40, 0x00, // wMaxPacketSize = 64 bytes
    0x00,       // bInterval = 0

    // --- Endpoint 2: Bulk-IN (Lector -> PC) (7 bytes) ---
    0x07,       // bLength = 7
    0x05,       // bDescriptorType = Endpoint (0x05)
    0x82,       // bEndpointAddress = EP 2 IN
    0x02,       // bmAttributes = Bulk (0x02)
    0x40, 0x00, // wMaxPacketSize = 64 bytes
    0x00,       // bInterval = 0

    // --- Endpoint 3: Interrupt-IN (Notificación de Tarjeta) (7 bytes) ---
    0x07,       // bLength = 7
    0x05,       // bDescriptorType = Endpoint (0x05)
    0x83,       // bEndpointAddress = EP 3 IN
    0x03,       // bmAttributes = Interrupt (0x03)
    0x08, 0x00, // wMaxPacketSize = 8 bytes
    0x20,       // bInterval = 32 ms
];

/// String Descriptor 0: Supported Language Codes (0x0409 = English US)
pub const STRING_DESCRIPTOR_LANGID: &[u8] = &[
    0x04,       // bLength = 4
    0x03,       // bDescriptorType = String (0x03)
    0x09, 0x04, // wLANGID[0] = 0x0409 (en-US)
];

/// String Descriptor 1: Fabricante ("ACS")
pub const STRING_DESCRIPTOR_MANUFACTURER: &[u8] = &[
    0x08,       // bLength = 8
    0x03,       // bDescriptorType = String (0x03)
    b'A', 0x00, b'C', 0x00, b'S', 0x00,
];

/// String Descriptor 2: Producto ("ACR122U USB Reader")
pub const STRING_DESCRIPTOR_PRODUCT: &[u8] = &[
    0x26,       // bLength = 38 (2 + 18 * 2)
    0x03,       // bDescriptorType = String (0x03)
    b'A', 0x00, b'C', 0x00, b'R', 0x00, b'1', 0x00, b'2', 0x00, b'2', 0x00, b'U', 0x00,
    b' ', 0x00, b'U', 0x00, b'S', 0x00, b'B', 0x00, b' ', 0x00, b'R', 0x00, b'e', 0x00,
    b'a', 0x00, b'd', 0x00, b'e', 0x00, b'r', 0x00,
];

/// Busca y devuelve el descriptor solicitado por la PC en Endpoint 0.
pub fn get_descriptor(desc_type: u8, desc_index: u8) -> Option<&'static [u8]> {
    match desc_type {
        0x01 => Some(ACR122U_DEVICE_DESCRIPTOR),
        0x02 => Some(ACR122U_CONFIG_DESCRIPTOR),
        0x03 => match desc_index {
            0 => Some(STRING_DESCRIPTOR_LANGID),
            1 => Some(STRING_DESCRIPTOR_MANUFACTURER),
            2 => Some(STRING_DESCRIPTOR_PRODUCT),
            _ => None,
        },
        0x21 => {
            // Functional / CCID Class Descriptor (offset 18 en Config Descriptor)
            if ACR122U_CONFIG_DESCRIPTOR.len() >= 18 + 54 {
                Some(&ACR122U_CONFIG_DESCRIPTOR[18..18 + 54])
            } else {
                None
            }
        }
        _ => None,
    }
}
