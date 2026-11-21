//! Cálculo de CRC-16 CCITT (Polinomio 0x1021, Init 0xFFFF).
//! Idéntico bit a bit a la implementación en Kotlin de Android.

const POLYNOMIAL: u16 = 0x1021;
const INITIAL_VALUE: u16 = 0xFFFF;

// Generar tabla de búsqueda en tiempo de compilación (const fn)
const fn generate_crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut temp = (i as u16) << 8;
        let mut j = 0;
        while j < 8 {
            if (temp & 0x8000) != 0 {
                temp = (temp << 1) ^ POLYNOMIAL;
            } else {
                temp <<= 1;
            }
            j += 1;
        }
        table[i] = temp;
        i += 1;
    }
    table
}

static CRC_TABLE: [u16; 256] = generate_crc_table();

/// Calcula el CRC-16 CCITT para un slice de bytes.
pub fn compute_crc16(bytes: &[u8]) -> u16 {
    let mut crc = INITIAL_VALUE;
    for &b in bytes {
        let table_index = (((crc >> 8) ^ (b as u16)) & 0x00FF) as usize;
        crc = CRC_TABLE[table_index] ^ (crc << 8);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_computation() {
        let data = b"123456789";
        let crc = compute_crc16(data);
        assert_eq!(crc, 0x29B1);
    }
}
