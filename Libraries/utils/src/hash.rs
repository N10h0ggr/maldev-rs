pub struct FastCrc32 {
    table: [u32; 256],
}

impl FastCrc32 {
    // Initialize the CRC32 table
    pub fn new() -> Self {
        let mut table = [0u32; 256];
        for i in 0..256 {
            let mut crc = i as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = 0xedb88320 ^ (crc >> 1);
                } else {
                    crc >>= 1;
                }
            }
            table[i as usize] = crc;
        }
        FastCrc32 { table }
    }

    // Compute the CRC32 checksum
    pub fn compute_hash(&self, bytes: &[u8]) -> u32 {
        let mut crc = 0xffffffff;
        for &byte in bytes {
            let index = ((crc as u8) ^ byte) as usize;
            crc = self.table[index] ^ (crc >> 8);
        }
        (crc ^ 0xffffffff) as _
    }
}

pub fn compute_crc32_hash(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    const CRC32_POLYNOMIAL: u32 = 0xEDB88320;

    for byte in data.iter() {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_POLYNOMIAL;
            } else {
                crc >>= 1;
            }
        }
    }

    crc ^ 0xFFFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_fast_crc32_ascii() {
        let crc32 = FastCrc32::new();
        let data = b"_CRC32";
        assert_eq!(crc32.compute_hash(data), 0x7C2DF918u32);
    }

    #[test]
    fn test_compute_crc32_hash() {
        let data = b"_CRC32";
        assert_eq!(compute_crc32_hash(data), 0x7C2DF918u32);
    }
}
