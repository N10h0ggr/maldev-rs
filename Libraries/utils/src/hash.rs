pub struct Crc32 {
    table: [u32; 256],
}

impl Crc32 {
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
        Crc32 { table }
    }

    // Compute the CRC32 checksum
    pub fn compute_hash(&self, bytes: &[u8]) -> u32 {
        let mut crc = 0xffffffff;
        for &byte in bytes {
            let index = ((crc as u8) ^ byte) as usize;
            crc = self.table[index] ^ (crc >> 8);
        }
        crc ^ 0xffffffff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_crc32_ascii() {
        let crc32 = Crc32::new();
        let data = b"_CRC32";
        assert_eq!(crc32.compute_hash(data), 0x7C2DF918);
    }
}
