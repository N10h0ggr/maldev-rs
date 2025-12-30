use super::HashAlg;

pub struct Crc32;

impl HashAlg for Crc32 {
    #[inline(always)]
    fn hash(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        let polynomial: u32 = 0xedb88320;

        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (polynomial & mask);
            }
        }

        !crc
    }
}