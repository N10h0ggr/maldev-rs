pub struct Crc32;

impl Crc32 {
    #[inline(always)]
    pub const fn hash(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        let polynomial: u32 = 0xedb88320;

        let mut i = 0;
        while i < data.len() {
            let b = crate::algorithms::normalize_byte(data[i]);

            crc ^= b as u32;
            let mut j = 0;
            while j < 8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (polynomial & mask);
                j += 1;
            }
            i += 1;
        }
        !crc
    }
}