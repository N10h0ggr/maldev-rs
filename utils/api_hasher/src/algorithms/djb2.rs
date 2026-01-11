pub struct Djb2;

impl Djb2 {
    #[inline(always)]
    pub const fn hash(data: &[u8]) -> u32 {
        let mut hash: u32 = 5381;
        let mut i = 0;
        while i < data.len() {
            // Normalize byte to lowercase for case-insensitivity
            let b = crate::algorithms::normalize_byte(data[i]);

            // hash * 33 + c
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u32);
            i += 1;
        }
        hash
    }
}