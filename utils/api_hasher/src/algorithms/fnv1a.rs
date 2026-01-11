pub struct Fnv1a;

impl Fnv1a {
    #[inline(always)]
    pub const fn hash(data: &[u8]) -> u32 {
        let mut hash: u32 = 0x811c9dc5;
        let mut i = 0;
        while i < data.len() {
            let b = crate::algorithms::normalize_byte(data[i]);

            hash ^= b as u32;
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        hash
    }
}