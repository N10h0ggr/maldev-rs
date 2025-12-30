use super::HashAlg;

pub struct Fnv1a;

impl HashAlg for Fnv1a {
    #[inline(always)]
    fn hash(data: &[u8]) -> u32 {
        let mut hash: u32 = 0x811c9dc5;

        for &byte in data {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }

        hash
    }
}