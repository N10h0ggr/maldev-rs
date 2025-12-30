use super::HashAlg;

pub struct Djb2;

impl HashAlg for Djb2 {
    #[inline(always)]
    fn hash(data: &[u8]) -> u32 {
        let mut hash: u32 = 5381;

        for &byte in data {
            // hash * 33 + byte
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u32);
        }

        hash
    }
}