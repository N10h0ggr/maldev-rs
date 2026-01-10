use crate::to_lowercase;
use crate::traits::{Hasher};

pub struct Sdbm { state: u32 }

impl Hasher for Sdbm {
    fn new(seed: u32) -> Self { Self { state: seed } }
    fn update(&mut self, byte: u8) {
        // hash = byte + (hash << 6) + (hash << 16) - hash;
        let b = byte as u32;
        self.state = b.wrapping_add(self.state << 6)
            .wrapping_add(self.state << 16)
            .wrapping_sub(self.state);
    }
    fn finalize(&self) -> u32 { self.state }
}

pub const fn get_sdbm_const(s: &str, seed: u32) -> u32 {
    let mut state = seed;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = to_lowercase(bytes[i]);
        let b = byte as u32;
        state = b.wrapping_add(state << 6)
            .wrapping_add(state << 16)
            .wrapping_sub(state);
        i += 1;
    }
    state
}