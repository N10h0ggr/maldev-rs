use crate::to_lowercase;
use crate::traits::{Hasher};

pub struct Djb2 { state: u32 }

impl Hasher for Djb2 {
    fn new(seed: u32) -> Self { Self { state: seed } }
    fn update(&mut self, byte: u8) {
        // ((hash << 5) + hash) + byte
        self.state = ((self.state << 5).wrapping_add(self.state)).wrapping_add(byte as u32);
    }
    fn finalize(&self) -> u32 { self.state }
}

pub const fn get_djb2_const(s: &str, seed: u32) -> u32 {
    let mut state = seed;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = to_lowercase(bytes[i]);
        state = ((state << 5).wrapping_add(state)).wrapping_add(byte as u32);
        i += 1;
    }
    state
}