use crate::to_lowercase;
use crate::traits::{Hasher};

pub struct Fnv1a { state: u32 }

impl Hasher for Fnv1a {
    fn new(seed: u32) -> Self {
        // FNV offset basis is usually 0x811c9dc5, we mix in the seed
        Self { state: 0x811c9dc5 ^ seed }
    }
    fn update(&mut self, byte: u8) {
        self.state ^= byte as u32;
        self.state = self.state.wrapping_mul(0x01000193); // FNV prime
    }
    fn finalize(&self) -> u32 { self.state }
}

pub const fn get_fnv1a_const(s: &str, seed: u32) -> u32 {
    let mut state = 0x811c9dc5 ^ seed;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = to_lowercase(bytes[i]);
        state ^= byte as u32;
        state = state.wrapping_mul(0x01000193);
        i += 1;
    }
    state
}