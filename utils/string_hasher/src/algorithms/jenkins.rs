use crate::to_lowercase;
use crate::traits::{Hasher};

pub struct Jenkins { state: u32 }

impl Hasher for Jenkins {
    fn new(seed: u32) -> Self { Self { state: seed } }
    fn update(&mut self, byte: u8) {
        self.state = self.state.wrapping_add(byte as u32);
        self.state = self.state.wrapping_add(self.state << 10);
        self.state ^= self.state >> 6;
    }
    fn finalize(&self) -> u32 {
        let mut h = self.state;
        h = h.wrapping_add(h << 3);
        h ^= h >> 11;
        h = h.wrapping_add(h << 15);
        h
    }
}

pub const fn get_jenkins_const(s: &str, seed: u32) -> u32 {
    let mut state = seed;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = to_lowercase(bytes[i]);
        state = state.wrapping_add(byte as u32);
        state = state.wrapping_add(state << 10);
        state ^= state >> 6;
        i += 1;
    }
    let mut h = state;
    h = h.wrapping_add(h << 3);
    h ^= h >> 11;
    h = h.wrapping_add(h << 15);
    h
}