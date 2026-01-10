use crate::to_lowercase;
use crate::traits::{Hasher};

pub struct Crc32 { state: u32 }

impl Hasher for Crc32 {
    fn new(seed: u32) -> Self { Self { state: seed } }
    fn update(&mut self, byte: u8) {
        let cur = byte as u32;
        self.state ^= cur;
        for _ in 0..8 {
            if (self.state & 1) != 0 { self.state = (self.state >> 1) ^ 0xEDB88320; }
            else { self.state >>= 1; }
        }
    }
    fn finalize(&self) -> u32 { !self.state }
}

pub const fn get_crc32_const(s: &str, seed: u32) -> u32 {
    let mut state = seed;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = to_lowercase(bytes[i]);
        let cur = byte as u32;
        state ^= cur;
        let mut bit = 0;
        while bit < 8 {
            if (state & 1) != 0 { state = (state >> 1) ^ 0xEDB88320; }
            else { state >>= 1; }
            bit += 1;
        }
        i += 1;
    }
    !state
}