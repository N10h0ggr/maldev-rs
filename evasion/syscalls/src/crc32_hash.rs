pub const fn crc32_const(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut crc = 0xFFFF_FFFF;
    let mut i = 0;

    while i < bytes.len() {
        let byte = bytes[i];
        crc ^= byte as u32;

        let mut j = 0;
        while j < 8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ 0xEDB88320
            } else {
                crc >> 1
            };
            j += 1;
        }
        i += 1;
    }
    !crc
}

pub fn compute_crc32_hash(s: &str) -> u32 {
    crc32_const(s)
}