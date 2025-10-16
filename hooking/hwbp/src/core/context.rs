/// Modifies a specific range of bits in the DR7 register.
///
/// # Parameters
/// - `current_dr7`: The current DR7 register value.
/// - `start_bit`: The starting bit position (0-indexed, from least significant bit).
/// - `num_bits`: The number of consecutive bits to modify starting at `start_bit`.
/// - `new_value`: The new bit value(s) to set in that range.
///
/// # Returns
/// The updated DR7 register value with the modified bits.
pub fn set_dr7_bits(current_dr7: u64, start_bit: u8, num_bits: u8, new_value: u64) -> u64 {
    // Create a bitmask of `num_bits` ones (e.g., num_bits=3 to 0b111)
    let mask = (1u64 << num_bits) - 1u64;

    // Clear the bits at the target range, then set them to the new value
    (current_dr7 & !(mask << start_bit)) | ((new_value & mask) << start_bit)
}