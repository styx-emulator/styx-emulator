use log::trace;

// This may require some extra stuff
pub fn parse_dotnew(insn: u32) -> Option<u32> {
    let iclass = (insn >> 28) & 0xf;

    // want bits 27 to 21
    let insn_0011_type = (insn >> 21) & 0b1111111;
    let insn_0100_type = (insn >> 21) & 0b111;
    let insn_1010_type = (insn >> 22) & 0b111;

    trace!(
        "dotnew: iclass is {:08b}, types 0011 type {:06b} 0100 type {:03b} 1010 type {:03b}",
        iclass,
        insn_0011_type,
        insn_0100_type,
        insn_1010_type,
    );

    // in a new-value instruction, there is a field Nt that exists.
    // It's bits 0 1 2 for iclass 0011
    // It's bits 8 9 10 for iclass 0100 and 1010
    // The lower bit in this 3-bit data section is reserved, so ignore it
    let bits_12 = (insn >> 1) & 0b11;
    let bits_910 = (insn >> 9) & 0b11;

    match iclass {
        0b1010 if insn_1010_type == 0b110 => Some(bits_910),
        0b0100 if insn_0100_type == 0b101 => Some(bits_910),
        0b0011 if insn_0011_type == 0b1011101 || insn_0011_type == 0b0100101 => Some(bits_12),
        _ => None,
    }
}
