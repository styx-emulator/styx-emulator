// SPDX-License-Identifier: BSD-2-Clause
use log::trace;

/// Information about the instruction class for each sub-instruction of a duplex instruction.
///
/// This information is available in section 10.2, and specifically table 10-2.
///
/// The slaspec used is unable to lookahead/backtrack on instructions, which requires Styx to separately parse the instruction classes for both
/// sub-instructions within the emulator. Infomation on parsing this is available in table 10-5.
#[derive(Copy, Clone, Debug)]
pub enum DuplexInsClass {
    A = 1,
    L1 = 2,
    L2 = 3,
    S1 = 4,
    S2 = 5,
}

/// Encodes instruction status as End of Packet, duplex, or not end of packet. Also Loop end.
///
/// See section 10.5. Occupies 15:14 of the instruction word.
///
/// By itself from one instruction this only indicates EndofPacket (see enum variant names). If combined as the first and second instructions in a packet you can construct the status of last/not last in a hardware loop. See section 10.6
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum PktLoopParseBits {
    Duplex = 0,
    NotEndOfPacket1 = 1,
    NotEndOfPacket2 = 2,
    EndOfPacket = 3,
    Other,
}

impl From<u8> for PktLoopParseBits {
    fn from(value: u8) -> Self {
        trace!("pkt loop parse bits from {value}");
        match value {
            0 => Self::Duplex,
            1 => Self::NotEndOfPacket1,
            2 => Self::NotEndOfPacket2,
            3 => Self::EndOfPacket,
            _ => Self::Other,
        }
    }
}

impl PktLoopParseBits {
    pub fn new_from_insn(insn_data: u32) -> Self {
        (((insn_data >> 14) & 0b11) as u8).into()
    }
}
