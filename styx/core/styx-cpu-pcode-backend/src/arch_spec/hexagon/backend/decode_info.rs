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

/// Hardware loop status. This is a context option in our slaspec, that indicates to the slaspec
/// that the current packet is the end of a hardware loop. Depending on whether or not hardware loop 0, hardware loop 1,
/// or both loops are run, different hardware loop counter registers are reset. The context option "endloop" indicates which
/// loop ends. The enum contains these options
///
/// Determining which loop is being ended depends on the first two instructions in the packet. See Table 10-7 for reference
/// and HardwareLoopStatus::parse for implementation.
///
/// This is repr(u32) because context options are u32s.
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum HardwareLoopStatus {
    NotLastInLoop = 0,
    LastInLoop0 = 1,
    LastInLoop1 = 2,
    LastInBothLoops = 3,
}

impl HardwareLoopStatus {
    /// Parse hardware loop from first 2 instructions in packet and LC0/LC1 register values.
    /// See Table 10-7, and Section 8.2. We use LC0 and LC1 to detect whether we are at all in a loop,
    /// since when LC0/LC1 are set to greater than 1 a loop is currently executing.
    pub fn parse(
        lc0: u32,
        lc1: u32,
        parse_now: PktLoopParseBits,
        parse_next: PktLoopParseBits,
    ) -> Option<Self> {
        // check for hardware loop
        // check if lc0/lc1 is greater than 1, since
        // a hwloop terminates when lc0/lc1 == 1
        // so it will never get set to zero after the hwloop executes
        trace!("hwloop help: lc0 {lc0} lc1 {lc1}");

        if lc0 > 1 || lc1 > 1 {
            // last in loop 1
            Some(
                if parse_now == PktLoopParseBits::NotEndOfPacket1
                    && parse_next == PktLoopParseBits::NotEndOfPacket2
                {
                    trace!("hwloop help: last in loop 1");
                    Self::LastInLoop1
                }
                // last in loop 0
                else if parse_now == PktLoopParseBits::NotEndOfPacket2
                    && (parse_next == PktLoopParseBits::NotEndOfPacket1
                    || parse_next == PktLoopParseBits::EndOfPacket
                    // Is this undocumented? the assembler will happily make endloop0
                    // spit out a duplex as last instruction, but
                    // this case isn't covered in the manual AFAICT.
                    // Endloop1 and 01 are fine since they must be padded with at least 2 nops.
                    || parse_next == PktLoopParseBits::Duplex)
                {
                    trace!("hwloop help: last in loop 0");
                    Self::LastInLoop0
                }
                // last in loop 0 and 1
                else if parse_now == PktLoopParseBits::NotEndOfPacket2
                    && parse_next == PktLoopParseBits::NotEndOfPacket2
                {
                    trace!("hwloop help: last in loop 0 and loop 1");
                    Self::LastInBothLoops
                }
                // not last pkt in loop
                else {
                    trace!("hwloop help: not the last packet in a hwloop");
                    Self::NotLastInLoop
                },
            )
        } else {
            None
        }
    }
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
