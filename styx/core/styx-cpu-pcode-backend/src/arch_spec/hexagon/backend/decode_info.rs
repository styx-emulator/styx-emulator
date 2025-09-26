// SPDX-License-Identifier: BSD-2-Clause
use arbitrary_int::*;
use bitbybit::{bitenum, bitfield};
use derive_more::derive::{BitAnd, BitOr, Shr};
use log::trace;

/// Some common parsing functionality for Hexagon instructions
/// This information comes from Table 10-4 in the Hexagon manual.
#[bitfield(u32)]
#[derive(Debug, Shr, PartialEq, BitAnd, BitOr)]
pub struct GeneralHexagonInstruction {
    #[bits([0..=13,16..=27] r)]
    reserved: u26,
    #[bits(14..=15, r)]
    parse: PktLoopParseBits,
    #[bits(28..=31, r)]
    nonduplex_iclass: Iclass,
    /// Table 10-4 in the Hexagon manual indicates that the ICLASS field in a Hexagon instruction
    /// is split to comprise of bits 31:29 as the high 3 bits and bit 13 as the lowest bit for duplexes.
    #[bits([13, 29..=31], r)]
    duplex_iclass: u4,
}

/// The non-duplex iclass values for Hexagon
///
/// The following information comes from QEMU's target/hexagon/imported/iclass.def
/// and section 10.4 of the Hexagon manual
#[bitenum(u4, exhaustive = true)]
#[derive(PartialEq)]
pub enum Iclass {
    Immext = 0b0000,
    Jump1 = 0b0001,
    Jump2 = 0b0010,
    IclassLoadStore = 0b0011,
    IclassConditionalGPLoadStore = 0b0100,
    Jump3 = 0b0101,
    Cr = 0b0110,
    Alu32_1 = 0b0111,
    XType1 = 0b1000,
    IclassLoad = 0b1001,
    IclassStore = 0b1010,
    Alu32_2 = 0b1011,
    XType2 = 0b1100,
    XType3 = 0b1101,
    XType4 = 0b1110,
    Alu32_3 = 0b1111,
}

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

/// Hardware loop status. This is a context option in our slaspec, that indicates to the slaspec
/// that the current packet is the end of a hardware loop. Depending on whether or not hardware loop 0, hardware loop 1,
/// or both loops are run, different hardware loop counter registers are reset. The context option "endloop" indicates which
/// packet ends a loop. The enum contains these options. The SLASPEC uses this context option to choose whether to continue the
/// loop by branching to the beginning, or fall through to whatever comes after the loop.
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

/// Encodes instruction status as End of Packet, duplex, or not end of packet. Also Loop end.
///
/// See section 10.5. Occupies 15:14 of the instruction word.
///
/// By itself from one instruction this only indicates EndofPacket (see enum variant names). If combined as the first and second instructions in a packet you can construct the status of last/not last in a hardware loop. See section 10.6
#[bitenum(u2, exhaustive = true)]
#[derive(Debug, PartialEq)]
pub enum PktLoopParseBits {
    Duplex = 0b00,
    NotEndOfPacket1 = 0b01,
    NotEndOfPacket2 = 0b10,
    EndOfPacket = 0b11,
}
