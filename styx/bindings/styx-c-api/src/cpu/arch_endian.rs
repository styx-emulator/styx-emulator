// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::core::macros::enum_mirror;

/// The order of bytes within a word of data
#[enum_mirror(styx_emulator::core::cpu::ArchEndian)]
#[repr(C)]
pub enum StyxArchEndian {
    /// The MSB is the leftmost bit
    LittleEndian,
    /// The MSB is the rightmost bit
    BigEndian,
}
