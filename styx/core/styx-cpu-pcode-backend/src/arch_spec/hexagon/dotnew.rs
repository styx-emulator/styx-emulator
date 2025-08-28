// SPDX-License-Identifier: BSD-2-Clause
// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use log::trace;

use crate::arch_spec::hexagon::parse_iclass;

// This may require some extra stuff
pub fn parse_dotnew(insn: u32) -> Option<u32> {
    let iclass = parse_iclass(insn);

    // want bits 27 to 21
    let insn_0011_type = (insn >> 21) & 0b1111111;
    let insn_0100_type = (insn >> 21) & 0b111;
    let insn_1010_type = (insn >> 22) & 0b111;

    trace!(
        "dotnew: iclass is {iclass:08b}, types 0011 type {insn_0011_type:06b} 0100 type {insn_0100_type:03b} 1010 type {insn_1010_type:03b}",
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
        0b0011
            if insn_0011_type == 0b1011101
                || insn_0011_type == 0b0100101
                || insn_0011_type == 0b0101101
                || insn_0011_type == 0b0110101
                || insn_0011_type == 0b0111101 =>
        {
            Some(bits_12)
        }
        _ => None,
    }
}
