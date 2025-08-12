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
//! Generic top level container for Hexagon registers
use std::collections::HashMap;
use std::num::NonZeroUsize;
use strum::IntoEnumIterator;

use crate::arch::{CpuRegister, RegisterValue};
use crate::macros::*;

// Hexagon seems to always be 32-bit as of now, so
// there's not really much point in distinguishing here.
//
// NOTE: If you rename any registers here, you must update the mapping
// in styx-sla/src/lib.rs
create_basic_register_enums!(
    Hexagon,
    // Registers definitions are found here:
    // https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/Hexagon/HexagonRegisterInfo.td

    // General purpose registers
    (R0, 32),
    (R1, 32),
    (R2, 32),
    (R3, 32),
    (R4, 32),
    (R5, 32),
    (R6, 32),
    (R7, 32),
    (R8, 32),
    (R9, 32),
    (R10, 32),
    (R11, 32),
    (R12, 32),
    (R13, 32),
    (R14, 32),
    (R15, 32),
    (R16, 32),
    (R17, 32),
    (R18, 32),
    (R19, 32),
    (R20, 32),
    (R21, 32),
    (R22, 32),
    (R23, 32),
    (R24, 32),
    (R25, 32),
    (R26, 32),
    (R27, 32),
    (R28, 32),
    (Sp, 32), // Stack pointer: alias to R29
    (Fp, 32), // Frame pointer: alias to R30
    (Lr, 32), // Link register: aliias to R31
    // Aliases of R* registers (combined to store 64 bit values)
    // P-Code backend typically aliases reg Dn to R<(n*2)+1><n*2>
    // Eg. D8 is R17R16
    (D0, 64),
    (D1, 64),
    (D2, 64),
    (D3, 64),
    (D4, 64),
    (D5, 64),
    (D6, 64),
    (D7, 64),
    (D8, 64),
    (D9, 64),
    (D10, 64),
    (D11, 64),
    (D12, 64),
    (D13, 64),
    (D14, 64),
    (D15, 64),
    // Predicate registers
    (P0, 8),
    (P1, 8),
    (P2, 8),
    (P3, 8),
    // Destination predicate registers, need to delineate these for predicate ANDing
    (DestP0, 8),
    (DestP1, 8),
    (DestP2, 8),
    (DestP3, 8),
    // Control registers
    (Sa0, 32),  // Alias to C0
    (Lc0, 32),  // Alias to C1
    (Sa1, 32),  // Alias to C2
    (Lc1, 32),  // Alias to C3
    (P3_0, 32), // Alias to C4
    (C5, 32),
    (M0, 32),         // Alias to C6
    (M1, 32),         // Alias to C7
    (Usr, 32),        // User status register, Alias to C8
    (Pc, 32),         // Alias to C9
    (Ugp, 32),        // Alias to C10
    (Gp, 32),         // Alias to C11
    (Cs0, 32),        // Alias to C12
    (Cs1, 32),        // Alias to C13
    (UpcycleLo, 32),  // Alias to C14
    (UpcycleHi, 32),  // Alias to C15
    (FrameLimit, 32), // Alias to C16
    (FrameKey, 32),   // Alias to C17
    (PktCountLo, 32), // Alias to C18
    (PktCountHi, 32), // Alias to C19
    // These registers seem to be undocumented/reserved!!
    (EmuPktCount, 32), // C20, From QEMU definitions: hex_regs.h and cpu.c's hexagon_regnmaes
    (EmuInsnCount, 32), // C21, From QEMU: see above
    (EmuHvxCount, 32), // C22, From QEMU: see above
    (C23, 32),
    (C24, 32),
    (C25, 32),
    (C26, 32),
    (C27, 32),
    (C28, 32),
    (C29, 32),
    (UtimerLo, 32), // Alias to C30
    (UtimerHi, 32), // Alias to C31
    // Control register pairs
    (C1C0, 64),
    (C3C2, 64),
    (C5C4, 64),
    (C7C6, 64),
    (C9C8, 64),
    (C11C10, 64),
    (Cs, 64),       // Alias to C13C12
    (Upcycle, 64),  // Alias to C15C14
    (C17C16, 64),   // Alias to C17C16
    (PktCount, 64), // Alias to C19C18
    (Utimer, 64),   // Alias to C31C30
    // Skipping HVX extensions for now
    // System registers
    (Sgp0, 32),    // S0
    (Sgp1, 32),    // S1
    (Stid, 32),    // S2
    (Elr, 32),     // S3
    (BadVa0, 32),  // S4
    (BadVa1, 32),  // S5
    (Ssr, 32),     // S6
    (Ccr, 32),     // S7
    (Htid, 32),    // S8
    (BadVa, 32),   // S9
    (Imask, 32),   // S10
    (S11, 32),     // S11
    (S12, 32),     // S12
    (S13, 32),     // S13
    (S14, 32),     // S14
    (S15, 32),     // S15
    (Evb, 32),     // S16
    (ModeCtl, 32), // S17
    (SysCfg, 32),  // S18
    (S19, 32),     // S19
    (S20, 32),     // S20
    (Vid, 32),     // S21
    (S22, 32),
    (S23, 32),
    (S24, 32),
    (S25, 32),
    (S26, 32),
    (CfgBase, 32),    // S27
    (Diag, 32),       // S28
    (Rev, 32),        // S29
    (PcycleLo, 32),   // S30
    (PcycleHi, 32),   // S31
    (IsdbSt, 32),     // S32
    (IsdbCfg0, 32),   // S33
    (IsdbCfg1, 32),   // S34
    (S35, 32),        // S35
    (BrkptPc0, 32),   // S36
    (BrkptCfg0, 32),  // S37
    (BrkptPc1, 32),   // S38
    (BrkptCfg1, 32),  // S39
    (IsdbMbxIn, 32),  // S40
    (IsdbMbxOut, 32), // S41
    (IsdbEn, 32),     // S42
    (IsdbGpr, 32),    // S43
    (S44, 32),        // S44
    (S45, 32),        // S45
    (S46, 32),        // S46
    (S47, 32),        // S47
    (PmuCnt0, 32),    // S48
    (PmuCnt1, 32),    // S49
    (PmuCnt2, 32),    // S50
    (PmuCnt3, 32),    // S51
    (PmuEvtCfg, 32),  // S52
    (PmuCfg, 32),     // S53
    (S54, 32),        // S54
    (S55, 32),        // S55
    (S56, 32),        // S56
    (S57, 32),        // S57
    (S58, 32),        // S58
    (S59, 32),        // S59
    (S60, 32),        // S60
    (S61, 32),        // S61
    (S62, 32),        // S62
    (S63, 32),        // S63
    (S64, 32),        // S64
    (S65, 32),        // S65
    (S66, 32),        // S66
    (S67, 32),        // S67
    (S68, 32),        // S68
    (S69, 32),        // S69
    (S70, 32),        // S70
    (S71, 32),        // S71
    (S72, 32),        // S72
    (S73, 32),        // S73
    (S74, 32),        // S74
    (S75, 32),        // S75
    (S76, 32),        // S76
    (S77, 32),        // S77
    (S78, 32),        // S78
    (S79, 32),        // S79
    (S80, 32),        // S80
    // System register pairs
    (SGP1SGP0, 64),
    (S3S2, 64),
    (S5S4, 64),
    (S7S6, 64),
    (S9S8, 64),
    (S11S10, 64),
    (S13S12, 64),
    (S15S14, 64),
    (S17S16, 64),
    (S19S18, 64),
    (S21S20, 64),
    (S23S22, 64),
    (S25S24, 64),
    (S27S26, 64),
    (S29S28, 64),
    (S31S30, 64),
    (S33S32, 64),
    (S35S34, 64),
    (S37S36, 64),
    (S39S38, 64),
    (S41S40, 64),
    (S43S42, 64),
    (S45S44, 64),
    (S47S46, 64),
    (S49S48, 64),
    (S51S50, 64),
    (S53S52, 64),
    (S55S54, 64),
    (S57S56, 64),
    (S59S58, 64),
    (S61S60, 64),
    (S63S62, 64),
    (S65S64, 64),
    (S67S66, 64),
    (S69S68, 64),
    (S71S70, 64),
    (S73S72, 64),
    (S75S74, 64),
    (S77S76, 64),
    (S79S78, 64),
    // Guest registers
    (Gelr, 32),      // G0
    (Gsr, 32),       // G1
    (Gosp, 32),      // G2
    (G3, 32),        // G3
    (G4, 32),        // G4
    (G5, 32),        // G5
    (G6, 32),        // G6
    (G7, 32),        // G7
    (G8, 32),        // G8
    (G9, 32),        // G9
    (G10, 32),       // G10
    (G11, 32),       // G11
    (G12, 32),       // G12
    (G13, 32),       // G13
    (G14, 32),       // G14
    (G15, 32),       // G15
    (Gpmucnt4, 32),  // G16
    (Gpmucnt5, 32),  // G17
    (Gpmucnt6, 32),  // G18
    (Gpmucnt7, 32),  // G19
    (G20, 32),       // G20
    (G21, 32),       // G21
    (G22, 32),       // G22
    (G23, 32),       // G23
    (Gpcyclelo, 32), // G24
    (Gpcyclehi, 32), // G25
    (Gpmucnt0, 32),  // G26
    (Gpmucnt1, 32),  // G27
    (Gpmucnt2, 32),  // G28
    (Gpmucnt3, 32),  // G29
    (G30, 32),       // G30
    (G31, 32),       // G31
    // Guest register pairs
    (G1G0, 64),
    (G3G2, 64),
    (G5G4, 64),
    (G7G6, 64),
    (G9G8, 64),
    (G11G10, 64),
    (G13G12, 64),
    (G15G14, 64),
    (G17G16, 64),
    (G19G18, 64),
    (G21G20, 64),
    (G23G22, 64),
    (G25G24, 64),
    (G27G26, 64),
    (G29G28, 64),
    (G31G30, 64),
    // TODO: HVX Registers
    // Some info found in Hexagon manuals, and
    // https://chipsandcheese.com/p/qualcomms-hexagon-dsp-and-now-npu
    // Vector data registers: 128 bytes
    (V0, 128),
    (V1, 128),
    (V2, 128),
    (V3, 128),
    (V4, 128),
    (V5, 128),
    (V6, 128),
    (V7, 128),
    (V8, 128),
    (V9, 128),
    (V10, 128),
    (V11, 128),
    (V12, 128),
    (V13, 128),
    (V14, 128),
    (V15, 128),
    (V16, 128),
    (V17, 128),
    (V18, 128),
    (V19, 128),
    (V20, 128),
    (V21, 128),
    (V22, 128),
    (V23, 128),
    (V24, 128),
    (V25, 128),
    (V26, 128),
    (V27, 128),
    (V28, 128),
    (V29, 128),
    (V30, 128),
    (V31, 128),
    // Register pairs for V registers
    // VhiVlo
    (W0, 256),  // V1V0
    (W1, 256),  // V3V2
    (W2, 256),  // V5V4
    (W3, 256),  // V7V6
    (W4, 256),  // V9V8
    (W5, 256),  // V11V10
    (W6, 256),  // V13V12
    (W7, 256),  // V15V14
    (W8, 256),  // V17V16
    (W9, 256),  // V19V18
    (W10, 256), // V21V20
    (W11, 256), // V23V22
    (W12, 256), // V25V24
    (W13, 256), // V27V26
    (W14, 256), // V29V28
    (W15, 256), // V31V30
    // Register pairs for Vector register (reversed)
    // VhiVlo
    (WR0, 256),  // V0V1
    (WR1, 256),  // V2V3
    (WR2, 256),  // V4V5
    (WR3, 256),  // V6V7
    (WR4, 256),  // V8V9
    (WR5, 256),  // V10V11
    (WR6, 256),  // V12V13
    (WR7, 256),  // V14V15
    (WR8, 256),  // V16V17
    (WR9, 256),  // V18V19
    (WR10, 256), // V20V21
    (WR11, 256), // V22V23
    (WR12, 256), // V24V25
    (WR13, 256), // V26V27
    (WR14, 256), // V28V29
    (WR15, 256), // V30V31
    // Registers for quad vectors
    // Comment: V highest ---> lowest, W highest --> lowest
    (VQ0, 512), // V3V2V1V0 or W1W0
    (VQ1, 512), // V7V6V5V4 or W3W2
    (VQ2, 512), // V11V10V9V8 or W5W4
    (VQ3, 512), // V15V14V13V12 or W7W6
    (VQ4, 512), // V19V18V17V16 or W9W8
    (VQ5, 512), // V23V22V21V20 or W11W10
    (VQ6, 512), // V27V26V25V24 or W13W12
    (VQ7, 512), // V31V30V29V28 or W15W14
    // Predicate registers
    (Q0, 128),
    (Q1, 128),
    (Q2, 128),
    (Q3, 128),
);

lazy_static::lazy_static! {
    /// List of all [HexagonRegister]s convert to string and uppercased.
    /// This is done in a [lazy_static::lazy_static] to avoid recomputing every time [HexagonRegister::register()] is called.
    static ref REGISTER_NAMES: HashMap<HexagonRegister, String> =  {
        HexagonRegister::iter()
            .map(|reg| (reg, reg.to_string().to_uppercase()))
            .collect()
    };
}

create_special_register_enums!(Hexagon);

#[cfg(test)]
mod tests {
    use super::*;
    use derive_more::FromStr;

    #[test]
    fn test_regs_from_str() {
        assert_eq!(
            HexagonRegister::R0,
            HexagonRegister::from_str("r0").unwrap()
        );
        assert_eq!(
            HexagonRegister::R1,
            HexagonRegister::from_str("r1").unwrap()
        );
        assert_eq!(
            HexagonRegister::R2,
            HexagonRegister::from_str("r2").unwrap()
        );
        assert_eq!(
            HexagonRegister::Pc,
            HexagonRegister::from_str("Pc").unwrap()
        );
        assert_eq!(
            HexagonRegister::Pc,
            HexagonRegister::from_str("pc").unwrap()
        );
        assert_eq!(
            HexagonRegister::Lr,
            HexagonRegister::from_str("Lr").unwrap()
        );
        assert_eq!(
            HexagonRegister::Lr,
            HexagonRegister::from_str("lr").unwrap()
        );
        assert_eq!(
            HexagonRegister::SysCfg,
            HexagonRegister::from_str("Syscfg").unwrap()
        );
        assert_eq!(
            HexagonRegister::SysCfg,
            HexagonRegister::from_str("syscfg").unwrap()
        );
    }
}
