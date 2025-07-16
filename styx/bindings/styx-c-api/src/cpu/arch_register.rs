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
use styx_emulator::{core::macros::enum_mirror, prelude::anyhow};

use crate::data::{CBool, OpaquePointerType, StyxFFIErrorPtr};

macro_rules! styx_basic_register_impl {
    (
        $(#[$($sattr:tt)*])*
        pub enum $sname:ident;
        $(
            $(#[$($iattr:tt)*])*
            pub enum $iname:ident: $basic_variant:ident($parent_ty:ty) {
                $(
                    $(#[$($vattr:tt)*])*
                    $vname:ident
                ),* $(,)?
            }
        )*
    ) => {
        $(
            $(#[$($iattr)*])*
            pub enum $iname {
                $(
                    $(#[$($vattr)*])*
                    $vname
                ),*
            }
        )*

        ::paste::paste! {
            $(#[$($sattr)*])*
            pub enum $sname {
                $( $( [< $basic_variant _ $vname >], )* )*
            }
        }

        impl From<$sname> for ::styx_emulator::prelude::ArchRegister {
            fn from(value: $sname) -> Self {
                Self::Basic(::styx_emulator::prelude::BasicArchRegister::from(value))
            }
        }

        ::paste::paste! {
            impl From<$sname> for ::styx_emulator::prelude::BasicArchRegister {
                fn from(value: $sname) -> Self {
                    match value {
                        $($(
                            $sname::[< $basic_variant _ $vname >] => Self::$basic_variant($parent_ty::$vname),
                        )*)*
                    }
                }
            }
        }
    };
}

styx_basic_register_impl! {
    #[allow(non_camel_case_types)]
    #[repr(C)]
    #[allow(unused)]
    pub enum StyxRegister;
    #[enum_mirror(styx_emulator::core::cpu::arch::arm::ArmRegister)]
    #[allow(unused)]
    pub enum ArmRegister: Arm(styx_emulator::core::cpu::arch::arm::ArmRegister) {
        Apsr,
        Cpsr,
        Fpexc,
        Fpscr,
        Fpsid,
        Mvfr0,
        Mvfr1,
        Itstate,
        Lr,
        Pc,
        Sp,
        Spsr,
        D0,
        D1,
        D2,
        D3,
        D4,
        D5,
        D6,
        D7,
        D8,
        D9,
        D10,
        D11,
        D12,
        D13,
        D14,
        D15,
        D16,
        D17,
        D18,
        D19,
        D20,
        D21,
        D22,
        D23,
        D24,
        D25,
        D26,
        D27,
        D28,
        D29,
        D30,
        D31,
        Q0,
        Q1,
        Q2,
        Q3,
        Q4,
        Q5,
        Q6,
        Q7,
        Q8,
        Q9,
        Q10,
        Q11,
        Q12,
        Q13,
        Q14,
        Q15,
        R0,
        R1,
        R2,
        R3,
        R4,
        R5,
        R6,
        R7,
        R8,
        R9,
        R10,
        R11,
        R12,
        S0,
        S1,
        S2,
        S3,
        S4,
        S5,
        S6,
        S7,
        S8,
        S9,
        S10,
        S11,
        S12,
        S13,
        S14,
        S15,
        S16,
        S17,
        S18,
        S19,
        S20,
        S21,
        S22,
        S23,
        S24,
        S25,
        S26,
        S27,
        S28,
        S29,
        S30,
        S31,
        Ipsr,
        Msp,
        Psp,
        Control,
        Iapsr,
        Eapsr,
        Xpsr,
        Epsr,
        Iepsr,
        Primask,
        Basepri,
        Faultmask,
        /// Backends should alias this to R9 under the hood
        /// (if supported)
        Sb,
        /// Backends should alias this to R10 under the hood
        /// (if supported)
        Sl,
        /// Backends should alias this to R11 under the hood
        /// (if supported)
        Fp,
        /// Backends should alias this to R12 under the hood
        /// (if supported)
        Ip,
        /// Backends should alias this to SP under the hood
        /// (if supported)
        R13,
        /// Backends should alias this to LR under the hood
        /// (if supported)
        R14,
        /// Backends should alias this to PC under the hood
        /// (if supported)
        R15,
    }

    #[enum_mirror(styx_emulator::core::cpu::arch::ppc32::Ppc32Register)]
    #[repr(C)]
    #[allow(unused)]
    pub enum Ppc32Register: Ppc32(styx_emulator::core::cpu::arch::ppc32::Ppc32Register) {
        R0,
        R1,
        R2,
        R3,
        R4,
        R5,
        R6,
        R7,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        R16,
        R17,
        R18,
        R19,
        R20,
        R21,
        R22,
        R23,
        R24,
        R25,
        R26,
        R27,
        R28,
        R29,
        R30,
        R31,
        /// Program Counter
        Pc,
        /// Machine State Register
        Msr,
        Cr0,
        Cr1,
        Cr2,
        Cr3,
        Cr4,
        Cr5,
        Cr6,
        Cr7,
        /// Condition Register
        Cr,
        /// Link Register
        Lr,
        /// Count Register
        Ctr,
        /// Fixed-Point Exception Register
        Xer,
        /// Time Base Lower (userspace read-only)
        TblR,
        /// Time Base Upper (userspace read-only)
        TbuR,
        /// Time Base Lower (supervisor read/write)
        TblW,
        /// Time Base Upper (userspace read/write)
        TbuW,
        /// Timer Control Register
        Tcr,
        /// Timer Status Register
        Tsr,
        /// Programmable Interval Timer,
        Pit,
        /// Debug Status Register
        Dbsr,
        /// Debug Control Register 0
        Dbcr0,
        /// Debug Control Register 1
        Dbcr1,
        /// Data Address Compare 1
        Dac1,
        /// Data Address Compare 2
        Dac2,
        /// Data Value Compare 1
        Dvc1,
        /// Data Value Compare 2
        Dvc2,
        /// Instruction Address Compare 1
        Iac1,
        /// Instruction Address Compare 2
        Iac2,
        /// Instruction Address Compare 3
        Iac3,
        /// Instruction Address Compare 4
        Iac4,
        /// Instruction Cache Debug Data Register
        Icdbr,
        /// Data Cache Control Register
        Dccr,
        /// Data Cache Write-through Register
        Dcwr,
        /// Instruction Cache Control Register
        Iccr,
        /// Storage Guarded Register
        Sgr,
        /// Storage Little-Endian Register
        Sler,
        /// Supervisor User 0 Register
        Su0r,
        /// Core Configuration Register
        Ccr0,
        /// SPR General Register 0
        Sprg0,
        /// SPR General Register 1
        Sprg1,
        /// SPR General Register 2
        Sprg2,
        /// SPR General Register 3
        Sprg3,
        /// SPR General Register 4
        Sprg4,
        /// SPR General Register 5
        Sprg5,
        /// SPR General Register 6
        Sprg6,
        /// SPR General Register 7
        Sprg7,
        /// Exception Vector Prefix Register
        Evpr,
        /// Exception Syndrome Register
        Esr,
        /// Data Exception Address Register
        Dear,
        /// Save/Restore Register 0
        SRR0,
        /// Save/Restore Register 1
        SRR1,
        /// Save/Restore Register 2
        SRR2,
        /// Save/Restore Register 3
        SRR3,
        /// Process ID
        Pid,
        /// Zone Protection Register
        Zpr,
        /// Processor Version Register,
        Pvr,
        Fpr0,
        Fpr1,
        Fpr2,
        Fpr3,
        Fpr4,
        Fpr5,
        Fpr6,
        Fpr7,
        Fpr8,
        Fpr9,
        Fpr10,
        Fpr11,
        Fpr12,
        Fpr13,
        Fpr14,
        Fpr15,
        Fpr16,
        Fpr17,
        Fpr18,
        Fpr19,
        Fpr20,
        Fpr21,
        Fpr22,
        Fpr23,
        Fpr24,
        Fpr25,
        Fpr26,
        Fpr27,
        Fpr28,
        Fpr29,
        Fpr30,
        Fpr31,
        Fpscr,
    }

    #[enum_mirror(styx_emulator::core::cpu::arch::blackfin::BlackfinRegister)]
    #[repr(C)]
    #[allow(unused)]
    pub enum BlackfinRegister: Blackfin(styx_emulator::core::cpu::arch::blackfin::BlackfinRegister) {
        Pc,
        R0,
        R1,
        R2,
        R3,
        R4,
        R5,
        R6,
        R7,
        P0,
        P1,
        P2,
        P3,
        P4,
        P5,
        Sp,
        Fp,
        I0,
        I1,
        I2,
        I3,
        L0,
        L1,
        L2,
        L3,
        B0,
        B1,
        B2,
        B3,
        M0,
        M1,
        M2,
        M3,
        A0,
        /// Top 8 bits of A0
        A0x,
        /// Bottom 32 bits of A0
        A0w,
        /// Top 8 bits of A1
        A1x,
        /// Bottom 32 bits of A1
        A1w,
        A1,
        LC0,
        LC1,
        LT0,
        LT1,
        LB0,
        LB1,
        /// Arithmetic Status Register
        ASTAT,
        /// ASTAT register fields
        CCflag,
        AZflag,
        ANflag,
        AQflag,
        RndModflag,
        AC0flag,
        AC1flag,
        AV0flag,
        AV0Sflag,
        AV1flag,
        AV1Sflag,
        Vflag,
        VSflag,
        RETI,
        RETN,
        RETX,
        RETE,
        RETS,
    }

    #[enum_mirror(styx_emulator::core::cpu::arch::superh::SuperHRegister)]
    #[repr(C)]
    #[allow(unused)]
    pub enum SuperHRegister: SuperH(styx_emulator::core::cpu::arch::superh::SuperHRegister) {
        R0,
        R1,
        R2,
        R3,
        R4,
        R5,
        R6,
        R7,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        Pc,
        Pr,
        Gbr,
        Vbr,
        Mach,
        Macl,
        Sr,
        Fpul,
        Fpscr,
        Fr0,
        Fr1,
        Fr2,
        Fr3,
        Fr4,
        Fr5,
        Fr6,
        Fr7,
        Fr8,
        Fr9,
        Fr10,
        Fr11,
        Fr12,
        Fr13,
        Fr14,
        Fr15,
        Ibcr,
        Ibnr,
        Tbr,
        Dr0,
        Dr2,
        Dr4,
        Dr6,
        Dr8,
        Dr10,
        Dr12,
        Dr14,
        // SH DSP specific registers
        Dsr,
        A0g,
        A0,
        A1g,
        A1,
        M0,
        M1,
        X0,
        X1,
        Y0,
        Y1,
        Mod,
        Rs,
        Re,
        // SH2A specific bank registers
        /// Pseudo register, only accessible via the GDB interface
        Bank,
        R0b,
        R1b,
        R2b,
        R3b,
        R4b,
        R5b,
        R6b,
        R7b,
        R8b,
        R9b,
        R10b,
        R11b,
        R12b,
        R13b,
        R14b,
        Pcb,
        Prb,
        Gbrb,
        Vbrb,
        Machb,
        Maclb,
        Ivnb,
        // SH3 specific registers
        Ssr,
        Spc,
        R0b0,
        R1b0,
        R2b0,
        R3b0,
        R4b0,
        R5b0,
        R6b0,
        R7b0,
        R0b1,
        R1b1,
        R2b1,
        R3b1,
        R4b1,
        R5b1,
        R6b1,
        R7b1,
        // Sh4 specific registers
        Fv0,
        Fv4,
        Fv8,
        Fv12,
    }

    #[enum_mirror(styx_emulator::core::cpu::arch::mips64::Mips64Register)]
    #[repr(C)]
    #[allow(unused)]
    pub enum Mips64Register: Mips64(styx_emulator::core::cpu::arch::mips64::Mips64Register) {
        R0,
        R1,
        R2,
        R3,
        R4,
        R5,
        R6,
        R7,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        R16,
        R17,
        R18,
        R19,
        R20,
        R21,
        R22,
        R23,
        R24,
        R25,
        R26,
        R27,
        R28,
        R29,
        R30,
        R31,
        Hi,
        Lo,
        Pc,
        F0,
        F1,
        F2,
        F3,
        F4,
        F5,
        F6,
        F7,
        F8,
        F9,
        F10,
        F11,
        F12,
        F13,
        F14,
        F15,
        F16,
        F17,
        F18,
        F19,
        F20,
        F21,
        F22,
        F23,
        F24,
        F25,
        F26,
        F27,
        F28,
        F29,
        F30,
        F31,
        Fir,
        Fccr,
        Fexr,
        Fenr,
        Fcsr,

        //
        // start DSP registers
        //
        Ac0,
        Ac1,
        Ac2,
        Ac3,
        Hi0,
        Hi1,
        Hi2,
        Hi3,
        Lo0,
        Lo1,
        Lo2,
        Lo3,
        /// DSP Control Register
        DSPControl,
        //
        // end DSP registers
        //

        //
        // start cnMIPS (Cavium) extension registers
        //
        /// (cnMIPS) Multiplier 0
        Mpl0,
        /// (cnMIPS) Multiplier 1
        Mpl1,
        /// (cnMIPS) Multiplier 2
        Mpl2,
        /// (cnMIPS) Product 0
        P0,
        /// (cnMIPS) Product 1
        P1,
        /// (cnMIPS) Product 2
        P2,
        /// (cnMIPS) CRC32 IV
        CrcIV,
        /// (cnMIPS) CRC32 Polynomial
        CrcPoly,
        /// (cnMIPS) CRC32 Length (Number of bytes to add)
        CrcLen,
        //
        // start cnMIPS+Crypto registers (present in the -SSP cpu models)
        //
        // cnMIPS Galois Field Multiplier instructions
        /// (cnMIPS) GFM Multiplier
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        GfmMul,
        /// (cnMIPS) GFM Result/Input
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        GfmResInp,
        /// (cnMIPS) GFM Polynomial
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        GfmPoly,
        /// (cnMIPS) Hash Input Data
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        HashDat,
        /// (cnMIPS) Hash IV
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        HashIV,
        /// (cnMIPS) 3DES Key
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        ThreeDESKey,
        /// (cnMIPS) 3DES IV
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        ThreeDESIV,
        /// (cnMIPS) 3DES Result
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        ThreeDESResult,
        /// (cnMIPS) AES Key
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        AesKey,
        /// (cnMIPS) AES Key Length Indicator
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        AesKeyLen,
        /// (cnMIPS) AES IV
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        AesIV,
        /// (cnMIPS) AES Result/Input
        /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
        AesResInp,
        //
        // end cnMIPS+Crypto
        //
        /// (cnMIPS) Local Scratchpad Memory
        CvmsegLm,
        //
        // end cnMIPS (Cavium) extension registers
    }
}

fn _keep_special_registers_in_sync(reg: styx_emulator::prelude::SpecialArchRegister) {
    use styx_emulator::prelude::SpecialArchRegister;

    fn yes_i_added_it<T: OpaquePointerType>() {}

    use styx_emulator::core::cpu::arch::arm::SpecialArmRegister;
    use styx_emulator::core::cpu::arch::ppc32::SpecialPpc32Register;
    match reg {
        SpecialArchRegister::Arm(reg) => match reg {
            SpecialArmRegister::CoProcessor(_) => {
                yes_i_added_it::<StyxRegister_ArmCoProcessorDesc_t>()
            }
        },
        SpecialArchRegister::Ppc32(reg) => match reg {
            SpecialPpc32Register::SprRegister(_) => yes_i_added_it::<StyxRegister_Ppc32SprDesc_t>(),
        },
        SpecialArchRegister::Blackfin(_) => {}
        SpecialArchRegister::SuperH(_) => {}
        SpecialArchRegister::Mips64(_) => {}
        SpecialArchRegister::Msp430(_) => {}
        SpecialArchRegister::Msp430X(_) => {}
    };
}

crate::data::opaque_pointer! {
    pub struct StyxRegister_ArmCoProcessorDesc(styx_emulator::core::cpu::arch::arm::CoProcessor)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn StyxRegister_ArmCoProcessorDesc_new(
    coproc: u32,
    crn: u32,
    crm: u32,
    opcode1: u32,
    opcode2: u32,
    security_state: CBool,
    out: *mut StyxRegister_ArmCoProcessorDesc,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        StyxRegister_ArmCoProcessorDesc::new(styx_emulator::core::cpu::arch::arm::CoProcessor {
            coproc: coproc
                .try_into()
                .map_err(|_| anyhow!("{coproc} not a valid coproc"))?,
            crn: crn
                .try_into()
                .map_err(|_| anyhow!("{crn} not a valid crn"))?,
            crm: crm
                .try_into()
                .map_err(|_| anyhow!("{crm} not a valid crm"))?,
            opc1: opcode1,
            opc2: opcode2,
            secure_state: security_state.into(),
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn StyxRegister_ArmCoProcessorDesc_free(ptr: *mut StyxRegister_ArmCoProcessorDesc) {
    StyxRegister_ArmCoProcessorDesc::free(ptr)
}

crate::data::opaque_pointer! {
    pub struct StyxRegister_Ppc32SprDesc(styx_emulator::core::cpu::arch::ppc32::SprRegister)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn StyxRegister_Ppc32SprDesc_new(
    index: u16,
    out: *mut StyxRegister_Ppc32SprDesc,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        StyxRegister_Ppc32SprDesc::new(
            styx_emulator::core::cpu::arch::ppc32::SprRegister::new(index)
                .ok_or_else(|| anyhow!("Invalid PowerPC32 Special Register index: {index}"))?,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn StyxRegister_Ppc32SprDesc_free(ptr: *mut StyxRegister_Ppc32SprDesc) {
    StyxRegister_Ppc32SprDesc::free(ptr)
}
