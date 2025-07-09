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
use styx_emulator::core::macros::enum_mirror;

/// this looks scary but it really isn't
///
/// this is a macro for constructing a single super-enum based on multiple sub-enum declarations
/// This macro is relatively simple:
///
/// ```rust
/// variants_super_enum! {
///   #[derive(Debug, Clone)]
///   enum SuperEnum;
///
///   #[derive(Debug, Clone)]
///   enum SubEnum1 {
///     Var1,
///     Var2
///   }
/// }
/// ```
macro_rules! variants_super_enum {
    (
        $(#[$($attr:tt)*])*
        enum $t:ident;
        $(
            $(#[$($eattr:tt)*])*
            pub enum $n:ident: $kind:ident, $p:ty, $meta_parent:ty {
                $(#[$($vattr:tt)*])*
                $($v:ident),+ $(,)?
            }
        )*
    ) => {
        $(
            $(#[$($eattr)*])*
            pub enum $n {
                $(#[$($vattr)*])*
                $($v),+
            }
        )*

        ::paste::paste! {
            $(#[$($attr)*])*
            pub enum $t {
                $($(
                    [< $n _ $v >],
                )+)*
            }
        }

        ::paste::paste! {
            impl From<$t> for styx_emulator::core::cpu::arch::backends::ArchVariant {
                fn from(value: $t) -> Self {
                    match value {
                        $(
                            $(
                                $t::[< $n _ $v >] => Self::$kind($meta_parent::from($p::$v)),
                            )+
                        )*
                    }
                }
            }
        }
    };
}

variants_super_enum! {
    /// An architecture supported by the styx emulator
    #[allow(non_camel_case_types)]
    #[repr(C)]
    enum StyxArchVariant;

    /// arm variants supported by the styx emulator
    #[enum_mirror(styx_emulator::core::cpu::arch::arm::ArmVariants)]
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub enum ArmVariants:
        Arm,
        styx_emulator::core::cpu::arch::arm::ArmVariants,
        styx_emulator::core::cpu::arch::arm::ArmMetaVariants
    {
        Arm926,
        Arm946,
        Arm1026,
        Arm1136r2,
        Arm1136,
        Arm1176,
        Arm11Mpcore,
        ArmCortexM0,
        ArmCortexM3,
        ArmCortexM4,
        ArmCortexM7,
        ArmCortexM33,
        ArmCortexR5,
        ArmCortexR5F,
        ArmCortexA7,
        ArmCortexA8,
        ArmCortexA9,
        ArmCortexA15,
        ArmTi925T,
        ArmSa1100,
        ArmSa1110,
        ArmPxa250,
        ArmPxa255,
        ArmPxa260,
        ArmPxa261,
        ArmPxa262,
        ArmPxa270,
        ArmPxa270a0,
        ArmPxa270a1,
        ArmPxa270b0,
        ArmPxa270b1,
        ArmPxa270c0,
        ArmPxa270c5,
    }


    /// blackfin variants supported by the styx emulator
    #[enum_mirror(styx_emulator::core::cpu::arch::blackfin::BlackfinVariants)]
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub enum BlackfinVariants:
        Blackfin,
        styx_emulator::core::cpu::arch::blackfin::BlackfinVariants,
        styx_emulator::core::cpu::arch::blackfin::BlackfinMetaVariants
    {
        Bf504,
        Bf504f,
        Bf506f,
        Bf512,
        Bf514,
        Bf516,
        Bf518,
        Bf522,
        Bf523,
        Bf524,
        Bf525,
        Bf526,
        Bf527,
        Bf531,
        Bf532,
        Bf533,
        Bf534,
        Bf535,
        Bf536,
        Bf537,
        Bf538,
        Bf539,
        Bf542,
        Bf542m,
        Bf544,
        Bf544b,
        Bf547,
        Bf548,
        Bf548m,
        Bf561,
        Bf592a,
    }

    /// ppc32 variants supported by the styx emulator
    #[enum_mirror(styx_emulator::core::cpu::arch::ppc32::Ppc32Variants)]
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub enum Ppc32Variants:
        Ppc32,
        styx_emulator::core::cpu::arch::ppc32::Ppc32Variants,
        styx_emulator::core::cpu::arch::ppc32::Ppc32MetaVariants
    {
        // PPC40x family
        Ppc401,
        Ppc405,
        Ppc440,
        Ppc470,
        // PowerQUICC I family
        // https://www.nxp.com/products/processors-and-microcontrollers/legacy-mpu-mcus/powerquicc-processors:POWERQUICC_HOME
        Mpc850,
        Mpc860,
        Mpc866,
        Mpc870,
        Mpc875,
        Mpc880,
        Mpc885,
        Mpc852T,
        Mpc853T,
        Mpc855T,
        Mpc859T,
        // PowerQUICC II family
        // PowerQUICC II PRO family
        // PowerQUICC III family
        // OTHER
        Mpc821,
        Mpc823,
        Mpc823E,
        Mpc857DSL,
        Mpc859DSL,
        Mpc862,
    }

    /// SuperH variants supported by the styx emulator
    #[enum_mirror(styx_emulator::core::cpu::arch::superh::SuperHVariants)]
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub enum SuperHVariants:
        SuperH,
        styx_emulator::core::cpu::arch::superh::SuperHVariants,
        styx_emulator::core::cpu::arch::superh::SuperHMetaVariants
    {
        SH1,
        SH1Dsp,
        SH2,
        SH2A,
        SH2E,
        SH3,
        SH3E,
        SH3Dsp,
        SH4,
        SH4NoFpu,
        SH4A,
        SH4ANoFpu,
        SH4ALDsp,
    }

    /// Mips64 Variants supported by the styx emulator
    #[enum_mirror(styx_emulator::core::cpu::arch::mips64::Mips64Variants)]
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub enum Mips64Variant:
        Mips64,
        styx_emulator::core::cpu::arch::mips64::Mips64Variants,
        styx_emulator::core::cpu::arch::mips64::Mips64MetaVariants
    {
        // mips64 generic
        Mips64R2Generic,
        // R4000 series
        Mips64R4000,
        // R5000 series
        Mips64Vrf5432,
        Mips645kc,
        Mips645kf,
        Mips6420kc,
        Mips645kec,
        Mips645kef,
        // MIPS Warrior I-class
        Mips64I6400,
        Mips64I6500,
        // MIPS Warrior P-class
        Mips64P6600,
        // Loongson
        Mips64Loongson2e,
        Mips64Loongson2f,
        Mips64DspR2,
        // Octeon Plus
        Mips64Cn5520,
        Mips64Cn5530,
        Mips64Cn5534,
        Mips64Cn5640,
        Mips64Cn5645,
        Mips64Cn5650,
        Mips64Cn5740,
        Mips64Cn5745,
        Mips64Cn5750,
        Mips64Cn5830,
        Mips64Cn5840,
        Mips64Cn5850,
        Mips64Cn5860,
        // Octeon II
        Mips64Cn6320,
        Mips64Cn6330,
        Mips64Cn6350,
        Mips64Cn6860,
        Mips64Cn6870,
        Mips64Cn6880,
    }
}
