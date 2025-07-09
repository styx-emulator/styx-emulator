// SPDX-License-Identifier: BSD-2-Clause
use pyo3::{exceptions::PyTypeError, pyclass, types::PyAnyMethods, Bound, FromPyObject};
use pyo3_stub_gen::{derive::*, PyStubType, TypeInfo};
use std::collections::HashSet;
use styx_emulator::prelude::enum_mirror;

#[allow(non_camel_case_types)]
#[derive(FromPyObject)]
pub enum ArchVariant<'py> {
    Arm(Bound<'py, ArmVariant>),
    Blackfin(Bound<'py, BlackfinVariant>),
    Mips64(Bound<'py, Mips64Variant>),
    Ppc32(Bound<'py, Ppc32Variant>),
    SuperH(Bound<'py, SuperHVariant>),
}

pyo3_stub_gen::impl_stub_type!(
    ArchVariant<'_> = ArmVariant | BlackfinVariant | Ppc32Variant | SuperHVariant | Mips64Variant
);

impl From<ArchVariant<'_>> for styx_emulator::prelude::ArchVariant {
    fn from(value: ArchVariant<'_>) -> Self {
        match value {
            ArchVariant::Arm(v) => styx_emulator::prelude::ArchVariant::Arm(
                styx_emulator::core::cpu::arch::arm::ArmVariants::from(*v.borrow()).into(),
            ),
            ArchVariant::Blackfin(v) => styx_emulator::prelude::ArchVariant::Blackfin(
                styx_emulator::core::cpu::arch::blackfin::BlackfinVariants::from(*v.borrow())
                    .into(),
            ),
            ArchVariant::Ppc32(v) => styx_emulator::prelude::ArchVariant::Ppc32(
                styx_emulator::core::cpu::arch::ppc32::Ppc32Variants::from(*v.borrow()).into(),
            ),
            ArchVariant::SuperH(v) => styx_emulator::prelude::ArchVariant::SuperH(
                styx_emulator::core::cpu::arch::superh::SuperHVariants::from(*v.borrow()).into(),
            ),
            ArchVariant::Mips64(v) => styx_emulator::prelude::ArchVariant::Mips64(
                styx_emulator::core::cpu::arch::mips64::Mips64Variants::from(*v.borrow()).into(),
            ),
        }
    }
}

// TODO: ArchVariant extractor

#[enum_mirror(styx_emulator::core::cpu::arch::arm::ArmVariants)]
#[gen_stub_pyclass_enum]
#[pyclass(eq, frozen, module = "arch.arm")]
#[derive(PartialEq, Clone, Copy)]
pub enum ArmVariant {
    Arm1026,
    Arm1136,
    Arm1136r2,
    Arm1176,
    Arm11Mpcore,
    Arm926,
    Arm946,
    ArmCortexA15,
    ArmCortexA7,
    ArmCortexA8,
    ArmCortexA9,
    ArmCortexM0,
    ArmCortexM3,
    ArmCortexM33,
    ArmCortexM4,
    ArmCortexM7,
    ArmCortexR5,
    ArmCortexR5F,
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
    ArmSa1100,
    ArmSa1110,
    ArmTi925T,
}

#[enum_mirror(styx_emulator::core::cpu::arch::blackfin::BlackfinVariants)]
#[gen_stub_pyclass_enum]
#[pyclass(eq, frozen, module = "arch.blackfin")]
#[derive(PartialEq, Clone, Copy)]
pub enum BlackfinVariant {
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

#[enum_mirror(styx_emulator::core::cpu::arch::ppc32::Ppc32Variants)]
#[gen_stub_pyclass_enum]
#[pyclass(eq, frozen, module = "arch.ppc32")]
#[derive(PartialEq, Clone, Copy)]
pub enum Ppc32Variant {
    // PowerQUICC II family
    // PowerQUICC II PRO family
    // PowerQUICC III family
    // OTHER
    Mpc821,
    Mpc823,
    Mpc823E,
    // PowerQUICC I family
    // https://www.nxp.com/products/processors-and-microcontrollers/legacy-mpu-mcus/powerquicc-processors:POWERQUICC_HOME
    Mpc850,
    Mpc852T,
    Mpc853T,
    Mpc855T,
    Mpc857DSL,
    Mpc859DSL,
    Mpc859T,
    Mpc860,
    Mpc862,
    Mpc866,
    Mpc870,
    Mpc875,
    Mpc880,
    Mpc885,
    // PPC40x family
    Ppc401,
    Ppc405,
    Ppc440,
    Ppc470,
}

#[enum_mirror(styx_emulator::core::cpu::arch::superh::SuperHVariants)]
#[gen_stub_pyclass_enum]
#[pyclass(eq, frozen, module = "arch.superh")]
#[derive(PartialEq, Clone, Copy)]
pub enum SuperHVariant {
    SH1,
    SH1Dsp,
    SH2,
    SH2A,
    SH2E,
    SH3,
    SH3Dsp,
    SH3E,
    SH4,
    SH4A,
    SH4ALDsp,
    SH4ANoFpu,
    SH4NoFpu,
}

#[enum_mirror(styx_emulator::core::cpu::arch::mips64::Mips64Variants)]
#[gen_stub_pyclass_enum]
#[pyclass(eq, frozen, module = "arch.mips64")]
#[derive(PartialEq, Clone, Copy)]
pub enum Mips64Variant {
    Mips6420kc,
    Mips645kc,
    Mips645kec,
    Mips645kef,
    Mips645kf,
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
    Mips64DspR2,
    // MIPS Warrior I-class
    Mips64I6400,
    Mips64I6500,
    // Loongson
    Mips64Loongson2e,
    Mips64Loongson2f,
    // MIPS Warrior P-class
    Mips64P6600,
    // mips64 generic
    Mips64R2Generic,
    // R4000 series
    Mips64R4000,
    // R5000 series
    Mips64Vrf5432,
}
