// SPDX-License-Identifier: BSD-2-Clause
use super::gdb_targets::*;
use super::SuperHRegister;
use crate::arch::{
    Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank, GdbTargetDescriptionImpl,
};
use derive_more::Display;
use paste::paste;

// Converts a register map to a CpuRegisterBank'd type
// not usable generically across architectures
macro_rules! register_map_to_cpu_register_bank {
    ($reg_map:ident) => {
        paste! {
            #[derive(Default)]
            pub struct [< $reg_map:camel >] {}

            impl CpuRegisterBank for [< $reg_map:camel >] {
                fn pc(&self) -> crate::arch::CpuRegister {
                    SuperHRegister::Pc.register()
                }

                fn sp(&self) -> crate::arch::CpuRegister {
                    SuperHRegister::R15.register()
                }

                fn registers(&self) -> Vec<crate::arch::CpuRegister> {
                    $reg_map.values().cloned().collect()
                }
            }
        }
    };
}

macro_rules! build_variant {
    ($name:ident, $reg_map:ident, $data_word:literal, $usize:literal, $gdb_desc:ident) => {
        paste! {
            #[derive(Debug, Display, PartialEq, Eq, Clone)]
            pub struct $name {}

            impl ArchitectureVariant for $name {}

            impl ArchitectureDef for $name {
                fn usize(&self) -> usize {
                    $usize
                }

                fn pc_size(&self) -> usize {
                    32
                }

                fn core_register_size(&self) -> usize {
                    32
                }

                fn data_word_size(&self) -> usize {
                    $data_word
                }

                fn insn_word_size(&self) -> usize {
                    16
                }

                fn addr_size(&self) -> usize {
                    32
                }

                fn architecture(&self) -> Arch {
                    Arch::SuperH
                }

                fn architecture_variant(&self) -> String {
                    format!("{}", self)
                }

                fn registers(&self) -> Box<dyn CpuRegisterBank> {
                    Box::<$reg_map>::default()
                }

                fn gdb_target_description(&self) -> GdbTargetDescriptionImpl {
                    <$gdb_desc>::default().into()
                }
            }
        }
    };
}

// make the `CpuRegisterBank` for all the variants
register_map_to_cpu_register_bank!(SH_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH_DSP_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH2_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH2A_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH2A_NOFPU_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH2E_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH3_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH3E_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH3_DSP_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH4_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH4_NOFPU_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH4A_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH4A_NOFPU_REGISTER_MAP);
register_map_to_cpu_register_bank!(SH4AL_DSP_REGISTER_MAP);

// now make the actual `ArchitectureVariant`'s
build_variant!(SH1, ShRegisterMap, 32, 32, ShDescription);
build_variant!(SH1Dsp, ShDspRegisterMap, 32, 32, ShDspDescription);
build_variant!(SH2, Sh2RegisterMap, 32, 32, Sh2Description);
build_variant!(SH2A, Sh2ARegisterMap, 32, 32, Sh2ADescription);
build_variant!(
    SH2ANoFpu,
    Sh2ANofpuRegisterMap,
    32,
    32,
    Sh2ANoFpuDescription
);
build_variant!(SH2E, Sh2ERegisterMap, 32, 32, Sh2EDescription);
build_variant!(SH3, Sh3RegisterMap, 32, 32, Sh3Description);
build_variant!(SH3E, Sh3ERegisterMap, 32, 32, Sh3EDescription);
build_variant!(SH3Dsp, Sh3DspRegisterMap, 32, 32, Sh3DspDescription);
build_variant!(SH4, Sh4RegisterMap, 32, 32, Sh4Description);
build_variant!(SH4NoFpu, Sh4NofpuRegisterMap, 32, 32, Sh4NoFpuDescription);
build_variant!(SH4A, Sh4ARegisterMap, 32, 32, Sh4ADescription);
build_variant!(
    SH4ANoFpu,
    Sh4ANofpuRegisterMap,
    32,
    32,
    Sh4ANoFpuDescription
);
build_variant!(SH4ALDsp, Sh4AlDspRegisterMap, 32, 32, Sh4ALDspDescription);
