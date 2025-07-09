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

//! Service that provides interop for tonic gRPC entitiies and styx enumerations
use styx_core::cpu::{
    arch::{arm::ArmVariants, blackfin::BlackfinVariants, ppc32::Ppc32Variants},
    ArchEndian, {Arch, Backend},
};
use styx_core::grpc::{
    args::{SupportedConfig, Target},
    emulation_registry::{
        ArchIdentity, ArchIdentityCompatability, BackendIdentity, Config, EndianIdentity,
        IdentityMappingResponse, LoaderIdentity, VariantIdentity,
    },
};

/// Create an id/name message from the enumeration
macro_rules! identity {
    ($ty: ty, $Variant: expr) => {
        <$ty>::new(
            $Variant as u32,
            std::stringify!($Variant)
                .replace("(", "")
                .replace(")", "")
                .as_str(),
        )
    };
}

/// Enumeration used to construct [LoaderIdentity]
pub enum Loader {
    Raw = 0,
    Elf,
    Paramaterized,
    BlackfinLDR,
}

/// Return the [LoaderIdentity] list
pub fn loaders() -> Vec<LoaderIdentity> {
    vec![
        identity!(LoaderIdentity, Loader::Raw),
        identity!(LoaderIdentity, Loader::Elf),
        identity!(LoaderIdentity, Loader::Paramaterized),
        identity!(LoaderIdentity, Loader::BlackfinLDR),
    ]
}

/// Construct and return [IdentityMappingResponse]
pub fn identity_mapping_response() -> IdentityMappingResponse {
    let arm_variants = arm_variants();
    let blackfin_variants = blackfin_variants();
    let ppc32_variants = ppc_variants();
    let mut all_variants = arm_variants.to_vec();
    all_variants.append(&mut blackfin_variants.to_vec());
    all_variants.append(&mut ppc32_variants.to_vec());

    let arm_compat = ArchIdentityCompatability {
        arch_identity: Some(identity!(ArchIdentity, Arch::Arm)),
        endian: Some(identity!(EndianIdentity, ArchEndian::LittleEndian)),
        variants: arm_variants.to_vec(),
    };
    let blackfind_compat = ArchIdentityCompatability {
        arch_identity: Some(identity!(ArchIdentity, Arch::Blackfin)),
        endian: Some(identity!(EndianIdentity, ArchEndian::BigEndian)),
        variants: blackfin_variants.to_vec(),
    };
    let ppc_compat = ArchIdentityCompatability {
        arch_identity: Some(identity!(ArchIdentity, Arch::Ppc32)),
        endian: Some(identity!(EndianIdentity, ArchEndian::LittleEndian)),
        variants: ppc32_variants.to_vec(),
    };

    IdentityMappingResponse {
        architectures: [arm_compat, blackfind_compat, ppc_compat].to_vec(),
        arch_idens: arch_idens(),
        backend_idens: backends(),
        endian_idens: endians(),
        loader_idens: loaders(),
        variant_idens: all_variants,
        supported_configs: supported_config::SupportedConfigs::default()
            .supported
            .clone(),
    }
}

/// Return all the mappings for [ArchIdentity]
pub fn arch_idens() -> Vec<ArchIdentity> {
    [
        identity!(ArchIdentity, Arch::Arm),
        identity!(ArchIdentity, Arch::Blackfin),
        identity!(ArchIdentity, Arch::Mips32),
        identity!(ArchIdentity, Arch::Mips64),
        identity!(ArchIdentity, Arch::X86),
        identity!(ArchIdentity, Arch::Ppc32),
        identity!(ArchIdentity, Arch::Sparc),
        identity!(ArchIdentity, Arch::M68k),
        identity!(ArchIdentity, Arch::Riscv),
        identity!(ArchIdentity, Arch::Tricore),
        identity!(ArchIdentity, Arch::Sharc),
        identity!(ArchIdentity, Arch::Microblaze),
        identity!(ArchIdentity, Arch::Tms320C1x),
        identity!(ArchIdentity, Arch::Tms320C2x),
        identity!(ArchIdentity, Arch::Tms320C3x),
        identity!(ArchIdentity, Arch::Tms320C4x),
        identity!(ArchIdentity, Arch::Tms320C8x),
        identity!(ArchIdentity, Arch::Tms320C5x),
        identity!(ArchIdentity, Arch::Tms320C6x),
        identity!(ArchIdentity, Arch::Avr),
        identity!(ArchIdentity, Arch::SuperH),
        identity!(ArchIdentity, Arch::Pic),
        identity!(ArchIdentity, Arch::Arch80xx),
        identity!(ArchIdentity, Arch::Z80),
    ]
    .to_vec()
}

/// Return all the mappings for [VariantIdentity]
pub fn arm_variants() -> Vec<VariantIdentity> {
    [
        identity!(VariantIdentity, ArmVariants::Arm926),
        identity!(VariantIdentity, ArmVariants::Arm946),
        identity!(VariantIdentity, ArmVariants::Arm1026),
        identity!(VariantIdentity, ArmVariants::Arm1136r2),
        identity!(VariantIdentity, ArmVariants::Arm1136),
        identity!(VariantIdentity, ArmVariants::Arm1176),
        identity!(VariantIdentity, ArmVariants::Arm11Mpcore),
        identity!(VariantIdentity, ArmVariants::ArmCortexM0),
        identity!(VariantIdentity, ArmVariants::ArmCortexM3),
        identity!(VariantIdentity, ArmVariants::ArmCortexM4),
        identity!(VariantIdentity, ArmVariants::ArmCortexM7),
        identity!(VariantIdentity, ArmVariants::ArmCortexM33),
        identity!(VariantIdentity, ArmVariants::ArmCortexR5),
        identity!(VariantIdentity, ArmVariants::ArmCortexR5F),
        identity!(VariantIdentity, ArmVariants::ArmCortexA7),
        identity!(VariantIdentity, ArmVariants::ArmCortexA8),
        identity!(VariantIdentity, ArmVariants::ArmCortexA9),
        identity!(VariantIdentity, ArmVariants::ArmCortexA15),
        identity!(VariantIdentity, ArmVariants::ArmTi925T),
        identity!(VariantIdentity, ArmVariants::ArmSa1100),
        identity!(VariantIdentity, ArmVariants::ArmSa1110),
        identity!(VariantIdentity, ArmVariants::ArmPxa250),
        identity!(VariantIdentity, ArmVariants::ArmPxa255),
        identity!(VariantIdentity, ArmVariants::ArmPxa260),
        identity!(VariantIdentity, ArmVariants::ArmPxa261),
        identity!(VariantIdentity, ArmVariants::ArmPxa262),
        identity!(VariantIdentity, ArmVariants::ArmPxa270),
        identity!(VariantIdentity, ArmVariants::ArmPxa270a0),
        identity!(VariantIdentity, ArmVariants::ArmPxa270a1),
        identity!(VariantIdentity, ArmVariants::ArmPxa270b0),
        identity!(VariantIdentity, ArmVariants::ArmPxa270b1),
        identity!(VariantIdentity, ArmVariants::ArmPxa270c0),
        identity!(VariantIdentity, ArmVariants::ArmPxa270c5),
    ]
    .to_vec()
}

/// Return Blackfin [VariantIdentity] list
pub fn blackfin_variants() -> Vec<VariantIdentity> {
    [
        identity!(VariantIdentity, BlackfinVariants::Bf504),
        identity!(VariantIdentity, BlackfinVariants::Bf504f),
        identity!(VariantIdentity, BlackfinVariants::Bf506f),
        identity!(VariantIdentity, BlackfinVariants::Bf512),
        identity!(VariantIdentity, BlackfinVariants::Bf514),
        identity!(VariantIdentity, BlackfinVariants::Bf516),
        identity!(VariantIdentity, BlackfinVariants::Bf518),
        identity!(VariantIdentity, BlackfinVariants::Bf522),
        identity!(VariantIdentity, BlackfinVariants::Bf523),
        identity!(VariantIdentity, BlackfinVariants::Bf524),
        identity!(VariantIdentity, BlackfinVariants::Bf525),
        identity!(VariantIdentity, BlackfinVariants::Bf526),
        identity!(VariantIdentity, BlackfinVariants::Bf527),
        identity!(VariantIdentity, BlackfinVariants::Bf531),
        identity!(VariantIdentity, BlackfinVariants::Bf532),
        identity!(VariantIdentity, BlackfinVariants::Bf533),
        identity!(VariantIdentity, BlackfinVariants::Bf534),
        identity!(VariantIdentity, BlackfinVariants::Bf535),
        identity!(VariantIdentity, BlackfinVariants::Bf536),
        identity!(VariantIdentity, BlackfinVariants::Bf537),
        identity!(VariantIdentity, BlackfinVariants::Bf538),
        identity!(VariantIdentity, BlackfinVariants::Bf539),
        identity!(VariantIdentity, BlackfinVariants::Bf542),
        identity!(VariantIdentity, BlackfinVariants::Bf542m),
        identity!(VariantIdentity, BlackfinVariants::Bf544),
        identity!(VariantIdentity, BlackfinVariants::Bf544b),
        identity!(VariantIdentity, BlackfinVariants::Bf547),
        identity!(VariantIdentity, BlackfinVariants::Bf548),
        identity!(VariantIdentity, BlackfinVariants::Bf548m),
        identity!(VariantIdentity, BlackfinVariants::Bf561),
        identity!(VariantIdentity, BlackfinVariants::Bf592a),
    ]
    .to_vec()
}

/// Return Ppc32 [VariantIdentity] list
pub fn ppc_variants() -> Vec<VariantIdentity> {
    [
        identity!(VariantIdentity, Ppc32Variants::Mpc850),
        identity!(VariantIdentity, Ppc32Variants::Mpc860),
        identity!(VariantIdentity, Ppc32Variants::Mpc866),
        identity!(VariantIdentity, Ppc32Variants::Mpc870),
        identity!(VariantIdentity, Ppc32Variants::Mpc875),
        identity!(VariantIdentity, Ppc32Variants::Mpc880),
        identity!(VariantIdentity, Ppc32Variants::Mpc885),
        identity!(VariantIdentity, Ppc32Variants::Mpc852T),
        identity!(VariantIdentity, Ppc32Variants::Mpc853T),
        identity!(VariantIdentity, Ppc32Variants::Mpc855T),
        identity!(VariantIdentity, Ppc32Variants::Mpc859T),
        identity!(VariantIdentity, Ppc32Variants::Mpc821),
        identity!(VariantIdentity, Ppc32Variants::Mpc823),
        identity!(VariantIdentity, Ppc32Variants::Mpc823E),
        identity!(VariantIdentity, Ppc32Variants::Mpc857DSL),
        identity!(VariantIdentity, Ppc32Variants::Mpc859DSL),
        identity!(VariantIdentity, Ppc32Variants::Mpc862),
    ]
    .to_vec()
}

/// Return [BackendIdentity] list
pub fn backends() -> Vec<BackendIdentity> {
    vec![
        identity!(BackendIdentity, Backend::Unicorn),
        identity!(BackendIdentity, Backend::Pcode),
    ]
}

/// Return [EndianIdentity] list
pub fn endians() -> Vec<EndianIdentity> {
    [
        identity!(EndianIdentity, ArchEndian::LittleEndian),
        identity!(EndianIdentity, ArchEndian::BigEndian),
    ]
    .to_vec()
}

pub mod supported_config {
    use styx_core::grpc::args::from_target_enum_value;

    use super::*;
    use std::collections::{HashMap, HashSet};
    macro_rules! conf {
        ($id: expr, $name: expr, $arch: expr, $variant: expr, $endian: expr,$loader: expr, $backend: expr) => {
            SupportedConfig {
                id: $id as u32,
                name: $name.into(),
                config: Some(Config {
                    arch_iden: Some(identity!(ArchIdentity, $arch)),
                    variant_iden: Some(identity!(VariantIdentity, $variant)),
                    endian_iden: Some(identity!(EndianIdentity, $endian)),
                    loader_iden: Some(identity!(LoaderIdentity, $loader)),
                    backend_iden: Some(identity!(BackendIdentity, $backend)),
                }),
            }
        };
    }

    #[derive(Debug, PartialEq)]
    pub struct SupportedConfigs {
        pub supported: Vec<SupportedConfig>,
        pub target_map: HashMap<u32, SupportedConfig>,
        pub config_set: HashSet<Config>,
        pub config_map: HashMap<Config, u32>,
    }

    impl SupportedConfigs {
        /// function that maps identifiers to conigs for known configs
        pub fn config_for(&self, id: impl TryInto<u32>) -> Option<Config> {
            if let Ok(v) = id.try_into() {
                if self.target_map.contains_key(&v) {
                    return Some(
                        self.target_map
                            .get(&v)
                            .cloned()
                            .unwrap()
                            .config
                            .unwrap()
                            .clone(),
                    );
                }
            }
            None
        }

        /// Given the config, try to return a known [Target]
        pub fn target_for(&self, config: &Config) -> Option<Target> {
            if let Some(id) = self.config_map.get(config) {
                from_target_enum_value(*id)
            } else {
                None
            }
        }
    }

    impl std::fmt::Display for SupportedConfigs {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}",
                self.target_map
                    .values()
                    .map(|c| format!("{}", c))
                    .collect::<Vec<String>>()
                    .join("\n")
            )
        }
    }

    impl Default for SupportedConfigs {
        fn default() -> Self {
            let supported = all_configs();
            let mut target_map: HashMap<u32, SupportedConfig> =
                HashMap::with_capacity(supported.len());
            for cfg in supported.iter() {
                target_map.insert(cfg.id, cfg.clone());
            }

            let mut config_set: HashSet<Config> = HashSet::with_capacity(supported.len());
            for cfg in supported.iter() {
                config_set.insert(cfg.config.clone().unwrap());
            }

            let mut config_map: HashMap<Config, u32> = HashMap::with_capacity(supported.len());
            for cfg in supported.iter() {
                config_map.insert(cfg.config.clone().unwrap(), cfg.id);
            }

            Self {
                supported,
                target_map,
                config_set,
                config_map,
            }
        }
    }

    fn all_configs() -> Vec<SupportedConfig> {
        vec![
            conf!(
                Target::Kinetis21,
                "Kinetis21",
                Arch::Arm,
                ArmVariants::ArmCortexM4,
                ArchEndian::LittleEndian,
                Loader::Raw,
                Backend::Unicorn
            ),
            conf!(
                Target::PowerQuicc,
                "PowerQUICC",
                Arch::Ppc32,
                Ppc32Variants::Mpc852T,
                ArchEndian::BigEndian,
                Loader::Raw,
                Backend::Unicorn
            ),
            conf!(
                Target::Stm32f107,
                "Stm32f107",
                Arch::Arm,
                ArmVariants::ArmCortexM3,
                ArchEndian::LittleEndian,
                Loader::Raw,
                Backend::Unicorn
            ),
            conf!(
                Target::CycloneV,
                "CycloneV",
                Arch::Arm,
                ArmVariants::ArmCortexA9,
                ArchEndian::LittleEndian,
                Loader::Paramaterized,
                Backend::Unicorn
            ),
            conf!(
                Target::Blackfin512,
                "Blackfin512",
                Arch::Blackfin,
                BlackfinVariants::Bf512,
                ArchEndian::LittleEndian,
                Loader::BlackfinLDR,
                Backend::Pcode
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use styx_core::grpc::args::Target;
    use styx_core::util::logging::init_logging;
    use supported_config::*;
    use tracing::debug;

    #[test]
    fn test_match_targets() {
        init_logging();
        let tested = SupportedConfigs::default();
        for target in [
            Target::Kinetis21,
            Target::PowerQuicc,
            Target::Stm32f107,
            Target::CycloneV,
            Target::Blackfin512,
        ]
        .iter()
        {
            let config = tested.config_for(*target as u32);
            assert!(config.is_some());
            let config = config.unwrap();
            let target_for = tested.target_for(&config);
            assert!(target_for.is_some());
            assert_eq!(target_for.unwrap(), *target);
        }
    }

    #[test]
    fn test_match_targets2() {
        init_logging();
        let supported = SupportedConfigs::default();
        let config1 = SupportedConfig {
            id: 0,
            name: "Kinetis21".into(),
            config: Some(Config {
                arch_iden: Some(ArchIdentity::new(1, "Arch::Arm")),
                variant_iden: Some(VariantIdentity::new(9, "ArmVariants::ArmCortexM4")),
                endian_iden: Some(EndianIdentity::new(0, "ArchEndian::LittleEndian")),
                loader_iden: Some(LoaderIdentity::new(0, "Loader::Raw")),
                backend_iden: Some(BackendIdentity::new(0, "Backend::Unicorn")),
            }),
        };
        let target_for = supported.target_for(&config1.config.unwrap());
        assert!(target_for.is_some());
        assert_eq!(target_for.unwrap(), Target::Kinetis21, "Ordering of variants in one of the core enums has may have changed (probably styx_core::cpu::Arch)");
    }

    #[test]
    fn test_match_targets3() {
        init_logging();
        let supported = SupportedConfigs::default();

        let config = serde_json::from_str::<Config>(
            r#"{
                "arch_iden": {"id": 1, "name": "Arch::Arm"},
                "endian_iden": {"id": 0, "name": "ArchEndian::LittleEndian"},
                "loader_iden": {"id": 0, "name": "Loader::Raw"},
                "backend_iden": {"id": 0, "name": "Backend::Unicorn"},
                "variant_iden": {"id": 9, "name": "ArmVariants::ArmCortexM4"}
                }"#,
        )
        .unwrap();
        debug!("{:?}", supported.target_for(&config));
        assert_eq!(supported.target_for(&config), Some(Target::Kinetis21), "Ordering of variants in one of the core enums has may have changed (probably styx_core::cpu::Arch)");

        let config = serde_json::from_str::<Config>(
            r#"{
                "arch_iden": {"id": 1, "name": "Arch::Arm"},
                "endian_iden": {"id": 0, "name": "ArchEndian::LittleEndian"},
                "loader_iden": {"id": 0, "name": "Loader::Raw"},
                "backend_iden": {"id": 0, "name": "Backend::Unicorn"},
                "variant_iden": {"id": 8, "name": "ArmVariants::ArmCortexM3"}
                }"#,
        )
        .unwrap();
        debug!("{:?}", supported.target_for(&config));
        assert_eq!(supported.target_for(&config), Some(Target::Stm32f107), "Ordering of variants in one of the core enums has may have changed (probably styx_core::cpu::Arch)");

        let config = serde_json::from_str::<Config>(
            r#"{
                "arch_iden": {"id": 1, "name": "Arch::Arm"},
                "endian_iden": {"id": 0, "name": "ArchEndian::LittleEndian"},
                "loader_iden": {"id": 2, "name":
                "Loader::Paramaterized"}, "backend_iden": {"id": 0, "name": "Backend::Unicorn"},
                "variant_iden": {"id": 16, "name": "ArmVariants::ArmCortexA9"}
                }"#,
        )
        .unwrap();
        debug!("{:?}", supported.target_for(&config));
        assert_eq!(supported.target_for(&config), Some(Target::CycloneV), "Ordering of variants in one of the core enums has may have changed (probably styx_core::cpu::Arch)");

        let config = serde_json::from_str::<Config>(
            r#"{
                "arch_iden": {"id": 6, "name": "Arch::Ppc32"},
                "endian_iden": {"id": 1, "name": "ArchEndian::BigEndian"},
                "loader_iden": {"id": 0, "name": "Loader::Raw"},
                "backend_iden": {"id": 0, "name": "Backend::Unicorn"},
                "variant_iden": {"id": 7, "name": "Ppc32Variants::Mpc852T"}
                }"#,
        )
        .unwrap();
        debug!("{:?}", supported.target_for(&config));
        assert_eq!(supported.target_for(&config), Some(Target::PowerQuicc), "Ordering of variants in one of the core enums has may have changed (probably styx_core::cpu::Arch)");

        let config = serde_json::from_str::<Config>(
            r#"{
                "arch_iden": {"id": 2, "name": "Arch::Blackfin"},
                "endian_iden": {"id": 0, "name": "ArchEndian::LittleEndian"},
                "loader_iden": {"id": 3, "name": "Loader::BlackfinLDR"},
                "backend_iden": {"id": 1, "name": "Backend::Pcode"},
                "variant_iden": {"id": 3, "name": "BlackfinVariants::Bf512"}}"#,
        )
        .unwrap();
        debug!("{:?}", supported.target_for(&config));
        assert_eq!(supported.target_for(&config), Some(Target::Blackfin512), "Ordering of variants in one of the core enums has may have changed (probably styx_core::cpu::Arch)");
    }
}
