// SPDX-License-Identifier: BSD-2-Clause
use std::{fmt::Debug, net::SocketAddr};

use super::{GdbExecutor, GdbPluginParams};

use tap::Conv;

use styx_core::{
    arch::{
        arm::ArmMetaVariants,
        ppc32::{gdb_targets::Ppc4xxTargetDescription, Ppc32MetaVariants},
        GdbTargetDescription, *,
    },
    cpu::arch::GdbArchIdSupportTrait,
    errors::UnknownError,
    prelude::{anyhow, ArchVariant, Context, ExecutorImpl},
};

#[derive(serde::Deserialize)]
pub struct GdbConfig {
    /// Connection info, either socket addr or uds param
    pub connection: String,
    #[serde(rename = "arch_variant")]
    pub arch: ArchVariant,
    #[serde(default)]
    pub verbose: bool,
}

/// Build a GDB executor with an [`ArchVariant`] and [`GdbPluginParams`].
///
/// This is useful for instantiating a GDB executor without knowledge of the architecture at compile
/// time.
pub fn build_gdb(
    arch: ArchVariant,
    params: GdbPluginParams,
) -> Result<Box<dyn ExecutorImpl>, UnknownError> {
    let gdb = new_gdb(arch, params).with_context(|| "could not create gdb plugin")?;
    Ok(gdb)
}

/// Build a GDB executor with a deserializable [`GdbConfig`].
///
/// This is useful for instantiating a GDB executor without knowledge of the architecture at compile
/// time, similar to [`build_gdb()`], but this has a deserializable config that can be use in yaml
/// configuration files.
pub fn build_gdb_config(config: GdbConfig) -> Result<Box<dyn ExecutorImpl>, UnknownError> {
    let connection = &config.connection;
    let verbose = config.verbose;

    let gdb_params = if let Ok(socket) = connection.parse::<SocketAddr>() {
        GdbPluginParams::tcp(socket.ip().to_string().leak(), socket.port(), verbose)
    } else {
        GdbPluginParams::uds(connection.to_owned().leak(), verbose)
    };

    let gdb = build_gdb(config.arch, gdb_params).with_context(|| "could not build gdb plugin")?;
    Ok(gdb)
}
styx_uconf::register_component_config_fn!(register executor: id = gdb, component_fn = build_gdb_config, config = GdbConfig);

/// Construct [`GdbExecutor`] with runtime [`ArchVariant`].
///
/// This unfortunately defines the GdbTarget separately from the `ArchitectureDescription` but to
/// prevent bugs it checks that the correct Gdb target is chosen, more info in [`check_gdb_type()`].
fn new_gdb(
    arch: impl Into<ArchVariant>,
    params: GdbPluginParams,
) -> Result<Box<dyn ExecutorImpl>, UnknownError> {
    let arch = arch.into();
    match arch {
        ArchVariant::Ppc32(Ppc32MetaVariants::Ppc405(_)) => {
            new_gdb_single::<Ppc4xxTargetDescription>(arch, params)
        }
        ArchVariant::Arm(meta) => match meta {
            ArmMetaVariants::ArmCortexM0(_)
            | ArmMetaVariants::ArmCortexM3(_)
            | ArmMetaVariants::ArmCortexM33(_) => {
                new_gdb_single::<arm::gdb_targets::ArmMProfileDescription>(arch, params)
            }
            ArmMetaVariants::ArmCortexM4(_) | ArmMetaVariants::ArmCortexM7(_) => {
                new_gdb_single::<arm::gdb_targets::Armv7emDescription>(arch, params)
            }
            _ => new_gdb_single::<arm::gdb_targets::ArmCoreDescription>(arch, params),
        },
        ArchVariant::Blackfin(_) => {
            new_gdb_single::<blackfin::gdb_targets::BlackfinDescription>(arch, params)
        }
        ArchVariant::Msp430(meta) => match meta {
            msp430::Msp430MetaVariants::Msp430x31x(_) => {
                new_gdb_single::<msp430::gdb_targets::Msp430CpuTargetDescription>(arch, params)
            }
        },
        ArchVariant::Mips64(meta) => {
            let name = meta
                .conv::<Box<dyn ArchitectureDef>>()
                .gdb_target_description()
                .gdb_arch_name();
            if &name == "mips" {
                new_gdb_single::<mips64::gdb_targets::Mips64CpuTargetDescription>(arch, params)
            } else if &name == "cnmips" {
                new_gdb_single::<mips64::gdb_targets::Mips64CaviumTargetDescription>(arch, params)
            } else {
                Err(anyhow!("unknown mips64 gdb description {name}"))
            }
        }
        ArchVariant::Mips32(_) => {
            new_gdb_single::<mips32::gdb_targets::Mips32CpuTargetDescription>(arch, params)
        }
        ArchVariant::Aarch64(_) => {
            new_gdb_single::<aarch64::gdb_targets::Aarch64CoreDescription>(arch, params)
        }
        _ => todo!(),
    }
}

/// Checks that the [`ArchVariant`] and `GdbArchImpl` match and creates a Gdb executor with that gdb
/// target description.
fn new_gdb_single<GdbArchImpl>(
    arch_variant: ArchVariant,
    params: GdbPluginParams,
) -> Result<Box<dyn ExecutorImpl>, UnknownError>
where
    GdbArchImpl: gdbstub::arch::Arch + GdbTargetDescription + Default + Debug + 'static,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: GdbArchIdSupportTrait,
{
    check_gdb_type::<GdbArchImpl>(arch_variant)?;
    Ok(Box::new(GdbExecutor::<GdbArchImpl>::new(params)?))
}

/// Verifies that the `ArchVariant`'s declared gdb target description (a la
/// ArchitectureDef::gdb_target_description()) matches `GdbArchImpl` via name comparison.
///
/// This is mostly a sanity check so we don't accidentally mismatch the wrong gdb impl in
/// `new_gdb()`.
fn check_gdb_type<GdbArchImpl: GdbTargetDescription + Default>(
    arch_variant: ArchVariant,
) -> Result<(), UnknownError> {
    let gdb_type_arch_name = GdbArchImpl::default().gdb_arch_name();
    let arch_gdb_arch_name = arch_variant
        .conv::<Box<dyn styx_core::arch::ArchitectureDef>>()
        .gdb_target_description()
        .gdb_arch_name();
    (gdb_type_arch_name == arch_gdb_arch_name).then_some(()).ok_or(anyhow!(
        "gdb type name {gdb_type_arch_name} does not match the architecture description name {arch_gdb_arch_name}"
    ))
}
