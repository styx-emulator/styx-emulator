// SPDX-License-Identifier: BSD-2-Clause
//! Styx to unicorn architecture and cpu model compatibility layer
use styx_cpu_type::arch::StyxCpuArchError;
use styx_cpu_type::arch::{backends::ArchVariant, Arch, ArchEndian};
use styx_cpu_type::Backend;
use unicorn_engine::unicorn_const;

/// Converts [`Arch`], [`ArchVariant`]
/// and [`ArchEndian`] into the proper unicorn
/// - [`unicorn_const::Arch`]
/// - [`unicorn_const::Mode`]
/// - `unicorn_model` @ [`i32`]
pub fn styx_to_unicorn_machine(
    arch: Arch,
    arch_variant: impl Into<ArchVariant>,
    endian: ArchEndian,
) -> Result<(unicorn_const::Arch, unicorn_const::Mode, i32), StyxCpuArchError> {
    let mut out_mode = unicorn_const::Mode::empty();

    // match on the desired architecture
    if let Ok(uc_arch) = arch.try_into() {
        // add our target endianness
        out_mode |= endian.into();

        // add arch options, required for some architectures for some reason
        out_mode |= match arch {
            Arch::Ppc32 => unicorn_const::Mode::PPC32,
            _ => unicorn_const::Mode::empty(),
        };

        // this adds more special behavior for unicorn
        let out_model: i32 = styx_to_unicorn_cpu_model(arch_variant)?;

        Ok((uc_arch, out_mode, out_model))
    } else {
        Err(StyxCpuArchError::NotSupportedArchOnBackend(
            arch,
            Backend::Unicorn,
        ))
    }
}

fn styx_to_unicorn_cpu_model(
    arch_variant: impl Into<ArchVariant>,
) -> Result<i32, StyxCpuArchError> {
    let out = match arch_variant.into() {
        ArchVariant::Arm(inner) => {
            let tmp: unicorn_engine::ArmCpuModel = inner.into();
            tmp.into()
        }
        ArchVariant::Ppc32(inner) => {
            let tmp: unicorn_engine::PpcCpuModel = inner.into();
            tmp.into()
        }
        other => {
            return Err(StyxCpuArchError::NotSupportedVariantOnBackend(
                other,
                Backend::Unicorn,
            ))
        }
    };

    Ok(out)
}
