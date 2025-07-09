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
