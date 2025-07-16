// SPDX-License-Identifier: BSD-2-Clause

use crate::data::{ArrayPtr, ArrayPtrMut, StyxFFIErrorPtr};

use styx_emulator::prelude::anyhow;
use styx_emulator::prelude::{Context, CpuBackendExt};

use super::hook_xmacro;

crate::data::opaque_pointer! {
    pub struct StyxProcessorCore(styx_emulator::prelude::CoreHandle<'static>)
}

#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_free(ptr: *mut StyxProcessorCore) {
    StyxProcessorCore::free(ptr)
}

macro_rules! styx_processor_add_hook_impl {
    (
        $name:ident( $($an:ident: $at:ty$(: $att:ty)?),* $(,)? ) $(-> $rt:ty: $rtt:ty)? $({
            $($pn:ident: $pt:ty),* $(,)?
        })? ;
    ) => {
        ::paste::paste! {
            #[unsafe(no_mangle)]
            pub extern "C" fn [< StyxProcessorCore_add_ $name:snake _hook>](
                mut this: StyxProcessorCore,
                hook: crate::cpu::[< StyxHook_ $name >],
                out: *mut crate::cpu::StyxHookToken,
            ) -> crate::data::StyxFFIErrorPtr {
                crate::try_out(out, || {
                    let this = this.as_mut()?;
                    let token = this.add_hook(hook.into())?;
                    crate::cpu::StyxHookToken::new(token)
                })
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn [< StyxProcessorCore_add_ $name:snake _data_hook>](
                mut this: StyxProcessorCore,
                hook: crate::cpu::[< StyxHook_ $name Data>],
                out: *mut crate::cpu::StyxHookToken,
            ) -> crate::data::StyxFFIErrorPtr {
                crate::try_out(out, || {
                    let this = this.as_mut()?;
                    let token = this.add_hook(hook.into())?;
                    crate::cpu::StyxHookToken::new(token)
                })
            }
        }
    };
}
hook_xmacro!(styx_processor_add_hook_impl);

#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_pc(
    mut this: StyxProcessorCore,
    out: *mut u64,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;

    crate::try_out(out, || Ok(this.pc()?))
}

/// write memory from a pre-allocated buffer
///
/// # Parameters
///  - `bytes` must be of size >= `size`
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_write_data(
    mut this: StyxProcessorCore,
    address: u64,
    size: u32,
    bytes: ArrayPtr<u8>,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let bytes = bytes.as_slice(size)?;
    this.write_data(address, bytes)?;
    StyxFFIErrorPtr::Ok
}

/// read memory into a pre-allocated buffer
///
/// # Parameters
///  - `out` must be of size >= `size`
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_read_data(
    mut this: StyxProcessorCore,
    address: u64,
    size: u32,
    mut out: ArrayPtrMut<u8>,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let bytes = out.as_slice_mut(size)?;
    this.read_data(address, bytes)?;
    StyxFFIErrorPtr::Ok
}

/// read an integer-based (no special registers) register, no matter what the size, to a u128
#[unsafe(no_mangle)]
// We use modern rust, so this lint is aiui OBE: <https://blog.rust-lang.org/2024/03/30/i128-layout-update.html>
#[allow(improper_ctypes_definitions)]
pub extern "C" fn StyxProcessorCore_read_register_any(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    out: *mut u128,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        use styx_emulator::core::cpu::arch::RegisterValue;
        let value: u128 = match reg.register_value_enum() {
            RegisterValue::u8(_) => this.cpu.read_register::<u8>(reg)?.into(),
            RegisterValue::u16(_) => this.cpu.read_register::<u16>(reg)?.into(),
            RegisterValue::u20(_) => this
                .cpu
                .read_register::<styx_emulator::prelude::u20>(reg)?
                .into(),
            RegisterValue::u32(_) => this.cpu.read_register::<u32>(reg)?.into(),
            RegisterValue::u64(_) => this.cpu.read_register::<u64>(reg)?.into(),
            RegisterValue::u40(_) => this
                .cpu
                .read_register::<styx_emulator::prelude::u40>(reg)?
                .into(),
            RegisterValue::u80(_) => this
                .cpu
                .read_register::<styx_emulator::prelude::u80>(reg)?
                .into(),
            RegisterValue::u128(_) => this.cpu.read_register::<u128>(reg)?,
            v @ RegisterValue::ArmSpecial(_) => {
                return Err(anyhow!("cannot cast {v:?} to u128"))
                    .context("while reading register")?
            }
            v @ RegisterValue::Ppc32Special(_) => {
                return Err(anyhow!("cannot cast {v:?} to u128"))
                    .context("while reading register")?
            }
        };
        Ok(value)
    })
}

/// read an 8-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_read_register_u8(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    out: *mut u8,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        let value = this.cpu.read_register::<u8>(reg)?;
        Ok(value)
    })
}

/// read a 16-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_read_register_u16(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    out: *mut u16,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        let value = this.cpu.read_register::<u16>(reg)?;
        Ok(value)
    })
}

/// read a 32-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_read_register_u32(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    out: *mut u32,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        let value = this.cpu.read_register::<u32>(reg)?;
        Ok(value)
    })
}

/// read a 40-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_read_register_u40(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    out: *mut u64,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        let value = this.cpu.read_register::<styx_emulator::prelude::u40>(reg)?;
        Ok(value.into())
    })
}

/// read a 64-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_read_register_u64(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    out: *mut u64,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        let value = this.cpu.read_register::<u64>(reg)?;
        Ok(value)
    })
}

/// read an 80-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_read_register_u80(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    out: *mut u128,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        let value = this.cpu.read_register::<styx_emulator::prelude::u80>(reg)?;
        Ok(value.into())
    })
}

/// read a 128-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_read_register_u128(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    out: *mut u128,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        let value = this.cpu.read_register::<u128>(reg)?;
        Ok(value)
    })
}

/// write an integer-based (no special registers) register, no matter what the size, to a u128
#[unsafe(no_mangle)]
// We use modern rust, so this lint is aiui OBE: <https://blog.rust-lang.org/2024/03/30/i128-layout-update.html>
#[allow(improper_ctypes_definitions)]
pub extern "C" fn StyxProcessorCore_write_register_any(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    value: u128,
) -> StyxFFIErrorPtr {
    crate::try_unit(|| {
        let this = this.as_mut()?;
        let reg: styx_emulator::prelude::ArchRegister = register.into();
        use styx_emulator::core::cpu::arch::RegisterValue;
        match reg.register_value_enum() {
            RegisterValue::u8(_) => {
                let value: u8 = value.try_into()?;
                this.cpu.write_register(reg, value)?;
            }
            RegisterValue::u16(_) => {
                let value: u16 = value.try_into()?;
                this.cpu.write_register(reg, value)?;
            }
            RegisterValue::u20(_) => {
                let value: u32 = value.try_into()?;
                let value = styx_emulator::prelude::u20::try_new(value)?;
                this.cpu.write_register(reg, value)?;
            }
            RegisterValue::u32(_) => {
                let value: u32 = value.try_into()?;
                this.cpu.write_register(reg, value)?;
            }
            RegisterValue::u64(_) => {
                let value: u64 = value.try_into()?;
                this.cpu.write_register(reg, value)?;
            }
            RegisterValue::u40(_) => {
                let value: u64 = value.try_into()?;
                let value = styx_emulator::prelude::u40::try_new(value)?;
                this.cpu.write_register(reg, value)?;
            }
            RegisterValue::u80(_) => {
                let value = styx_emulator::prelude::u80::try_new(value)?;
                this.cpu.write_register(reg, value)?;
            }
            RegisterValue::u128(_) => {
                this.cpu.write_register(reg, value)?;
            }
            v @ RegisterValue::ArmSpecial(_) => {
                return Err(anyhow!("cannot cast {v:?} to u128"))
                    .context("while reading register")?
            }
            v @ RegisterValue::Ppc32Special(_) => {
                return Err(anyhow!("cannot cast {v:?} to u128"))
                    .context("while reading register")?
            }
        };
        Ok(())
    })
}

/// read an 8-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_write_register_u8(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    value: u8,
) -> StyxFFIErrorPtr {
    crate::try_unit(|| {
        let this = this.as_mut()?;
        this.cpu.write_register(register, value)?;
        Ok(())
    })
}

/// read a 16-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_write_register_u16(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    value: u16,
) -> StyxFFIErrorPtr {
    crate::try_unit(|| {
        let this = this.as_mut()?;
        this.cpu.write_register(register, value)?;
        Ok(())
    })
}

/// read a 32-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_write_register_u32(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    value: u32,
) -> StyxFFIErrorPtr {
    crate::try_unit(|| {
        let this = this.as_mut()?;
        this.cpu.write_register(register, value)?;
        Ok(())
    })
}

/// read a 40-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_write_register_u40(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    value: u64,
) -> StyxFFIErrorPtr {
    crate::try_unit(|| {
        let this = this.as_mut()?;
        let value = styx_emulator::prelude::u40::try_new(value)?;
        this.cpu.write_register(register, value)?;
        Ok(())
    })
}

/// read a 64-bit register
#[unsafe(no_mangle)]
pub extern "C" fn StyxProcessorCore_write_register_u64(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    value: u64,
) -> StyxFFIErrorPtr {
    crate::try_unit(|| {
        let this = this.as_mut()?;
        this.cpu.write_register(register, value)?;
        Ok(())
    })
}

/// read an 80-bit register
#[unsafe(no_mangle)]
// We use modern rust, so this lint is aiui OBE: <https://blog.rust-lang.org/2024/03/30/i128-layout-update.html>
#[allow(improper_ctypes_definitions)]
pub extern "C" fn StyxProcessorCore_write_register_u80(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    value: u128,
) -> StyxFFIErrorPtr {
    crate::try_unit(|| {
        let this = this.as_mut()?;
        let value = styx_emulator::prelude::u80::try_new(value)?;
        this.cpu.write_register(register, value)?;
        Ok(())
    })
}

/// read a 128-bit register
#[unsafe(no_mangle)]
// We use modern rust, so this lint is aiui OBE: <https://blog.rust-lang.org/2024/03/30/i128-layout-update.html>
#[allow(improper_ctypes_definitions)]
pub extern "C" fn StyxProcessorCore_write_register_u128(
    mut this: StyxProcessorCore,
    register: super::StyxRegister,
    value: u128,
) -> StyxFFIErrorPtr {
    crate::try_unit(|| {
        let this = this.as_mut()?;
        this.cpu.write_register(register, value)?;
        Ok(())
    })
}

// TODO: this is for special registers
//#[no_mangle]
//pub extern "C" fn StyxProcessorCore_read_register_ex(
//    this: StyxProcessorCore,
//    register: StyxRegisterDescriptor,
//) {
//}
