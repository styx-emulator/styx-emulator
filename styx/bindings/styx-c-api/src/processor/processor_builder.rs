// SPDX-License-Identifier: BSD-2-Clause
use std::sync::{Arc, Mutex};

use styx_emulator::{
    cpu::{arch::ppc32::Ppc32Variants, ArchEndian},
    processors::{
        arm::{
            cyclonev::CycloneVBuilder, kinetis21::Kinetis21Builder, stm32f107::Stm32f107Builder,
            stm32f405::Stm32f405Builder,
        },
        bfin::blackfin::BlackfinBuilder,
        ppc::{powerquicci::Mpc8xxBuilder, ppc4xx::PowerPC405Builder},
        superh::superh2a::SuperH2aBuilder,
    },
};

use crate::{
    cpu::hook_xmacro,
    data::{ArrayPtr, CStrPtr, StyxFFIErrorPtr},
};

crate::data::opaque_pointer! {
    /// A builder type for constructing a processor
    pub struct StyxProcessorBuilder(styx_emulator::core::processor::ProcessorBuilder<'static>)
}

#[no_mangle]
/// Create a new, default processor builder
pub extern "C" fn StyxProcessorBuilder_new(out: *mut StyxProcessorBuilder) -> StyxFFIErrorPtr {
    crate::try_out(out, || StyxProcessorBuilder::new(Default::default()))?;
    StyxFFIErrorPtr::Ok
}

#[no_mangle]
pub extern "C" fn StyxProcessorBuilder_free(out: *mut StyxProcessorBuilder) {
    StyxProcessorBuilder::free(out)
}

#[no_mangle]
pub extern "C" fn StyxProcessorBuilder_set_target_program(
    mut this: StyxProcessorBuilder,
    path: CStrPtr,
    path_len: u32,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let path = path.as_str(path_len)?;
    let tmp = std::mem::take(this);
    let tmp = tmp.with_target_program(path.to_string());
    *this = tmp;
    StyxFFIErrorPtr::Ok
}

// TODO: we need another, non-clone version that people can use with the borrowed stuff
#[no_mangle]
pub extern "C" fn StyxProcessorBuilder_set_input_bytes(
    mut this: StyxProcessorBuilder,
    bytes: ArrayPtr<u8>,
    len: u32,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let bytes = bytes.as_slice(len)?.to_vec();
    let tmp = std::mem::take(this);
    let tmp = tmp.with_input_bytes(bytes.into());
    *this = tmp;
    StyxFFIErrorPtr::Ok
}

/// Specify what the processor should do in case of an exception
#[no_mangle]
pub extern "C" fn StyxProcessorBuilder_set_exception_behavior(
    mut this: StyxProcessorBuilder,
    behavior: crate::processor::StyxExceptionBehavior,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let tmp = std::mem::take(this);
    let tmp = tmp.with_exception_behavior(behavior.into());
    *this = tmp;
    StyxFFIErrorPtr::Ok
}

/// Set the inter-processor communication (IPC) port for this processor (this should be unique). A
/// value of zero chooses an open port.
#[no_mangle]
pub extern "C" fn StyxProcessorBuilder_set_ipc_port(
    mut this: StyxProcessorBuilder,
    ipc_port: u16,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let tmp = std::mem::take(this);
    let tmp = tmp.with_ipc_port(ipc_port);
    *this = tmp;
    StyxFFIErrorPtr::Ok
}

#[no_mangle]
extern "C" fn StyxProcessorBuilder_add_plugin(
    mut this: StyxProcessorBuilder,
    plugin: crate::plugin::StyxPlugin,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let tmp = std::mem::take(this);
    let tmp = tmp.add_plugin_box(plugin.take()?);
    *this = tmp;
    StyxFFIErrorPtr::Ok
}

#[no_mangle]
extern "C" fn StyxProcessorBuilder_set_executor(
    mut this: StyxProcessorBuilder,
    executor: crate::executor::StyxExecutor,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let tmp = std::mem::take(this);
    let tmp = tmp.with_executor_box(executor.take()?);
    *this = tmp;
    StyxFFIErrorPtr::Ok
}

#[no_mangle]
extern "C" fn StyxProcessorBuilder_set_loader(
    mut this: StyxProcessorBuilder,
    loader: crate::loader::StyxLoader,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let tmp = std::mem::take(this);
    let tmp = tmp.with_loader_box(loader.take()?);
    *this = tmp;
    StyxFFIErrorPtr::Ok
}

/// Set which backend the processor should use
#[no_mangle]
extern "C" fn StyxProcessorBuilder_set_backend(
    mut this: StyxProcessorBuilder,
    backend: crate::cpu::StyxBackend,
) -> StyxFFIErrorPtr {
    let this = this.as_mut()?;
    let tmp = std::mem::take(this);
    let tmp = tmp.with_backend(backend.into());
    *this = tmp;
    StyxFFIErrorPtr::Ok
}

#[no_mangle]
extern "C" fn StyxProcessorBuilder_build(
    mut this: StyxProcessorBuilder,
    target: crate::target::StyxTarget,
    out: *mut crate::processor::StyxProcessor,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let this = this.as_mut()?;
        let builder = std::mem::take(&mut *this);
        let builder = match target {
            crate::target::StyxTarget::CycloneV => builder.with_builder(CycloneVBuilder::default()),
            crate::target::StyxTarget::Mpc8xx => builder.with_builder(Mpc8xxBuilder::new(
                Ppc32Variants::Mpc860,
                ArchEndian::BigEndian,
            )?),
            crate::target::StyxTarget::Ppc4xx => builder.with_builder(PowerPC405Builder::default()),
            crate::target::StyxTarget::Kinetis21 => {
                builder.with_builder(Kinetis21Builder::default())
            }
            crate::target::StyxTarget::Stm32f107 => {
                builder.with_builder(Stm32f107Builder::default())
            }
            crate::target::StyxTarget::Stm32f405 => {
                builder.with_builder(Stm32f405Builder::default())
            }
            crate::target::StyxTarget::Bf512 => builder.with_builder(BlackfinBuilder::default()),
            crate::target::StyxTarget::Raw => {
                todo!("need cannot determine variant, arch, and endian here");
            }
            crate::target::StyxTarget::SuperH2A => builder.with_builder(SuperH2aBuilder),
        };
        let cpu = builder.build()?;
        let proc = crate::processor::StyxProcessor::new(Arc::new(Mutex::new(cpu)))?;
        Ok(proc)
    })
}

macro_rules! styx_processor_add_hook_impl {
    (
        $name:ident( $($an:ident: $at:ty$(: $att:ty)?),* $(,)? ) $(-> $rt:ty: $rtt:ty)? $({
            $($pn:ident: $pt:ty),* $(,)?
        })? ;
    ) => {
        ::paste::paste! {
            #[no_mangle]
            pub extern "C" fn [< StyxProcessorBuilder_add_ $name:snake _hook>](
                mut this: StyxProcessorBuilder,
                hook: crate::cpu::[< StyxHook_ $name >],
            ) -> crate::data::StyxFFIErrorPtr {
                let this = this.as_mut()?;
                let tmp = std::mem::take(this);
                let tmp = tmp.add_hook(hook.into());
                *this = tmp;
                crate::data::StyxFFIErrorPtr::Ok
            }

            #[no_mangle]
            pub extern "C" fn [< StyxProcessorBuilder_add_ $name:snake _data_hook>](
                mut this: StyxProcessorBuilder,
                hook: crate::cpu::[< StyxHook_ $name Data>],
            ) -> crate::data::StyxFFIErrorPtr {
                let this = this.as_mut()?;
                let tmp = std::mem::take(this);
                let tmp = tmp.add_hook(hook.into());
                *this = tmp;
                crate::data::StyxFFIErrorPtr::Ok
            }
        }
    };
}
hook_xmacro!(styx_processor_add_hook_impl);
