// SPDX-License-Identifier: BSD-2-Clause
//! [ProcessorFactory]: Create a [Processor] based on input parameters

use crate::svc::ProcessorProcess;
use crate::svc_executor::ServiceExecutor;
use styx_core::core::ExceptionBehavior;
use styx_core::cpu::{arch::blackfin::BlackfinVariants, arch::ppc32::Ppc32Variants, ArchEndian};
use styx_core::errors::{StyxMachineError, UnknownError};
use styx_core::executor::ExecutorImpl;
use styx_core::grpc::args::{HasEmulationArgs, Target};
use styx_core::loader::BlackfinLDRLoader;
use styx_core::prelude::*;
use styx_core::tracebus::{mkpath, SRB_TRACE_FILE_EXT};
use styx_plugins::styx_trace::StyxTracePlugin;
use styx_processors::arm::cyclonev::CycloneVBuilder;
use styx_processors::arm::kinetis21::Kinetis21Builder;
use styx_processors::arm::stm32f107::Stm32f107Builder;
use styx_processors::bfin::blackfin::BlackfinBuilder;
use styx_processors::ppc::powerquicci::Mpc8xxBuilder;

/// Fallback peripheral IPC port to use when not set with the `Processor` builder.
///
/// If the value of `ipc_port` is set with the builder, that value
/// will be used (regardless of test mode).
///
/// If not set with the processor builder, the value is set based on test mode:
/// - if not `cfg(test)`, set to the value of
///   [DEFAULT_IPC_PORT](styx_core::grpc::args::DEFAULT_IPC_PORT).
/// - if `cfg(test)`, set to zero - the OS will choose a random unused port.
pub const CONFIGURED_IPC_PORT: u16 = {
    #[cfg(test)]
    {
        0
    }
    #[cfg(not(test))]
    {
        styx_core::grpc::args::DEFAULT_IPC_PORT
    }
};

/// Create a [Processor] based on input parameters
pub struct ProcessorFactory {}
impl ProcessorFactory {
    /// Create a [Processor] based on the parameters
    /// in [HasEmulationArgs]. The current logic discriminates exclusively
    /// on the [Target] within the parameters.
    ///
    /// Returns a [ProcessorProcess]. The `Processor`:
    /// - **Has been initialized, but has not been started**
    /// - Firmware has been loaded
    /// - Plusins have been initialized
    pub fn create_processor<T: HasEmulationArgs>(
        args: &T,
    ) -> Result<ProcessorProcess, StyxMachineError> {
        let trace_path = mkpath(None, SRB_TRACE_FILE_EXT);
        std::env::set_var("STRACE_KEY", &trace_path);

        let target = args.target();

        let (executor, executor_handle) = ServiceExecutor::new();

        // future: for now, always enable trace plugin - this needs to be optional
        let trace_plugin = StyxTracePlugin::from(args.trace_plugin_args_or_default());
        let proc = Self::processor(
            &target,
            executor,
            trace_plugin,
            &args.firmware_path(),
            args.ipc_port(),
        )?;
        ProcessorProcess::new(proc, executor_handle, &trace_path, &target)
    }

    /// Just create a processor, no process needed.
    pub fn create_processor_no_svc<T: HasEmulationArgs>(
        args: &T,
        executor: impl ExecutorImpl + 'static,
    ) -> Result<Processor, UnknownError> {
        let trace_path = mkpath(None, SRB_TRACE_FILE_EXT);
        std::env::set_var("STRACE_KEY", &trace_path);

        let target = args.target();

        // future: for now, always enable trace plugin - this needs to be optional
        let trace_plugin = StyxTracePlugin::from(args.trace_plugin_args_or_default());
        let proc = Self::processor(
            &target,
            executor,
            trace_plugin,
            &args.firmware_path(),
            args.ipc_port(),
        )?;
        Ok(proc)
    }

    /// The `processor` is **ready to be started, but is not started**
    /// - CPU is created and initialized
    /// - Peripherals and plugins initialized
    /// - Firmware has been loaded
    fn processor(
        target: &Target,
        executor: impl ExecutorImpl + 'static,
        trace_plugin: StyxTracePlugin,
        firmware_path: &str,
        ipc_port: Option<u16>,
    ) -> Result<Processor, UnknownError> {
        // If the port is None, use `CONFIGURED_IPC_PORT` - it's set to the
        // default value or zero in `cfg(test)` tests
        let ipc_port = ipc_port.unwrap_or(CONFIGURED_IPC_PORT);
        match target {
            Target::Kinetis21 => {
                let proc = ProcessorBuilder::default()
                    .with_builder(Kinetis21Builder::default())
                    .with_executor(executor)
                    .add_plugin(trace_plugin)
                    .with_target_program(firmware_path.to_string())
                    .with_ipc_port(ipc_port)
                    .build()?;

                Ok(proc)
            }
            Target::CycloneV => {
                let proc = ProcessorBuilder::default()
                    .with_builder(CycloneVBuilder::default())
                    .with_executor(executor)
                    .add_plugin(trace_plugin)
                    .with_target_program(firmware_path.to_string())
                    .with_ipc_port(ipc_port)
                    .build()?;

                Ok(proc)
            }
            Target::PowerQuicc => {
                let proc = ProcessorBuilder::default()
                    .with_builder(Mpc8xxBuilder::new(
                        Ppc32Variants::Mpc852T,
                        ArchEndian::BigEndian,
                    )?)
                    .add_plugin(trace_plugin)
                    .with_executor(executor)
                    .with_target_program(firmware_path.to_string())
                    .with_ipc_port(ipc_port)
                    .build()?;

                Ok(proc)
            }

            Target::Stm32f107 => {
                let proc = ProcessorBuilder::default()
                    .with_builder(Stm32f107Builder {
                        exception_behavior: ExceptionBehavior::Panic,
                    })
                    .add_plugin(trace_plugin)
                    .with_executor(executor)
                    .with_target_program(firmware_path.to_string())
                    .with_ipc_port(ipc_port)
                    .build()?;

                Ok(proc)
            }

            Target::Blackfin512 => {
                let proc = ProcessorBuilder::default()
                    .with_builder(BlackfinBuilder {
                        variant: BlackfinVariants::Bf512,
                    })
                    .with_loader(BlackfinLDRLoader)
                    .add_plugin(trace_plugin)
                    .with_executor(executor)
                    .with_target_program(firmware_path.to_string())
                    .with_ipc_port(ipc_port)
                    .build()?;

                Ok(proc)
            }
        }
    }
}

// XXX: This need to become generic and user provided
pub fn blackfin_512_hooks(mmu: &mut Mmu) {
    // sets the SPORT1 TXHRE (TX hold register is empty) bit to allow sport/dma config to
    // succeed.
    let mut a = styx_blackfin_sys::bf512::ADI_SPORT_STATUS_REG::default();
    a.set_txhre(1);
    mmu.data()
        .write(styx_blackfin_sys::bf512::SPORT1_STAT)
        .le()
        .value(0x40u32)
        .unwrap();
}
