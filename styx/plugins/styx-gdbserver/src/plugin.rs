// SPDX-License-Identifier: BSD-2-Clause
//! Implementation of [`GdbExecutor`], used to debug styx processors with "remote" _gdb clients_.
//!
//! [`GdbExecutor`] is implemented as a [`ExecutorImpl`]
//! and leverages the [`gdbstub`] crate. The plugin implements the
//! [`ExecutorImpl`] trait because
//! it will control execution of the styx emulator (ie: start and stop the cpu).
//!
//! ## Loading and using [`GdbExecutor`]
//! In order to instantiate and debug a styx emulator with [`GdbExecutor`], all of
//! the following constraints apply:
//! - The underlying cpu and peripherals are fully instantiated and runnable
//! - The underlying cpu is not running
//!
//! ### Example
//! The plugin will wait for a connection from gdb client on `tcp port 9999`.
//!
//! ```no_run
//! use styx_core::cpu::arch::arm::gdb_targets::Armv7emDescription as ArmGdb;
//! use styx_core::cpu::arch::arm::ArmVariants;
//! use styx_core::cpu::ArchEndian;
//! use styx_core::loader::RawLoader;
//! use styx_core::executor::Forever;
//! use styx_emulator::processors::arm::kinetis21::Kinetis21Builder;
//! use styx_gdbserver::{GdbExecutor, GdbPluginParams};
//! use styx_core::processor::*;
//! use styx_core::sync::sync::Arc;
//!
//! let executor = GdbExecutor::<ArmGdb>::new(GdbPluginParams::tcp("0.0.0.0", 9999, true)).unwrap();
//! let mut proc = ProcessorBuilder::default()
//!     .with_builder(Kinetis21Builder::default())
//!     .with_executor(executor)
//!     .with_loader(RawLoader)
//!     .with_target_program(String::from("path to program"))
//!     .build()
//!     .unwrap();
//!
//! proc.run(Forever).unwrap();
//! ```
use crate::{event_loop, target_impl::TargetImpl};
use event_loop::WaitForConnection;
use gdbstub::stub::{DisconnectReason, GdbStub};
use std::marker::PhantomData;
use styx_core::plugins::Plugins;
use styx_core::prelude::*;
use styx_core::{executor::ExecutorImpl, sync::sync::Arc};
use tracing::{error, info, warn};

#[derive(Debug)]
pub struct GdbExecutor<GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch + 'static,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// Remote server connection params
    params: Arc<event_loop::GdbPluginParams>,

    /// Holds the currently-in-use port assigned by the operating system,
    /// defaults to 0, and reports port 0 when utilizing a unix domain
    /// socket
    port_in_use: u16,
    _unused: PhantomData<GdbArchImpl>,
}

unsafe impl<GdbArchImpl> Send for GdbExecutor<GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch + 'static,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
}

unsafe impl<GdbArchImpl> Sync for GdbExecutor<GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch + 'static,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
}

impl<GdbArchImpl> GdbExecutor<GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch + 'static,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// Construct new plugin with the given listen parameters
    /// ## Example (tcp)
    /// ```no_run
    /// # use styx_gdbserver::{GdbExecutor, GdbPluginParams};
    /// # use styx_core::cpu::arch::arm::gdb_targets::ArmMProfileDescription as ArmGdb;
    /// let plugin = GdbExecutor::<ArmGdb>::new(GdbPluginParams::tcp("0.0.0.0", 9999, true));
    /// ```
    /// ## Example (unix domain socket)
    /// ```no_run
    /// # use styx_gdbserver::{GdbExecutor, GdbPluginParams};
    /// # use styx_core::cpu::arch::arm::gdb_targets::ArmMProfileDescription as ArmGdb;
    /// let plugin = GdbExecutor::<ArmGdb>::new(GdbPluginParams::uds("/tmp/gdb.x", true));
    /// ```
    ///
    /// ## Also See
    /// Full example in [`plugin module docs`](self)
    pub fn new(params: event_loop::GdbPluginParams) -> Result<Self, UnknownError> {
        // get the gdb bind parameters, and bind
        if let Err(_e) = params.bind() {
            return Err(anyhow::anyhow!(
                "Error binding to assigned port, gdb plugin is tearing down"
            ));
        }

        // Now that we have bound to a port or UDS:
        // set port in use (will be 0 if UDS)
        let port = *params.port_in_use.lock().unwrap();

        Ok(Self {
            params: Arc::new(params),
            port_in_use: port,
            _unused: PhantomData::<GdbArchImpl> {},
        })
    }

    /// Getter for the port assigned to the plugin assigned by the operating
    /// system.
    ///
    /// # Note
    ///
    /// When using a unix domain socket for the network bind address, this
    /// will be `0`
    pub fn port(&self) -> u16 {
        self.port_in_use
    }

    pub fn run_gdb(&mut self, proc: &mut ProcessorCore) {
        let params = self.params.clone();

        // create a single handle to emulation
        let mut emu = TargetImpl::<GdbArchImpl>::new(proc);

        // run loop, only exit's on error
        loop {
            // now wait for client connection
            let cnx = params.wait_for_connection().unwrap();
            let stub = GdbStub::new(cnx);

            // run gdb stub with our connection, and custom event loop
            let exit_reason =
                stub.run_blocking::<&event_loop::EmuGdbEventLoop<GdbArchImpl>>(&mut emu);

            // handle the exit reason
            match exit_reason {
                Ok(disconnect_reason) => match disconnect_reason {
                    // client disconnected, continue execution loop
                    DisconnectReason::Disconnect => {
                        info!("Client has disconnected, waiting for next connection");
                    }
                    // target crashed, so handle and then exit loop
                    DisconnectReason::TargetExited(code) => {
                        info!("Target exited with code {}!", code);
                        break;
                    }
                    // target terminated, so handle and then exit loop
                    DisconnectReason::TargetTerminated(sig) => {
                        info!("Target terminated with signal {}!", sig);
                        break;
                    }
                    // target killed, so handle and then exit loop
                    DisconnectReason::Kill => {
                        info!("GDB sent a kill command!");
                        break;
                    }
                },
                Err(gdbstub_error) => {
                    if gdbstub_error.is_connection_error() {
                        error!("Connection error, dropping client connection, please reconnect");
                    } else if gdbstub_error.is_target_error() {
                        warn!("The target has errored and cannot continue");
                        break;
                    } else {
                        error!("gdbstub encountered fatal error: {gdbstub_error:?}");
                    }
                }
            }
        }
    }
}

impl<GdbArchImpl> ExecutorImpl for GdbExecutor<GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch + 'static + std::fmt::Debug,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn emulation_setup(
        &mut self,
        proc: &mut ProcessorCore,
        _plugins: &mut Plugins,
    ) -> Result<(), UnknownError> {
        self.run_gdb(proc);
        Ok(())
    }

    fn valid_emulation_conditions(&mut self, _proc: &mut ProcessorCore) -> bool {
        false
    }
}
