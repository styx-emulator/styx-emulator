// SPDX-License-Identifier: BSD-2-Clause
//! Styx GDB monitor command for runtime introspection of the Styx emulator at the GDB console.
//!
//! The GDB monitor command specified by the GDB serial protocol allows for the GDB server to
//! specify completely custom behavior around the monitor command's arguments and stdout-like
//! console output to the user.
//!
//! For Styx we use this to provide interaction with the Styx emulator internals. We use [`clap`] to
//! parse the monitor command arguments. Define custom commands by deriving a [`clap::Parser`],
//! implementing [`SubcommandRunnable`], and adding the command to [`Commands`]. See [`events`] and
//! [`hooks`] as examples of adding custom commands.
//!

mod events;
mod hooks;

use std::str::from_utf8;

mod common {
    pub(super) use super::SubcommandRunnable;
    pub(super) use crate::target_impl::TargetImpl;
    pub(super) use clap::{Parser, Subcommand};
    pub(super) use gdbstub::{outputln, target::ext::monitor_cmd::ConsoleOutput};
    pub(super) use styx_core::{
        arch::{GdbArchIdSupportTrait, GdbRegistersHelper},
        core::ProcessorCore,
        errors::anyhow::anyhow,
        errors::UnknownError,
    };
}
use common::*;
use gdbstub::target;

/// gdb_stub `MonitorCmd` implementation.
///
/// Basically a wrapper around [`handle_monitor`] and handles fatal errors by simply printing them
/// to the gdb output.
impl<'a, GdbArchImpl> target::ext::monitor_cmd::MonitorCmd for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn handle_monitor_cmd(
        &mut self,
        cmd_raw_bytes: &[u8], // input bytes after `monitor`
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), Self::Error> {
        // from my understanding, returning Err() in this fn exits gdb which is not what we want.

        // instead, print fatal errors
        let cmd = match parse_cli(cmd_raw_bytes) {
            Ok(v) => v,
            Err(v) => {
                outputln!(out, "{v}");
                return Ok(());
            }
        };

        if let Err(e) = handle_monitor(self, &cmd, &mut out) {
            if cmd.verbose {
                outputln!(out, "{e:?}");
            } else {
                outputln!(
                    out,
                    "{e}\n\nfor more info use -v/--verbose to show backtrace"
                );
            }
        }
        Ok(())
    }
}

/// Parses command bytes to utf-8 and into [`MonitorCli`]
fn parse_cli(cmd: &[u8]) -> Result<MonitorCli, UnknownError> {
    let cmd = from_utf8(cmd)
        .map_err(|_| anyhow!("monitor command not valid utf-8"))?
        .split_whitespace();

    Ok(MonitorCli::try_parse_from(cmd)?)
}

/// Processor monitor command including support for a fatal Err().
fn handle_monitor<GdbArchImpl>(
    target: &mut TargetImpl<'_, GdbArchImpl>,
    cmd: &MonitorCli,
    out: &mut target::ext::monitor_cmd::ConsoleOutput<'_>,
) -> Result<(), UnknownError>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    match &cmd.commands {
        Commands::Hooks(hooks_command) => hooks_command.run(target, out),
        Commands::Events(events_command) => events_command.run(target, out),
    }
}

/// Styx custom commands to evaluate styx internals from gdb.
///
/// The Styx "monitor" commands can be used to view Emulator internals such as hooks, event
/// controller, peripheral status, etc. from the gdb console. Using this can aid debugging by
/// providing introspection into running processor internals.
#[derive(Parser)]
#[command(name = "monitor", no_binary_name = true)]
struct MonitorCli {
    /// Show backtraces on error.
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand, Clone)]
enum Commands {
    Events(events::EventsCommand),
    Hooks(hooks::HooksCommand),
}

trait SubcommandRunnable {
    fn run<GdbArchImpl>(
        &self,
        target: &mut TargetImpl<'_, GdbArchImpl>,
        out: &mut target::ext::monitor_cmd::ConsoleOutput<'_>,
    ) -> Result<(), UnknownError>
    where
        GdbArchImpl: gdbstub::arch::Arch,
        GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
        GdbArchImpl::RegId: GdbArchIdSupportTrait;
}
