// SPDX-License-Identifier: BSD-2-Clause
use std::fmt::Write;

use styx_core::prelude::Context;

use super::common::*;

/// View and list events
#[derive(Parser, Clone)]
#[command(name = "event")]
pub(super) struct EventsCommand {
    #[command(subcommand)]
    commands: EventSubcommands,
}

#[derive(Subcommand, Clone)]
enum EventSubcommands {
    /// Get runtime information about the event controller.
    Info,
    /// Latch an event on the event controller.
    Latch {
        /// The event to latch.
        event: i32,
    },
    /// List current peripherals installed in the event controller.
    Peripherals,
}

impl SubcommandRunnable for EventsCommand {
    fn run<GdbArchImpl>(
        &self,
        target: &mut TargetImpl<'_, GdbArchImpl>,
        out: &mut ConsoleOutput<'_>,
    ) -> Result<(), UnknownError>
    where
        GdbArchImpl: gdbstub::arch::Arch,
        GdbArchImpl::Registers: GdbRegistersHelper,
        GdbArchImpl::RegId: GdbArchIdSupportTrait,
    {
        match self.commands {
            EventSubcommands::Peripherals => print_peripherals(target.proc, out),
            EventSubcommands::Info => {
                print_peripherals(target.proc, out)?;
                print_current_exception(target.proc, out)?;
                Ok(())
            }
            EventSubcommands::Latch { event } => latch(target.proc, out, event),
        }
    }
}

fn print_peripherals(
    core: &mut ProcessorCore,
    out: &mut ConsoleOutput<'_>,
) -> Result<(), UnknownError> {
    outputln!(out, "installed peripherals: ");
    let a: String =
        core.event_controller
            .peripherals
            .peripherals
            .iter()
            .fold(String::new(), |mut p, a| {
                writeln!(p, "  - {}", a.name()).unwrap();
                p
            });

    outputln!(out, "{}", a);
    Ok(())
}

fn print_current_exception(
    core: &mut ProcessorCore,
    out: &mut ConsoleOutput<'_>,
) -> Result<(), UnknownError> {
    let current = core.event_controller.inner.current_exception();
    match current {
        Ok(e) => match e {
            Some(e) => outputln!(out, "current exception: {e}"),
            None => outputln!(out, "current exception: none"),
        },
        Err(e) => match e {
            styx_core::event_controller::OptionalFeatureError::Unsupported => {
                outputln!(
                    out,
                    "current exception not supported for this event controller"
                )
            }
            styx_core::event_controller::OptionalFeatureError::Other(error) => {
                outputln!(out, "error getting current exception: {error}")
            }
        },
    }

    Ok(())
}

fn latch(
    core: &mut ProcessorCore,
    out: &mut ConsoleOutput<'_>,
    event: i32,
) -> Result<(), UnknownError> {
    core.latch_event(event)
        .with_context(|| format!("failed to latch event {event}"))?;
    outputln!(out, "event # {event} latched");
    Ok(())
}
