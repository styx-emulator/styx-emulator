// SPDX-License-Identifier: BSD-2-Clause
use std::fmt::Write;

use gdbstub::output;
use styx_core::core::VcpuId;

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
        /// The vcpu to latch on.
        #[arg(default_value_t = 0)]
        vcpu: VcpuId,
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
            EventSubcommands::Peripherals => print_peripherals(target.core, out),
            EventSubcommands::Info => {
                print_peripherals(target.core, out)?;
                print_current_exception_each(
                    target.vcpus.iter_mut().map(|v| &mut v.event_controller),
                    out,
                );
                Ok(())
            }
            EventSubcommands::Latch { event, vcpu } => {
                let target_vcpus = target.vcpus.len();
                if vcpu as usize > target_vcpus {
                    output!(
                        out,
                        "vcpu {vcpu} too large (target has {target_vcpus} vcpus)"
                    );
                    return Ok(());
                }
                latch(
                    &mut target.vcpus[vcpu as usize].event_controller,
                    out,
                    event,
                )
            }
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

fn print_current_exception_each<'a>(
    ecs: impl Iterator<Item = &'a mut EventController>,
    out: &mut ConsoleOutput<'_>,
) {
    for (i, ec) in ecs.enumerate() {
        output!(out, "vcpu {i}: ");
        print_current_exception(ec, out);
    }
}

/// "current exception: {e}"
fn print_current_exception(ec: &mut EventController, out: &mut ConsoleOutput<'_>) {
    let current = ec.current_exception();
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
}

fn latch(
    ec: &mut EventController,
    out: &mut ConsoleOutput<'_>,
    event: i32,
) -> Result<(), UnknownError> {
    ec.latch(event)
        .with_context(|| format!("failed to latch event {event}"))?;
    outputln!(out, "event # {event} latched");
    Ok(())
}
