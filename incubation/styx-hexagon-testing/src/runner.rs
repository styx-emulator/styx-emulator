// SPDX-License-Identifier: BSD-2-Clause
//! Functions/structs/enums to assist in running hexagon binaries. Used by the tester harness and main (command line).

use styx_emulator::cpu::arch::hexagon::gdb_targets::HexagonHvxCpuTargetDescription;
use styx_emulator::prelude::gdb::{GDBOptions, GdbExecutor, GdbPluginParams, StepIRQs};
use styx_emulator::prelude::styx_async::sync::broadcast;
use styx_emulator::prelude::*;
use styx_emulator::processors::hexagon::hexagon::HexagonBuilder;
use styx_emulator::{errors::UnknownError, prelude::Processor};

use crate::devices::HexagonDevice;

pub enum HexagonBinaryType<'a> {
    FilePath(String),

    // Unused in tests, but Rust will warn if only used in a test.
    #[allow(unused)]
    BinaryData(&'a [u8]),
}

pub struct HexagonDebuggerInfo {
    pub gdb_remote_port: u16,
}

pub fn setup_load_hexagon(
    bin_type: HexagonBinaryType,
    debug: Option<HexagonDebuggerInfo>,
    device: &dyn HexagonDevice,
    semihosting_tx: Arc<broadcast::Sender<u8>>,
) -> Result<Processor, UnknownError> {
    let mut config = device
        .proc_config()
        .expect("couldn't register hexagon-related processor config");

    // Update for tx
    config.semihosting_tx = Some(semihosting_tx);

    let mut proc = ProcessorBuilder::default()
        .with_builder(HexagonBuilder::default())
        .with_backend(Backend::Pcode)
        .with_loader(ElfLoader::default())
        .register_config(config);

    if let Some(debug) = debug {
        let gdb_params = GdbPluginParams::tcp("0.0.0.0", debug.gdb_remote_port, true);
        proc = proc.with_custom_executor(
            GdbExecutor::<HexagonHvxCpuTargetDescription>::new(gdb_params)?.with_options(
                GDBOptions {
                    step_irqs: StepIRQs::Enabled,
                    ..Default::default()
                },
            ),
        )
    }

    let mut proc = match bin_type {
        HexagonBinaryType::FilePath(path) => proc.with_target_program(path),
        HexagonBinaryType::BinaryData(bin) => proc.with_input_bytes(bin.into()),
    }
    .build()?;

    // Setup hooks
    for vcpu in proc.vcpus.iter_mut() {
        for hook in device.hooks().expect("couldn't get hexagon hooks") {
            vcpu.cpu.add_hook(hook).expect("Couldn't add hexagon hook");
        }
    }

    device.post_init(&mut proc)?;

    Ok(proc)
}
