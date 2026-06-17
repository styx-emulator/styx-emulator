// SPDX-License-Identifier: BSD-2-Clause
//! Interactive two-core PowerPC 405 emulation exposed over a GDB remote on `:9999`.
//!
//! Connect with:
//! ```text
//! gdb-multiarch -ex 'set endian big' -ex 'target remote :9999'
//! (gdb) info threads        # two threads == the two PPC405 cores
//! (gdb) thread 2            # switch to core 1
//! (gdb) p/x $r3            # 0x40000 on core 0, 0x50000 on core 1
//! (gdb) break *0x10034     # core 0's private stw -> only stops thread 1
//! (gdb) x/x 0x30000        # shared counter climbing
//! (gdb) break *0x10010     # the `bl incr_private`; `nexti` here steps over it
//! ```
use gdb_multicore_ppc::{DualPpc405Builder, CODE_BASE_0};
use styx_emulator::arch::ppc32::gdb_targets::Ppc4xxTargetDescription;
use styx_emulator::core::util::logging::init_logging;
use styx_emulator::plugins::gdb::{GdbExecutor, GdbPluginParams};
use styx_emulator::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let gdb_params = GdbPluginParams::tcp("0.0.0.0", 9999, true);
    let mut proc = ProcessorBuilder::default()
        .with_builder(DualPpc405Builder::default())
        .with_custom_executor(GdbExecutor::<Ppc4xxTargetDescription>::new(gdb_params)?)
        .build()?;

    println!("gdb server listening on :9999 — connect with:");
    println!("  gdb-multiarch -ex 'set endian big' -ex 'target remote :9999'");
    println!(
        "  (for `nexti` over the call, first: add-symbol-file {} 0x{:x})",
        env!("FIRMWARE_OBJ_FILE"),
        CODE_BASE_0
    );

    proc.run_multi(Forever)?;
    Ok(())
}
