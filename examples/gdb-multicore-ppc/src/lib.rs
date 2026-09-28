// SPDX-License-Identifier: BSD-2-Clause
//! Custom two-core PowerPC 405 processor for exercising the GDB plugin against a
//! multi-vCPU target. See `README.md` for the interactive walkthrough.

use styx_emulator::core::core::builder::{BuildProcessorImplArgs, ProcessorImpl};
use styx_emulator::core::core::ProcessorBundle;
use styx_emulator::core::memory::helpers::WriteExt;
use styx_emulator::cpu::arch::ppc32::{Ppc32Register, Ppc32Variants};
use styx_emulator::cpu::PcodeBackend;
use styx_emulator::prelude::*;

/// Address of core 0's firmware copy / initial PC.
pub const CODE_BASE_0: u64 = 0x0001_0000;
/// Address of core 1's firmware copy / initial PC.
pub const CODE_BASE_1: u64 = 0x0002_0000;
/// Shared word both cores increment via a (non-atomic) read-modify-write.
pub const SHARED_COUNTER: u64 = 0x0003_0000;
/// Core 0's private counter word (in core 0's `r3`).
pub const PRIV_BASE_0: u64 = 0x0004_0000;
/// Core 1's private counter word (in core 1's `r3`).
pub const PRIV_BASE_1: u64 = 0x0005_0000;
/// Core 0's stack top (in core 0's `r1`).
pub const STACK_BASE_0: u64 = 0x0006_0000;
/// Core 1's stack top (in core 1's `r1`).
pub const STACK_BASE_1: u64 = 0x0007_0000;

/// Offset of the `bl incr_private` call. `stepi` over it enters the subroutine;
/// `nexti` over it steps past it. This is the `nexti`/`stepi` test target.
pub const BL_OFFSET: u64 = 0x10;
/// Offset of the instruction after `bl incr_private` (the `nop`). A correct
/// `nexti` over the call must land here.
pub const RETURN_OFFSET: u64 = 0x14;
/// Offset of the `incr_private` subroutine entry. A `stepi` over the `bl` lands
/// here; a `nexti` must *not*.
pub const PRIV_SUB_OFFSET: u64 = 0x20;
/// Offset of the per-core private `stw r4, 0(r3)` (inside `incr_private`). The
/// breakpoint/watchpoint tests target this.
pub const PRIV_STW_OFFSET: u64 = 0x34;
/// Offset of the `incr_shared` subroutine entry.
pub const SHARED_SUB_OFFSET: u64 = 0x48;

/// Big-endian PPC405 machine code for `firmware/firmware.S`.
///
/// One position-independent routine: each loop iteration calls `incr_private`
/// (per-core write at `0(r3)`) and `incr_shared` (shared RMW at
/// [`SHARED_COUNTER`]) via `bl`. Per-core differences (private base in `r3`,
/// stack top in `r1`, PC) are supplied by the builder, so the same instructions run on
/// both cores. The firmware follows the PowerPC SysV stack conventions so the
/// gdb client can unwind and `nexti` can step over a `bl`.
///
/// The bytes are the `.text` of `firmware/firmware.S`, assembled at build time
/// (see `build.rs`). The same build keeps the full object (with symbols) for the
/// gdb tests to load via `add-symbol-file` (`FIRMWARE_OBJ_FILE`). The
/// `firmware_layout_invariants` test the layout the example relies on.
pub const FIRMWARE: &[u8] = include_bytes!(env!("FIRMWARE_TEXT_BIN"));

/// Place `text` (raw `.text` firmware bytes) into `memory`'s code space at
/// `base`.
fn load_firmware(memory: &MemoryBackend, base: u64, text: &[u8]) -> Result<(), UnknownError> {
    memory.code().write(base).bytes(text)?;
    Ok(())
}

/// Single-core PPC405 running with memory preloaded with the firmware.
#[derive(Default)]
pub struct SinglePpc405Builder {}

impl ProcessorImpl for SinglePpc405Builder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let memory = MemoryBackend::new_flat();
        load_firmware(&memory, CODE_BASE_0, FIRMWARE)?;

        let cpu = DualPpc405Builder::make_cpu(args, CODE_BASE_0, PRIV_BASE_0, STACK_BASE_0)?;

        Ok(ProcessorBundle::builder()
            .with_memory(memory)
            .with_vcpu(|v| v.with_cpu_box(cpu))
            .with_arch_hint(Arch::Ppc32)
            .build()?)
    }
}

/// Dual-core PPC405 running with memory preloaded with a firmware copy for each vCPU.
#[derive(Default)]
pub struct DualPpc405Builder {}

impl DualPpc405Builder {
    /// Build one PPC405 CPU, apply PPC405 reset SPRs, preset its private base in
    /// `r3` and stack top in `r1`, and point its PC at its own firmware copy.
    fn make_cpu(
        args: &BuildProcessorImplArgs,
        pc: u64,
        priv_base: u64,
        stack_base: u64,
    ) -> Result<Box<dyn CpuBackend>, UnknownError> {
        let mut cpu = PcodeBackend::new_engine_config(
            Ppc32Variants::Ppc405,
            ArchEndian::BigEndian,
            &args.into(),
        );
        // PPC405 SPR reset values (mirrors the stock PowerPC405Builder).
        cpu.write_register(Ppc32Register::Ccr0, 0x0070_0000u32)?;
        cpu.write_register(Ppc32Register::Dbsr, 0b01u32)?;
        cpu.write_register(Ppc32Register::Sgr, 0xFFFF_FFFFu32)?;
        // Per-core private base pointer and stack top (the registers that differ
        // per core).
        cpu.write_register(Ppc32Register::R3, priv_base as u32)?;
        cpu.write_register(Ppc32Register::R1, stack_base as u32)?;
        cpu.set_pc(pc)?;
        Ok(Box::new(cpu))
    }
}

impl ProcessorImpl for DualPpc405Builder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let memory = MemoryBackend::new_flat();

        // Two independent copies of identical firmware bytes.
        load_firmware(&memory, CODE_BASE_0, FIRMWARE)?;
        load_firmware(&memory, CODE_BASE_1, FIRMWARE)?;

        let cpu0 = Self::make_cpu(args, CODE_BASE_0, PRIV_BASE_0, STACK_BASE_0)?;
        let cpu1 = Self::make_cpu(args, CODE_BASE_1, PRIV_BASE_1, STACK_BASE_1)?;

        Ok(ProcessorBundle::builder()
            .with_memory(memory)
            .with_vcpu(|v| v.with_cpu_box(cpu0))
            .with_vcpu(|v| v.with_cpu_box(cpu1))
            .with_arch_hint(Arch::Ppc32)
            .build()?)
    }
}

#[cfg(test)]
mod firmware_tests {
    use super::*;

    /// Checks that the stw/bl offset constants are correct.
    ///
    /// Checks:
    /// - Number of instructions
    /// - The stw breakpoint [`PRIV_STW_OFFSET`] points to the right instruction.
    /// - The [`BL_OFFSET`] points to a BL instruction.
    ///
    /// The test/constants will have to be updated if the firmware changes.
    #[test]
    fn firmware_layout_invariants() {
        // 28 instructions, word-aligned.
        const NUM_INSTRUCTIONS: usize = 28;
        assert_eq!(FIRMWARE.len(), NUM_INSTRUCTIONS * 4);
        assert_eq!(FIRMWARE.len() % 4, 0);

        // The private write the breakpoint/watchpoint tests rely on is
        // `stw r4, 0(r3)` at PRIV_STW_OFFSET.
        let stw = &FIRMWARE[PRIV_STW_OFFSET as usize..PRIV_STW_OFFSET as usize + 4];
        assert_eq!(
            stw,
            &[0x90, 0x83, 0x00, 0x00],
            "stw must be at PRIV_STW_OFFSET"
        );

        // BL_OFFSET must be a branch-and-link (`bl`): primary opcode 18, LK=1.
        let bl = u32::from_be_bytes(
            FIRMWARE[BL_OFFSET as usize..BL_OFFSET as usize + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            bl & 0xFC00_0003,
            0x4800_0001,
            "bl (opcode 18, LK=1) at BL_OFFSET"
        );

        // RETURN_OFFSET is the instruction right after the call.
        assert_eq!(RETURN_OFFSET, BL_OFFSET + 4);
    }
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    use styx_emulator::core::memory::helpers::ReadExt;

    // Runs the dual proc for a bit and checks that counters properly incremented.
    #[test]
    fn dual_cores_execute_and_increment() {
        let mut proc = ProcessorBuilder::default()
            .with_builder(DualPpc405Builder::default())
            .build()
            .unwrap();

        // This number is arbitrary, just needs to run enough to increment the counters once.
        const NUM_INSTRUCTIONS: u64 = 50_000;
        proc.run_multi(NUM_INSTRUCTIONS).unwrap();

        let shared = proc
            .memory()
            .data()
            .read(SHARED_COUNTER)
            .be()
            .u32()
            .unwrap();
        let p0 = proc.memory().data().read(PRIV_BASE_0).be().u32().unwrap();
        let p1 = proc.memory().data().read(PRIV_BASE_1).be().u32().unwrap();

        assert!(p0 > 0, "core 0 private counter never incremented");
        assert!(p1 > 0, "core 1 private counter never incremented");
        assert!(shared > 0, "shared counter never incremented");
        // Each loop does one private write then one shared increment, so the
        // shared counter can never exceed the sum of both private counters.
        assert!(
            shared <= p0 + p1,
            "shared ({shared}) exceeded p0+p1 ({p0}+{p1})"
        );
    }
}
