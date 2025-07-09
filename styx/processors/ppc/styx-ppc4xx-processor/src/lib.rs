// SPDX-License-Identifier: BSD-2-Clause
//! Implementations of the PowerPC 4xx Processor Family
//!
//! Implementations come from the PowerPC 405 Embedded Processor Core User’s
//! Manual Fifth Edition published by IBM in 2001.
//!
mod core_event_controller;
mod ethernet;
mod timers;
mod tlb;
mod uart;

use anyhow::Context;
use core_event_controller::CoreEventController;
use ethernet::EthernetController;
use styx_core::core::builder::BuildProcessorImplArgs;
use styx_core::core::builder::ProcessorImpl;
use styx_core::cpu::arch::ppc32::Ppc32Register;
use styx_core::cpu::arch::ppc32::Ppc32Variants;
use styx_core::cpu::BackendNotSupported;
use styx_core::cpu::PcodeBackend;
use styx_core::memory::physical::PhysicalMemoryVariant;
use styx_core::prelude::*;
use styx_peripherals::uart::{UartController, UartInterface};
use timers::Timers;
use uart::NewUartPortInner;

/// The processor fetches and executes this instruction first.
const INITIAL_PC: u64 = 0xFFFFFFFC;

#[derive(Default)]
pub struct PowerPC405Builder {}

impl PowerPC405Builder {
    pub fn new() -> Self {
        Self::default()
    }

    fn initial_registers(&self, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        // spr reset values taken from section 3.1.2 and 3.2
        // these are magic values defined by the processor manual
        // all other sprs are reset as 0

        // Sets ICU and DCU PLB priorities
        cpu.write_register(Ppc32Register::Ccr0, 0x00700000u32)
            .with_context(|| "failed to set ccr0")?;
        // sets most recent reset to "core reset"
        cpu.write_register(Ppc32Register::Dbsr, 0b01u32)
            .with_context(|| "failed to set dbsr")?;
        // Storage is guarded
        cpu.write_register(Ppc32Register::Sgr, 0xFFFFFFFFu32)
            .with_context(|| "failed to set sgr")?;
        // start execution at [INITIAL_PC]
        cpu.set_pc(INITIAL_PC).context("could not set pc")?;
        Ok(())
    }
}

impl ProcessorImpl for PowerPC405Builder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let mut cpu = if let Backend::Pcode = args.backend {
            Box::new(PcodeBackend::new_engine_config(
                Ppc32Variants::Ppc405,
                ArchEndian::BigEndian,
                &args.into(),
            ))
        } else {
            return Err(BackendNotSupported(args.backend))
                .context("ppc405 processor only supports pcode backend");
        };

        let tlb = Box::new(tlb::Ppc405Tlb::new());
        let mut mmu = Mmu::new(tlb, PhysicalMemoryVariant::RegionStore, cpu.as_mut())?;
        mmu.memory_map(0, 2u64.pow(32), MemoryPermissions::all())?;

        self.initial_registers(cpu.as_mut())?;
        let cec = Box::new(CoreEventController::new(cpu.as_mut(), args.runtime.clone()));

        let mut peripherals: Vec<Box<dyn Peripheral>> = Vec::new();
        let timers = Box::new(Timers::new(cpu.as_mut()));
        peripherals.push(timers);
        let uart = UartController::new(vec![UartInterface::new("0".into(), NewUartPortInner)]);
        peripherals.push(Box::new(uart));
        let ethernet = EthernetController::new();
        peripherals.push(Box::new(ethernet));

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Ppc32));
        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller: cec,
            peripherals,
            loader_hints: hints,
        })
    }
}

#[cfg(test)]
mod tests {
    use styx_core::{
        cpu::arch::ppc32::{Ppc32Register, SpecialPpc32Register, SprRegister},
        executor::Forever,
        hooks::StyxHook,
        memory::helpers::WriteExt,
        prelude::{ProcessorBuilder, *},
        util::logging::init_logging,
    };
    use tracing::debug;

    use crate::PowerPC405Builder;

    const INSTRUCTION_TEST_START: u64 = 0x100;

    /// Runs a C program `ppc4xx_instruction_test` that tests basic
    /// instruction emulation capabilities including arithmetic, bitwise, and
    /// branch operations. Good sanity check to make sure PowerPC instruction emulation works.
    ///
    /// The result of the program is r15 is loaded with 0xFFFFFFFF. Any failed
    /// test will clear a unique bit in the result.
    ///
    /// This tests also tests a read from an SPR register.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_basic_instructions() {
        let input_bytes = include_bytes!("../test-data/ppc4xx_instruction_test");

        styx_core::util::logging::init_logging();
        let mut proc = ProcessorBuilder::default()
            .with_builder(PowerPC405Builder::default())
            .build()
            .unwrap();

        proc.core.mmu.code().write(0).bytes(input_bytes).unwrap();
        // Add a code hook to automatically stop when we hit the infinite loop
        // at the end of the benchmark.
        proc.add_hook(StyxHook::code(0..=0xffffffff, |cpu: CoreHandle| {
            // Either of these are probable "infinite loop" instructions
            let stop_instructions = [
                0x4bfffffcu32, // b pc-1
                0x48000000u32, // b pc ; generated by -O3
            ]
            .map(|instr| instr.to_be_bytes());
            let mut stop_instructions = stop_instructions.iter().map(|bytes| bytes.as_slice());

            let pc = cpu.cpu.pc().unwrap();
            let current_instruction = cpu.mmu.data().read(pc).vec(4).unwrap();
            if stop_instructions.any(|instr| instr == current_instruction) {
                debug!("Found infinite loop, stopping");
                cpu.cpu.stop();
            }
            Ok(())
        }))
        .unwrap();

        proc.core.cpu.set_pc(INSTRUCTION_TEST_START).unwrap();

        // run firmware
        proc.run(Forever).unwrap();

        // check final result value stored in r15
        // must be changed if more tests are added/removed
        let result = proc
            .core
            .cpu
            .read_register::<u32>(Ppc32Register::R15)
            .unwrap();
        assert_eq!(result, 0xFFFF, "Test result is wrong value 0b{result:b}");

        // check SPR 0x3DA (TCR)
        // this is set at end of firmware
        let tcr_value = proc
            .core
            .cpu
            .read_register::<u32>(SpecialPpc32Register::SprRegister(
                SprRegister::new(0x3DA).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            tcr_value, 0x1337,
            "tcr_value is wrong value 0x{tcr_value:b}!"
        );
        let tcr_value = proc
            .core
            .cpu
            .read_register::<u32>(Ppc32Register::Tcr)
            .unwrap();
        assert_eq!(
            tcr_value, 0x1337,
            "tcr_value is wrong value 0x{tcr_value:b}!"
        );
        let _a = (10..12).collect::<Vec<_>>();
    }

    /// Writes and reads back to SPR 0x150..0x200.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_spr_read_write() {
        let mut proc = ProcessorBuilder::default()
            .with_builder(PowerPC405Builder::default())
            .build()
            .unwrap();

        for i in 0x150..0x200 {
            let spr_reg = SpecialPpc32Register::SprRegister(SprRegister::new(i).unwrap());
            let value = (i % 0x13) as u32;
            proc.core.cpu.write_register(spr_reg, value).unwrap();
            let read_value = proc.core.cpu.read_register::<u32>(spr_reg).unwrap();
            assert_eq!(
                value, read_value,
                "incorrect value read back 0x{read_value:x} != 0x{value:x}"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_big_endian_execution() {
        init_logging();
        let objdump = r#"
             00:	38 80 00 04 	li      r4,4
             04:    3d 20 51 eb     lis     r9,20971
             "#;
        let input_bytes = styx_core::util::parse_objdump(objdump).unwrap();
        let mut proc = ProcessorBuilder::default()
            .with_builder(PowerPC405Builder::default())
            .build()
            .unwrap();
        proc.core.mmu.code().write(0x0).bytes(&input_bytes).unwrap();

        proc.core.cpu.set_pc(0).unwrap();
        proc.core
            .cpu
            .write_register(Ppc32Register::R4, 0u32)
            .unwrap();
        proc.core
            .cpu
            .write_register(Ppc32Register::R9, 0u32)
            .unwrap();
        proc.run(2).unwrap();
        let r4 = proc
            .core
            .cpu
            .read_register::<u32>(Ppc32Register::R4)
            .unwrap();
        assert_eq!(4, r4);
        let r4 = proc
            .core
            .cpu
            .read_register::<u32>(Ppc32Register::R9)
            .unwrap();
        assert_eq!(20971 << 16, r4);
    }
}
