// SPDX-License-Identifier: BSD-2-Clause

//! Testing harness to be used specifically with the data in data/test-binaries/arm/marvell88f6281
//! Takes .bin files (actually .elf in disguise) stored in firmware path
//! Code is then ran on a RawProcessor Arm 1026 Processor

use std::env;
use std::fs;
use std::path::Path;
use styx_emulator::cpu::arch::arm::{ArmRegister, ArmVariants};
use styx_emulator::hooks::CoreHandle;
use styx_emulator::prelude::*;
use styx_emulator::processors::RawProcessor;
use tracing::{debug, trace};

/// Modify relative_path to run different .bin/.elf files
/// The files produced by the docker are .elf files
fn get_firmware_path() -> String {
    match env::var("FIRMWARE_PATH") {
        Ok(v) => v,
        Err(_) => styx_emulator::core::util::resolve_test_bin("arm/marvell-88f6281/elf/"),
    }
}

/// creates a loader .yaml file that the processor uses for memory locations
fn get_loader(path: &Path) -> Result<String, std::io::Error> {
    let loader_yaml = format!(
        r#"
                - !FileElf
                base: 0x0100
                file: {}
                perms: !AllowAll
                - !RegisterImmediate
                register: pc
                value: 0x100
                "#,
        path.display()
    );
    Ok(loader_yaml)
}

/// pass & fail are trpped when .bin files branch to their respective code hook addresses (testutils.inc)
// They immediately stop program execution & print results
fn pass(proc: CoreHandle) -> Result<(), UnknownError> {
    trace!("Passed");
    proc.cpu.stop();
    Ok(())
}

fn fail(proc: CoreHandle) -> Result<(), UnknownError> {
    trace!("FAIL");
    let bla = proc.cpu.read_register::<u32>(ArmRegister::R3).unwrap();
    debug!("Register 3 is: {:x}", bla);
    proc.cpu.stop();

    Ok(())
}

fn main() -> Result<(), UnknownError> {
    for entry in fs::read_dir(get_firmware_path())? {
        let entry = entry?;
        let path = entry.path();
        trace!(
            "--------------------------\nNow running test file: {:?}",
            entry
        );
        // This is used by the [`ParameterizedLoader`] to take in each .bin file.
        // In this case, the .bin files being used are .elf formatted, hence FileElf
        debug!("Turning .elf into .yaml for processor");
        let loader_yaml = get_loader(&path)
            .unwrap_or_else(|_| panic!("Failed to load file at: {}", path.display()));

        // Create a builder for the processor & attach needed parts
        debug!("Assembling the processor builder");
        let builder = ProcessorBuilder::default()
            .with_builder(RawProcessor::new(
                Arch::Arm,
                ArmVariants::Arm1026,
                ArchEndian::BigEndian,
            ))
            .with_backend(Backend::Unicorn)
            .with_loader(ParameterizedLoader::default())
            .with_input_bytes(loader_yaml.as_bytes().into());

        // "Build" the processor using the builder-pattern.
        // All it does is consume all the inputs to create a final
        // processor you can interact with and execute code with
        debug!("Calling .build() on processor");
        let mut proc = builder.build()?;

        // Hooks for pass/fail - pass is at #7 & fail at #8
        // Branch instructions are at data/test-binaries/arm/marvell-88f6281/testutils.inc
        debug!("Adding hooks");
        proc.core
            .cpu
            .add_hook(StyxHook::Code((0..7).into(), Box::new(pass)))
            .unwrap();
        proc.core
            .cpu
            .add_hook(StyxHook::Code((8..9).into(), Box::new(fail)))
            .unwrap();

        // Start the execution of the input `TargetProgram`
        // If program hangs or runs for an extended period of time:
        // Hooks may need to be updated
        // Starting register/code location may need to be updated
        trace!("Running process");
        proc.run(Forever)?;
    }

    Ok(())
}

#[cfg(test)]
mod test_machine {
    use super::*;
    use keystone_engine::{Arch as KeystoneArch, Keystone, Mode};

    struct TestMachine {
        proc: Processor,
        instruction_count: u64,
    }

    impl TestMachine {
        // Create a machine to run given instructions
        fn new_machine(instr: String) -> Self {
            let mut proc = ProcessorBuilder::default()
                .with_builder(RawProcessor::new(
                    Arch::Arm,
                    ArmVariants::Arm1026,
                    ArchEndian::BigEndian,
                ))
                .with_backend(Backend::Unicorn)
                .build()
                .unwrap();

            let engine = Keystone::new(KeystoneArch::ARM, Mode::ARM | Mode::BIG_ENDIAN)
                .expect("Could not initialize Keystone engine");

            let result = engine.asm(instr, 0).expect("Could not assemble");
            // now we convert the code from KeystoneOutput to Vec for our write op
            let code = result.bytes;
            let instruction_count = result.stat_count.into();
            debug!("INS Set: {:?}", code);
            proc.core.mmu.write_code(0x1000, &code).unwrap();
            // we write to the program counter in ARM mode - our skeleton does do THUMB but we aren't doing that
            proc.core
                .cpu
                .write_register(ArmRegister::Pc, 0x1000u32)
                .unwrap();

            TestMachine {
                proc,
                instruction_count,
            }
        }

        // get memory
        fn read_memory(&mut self, addr: u64) -> u32 {
            let mut buf: [u8; 4] = [0; 4];
            self.proc.core.mmu.read_data(addr, &mut buf).unwrap();
            u32::from_le_bytes(buf)
        }

        fn run(&mut self) {
            debug!("Instruction count: {}", self.instruction_count);

            match self.proc.run(self.instruction_count) {
                Ok(n) => {
                    debug!("Report:\n{n:#?}");
                    assert_eq!(n.exit_reason, TargetExitReason::InstructionCountComplete);
                }
                Err(err) => debug!("Error: {:?}", err),
            }
        }
    }

    // This writes data manually:
    // Data: 0xDE = #222 @ address 0x2000_0000
    // R3: 0x2000_0000
    // OPS:
    // Loads data at address in R3 to R1
    #[test]
    fn test_memory_read() {
        // grab data at R3's address & put in R1
        let instr = "ldr r1, [r3]".to_owned();
        let mut machine = TestMachine::new_machine(instr);

        // start with data written to memory
        let data = &[0xDE]; //==222
        machine.proc.core.write_data(0x2000_0000, data).unwrap();

        // filler data - we know that something went wrong if we get back 1s
        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R1, 0xFFFFFFFFu32)
            .unwrap();

        // address of data written to a different register
        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R3, 0x2000_0000u32)
            .unwrap();

        //these asserts verify that registers have been written to
        let value = machine.read_memory(0x2202_0000);

        trace!("Value stored @ 0x2202_0000: {:x}", value);
        assert_eq!(value, 0);

        let value = machine.read_memory(0x2000_0000);

        trace!("Value stored @ 0x2000_0000: {:x}", value);
        assert_eq!(value, 222);

        // actually run the assembly that we put into the processor
        trace!("--------------------running-------------------");
        machine.run();

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R3)
            .unwrap();
        trace!("Register 3: {:x}", value);

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R1)
            .unwrap();
        trace!("Register 1: {:x}", value);

        // final check that we got our value back
        assert_eq!(value, 3724541952);
    }

    // This adds 1+1:
    // OPS:
    // Mov #2 into R1
    // Adds R1 + R1 into R3
    #[test]
    fn test_one_plus_one() {
        let instr = "mov r1, #2; add r2, r1, r1".to_owned();
        let mut machine = TestMachine::new_machine(instr);

        // actually run the assembly that we put into the processor
        trace!("--------------------running-------------------");
        machine.run();

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R1)
            .unwrap();

        trace!("Register 1: {:x}", value);

        assert_eq!(value, 2);

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R2)
            .unwrap();
        trace!("Register 2: {:x}", value);

        assert_eq!(value, 4);
    }

    // This reads out the instructions written in:
    // Data: LDR R1, [R3] = #: 229, 147, 16, 0 @ 0x1000
    // R3: 0x0000_1000 # address that machine code written to
    // OPS:
    // Loads data at address in R3 to R1
    #[test]
    fn test_read_instructions() {
        let instr = "ldr r1, [r3]".to_owned();
        let mut machine = TestMachine::new_machine(instr);

        // filler data
        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R1, 0xFFFFFFFFu32)
            .unwrap();

        // address of data written
        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R3, 0x0000_1000u32)
            .unwrap();

        // actually run the assembly that we put into the processor
        trace!("--------------------running-------------------");
        machine.run();

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R1)
            .unwrap();

        trace!("Register 1: {:x}", value);

        assert_eq!(value, 0xE5931000);

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R3)
            .unwrap();

        trace!("Register 3: {:x}", value);

        assert_eq!(value, 0x1000);
    }

    #[test]
    // This test is past manually loading blocks of mem, we handle all memory with ldr/mov/str
    fn test_store_n_load() {
        let instr = "mov r0, 0xDE; mov r1, 0x2000; str r0,[r1];ldr r3,[r1]".to_owned();
        let mut machine = TestMachine::new_machine(instr);

        trace!("--------------------running-------------------");
        machine.run();

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R3)
            .unwrap();

        trace!("Register 3: {:x}", value);

        assert_eq!(value, 0xDE);
    }
}
