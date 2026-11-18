// SPDX-License-Identifier: BSD-2-Clause
//! Use `Styx` purely as a CPU emulator.
use std::borrow::Cow;

use styx_emulator::core::cpu::arch::arm::{ArmRegister, ArmVariants};
use styx_emulator::core::executor::DefaultExecutor;
use styx_emulator::prelude::*;
use styx_emulator::processors::RawProcessor;

use keystone_engine::Keystone;

/*
    MOV     R0, #5                ; Load 5 into register R0
    MOV     R1, #3                ; Load 3 into register R1
    MUL     R2, R0, R1            ; Multiply R0 by R1, store result in R2
    SVC     #0                    ; Trigger a software interrupt
*/
const THUMB_CODE: &str = "MOV R0, #5; MOV R1, #3; MUL R2, R0, R1; SVC #0";

/// Uses Keystone to assemble some Arm instructions and return the resulting bytes
fn assemble_code() -> Vec<u8> {
    let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::THUMB)
        .expect("Could not initialize Keystone engine");
    let asm = ks
        .asm(THUMB_CODE.to_string(), 0x4000)
        .expect("Could not assemble");

    println!("Assembled {} instructions", asm.stat_count);
    asm.bytes
}

/// Callback for tracing instructions
fn hook_code(mut proc: CoreHandle) -> Result<(), UnknownError> {
    println!(">>> Tracing instruction at 0x{:x}", proc.pc()?);
    Ok(())
}

/// Callback for tracing interrupts
fn hook_interrupts(mut proc: CoreHandle, intno: i32) -> Result<(), UnknownError> {
    println!(
        ">>> Tracing interrupt at 0x{:x}, interrupt number = {intno}",
        proc.pc()?
    );
    // quit emulation
    proc.stop();
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a RawProcessor (i.e. minimal processor) for 32 bit Arm LE, using the PCode backend
    let mut proc = ProcessorBuilder::default()
        .with_backend(Backend::Pcode)
        .with_builder(RawProcessor::new(
            Arch::Arm,
            ArmVariants::ArmCortexM4,
            ArchEndian::LittleEndian,
        ))
        .with_loader(RawLoader)
        .with_executor(DefaultExecutor::default())
        .with_input_bytes(Cow::Owned(assemble_code()))
        // add hooks for instructions and interrupts
        .add_hook(StyxHook::code(u64::MIN..=u64::MAX, hook_code))
        .add_hook(StyxHook::interrupt(hook_interrupts))
        .build()?;

    // start emulation
    proc.run(Forever)?;

    // check that R2 holds the value 15 to see if emulation was successful
    assert_eq!(
        proc.vcpus[0].cpu.read_register::<u32>(ArmRegister::R2)?,
        15_u32
    );

    Ok(())
}
