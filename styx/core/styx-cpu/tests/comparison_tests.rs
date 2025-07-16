// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! Compares the behaviour of Pcode and Unicorn backends to make sure we maintain
//! parity between the two.
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};

use keystone_engine::Keystone;
use std::fmt::Debug;
use styx_cpu::{
    arch::{
        arm::{ArmMetaVariants, ArmRegister},
        backends::{ArchRegister, ArchVariant},
    },
    Arch, ArchEndian, Backend, PcodeBackend, TargetExitReason, UnicornBackend,
};
use styx_errors::UnknownError;
use styx_processor::{
    core::{
        builder::{BuildProcessorImplArgs, ProcessorImpl},
        ProcessorBundle,
    },
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::DummyEventController,
    executor::Forever,
    hooks::{CoreHandle, Hookable, MemFaultData, Resolution, StyxHook},
    memory::{MemoryPermissions, Mmu},
    processor::{Processor, ProcessorBuilder},
};

use styx_sync::sync::{Arc, OnceLock};

/// Compare TargetExitReason when terminating because of instruction count met.
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_abrupt_stop() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "mov r0, 0xde; mov r1, 0xde",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);
            machine
                .proc
                .core
                .cpu
                .code_hook(
                    machine.start_address,
                    machine.start_address,
                    // change some state in the code hook to catch if one backend executes
                    Box::new(|proc: CoreHandle| {
                        proc.cpu.write_register(ArmRegister::R7, 0x1337u32).unwrap();
                        Ok(())
                    }),
                )
                .unwrap();
            machine.proc.run(1).unwrap();

            snapshot.snapshot("After running", machine)
        },
    )
}

/// Compare TargetExitReason and pc when terminating because of HostStopRequest
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_stop_request() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "mov r1, #1",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);
            machine
                .proc
                .core
                .cpu
                .code_hook(
                    machine.start_address,
                    machine.start_address,
                    Box::new(|proc: CoreHandle| {
                        proc.cpu.stop();
                        Ok(())
                    }),
                )
                .unwrap();

            machine.proc.run(Forever).unwrap();
            let snapshot = snapshot.snapshot("After running", machine);
            assert_eq!(machine.proc.core.cpu.pc().unwrap(), machine.start_address);
            snapshot.push("The answer", 42)
        },
    )
}

/// Tests an empty read to memory and empty write to memory (should nop)
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_read_memory_write_empty() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);

            let mut buf = [];
            machine
                .proc
                .core
                .mmu
                .read_data(machine.start_address, &mut buf)
                .unwrap();

            let snapshot = snapshot.snapshot("After read", machine);

            machine
                .proc
                .core
                .mmu
                .write_data(machine.start_address, &buf)
                .unwrap();

            snapshot.snapshot("After running", machine)
        },
    )
}

/// Compare machine state after register and memory writes without running any code.
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_simple_no_run() {
    let mut machines = create_machines("mov r0, 0xde; mov r1, 0xde");

    compare_two(
        &mut machines,
        Box::new(|machine| {
            machine
                .proc
                .core
                .cpu
                .write_register(ArmRegister::R0, 0x1337u32)
                .unwrap()
        }),
    );
    compare_two(
        &mut machines,
        Box::new(|machine| {
            machine
                .proc
                .core
                .cpu
                .write_register(ArmRegister::Pc, 0x4000u32)
                .unwrap()
        }),
    );
    compare_two(
        &mut machines,
        Box::new(|machine| {
            machine
                .proc
                .core
                .mmu
                .write_code(machine.start_address, &[0xCA, 0xFE, 0xBA, 0xBE])
                .unwrap()
        }),
    );
    compare_two(
        &mut machines,
        Box::new(|machine| {
            machine
                .proc
                .core
                .cpu
                .write_register(ArmRegister::Sp, 0x400000u32)
                .unwrap()
        }),
    );
    compare_two(&mut machines, Box::new(full_compare));
}

/// Compare machine state before and after running simple mov.
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_simple_run() {
    let mut machines = create_machines("mov r0, 0xde; mov r1, 0xde");

    compare_two(&mut machines, Box::new(full_compare));
    compare_two(&mut machines, Box::new(|machine| machine.run()));
    compare_two(&mut machines, Box::new(full_compare));
}

#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_simple_load() {
    let mut machines = create_machines("mov r0, #0x00; ldr r1, [r0]");

    compare_two(
        &mut machines,
        Box::new(|machine| {
            machine
                .proc
                .core
                .mmu
                .memory_map(0x00, 0x1000, MemoryPermissions::all())
                .unwrap();
        }),
    );
    compare_two(&mut machines, Box::new(full_compare));
    compare_two(&mut machines, Box::new(|machine| machine.run()));
    compare_two(&mut machines, Box::new(full_compare));
}

/// Tests a single address code hook and modifying a value that will get overridden.
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_simple_code_hook() {
    let mut machines = create_machines("movs r0, 0xde; movs r1, 0xde; movs r2, 0xde");

    compare_two(
        &mut machines,
        Box::new(|machine| {
            // hook data can only be written to once
            let hook_data: Arc<OnceLock<MachineState>> = Arc::new(OnceLock::new());
            let hook_data_result = hook_data.clone();

            machine
                .proc
                .core
                .cpu
                .code_hook(
                    machine.start_address + 2,
                    machine.start_address + 2,
                    Box::new(move |proc: CoreHandle| {
                        // R0 will be overridden by the current instruction
                        proc.cpu.write_register(ArmRegister::R0, 0xFFu32).unwrap();
                        assert_eq!(proc.cpu.read_register::<u32>(ArmRegister::R1).unwrap(), 0);

                        let machine_state = MachineState::from_backend(proc);
                        // panics if hook data has already been written to
                        hook_data.set(machine_state).unwrap();
                        Ok(())
                    }),
                )
                .unwrap();

            machine.run();

            hook_data_result.get().unwrap().clone()
        }),
    );

    // compare final execution state
    compare_two(&mut machines, Box::new(full_compare));
}

/// Tests a single address code hook and modifying a value that will get overridden.
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_simple_code_hook_blah() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "movs r0, 0xde; movs r1, 0xde; movs r2, 0xde",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);
            // hook data can only be written to once
            let hook_data: Arc<OnceLock<MachineState>> = Arc::new(OnceLock::new());
            let hook_data_result = hook_data.clone();

            machine
                .proc
                .code_hook(
                    machine.start_address + 2,
                    machine.start_address + 2,
                    Box::new(move |proc: CoreHandle| {
                        // R0 will be overridden by the current instruction
                        proc.cpu.write_register(ArmRegister::R0, 0xFFu32).unwrap();
                        assert_eq!(proc.cpu.read_register::<u32>(ArmRegister::R1).unwrap(), 0);

                        let machine_state = MachineState::from_backend(proc);
                        // panics if hook data has already been written to
                        hook_data.set(machine_state).unwrap();
                        Ok(())
                    }),
                )
                .unwrap();

            machine.run();
            let snapshot = snapshot.snapshot("After run", machine);

            let snapshot = snapshot.push(
                "Hook data after run",
                hook_data_result.get().unwrap().clone(),
            );

            snapshot
        },
    );
}

/// Tests a simple interrupt hook by calling svc and checking machine state
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_simple_interrupt_hook() {
    let mut machines = create_machines("movs r0, 0xde; movs r1, 0xde; movs r2, 0xde; svc #0");

    compare_two(
        &mut machines,
        Box::new(|machine| {
            type HookData = MachineState;
            // hook data can only be written to once
            let hook_data: Arc<OnceLock<HookData>> = Arc::new(OnceLock::new());
            let hook_data_result = hook_data.clone();

            machine
                .proc
                .intr_hook(
                    // Purposefully do not check irqn because we know unicorn has incorrect values
                    Box::new(move |backend: CoreHandle, _irqn| {
                        let machine_state = MachineState::from_backend(backend);
                        // panics if hook data has already been written to
                        hook_data.set(machine_state).unwrap();
                        Ok(())
                    }),
                )
                .unwrap();

            machine.run();

            hook_data_result.get().unwrap().clone()
        }),
    );

    // compare final execution state
    compare_two(&mut machines, Box::new(full_compare));
}

#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_read_memory_hook_args() {
    let mut machines = create_machines(
        "movs r0, #0x00
         ldr r1, [r0]",
    );

    // map memory at 0x00
    compare_two(
        &mut machines,
        Box::new(|machine| {
            machine
                .proc
                .core
                .mmu
                .memory_map(0x00, 0x1000, MemoryPermissions::all())
                .unwrap();
            machine
                .proc
                .core
                .mmu
                .write_data(0x00, &(1u8..100u8).collect::<Vec<_>>())
                .unwrap();
        }),
    );

    compare_two(
        &mut machines,
        Box::new(|machine| {
            // hook data can only be written to once
            let hook_data: Arc<OnceLock<(u64, u32, Vec<u8>)>> = Arc::new(OnceLock::new());

            let hook_data2 = hook_data.clone();
            machine
                .proc
                .mem_read_hook(
                    0x0000,
                    0x0100,
                    Box::new(
                        move |_backend: CoreHandle, address, size, data: &mut [u8]| {
                            println!(
                                "memory read: address={address:x}, size={size}, data={data:?}"
                            );
                            // mutate read data
                            data[0] = 0xFF;

                            // panics if hook data has already been written to
                            hook_data2
                                .set((address, size, data.to_vec()))
                                .expect("Hook data has already been written to.");
                            Ok(())
                        },
                    ),
                )
                .unwrap();

            machine.run();
            hook_data.get().unwrap().clone()
        }),
    );

    // compare final execution state
    compare_two(&mut machines, Box::new(full_compare));
}

/// Compares memory read hooks
///
/// Compares:
/// - Machine state during hook
/// - Machine state after execution
/// - Writing to mutable byte slice in hook
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_simple_read_memory_hook() {
    let mut machines = create_machines(
        "movs r0, #0x00
         ldr r1, [r0]
         ldr r1, [r0, #20]",
    );

    // map memory at 0x00
    compare_two(
        &mut machines,
        Box::new(|machine| {
            machine
                .proc
                .core
                .mmu
                .memory_map(0x00, 0x1000, MemoryPermissions::all())
                .unwrap();
            machine
                .proc
                .core
                .mmu
                .write_data(0x00, &(1u8..100u8).collect::<Vec<_>>())
                .unwrap();
        }),
    );

    compare_two(
        &mut machines,
        Box::new(|machine| {
            // hook data can only be written to once
            let hook_data: Arc<OnceLock<MachineState>> = Arc::new(OnceLock::new());

            let hook_data2 = hook_data.clone();
            let hook_token = machine
                .proc
                .mem_read_hook(
                    0x0000,
                    0x0100,
                    Box::new(
                        move |backend: CoreHandle, _address, _size, data: &mut [u8]| {
                            // mutate read data
                            data[0] = 0xFF;

                            let machine_state = MachineState::from_backend(backend);
                            // panics if hook data has already been written to
                            hook_data2
                                .set(machine_state)
                                .expect("Hook data has already been written to.");
                            Ok(())
                        },
                    ),
                )
                .unwrap();

            machine.proc.run(2).unwrap();
            machine.proc.core.cpu.delete_hook(hook_token).unwrap();
            hook_data.get().unwrap().clone()
        }),
    );

    compare_two(
        &mut machines,
        Box::new(|machine| {
            // hook data can only be written to once
            let hook_data: Arc<OnceLock<MachineState>> = Arc::new(OnceLock::new());

            let hook_data2 = hook_data.clone();
            let hook_token = machine
                .proc
                .mem_read_hook(
                    0x0000,
                    0x0100,
                    Box::new(
                        move |backend: CoreHandle, _address, _size, data: &mut [u8]| {
                            // mutate read data
                            data[0] = 0xFF;

                            let machine_state = MachineState::from_backend(backend);
                            // panics if hook data has already been written to
                            hook_data2.set(machine_state).unwrap();

                            Ok(())
                        },
                    ),
                )
                .unwrap();

            machine.proc.run(1).unwrap();
            machine.proc.core.cpu.delete_hook(hook_token).unwrap();
            hook_data.get().unwrap().clone()
        }),
    );

    // compare final execution state
    compare_two(&mut machines, Box::new(full_compare));
}

#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_compare_simple_write_memory_hook() {
    let mut machines = create_machines(
        "movs r0, #0x00
         movs r1, #0xDE
         str r1, [r0]
         movs r1, #0xAA
         str r1, [r0, #20]",
    );

    // map memory at 0x00
    compare_two(
        &mut machines,
        Box::new(|machine| {
            machine
                .proc
                .core
                .mmu
                .memory_map(0x00, 0x1000, MemoryPermissions::all())
                .unwrap();
        }),
    );

    compare_two(
        &mut machines,
        Box::new(|machine| {
            // hook data can only be written to once
            let hook_data: Arc<OnceLock<MachineState>> = Arc::new(OnceLock::new());

            let hook_data2 = hook_data.clone();
            let hook_token = machine
                .proc
                .mem_write_hook(
                    0x0000,
                    0x0100,
                    Box::new(move |backend: CoreHandle, _address, size, data: &[u8]| {
                        assert_eq!(size, 4);
                        assert_eq!(&data[0..size as usize], &0xDEu32.to_le_bytes());
                        let machine_state = MachineState::from_backend(backend);
                        // panics if hook data has already been written to
                        hook_data2
                            .set(machine_state)
                            .expect("Hook data has already been written to.");
                        Ok(())
                    }),
                )
                .unwrap();

            machine.proc.run(3).unwrap();
            machine.proc.core.cpu.delete_hook(hook_token).unwrap();
            hook_data.get().unwrap().clone()
        }),
    );

    compare_two(
        &mut machines,
        Box::new(|machine| {
            // hook data can only be written to once
            let hook_data: Arc<OnceLock<MachineState>> = Arc::new(OnceLock::new());

            let hook_data2 = hook_data.clone();
            let hook_token = machine
                .proc
                .mem_write_hook(
                    0x0000,
                    0x0100,
                    Box::new(move |backend: CoreHandle, _address, size, data: &[u8]| {
                        // mutate read data
                        assert_eq!(size, 4);
                        assert_eq!(&data[0..size as usize], &0xAAu32.to_le_bytes());

                        let machine_state = MachineState::from_backend(backend);
                        // panics if hook data has already been written to
                        hook_data2.set(machine_state).unwrap();
                        Ok(())
                    }),
                )
                .unwrap();

            machine.proc.run(2).unwrap();
            machine.proc.core.cpu.delete_hook(hook_token).unwrap();
            hook_data.get().unwrap().clone()
        }),
    );

    // compare final execution state
    compare_two(&mut machines, Box::new(full_compare));
}

/// Tests that the invalid instruction hook gets executed when valid code gets
/// overwritten with intentionally bad data. This test clobbers the end of this
/// while true insn data to provide invalid opcodes starting @ 0x1004
#[test]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_invalid_insn_hooks() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "movw r1, #0x400b; mov r8, r8; mov r8, r8; bx r1",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);

            let invalid_instruction_address = machine.start_address + 4;
            // write invalid data 2 instructions in
            machine
                .proc
                .core
                .mmu
                .write_data(invalid_instruction_address, &[0xff, 0xff, 0xff, 0xff])
                .unwrap();
            let snapshot = snapshot.snapshot("after invalid instruction write", machine);

            let cb = move |proc: CoreHandle| -> Result<Resolution, UnknownError> {
                println!("hit invalid insn @ pc: {:#x}", proc.cpu.pc().unwrap());
                assert_eq!(proc.cpu.pc().unwrap(), invalid_instruction_address);

                proc.cpu.write_register(ArmRegister::R4, 3u32).unwrap();

                // "keep searching other callbacks"
                Ok(Resolution::NotFixed)
            };

            let token1 = machine
                .proc
                .core
                .cpu
                .add_hook(StyxHook::InvalidInstruction(Box::new(cb)))
                .unwrap();

            // asserts we get an insn decode error
            // reasoning:
            //  - both callbacks return "false", meaning they did not handle the error
            //  - unicorn runs out of callbacks, so it propagates the error
            machine.run_with_exit_reason(TargetExitReason::InstructionDecodeError);
            // where we put the bad data
            assert_eq!(
                invalid_instruction_address,
                machine.proc.core.cpu.pc().unwrap()
            );
            let snapshot = snapshot.snapshot(
                "after running machine and hitting invalid instruction",
                machine,
            );

            let r4_val = machine
                .proc
                .core
                .cpu
                .read_register::<u32>(ArmRegister::R4)
                .unwrap();
            assert_eq!(r4_val, 3, "cb failed");

            machine.proc.core.cpu.delete_hook(token1).unwrap();

            snapshot
        },
    );
}

/// Tests triggering an invalid instruction hook and then fixing and returning true to continue
/// execution.
///
/// TODO: not working for unicorn???
#[test]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_invalid_insn_hook_fix() {
    cpu_test(
        &[Backend::Pcode],
        &DEFAULT_CONFIGURAION,
        "movs r1, #0x4; movs r2, #21; movs r2, #21; movs r3, #21",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);

            let invalid_instruction_address = machine.start_address + 2;
            // write invalid data 2 instructions in
            machine
                .proc
                .core
                .mmu
                .write_data(invalid_instruction_address, &[0xff, 0xff, 0xff, 0xff])
                .unwrap();
            let snapshot = snapshot.snapshot("after invalid instruction write", machine);

            let cb = move |proc: CoreHandle| -> Result<Resolution, UnknownError> {
                println!("hit invalid insn @ pc: {:#x}", proc.cpu.pc().unwrap());
                assert_eq!(proc.cpu.pc().unwrap(), invalid_instruction_address);

                proc.cpu.write_register(ArmRegister::R4, 3u32).unwrap();

                proc.mmu
                    .write_data(invalid_instruction_address, &[0xc0, 0x46, 0xc0, 0x46]) // no op
                    .unwrap();

                // "fixed"
                Ok(Resolution::Fixed)
            };

            let token1 = machine
                .proc
                .add_hook(StyxHook::InvalidInstruction(Box::new(cb)))
                .unwrap();

            // asserts we completed all our instructions
            machine.run_with_exit_reason(TargetExitReason::InstructionCountComplete);
            assert_eq!(machine.proc.core.pc().unwrap(), machine.start_address + 8);

            let snapshot = snapshot.snapshot(
                "after running machine and hitting invalid instruction",
                machine,
            );

            assert_eq!(
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R4)
                    .unwrap(),
                3,
                "cb failed"
            );
            assert_ne!(
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R2)
                    .unwrap(),
                21,
                "invalid instruction overwrite failed"
            );
            assert_eq!(
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R3)
                    .unwrap(),
                21,
                "continue after fix invalid instruction failed"
            );

            machine.proc.core.cpu.delete_hook(token1).unwrap();

            snapshot
        },
    );
}

/// tests that the hook gets called when we read from an unmapped address
#[test]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_unmapped_read_hooks() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "movw r1, #0x9999; ldr r4, [r1];",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);
            let cb = |proc: CoreHandle,
                      addr: u64,
                      size: u32,
                      fault_data: MemFaultData|
             -> Result<Resolution, UnknownError> {
                println!("unmapped fault: 0x{addr:x} of size: {size}, type: {fault_data:?}");

                proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

                Ok(Resolution::NotFixed)
            };

            // insert hooks and collect tokens for removal later
            let token1 = machine
                .proc
                .unmapped_fault_hook(0, u64::MAX, Box::new(cb))
                .unwrap();

            // both callback return `false`, so emulation should also exit
            // with an UnmappedMemoryRead error
            machine.run_with_exit_reason(TargetExitReason::UnmappedMemoryRead);
            let snapshot = snapshot.snapshot("After execution", machine);

            let end_pc = machine.proc.core.pc().unwrap();

            // basic assertions are correct
            assert_eq!(
                machine.start_address + 4,
                end_pc,
                "Stopped at incorrect instruction: {end_pc:#x}",
            );
            assert_eq!(
                0x9999,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R1)
                    .unwrap(),
                "r1 is incorrect immediate value",
            );

            // assertions to test that the hooks we successfully called
            assert_eq!(
                1,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R2)
                    .unwrap(),
                "normal hook failed"
            );

            // removal of hooks is correct
            machine.proc.core.cpu.delete_hook(token1).unwrap();

            snapshot
        },
    );
}

// tests that the hook gets called when we write to an unmapped address
#[test]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_unmapped_write_hooks() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "movw r1, #0x9999;str r4, [r1];",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);
            let cb = |proc: CoreHandle,
                      addr: u64,
                      size: u32,
                      fault_data: MemFaultData|
             -> Result<Resolution, UnknownError> {
                println!("unmapped fault: 0x{addr:x} of size: {size}, type: {fault_data:?}");

                proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

                Ok(Resolution::NotFixed)
            };

            // insert hooks and collect tokens for removal later
            let token1 = machine
                .proc
                .unmapped_fault_hook(0, u64::MAX, Box::new(cb))
                .unwrap();

            // both callback return `false`, so emulation should also exit
            // with an UnmappedMemoryWrite error
            machine.run_with_exit_reason(TargetExitReason::UnmappedMemoryWrite);
            let snapshot = snapshot.snapshot("After execution", machine);

            let end_pc = machine.proc.core.pc().unwrap();

            // basic assertions are correct
            assert_eq!(
                machine.start_address + 4,
                end_pc,
                "Stopped at incorrect instruction: {end_pc:#x}",
            );
            assert_eq!(
                0x9999,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R1)
                    .unwrap(),
                "r1 is incorrect immediate value",
            );

            // assertions to test that the hooks we successfully called
            assert_eq!(
                1,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R2)
                    .unwrap(),
                "normal hook failed"
            );

            // removal of hooks is correct
            machine.proc.core.cpu.delete_hook(token1).unwrap();

            snapshot
        },
    );
}

/// tests that the hook gets called when we read from an unmapped address, and that the read is
/// re-executed if the hook returns true
#[test]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_unmapped_read_hook_fixed() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "movw r1, #0x0000; ldr r4, [r1]",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);
            let cb = |proc: CoreHandle,
                      addr: u64,
                      size: u32,
                      fault_data: MemFaultData|
             -> Result<Resolution, UnknownError> {
                println!("unmapped fault: 0x{addr:x} of size: {size}, type: {fault_data:?}");

                proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

                proc.mmu
                    .memory_map(0x0000, 0x1000, MemoryPermissions::all())
                    .unwrap();
                proc.mmu
                    .write_data(0x0000, &0x1337u32.to_le_bytes())
                    .unwrap();

                Ok(Resolution::Fixed)
            };

            // insert hooks and collect tokens for removal later
            let token1 = machine
                .proc
                .unmapped_fault_hook(0, u64::MAX, Box::new(cb))
                .unwrap();

            // one callback returned `true`, so emulation should exit correctly
            machine.run();
            let snapshot = snapshot.snapshot("After execution", machine);

            // basic assertions are correct
            assert_eq!(
                0x0000,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R1)
                    .unwrap(),
                "r1 is incorrect immediate value",
            );

            // assertions to test that the hook was called
            assert_eq!(
                1,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R2)
                    .unwrap(),
                "normal hook was not called"
            );
            assert_eq!(
                0x1337,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R4)
                    .unwrap(),
                "hook did not read data properly"
            );

            // removal of hooks is correct
            machine.proc.core.cpu.delete_hook(token1).unwrap();

            snapshot
        },
    );
}

/// tests that the hook gets called when we write to an unmapped address, and that the write is
/// re-executed if the hook returns true
#[test]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_unmapped_write_hook_fixed() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "movw r1, #0x0000; str r4, [r1];",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);
            let cb = |proc: CoreHandle,
                      addr: u64,
                      size: u32,
                      fault_data: MemFaultData|
             -> Result<Resolution, UnknownError> {
                println!("unmapped fault: 0x{addr:x} of size: {size}, type: {fault_data:?}");

                proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

                proc.mmu
                    .memory_map(0x0000, 0x1000, MemoryPermissions::all())
                    .unwrap();

                Ok(Resolution::Fixed)
            };

            // insert hooks and collect tokens for removal later
            let token1 = machine
                .proc
                .unmapped_fault_hook(0, u64::MAX, Box::new(cb))
                .unwrap();

            machine
                .proc
                .core
                .cpu
                .write_register(ArmRegister::R4, 0x1337u32)
                .unwrap();

            // one callback returned `true`, so emulation should exit correctly
            machine.run();
            let snapshot = snapshot.snapshot("After execution", machine);

            // basic assertions are correct
            assert_eq!(
                0x0000,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R1)
                    .unwrap(),
                "r1 is incorrect immediate value",
            );

            // assertions to test that the hook was called
            assert_eq!(
                1,
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R2)
                    .unwrap(),
                "normal hook was not called"
            );
            let mut buf = [0u8; 4];
            machine.proc.core.mmu.read_data(0x0000, &mut buf).unwrap();
            assert_eq!(
                &0x1337u32.to_le_bytes(),
                &buf,
                "hook did not write data properly"
            );

            // removal of hooks is correct
            machine.proc.core.cpu.delete_hook(token1).unwrap();

            snapshot
        },
    );
}

// tests that the basic block hook event will fire when this while true
// loop is translated then executed
#[test]
#[ignore = "basic block hooks not implemented for all backends"]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_bb_hooks() {
    cpu_test(
        &ALL_BACKENDS,
        &DEFAULT_CONFIGURAION,
        "movw r1, #0x100b; mov r8, r8; mov r8, r8; bx r1",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);

            let hook_snapshots = Arc::new(Mutex::new(Vec::<u64>::new()));
            let cb = {
                let hook_snapshots = hook_snapshots.clone();
                move |proc: CoreHandle, addr: u64, size: u32| {
                    println!(
                        "hit bb: 0x{:x} of size: {} at pc 0x{:X}",
                        addr,
                        size,
                        proc.cpu.pc().unwrap()
                    );
                    hook_snapshots.lock().unwrap().push(proc.cpu.pc().unwrap());

                    let temp = proc.cpu.read_register::<u32>(ArmRegister::R2).unwrap() + 1;
                    proc.cpu.write_register(ArmRegister::R2, temp).unwrap();
                    Ok(())
                }
            };

            machine
                .proc
                .add_hook(StyxHook::Block(Box::new(cb)))
                .unwrap();
            machine.run();
            let snapshot = snapshot.snapshot("After execution", machine);

            assert_eq!(
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R2)
                    .unwrap(),
                2,
                "callback hook not run"
            );

            let states = hook_snapshots.lock().unwrap();
            assert_eq!(states.len(), 2, "hook ran an incorrect amount of times");
            let snapshot = snapshot.push("hook 0", states[0]);
            snapshot.push("hook 1", states[1])
        },
    );
}

// tests switching from arm mode to thumb mode
// XXX: We ignore this test for now. A proper reset value for the cpsr would allow this test to
//      pass. We do that currently for the Cyclone V, but it doesn't happen in the generic
//      Cortex-A7 processor that gets built for this test.
#[test]
#[ignore = "Cortex-A7 doesn't have a proper reset value for CPSR"]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_arm_thumb_mode_switch() {
    cpu_test(
        &ALL_BACKENDS,
        &CORTEX_A7_CONFIGURATION,
        "mov r1, #0x1009; bx r1;",
        |machine, snapshot| {
            let snapshot = snapshot.initial_snapshot(machine);
            machine
                .proc
                .core
                .mmu
                .write_data(machine.start_address + 8, &[0x0D, 0x22])
                .unwrap(); // movs r2, #13
            let snapshot = snapshot.snapshot("Write thumb code", machine);

            machine.run_instructions(3);

            assert_eq!(
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R1)
                    .unwrap(),
                0x1009
            );
            assert_eq!(
                machine
                    .proc
                    .core
                    .cpu
                    .read_register::<u32>(ArmRegister::R2)
                    .unwrap(),
                13
            );

            snapshot.snapshot("Final state", machine)
        },
    )
}

#[derive(PartialEq, Eq, Debug, Clone)]
struct MachineState {
    registers: BTreeMap<ArchRegister, u32>,
    memory: HashMap<u64, u8>,
}
impl MachineState {
    fn from_backend(backend: CoreHandle) -> Self {
        let mut registers = BTreeMap::new();
        for register in backend.architecture().registers().registers() {
            // Bad register
            if register.name() == "XPSR" {
                continue;
            }
            registers.insert(
                register.variant(),
                backend
                    .cpu
                    .read_register::<u32>(register.variant())
                    .unwrap_or(0),
            );
        }

        let valid_memory = backend.mmu.valid_memory_range();

        let mut memory: HashMap<u64, u8> = Default::default();
        let mut buf = [0u8];
        for address in valid_memory {
            if backend.mmu.read_data(address, &mut buf).is_ok() && buf[0] != 0 {
                memory.insert(address, buf[0]);
            };
        }

        Self { registers, memory }
    }
}
fn full_compare(machine: &mut TestMachine) -> MachineState {
    let backend = &mut machine.proc.core;

    MachineState::from_backend(CoreHandle::new(
        backend.cpu.as_mut(),
        &mut backend.mmu,
        &mut backend.event_controller,
    ))
}

fn compare_two<R: PartialEq + Debug>(
    machines: &mut [TestMachine; 2],
    function: Box<dyn Fn(&mut TestMachine) -> R>,
) {
    println!("Running first.");
    let first = function(&mut machines[0]);
    println!("Running second.");
    let second = function(&mut machines[1]);
    assert_eq!(first, second);
}

pub struct TestProcessor {
    arch: Arch,
    arch_variant: ArchVariant,
    endian: ArchEndian,
}

impl TestProcessor {
    pub fn new(arch: Arch, arch_variant: impl Into<ArchVariant>, endian: ArchEndian) -> Self {
        Self {
            arch,
            arch_variant: arch_variant.into(),
            endian,
        }
    }
}

impl ProcessorImpl for TestProcessor {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let cpu: Box<dyn CpuBackend> = match args.backend {
            Backend::Pcode => Box::new(PcodeBackend::new_engine(
                self.arch,
                self.arch_variant.clone(),
                self.endian,
            )),
            Backend::Unicorn => Box::new(UnicornBackend::new_engine(
                self.arch,
                self.arch_variant.clone(),
                self.endian,
            )),
        };

        Ok(ProcessorBundle {
            cpu,
            mmu: Mmu::default_region_store(),
            event_controller: Box::new(DummyEventController::default()),
            peripherals: vec![],
            loader_hints: HashMap::default(),
        })
    }
}

/// Test fixture that uses the TestProcessor to test backend behaviour
struct TestMachine {
    proc: Processor,
    instruction_count: u32,
    start_address: u64,
}
impl TestMachine {
    fn from_proc(instr: &str, mut backend: Processor, configuration: &Configuration) -> Self {
        let start_address = 0x1000;
        // Assemble instructions
        // Processor default to thumb so we use that
        let ks = Keystone::new(configuration.keystone_arch, configuration.keystone_mode)
            .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm(instr.to_owned(), start_address)
            .expect("Could not assemble");
        let code = asm.bytes;
        let instruction_count = asm.stat_count;

        backend
            .core
            .mmu
            .memory_map(start_address, 0x1000, MemoryPermissions::all())
            .unwrap();

        // Write generated instructions to memory
        backend.core.mmu.write_code(start_address, &code).unwrap();
        // Start execution at our instructions
        let offset = if configuration.keystone_mode == keystone_engine::Mode::THUMB {
            1
        } else {
            0
        };
        backend
            .core
            .cpu
            .write_register(ArmRegister::Pc, start_address as u32 + offset)
            .unwrap();

        // get pc
        assert_eq!(
            start_address,
            backend.core.pc().unwrap(),
            "pc is not correct"
        );
        let pc_val = backend
            .core
            .cpu
            .read_register::<u32>(ArmRegister::Pc)
            .unwrap();
        assert_eq!(start_address, pc_val as u64, "did not read pc correctly");

        TestMachine {
            proc: backend,
            instruction_count,
            start_address,
        }
    }
    fn from_builder(instr: &str, builder: ProcessorBuilder, configuration: &Configuration) -> Self {
        Self::from_proc(instr, builder.build().unwrap(), configuration)
    }
    fn from_backend_type(
        instr: &str,
        backend_type: Backend,
        configuration: &Configuration,
    ) -> Self {
        Self::from_builder(
            instr,
            ProcessorBuilder::default()
                .with_builder(TestProcessor::new(
                    configuration.backend_arch,
                    configuration.backend_arch_variant.clone(),
                    configuration.backend_endian,
                ))
                .with_backend(backend_type),
            configuration,
        )
    }

    /// Runs all instructions
    fn run(&mut self) {
        self.run_raw(
            TargetExitReason::InstructionCountComplete,
            self.instruction_count as u64,
        )
    }

    fn run_instructions(&mut self, num_instructions: u64) {
        self.run_raw(TargetExitReason::InstructionCountComplete, num_instructions)
    }

    fn run_with_exit_reason(&mut self, expected_exit_reason: TargetExitReason) {
        self.run_raw(expected_exit_reason, self.instruction_count as u64)
    }

    fn run_raw(&mut self, expected_exit_reason: TargetExitReason, num_instructions: u64) {
        let exit_report = self.proc.run(num_instructions).unwrap();
        assert_eq!(exit_report.exit_reason, expected_exit_reason);
    }
}
fn create_machines(instr: &str) -> [TestMachine; 2] {
    [
        TestMachine::from_backend_type(instr, Backend::Unicorn, &DEFAULT_CONFIGURAION),
        TestMachine::from_backend_type(instr, Backend::Pcode, &DEFAULT_CONFIGURAION),
    ]
}

#[derive(Debug, PartialEq, Eq)]
struct SnapshotParent;

#[derive(PartialEq, Eq)]
struct Snapshot<T, N> {
    message: Option<Box<str>>,
    data: Box<T>,
    parent: Box<N>,
}
impl<T> Snapshot<T, SnapshotParent> {
    fn new(data: T) -> Self {
        Snapshot {
            message: None,
            data: Box::new(data),
            parent: Box::new(SnapshotParent),
        }
    }
}
impl<T, N> Snapshot<T, N> {
    fn push<T2>(self, message: impl Into<Box<str>>, data: T2) -> Snapshot<T2, Self> {
        let message = message.into();
        println!("[+] Pushing \"{message}\".");
        Snapshot {
            message: Some(message),
            data: Box::new(data),
            parent: Box::new(self),
        }
    }
    fn initial_snapshot(self, machine: &mut TestMachine) -> Snapshot<MachineState, Self> {
        self.snapshot("Initial machine state.", machine)
    }
    fn snapshot(
        self,
        message: impl Into<Box<str>>,
        machine: &mut TestMachine,
    ) -> Snapshot<MachineState, Self> {
        self.push(
            message,
            MachineState::from_backend(CoreHandle::new(
                machine.proc.core.cpu.as_mut(),
                &mut machine.proc.core.mmu,
                &mut machine.proc.core.event_controller,
            )),
        )
    }
}

trait Compare {
    fn compare(&self, other: &Self);
}

impl<T: Eq + Debug, N: Compare> Compare for Snapshot<T, N> {
    fn compare(&self, other: &Self) {
        if let Some(message) = &self.message {
            println!("[+] Compare snapshots \"{message}\"");
        } else {
            println!("[+] Compare snapshots");
        }

        assert_eq!(self.data, other.data);
        println!("[+] Snapshots equal!\n");

        self.parent.compare(&other.parent)
    }
}

impl Compare for SnapshotParent {
    fn compare(&self, _other: &Self) {
        // these are always equal
    }
}

impl<T: Debug, N: Debug> Debug for Snapshot<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(message) = &self.message {
            writeln!(f, "Snapshot: {message}")?;
        } else {
            writeln!(f, "Snapshot:")?;
        }

        writeln!(f, "\t{:?}", self.data)?;
        write!(f, "{:?}", self.parent)?;

        Ok(())
    }
}

/// List of all working backends to test.
const ALL_BACKENDS: [Backend; 2] = [Backend::Unicorn, Backend::Pcode];

struct Configuration {
    keystone_arch: keystone_engine::Arch,
    keystone_mode: keystone_engine::Mode,
    backend_arch: Arch,
    backend_arch_variant: ArchVariant,
    backend_endian: ArchEndian,
}

const DEFAULT_CONFIGURAION: Configuration = Configuration {
    keystone_arch: keystone_engine::Arch::ARM,
    keystone_mode: keystone_engine::Mode::THUMB,
    backend_arch: Arch::Arm,
    backend_arch_variant: ArchVariant::Arm(ArmMetaVariants::ArmCortexM4(
        styx_cpu::arch::arm::variants::ArmCortexM4 {},
    )),
    backend_endian: ArchEndian::LittleEndian,
};

const CORTEX_A7_CONFIGURATION: Configuration = Configuration {
    keystone_arch: keystone_engine::Arch::ARM,
    keystone_mode: keystone_engine::Mode::ARM,
    backend_arch: Arch::Arm,
    backend_arch_variant: ArchVariant::Arm(ArmMetaVariants::ArmCortexA7(
        styx_cpu::arch::arm::variants::ArmCortexA7 {},
    )),
    backend_endian: ArchEndian::LittleEndian,
};

/// Builds machines, runs give test function on all machines, and compares returned snapshots.
///
/// Main function for testing all backends.
///
/// `backend_types` is a list of [Backend]s to build a [TestMachine] and run the test on.
///
/// `instructions` is a string of instructions to compile and put in the [TestMachine].
///
/// `test_fn` is the main function to test each machine. Each execution of the `test_fn` is given a
/// [TestMachine] that has been built with one of the given backends and loaded with the supplied
/// instructions. Additionally, the second argument in a [SnapshotTest] that you must return from
/// the `test_fn`.
fn cpu_test<T: Compare>(
    backend_types: &[Backend],
    configuration: &Configuration,
    instructions: &str,
    mut test_fn: impl FnMut(&mut TestMachine, Snapshot<SnapshotParent, SnapshotParent>) -> T,
) {
    let results: Vec<_> = backend_types
        .iter()
        .copied()
        .map(|backend_type| {
            println!("[+] Running test on {backend_type:?} backend");
            let mut machine =
                TestMachine::from_backend_type(instructions, backend_type, configuration);
            test_fn(&mut machine, Snapshot::new(SnapshotParent))
        })
        .collect();

    all_equal(&results)
}

fn all_equal<T: Compare>(slice: &[T]) {
    for window in slice.windows(2) {
        window[0].compare(&window[1]);
    }
}

#[test]
fn test_snapshot() {
    let s: Snapshot<i32, SnapshotParent> = Snapshot::new(5);
    let s2 = s.push("Before yo", "Yo".to_owned());

    let p: Snapshot<i32, SnapshotParent> = Snapshot::new(5);
    let p2 = p.push("After yo", "Yo".to_owned());

    s2.compare(&p2);
}
