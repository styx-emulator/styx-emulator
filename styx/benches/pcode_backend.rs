// SPDX-License-Identifier: BSD-2-Clause
//! Benchmark for simple pcode cpu backend operation.
//!
//! This benchmark tests the raw speed of pcode emulation. This is done using a [`RawProcessor`] so
//! no peripherals are in play. The assembly used is stored in strings below and assembled using
//! keystone.
//!
//! - Run all benchmarks (takes a while)
//!   - `cargo bench --package styx-emulator --bench pcode_backend`
//! - Run single benchmark (replace `fibonacci-register` with filter)
//!   - `cargo bench --package styx-emulator --bench pcode_backend -- fibonacci-register`
//! - Save a baseline and then compares against it later
//!   - `cargo bench --package styx-emulator --bench pcode_backend -- fibonacci-register
//!     --save-baseline base`
//!   - `cargo bench --package styx-emulator --bench pcode_backend -- fibonacci-register --baseline
//!     base`
//! - Generate a flame graph of function calls to find performance culprits
//!   - `cargo install flamegraph # only needed once`
//!   - `cargo flamegraph --package styx-emulator --bench pcode_backend -- --bench --profile-time 5
//!     fibonacci-register`
//!
//! - `fibonacci-register` and `fibonacci-memory` run fibonacci computation code using
//!   registers/memory for intermediate values.
//! - `fibonacci-code-hook-hit` runs `fibonacci-register` but with code hooks on every address.
//!   - intends to measure the performance impact of executing code hooks.
//!   - the code hooks are no-ops with a [`black_box()`] to measure the raw code hook call
//!     performance
//! - `fibonacci-code-hooks-hit`tests multiple code hooks that get hit on each pc
//! - `fibonacci-code-hooks-no-hit`tests multiple code hooks that don't get triggered
//! - `fibonacci-memory-hooks-hit`/`fibonacci-memory-hooks-no-hit` same but for memory hooks
//!
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keystone_engine::Keystone;
use std::hint::black_box;
use std::time::Duration;
use styx_core::cpu::arch::arm::{ArmRegister, ArmVariants};
use styx_core::cpu::{ArchEndian, TargetExitReason};
use styx_core::errors::UnknownError;
use styx_core::hooks::{CoreHandle, Hookable};
use styx_core::prelude::{CpuBackendExt, Forever, Processor, ProcessorBuilder};
use styx_processors::RawProcessor;

/// First address of code.
const START_ADDRESS: u64 = 0x1000;

/// Creates pcode backend with code written to START_ADDRESS.
fn build_backend(instructions: &str) -> Processor {
    let mut proc = ProcessorBuilder::default()
        .with_backend(styx_core::cpu::Backend::Pcode)
        .with_builder(RawProcessor::new(
            styx_core::cpu::Arch::Arm,
            ArmVariants::ArmCortexM4,
            ArchEndian::LittleEndian,
        ))
        .build()
        .unwrap();

    // Assemble instructions
    // Processor default to thumb so we use that
    let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::THUMB)
        .expect("Could not initialize Keystone engine");
    let asm = ks
        .asm(instructions.to_owned(), START_ADDRESS)
        .expect("Could not assemble");
    let code = asm.bytes;

    // stop cpu on svc
    proc.intr_hook(Box::new(|mut proc: CoreHandle, _irqn| {
        proc.stop();
        Ok(())
    }))
    .unwrap();

    proc.core.mmu.write_code(START_ADDRESS, &code).unwrap();

    proc
}

/// Calculate correct fibonacci number at compile time.
const fn fibonacci(n: u32) -> u32 {
    const fn rec(i: u32, current: u32, next: u32) -> u32 {
        if i == 0 {
            current
        } else {
            // wrapping add because hardware registers will always wrap-around
            rec(i - 1, next, current.wrapping_add(next))
        }
    }

    rec(n, 0, 1)
}

fn run(backend: &mut Processor, fibonacci_iteration: u32) {
    // reset machine state to run the correct number of iterations
    backend
        .core
        .cpu
        .write_register(ArmRegister::R5, fibonacci_iteration - 1)
        .unwrap();

    backend.core.set_pc(START_ADDRESS + 1).unwrap();

    let exit_report = backend.run(Forever).unwrap();
    assert_eq!(exit_report.exit_reason, TargetExitReason::HostStopRequest);

    let r0 = backend
        .core
        .cpu
        .read_register::<u32>(ArmRegister::R0)
        .unwrap();
    assert_eq!(r0, fibonacci(fibonacci_iteration));
}

// Simple fibonacci calculator
// r5 is iteration to calculate
// r0 is last value
// r1 is second to last
const FIB: &str = "
    movs r0, #1
    movs r1, #0
fib:
    adds r1, r0
    mov r3, r1
    mov r1, r0
    mov r0, r3
check:
    subs r5, #1
    bne fib

exit:
    svc #0
";

const FIB_MEMORY: &str = "
    movs r4, #0
    movs r0, #1
    movs r1, #0
    str r0, [r4]
    str r1, [r4, #4]
fib:
    ldr r0, [r4]
    ldr r1, [r4, #4]
    adds r1, r0
    mov r3, r1
    mov r1, r0
    mov r0, r3
    str r0, [r4]
    str r1, [r4, #4]
check:
    subs r5, #1
    bne fib

exit:
    svc #0
";

fn black_box_code_cb(proc: CoreHandle) -> Result<(), UnknownError> {
    black_box(proc);
    Ok(())
}

fn black_box_mem_read_cb(
    proc: CoreHandle,
    _: u64,
    _: u32,
    _: &mut [u8],
) -> Result<(), UnknownError> {
    black_box(proc);
    Ok(())
}

fn black_box_mem_write_cb(proc: CoreHandle, _: u64, _: u32, _: &[u8]) -> Result<(), UnknownError> {
    black_box(proc);
    Ok(())
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcode-backend");
    group.warm_up_time(Duration::from_secs(10));

    // Do machine initialization before measurement.
    let mut backend = build_backend(FIB);
    group.bench_function("fibonacci-register", |b| b.iter(|| run(&mut backend, 47)));

    // Do machine initialization before measurement.
    let mut backend = build_backend(FIB_MEMORY);
    group.bench_function("fibonacci-memory", |b| b.iter(|| run(&mut backend, 47)));

    // Do machine initialization before measurement.
    let mut backend = build_backend(FIB);
    backend
        .code_hook(0x1000, 0x2000, Box::new(black_box_code_cb))
        .unwrap();
    group.bench_function("fibonacci-code-hook-hit", |b| {
        b.iter(|| run(&mut backend, 47))
    });

    // Do machine initialization before measurement.
    let mut backend = build_backend(FIB_MEMORY);

    backend
        .mem_read_hook(0x0, 0x1000, Box::new(black_box_mem_read_cb))
        .unwrap();
    backend
        .mem_write_hook(0x0, 0x1000, Box::new(black_box_mem_write_cb))
        .unwrap();

    group.bench_function("fibonacci-memory-hook", |b| {
        b.iter(|| run(&mut backend, 47))
    });

    for hooks in [10, 20, 30, 40].iter() {
        group.bench_with_input(
            BenchmarkId::new("fibonacci-code-hooks-hit", hooks),
            hooks,
            |b, h| {
                let mut backend = build_backend(FIB);
                for _ in 0..*h {
                    backend
                        .code_hook(0x1000, 0x2000, Box::new(black_box_code_cb))
                        .unwrap();
                }
                b.iter(|| run(&mut backend, 47))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("fibonacci-code-hooks-no-hit", hooks),
            hooks,
            |b, h| {
                let mut backend = build_backend(FIB);
                for _ in 0..*h {
                    backend
                        .code_hook(0x9999, 0x9999, Box::new(black_box_code_cb))
                        .unwrap();
                }
                b.iter(|| run(&mut backend, 47))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("fibonacci-memory-hooks-hit", hooks),
            hooks,
            |b, h| {
                let mut backend = build_backend(FIB_MEMORY);
                for _ in 0..*h {
                    backend
                        .mem_read_hook(0x0, 0x1000, Box::new(black_box_mem_read_cb))
                        .unwrap();
                    backend
                        .mem_write_hook(0x0, 0x1000, Box::new(black_box_mem_write_cb))
                        .unwrap();
                }
                b.iter(|| run(&mut backend, 47))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("fibonacci-memory-hooks-no-hit", hooks),
            hooks,
            |b, h| {
                let mut backend = build_backend(FIB_MEMORY);
                for _ in 0..*h {
                    backend
                        .mem_read_hook(0x9999, 0x9999, Box::new(black_box_mem_read_cb))
                        .unwrap();
                    backend
                        .mem_write_hook(0x9999, 0x9999, Box::new(black_box_mem_write_cb))
                        .unwrap();
                }
                b.iter(|| run(&mut backend, 47))
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark
}
criterion_main!(benches);
