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

//! Benchmark pcode backend execution with a powerpc processor.
//!
//! The benchmark tests with and without register hooks enabled to estimate their impact on
//! performance.
//!
//! - Run all benchmarks
//!   - `cargo bench --package styx-emulator --bench pcode_register_hooks`
//! - Run single benchmark (replace `"with register hooks"` with filter)
//!   - `cargo bench --package styx-emulator --bench pcode_register_hooks -- "with register hooks"`
//! - Save a baseline and then compares against it later
//!   - `cargo bench --package styx-emulator --bench pcode_register_hooks -- "with register hooks"
//!     --save-baseline base`
//!   - `cargo bench --package styx-emulator --bench pcode_register_hooks -- "with register hooks" --baseline
//!     base`
//! - Generate a flame graph of function calls to find performance culprits
//!   - `cargo install flamegraph # only needed once`
//!   - `cargo flamegraph --package styx-emulator --bench pcode_backend -- --bench --profile-time 5
//!     "with register hooks"`

use criterion::{criterion_group, criterion_main, Criterion};

use styx_core::{
    arch::ppc32::Ppc32Variants,
    cpu::{PcodeBackend, PcodeBackendConfiguration},
};
use styx_emulator::prelude::*;

struct Proc {
    cpu: PcodeBackend,
    mmu: Mmu,
    ev: EventController,
}
fn build(register_hooks_enabled: bool) -> Proc {
    let instruction_test = &styx_emulator::core::util::resolve_test_bin("ppc/fib/fib.text");
    let instruction_test_bytes = &std::fs::read(instruction_test).unwrap();

    let mut cpu = PcodeBackend::new_engine_config(
        Ppc32Variants::Ppc405,
        ArchEndian::BigEndian,
        &PcodeBackendConfiguration {
            register_read_hooks: register_hooks_enabled,
            register_write_hooks: register_hooks_enabled,
            ..Default::default()
        },
    );

    let mut mmu = Mmu::default();
    let ev = EventController::default();
    mmu.code()
        .write(0x100)
        .bytes(instruction_test_bytes)
        .unwrap();
    cpu.add_hook(StyxHook::code(0x134..=0x134, |proc: CoreHandle| {
        proc.cpu.stop();
        Ok(())
    }))
    .unwrap();

    Proc { cpu, mmu, ev }
}
fn fibonacci(proc: &mut Proc) {
    proc.cpu.set_pc(0x100).unwrap();
    // init_logging();
    let exit = proc
        .cpu
        .execute(&mut proc.mmu, &mut proc.ev, u64::MAX) // huge value, the code hook above should stop the processor
        .unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::HostStopRequest);
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("fib");
    group.bench_function("without register hooks", |b| {
        let mut proc = build(false);
        b.iter(|| fibonacci(&mut proc))
    });
    group.bench_function("with register hooks", |b| {
        let mut proc = build(true);
        b.iter(|| fibonacci(&mut proc))
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
