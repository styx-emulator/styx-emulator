// SPDX-License-Identifier: BSD-2-Clause
//! Benchmark for processor snapshots.
//!
//! The benchmark tests snapshot saving, snapshot restoring, and both combined. The processor is run
//! halfway through the wolfssl tests before performing the tests.
//!
//! - Run all benchmarks
//!   - `cargo bench --package styx-emulator --bench snapshot`
//! - Run single benchmark (replace `fibonacci-register` with filter)
//!   - `cargo bench --package styx-emulator --bench snapshot -- "restore only"
//! - Save a baseline and then compares against it later
//!   - `cargo bench --package styx-emulator --bench snapshot -- "restore only" --save-baseline
//!     base`
//!   - `cargo bench --package styx-emulator --bench snapshot -- "restore only" --baseline base`
//! - Generate a flame graph of function calls to find performance culprits
//!   - `cargo install flamegraph # only needed once`
//!   - `cargo flamegraph --package styx-emulator --bench snapshot -- --bench --profile-time 5
//!     "restore only"

use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;
use styx_core::loader::RawLoader;
use styx_core::prelude::{IPCPort, Processor};
use styx_core::processor::ProcessorBuilder;
use styx_core::util::resolve_test_bin;
use styx_processors::arm::kinetis21::Kinetis21Builder;

fn get_firmware_path() -> String {
    const FW_PATH: &str = "arm/kinetis_21/bin/wolfssl_selftest/wolfssl_selftest_debug.bin";
    resolve_test_bin(FW_PATH)
}

const HALFWAY_POINT: u64 = 16500;

/// Build the processor and run the emulation.
fn build_proc() -> Processor {
    let mut proc = ProcessorBuilder::default()
        .with_builder(Kinetis21Builder::default())
        .with_loader(RawLoader)
        .with_target_program(get_firmware_path())
        .with_ipc_port(IPCPort::any())
        .build()
        .unwrap();

    // Run part of the test program.
    proc.run(HALFWAY_POINT).unwrap();
    proc
}

enum TestType {
    RestoreOnly,
    SaveOnly,
    SaveRestore,
}

/// Run the indicated operations on the processor. This is typically the step we are attempting to
/// benchmark.
fn run(proc: &mut Processor, test_type: TestType) {
    match test_type {
        TestType::RestoreOnly => {
            assert!(proc.context_restore().is_ok());
        }
        TestType::SaveOnly => {
            assert!(proc.context_save().is_ok());
        }
        TestType::SaveRestore => {
            assert!(proc.context_save().is_ok());
            assert!(proc.context_restore().is_ok());
        }
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    const SAMPLES: usize = 10;
    const MEASUREMENT_TIME: Duration = Duration::from_secs(160);
    const WARMUP_TIME: Duration = Duration::from_secs(3);
    let mut group = c.benchmark_group("Context snapshot benchmarks");
    group
        .sample_size(SAMPLES)
        .warm_up_time(WARMUP_TIME)
        .measurement_time(MEASUREMENT_TIME);

    // We use `BatchSize::PerIteration` below in order to perform only one iteration per batch.
    // This is necessary since we are sharing an pointer to the same Processor instance. Otherwise,
    // we may introduce contention that would affect our timing.
    //
    // Note, ideally, we would build the processor and emulate for each sample so they could all
    // have a distinct processor instance. However, doing so causes the benchmarks to fail by
    // running out of memory. This happened with all `BatchSize` variants.
    let mut proc = build_proc();
    group.bench_function("snapshot only", |b| {
        b.iter(|| run(&mut proc, TestType::SaveOnly))
    });

    //let mut proc = build_proc();
    group.bench_function("snapshot and restore", |b| {
        b.iter(|| run(&mut proc, TestType::SaveRestore))
    });

    //let mut proc = build_proc();
    // run(&mut proc, TestType::SaveOnly);
    group.bench_function("restore only", |b| {
        b.iter(|| run(&mut proc, TestType::RestoreOnly))
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark
}
criterion_main!(benches);
