// SPDX-License-Identifier: BSD-2-Clause
//! Benchmark of full-system performance in a GPIO heavy application.
//!
//! The `led_output` test binary initializes GPIO and toggles the GPIO pin twice
//! before exiting.
//!
//! - Run this benchmark
//!   - `cargo bench --package styx-emulator --bench kinetis21_gpio`
//! - Save a baseline and then compare against it later
//!   - `cargo bench --package styx-emulator --bench kinetis21_gpio -- --save-baseline bitband`
//!   - `cargo bench --package styx-emulator --bench kinetis21_gpio -- --baseline bitband`

use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;
use styx_core::loader::RawLoader;
use styx_core::prelude::Forever;
use styx_core::processor::ProcessorBuilder;
use styx_core::util::resolve_test_bin;
use styx_processors::arm::kinetis21::Kinetis21Builder;

const FW_PATH: &str = "arm/kinetis_21/bin/led_output/led_output_debug.bin";

/// Build the processor and run the target program to completion.
fn run() {
    let mut proc = ProcessorBuilder::default()
        .with_builder(Kinetis21Builder::default())
        .with_loader(RawLoader)
        .with_target_program(resolve_test_bin(FW_PATH))
        .build()
        .unwrap();

    proc.run(Forever).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("gpio-full");
    group.sample_size(10).warm_up_time(Duration::from_secs(10));
    group.bench_function("gpio-full", |b| b.iter(run));
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
