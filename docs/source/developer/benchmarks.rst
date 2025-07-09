.. _benchmarks:

Benchmarking
############

Benchmarking is measure of the execution speed of your project. The
idea is to have a set of standard tests that exercise most of the
program's functionality so that performance improvements and
regressions that happen during development can be caught,
quantified, and handled. In styx in particular, emulation speed is
critical to providing usable fuzzing and a better user experience.

Current benchmarking in styx is sparse but the scaffolding is there so
that after adding new features or investigating performance issues, new
benchmarks can be put in place.

Running Benchmarks
==================

Run All Benchmarks
^^^^^^^^^^^^^^^^^^

To run all benchmarks in styx you can run the following in the root
of the project directory.

.. code-block:: console

    $ just bench

Run A Single Benchmark
^^^^^^^^^^^^^^^^^^^^^^

Most likely, you will want to focus on a single benchmark that you aim to
improve. For example, if I want to improve k21 gpio performance
then the `kinetis21_gpio` benchmark would be a perfect benchmark to focus on.

Run the single benchmark:

.. code-block:: console

    $ cargo bench --bench kinetis21_gpio

       Finished bench [optimized] target(s) in 0.15s
        Running benches/kinetis21_gpio.rs (target/release/deps/kinetis21_gpio-5beb4b191b7fef4d)
    Gnuplot not found, using plotters backend
    Benchmarking gpio-full/gpio-full: Warming up for 10.000 s
    Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 82.6s.
    gpio-full/gpio-full     time:   [8.7447 s 8.9288 s 9.1197 s]

Our benching framework (`criterion-rs <https://bheisler.github.io/criterion.rs/book/criterion_rs.html>`_)
will "warm up" the cpu before executing the benchmark 10 times to
get an accurate measurement. The middle number will give the mean
time to execute.

Then, make your changes and run again:

.. code-block:: console

    $ cargo bench --bench kinetis21_gpio

       Finished bench [optimized] target(s) in 1m 11s
        Running benches/kinetis21_gpio.rs (target/release/deps/kinetis21_gpio-a196b6352116c122)
    Gnuplot not found, using plotters backend
    Benchmarking gpio-full/gpio-full: Warming up for 10.000 s
    Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 82.5s.
    gpio-full/gpio-full     time:   [8.6132 s 8.7699 s 8.9291 s]
                            change: [-4.4853% -1.7798% +0.8497%] (p = 0.25 > 0.05)
                            No change in performance detected.

Criterion compares the previous bench run with the current one to
give an insight into performance changes. In this case our mean
execution time improved by 1.7% but this was not enough to suggest
a significant change in performance and can be attributed to
measurement noise.

Create a Named Baseline
^^^^^^^^^^^^^^^^^^^^^^^

It may also help to specify a baseline benchmark result with which
to compare future benchmark runs to, without overwriting the original
results. The baseline feature will save a benchmark
by name so future bench runs can compare against that instead of the
previous run.

To save a baseline named `before`:

.. code-block:: console

    $ cargo bench --bench kinetis21_gpio -- --save-baseline before

Then to bench again and compare against the `before` baseline:

.. code-block:: console

    $ cargo bench --bench kinetis21_gpio -- --baseline before


Creating Benchmarks
===================

A single benchmark consists of a file in the ``benches/`` directory.
Create a file in there and put the following table in the crates
``Cargo.toml``, example is for a ``my_benchmark.rs``:

.. code-block:: toml

    [[bench]]
    name = "my_benchmark"
    harness = false

Then in your benchmark code file:

.. code-block:: rust
    :caption: my_benchmark.rs

    use criterion::{black_box, criterion_group, criterion_main, Criterion};

    fn fibonacci(n: u64) -> u64 {
        match n {
            0 => 1,
            1 => 1,
            n => fibonacci(n-1) + fibonacci(n-2),
        }
    }

    fn criterion_benchmark(c: &mut Criterion) {
        let mut group = c.benchmark_group("fibonacci");
        group.sample_size(10).warm_up_time(Duration::from_secs(10));
        group.bench_function("fibonacci", |b| b.iter(|| fibonacci(20)));
        group.finish();
    }

    criterion_group!(benches, criterion_benchmark);
    criterion_main!(benches);

You can modify the number passed to sample size to increase/decrease
the number of samples and thus runtime of your test.

Limitations
===========

There a couple limitations to benchmarking in styx that you should
know about.

Measurement Accuracy
^^^^^^^^^^^^^^^^^^^^

Because benchmarks are just measuring time to execute, they are
susceptible to changes in computing environment. Most obvious is that
measurements performed on different computers cannot be meaningfully
compared to each other, including on CI pipelines.

More subtly is that even measurements on the same computer can be skewed
by other processes running on the system, dependency updates, laptop
running on battery vs charging, etc.

Averaging the measurements of multiple consecutive runs filters out most of
the noise but validating measurement accuracy should always in the back of
your mind.

Slow
^^^^

When emulating full binaries as benchmarks the time to run can be
excruciating long, slowing down the development process and testing
developer sanity. While benchmarking "real world" applications is
optimal, sometimes they take too long to practically use as benchmarks.
This is true especially considering that benchmarks must run them
several times to get an accurate measurement. The balance between
measurement accuracy and time to execute should be considered when
designing benchmarks.

Likewise, when using benchmarks to test performance of a specific
feature, be mindful of whether or not the benchmark accurately
reflects the real world performance of the feature you're testing.

Case Study - ``kinetis21_gpio``
===============================

A useful example of using a benchmark to debug performance issues is the
``kinetis21_gpio`` benchmark in ``./benches`` (code found at the end
of this section).

After implementing bit-banding in the kinetis21 cpu, we noticed our example for
this cpu was running much slower than before showing a roughly a 2-3x slowdown.
This particular example ran the led_output binary built for the kinetis21 which
toggles an led on a gpio pin in a loop with a delay. After running with trace
logging, we quickly realized that each loop had many writes to the peripheral
memory range to activate the gpio pin and led. The peripheral memory range was
also covered by bit-banding which meant that every write to the peripheral memory
range caused 32 writes in the bit-band alias region. Not good.

The fix for this issue was fairly small but it could have been caught before it
was committed if there was a benchmark to quantify performance changes from a
code change. Additionally, while this regression was caught quick, it could have
easily fell through the cracks and halved performance for many releases to come.

To aid in fixing this regression, we added a kinetis21 gpio benchmark to monitor
performance of gpio heavy applications. The benchmark looks simple but it's running
the ``led_output_debug.bin`` found in the test-binaries directory, effectively
mimicking a whole system use case.

Using the benchmark was simple. Before making any changes create a baseline:

.. code-block:: console

    $ cargo bench --bench kinetis21_gpio -- --save-baseline bitband

Then after making our changes run again and compare our results:

.. code-block:: console

    $ cargo bench --bench kinetis21_gpio -- --baseline bitband

A non-obvious benefit of a whole system benchmark is that performance changes
caught in a system benchmark are truly meaningful to the user. I could spend hours
tweaking assembly to get a 5x speed up of a function level benchmark that might not
even impact system performance when running actual binaries. With a solid benchmark
in place, we can be confident that our fix has a meaningful improvement on
performance.

Benchmark Code
^^^^^^^^^^^^^^

.. code-block:: rust
    :caption: benches/benches/kinetis21_gpio.rs

    //! Benchmark of full-system performance in a GPIO heavy application.
    //!
    //! The `led_output` test binary initializes GPIO and toggles
    //! the GPIO ping twice before exiting.
    use criterion::{criterion_group, criterion_main, Criterion};

    use std::time::Duration;
    use styx_cpu::arch::arm::ArmVariants;
    use styx_cpu::ArchEndian;
    use styx_loader::RawLoader;
    use styx_machines::arm::nxp::kinetis_21::Kinetis21Cpu;
    use styx_machines::processor_prelude::*;
    use tracing::info;

    const FW_PATH: &str = "../data/test-binaries/arm/kinetis_21/bin/led_output/led_output_debug.bin";

    fn run() {
        info!("Building processor.");
        let builder = ProcessorBuilder::<Kinetis21Cpu>::default()
            .with_endian(ArchEndian::LittleEndian)
            .with_executor(Executor::default())
            .with_loader(RawLoader)
            .with_target_program(FW_PATH.to_owned())
            .with_variant(ArmVariants::ArmCortexM4);

        let proc = builder.build().unwrap();

        info!("Starting emulator");
        proc.start().unwrap();
    }

    fn criterion_benchmark(c: &mut Criterion) {
        let mut group = c.benchmark_group("gpio-full");
        group.sample_size(10).warm_up_time(Duration::from_secs(10));
        group.bench_function("gpio-full", |b| b.iter(run));
        group.finish();
    }

    criterion_group!(benches, criterion_benchmark);
    criterion_main!(benches);
