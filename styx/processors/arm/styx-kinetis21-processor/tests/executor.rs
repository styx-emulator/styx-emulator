// SPDX-License-Identifier: BSD-2-Clause
use std::time::{Duration, Instant};

use styx_core::prelude::*;
use styx_kinetis21_processor::Kinetis21Builder;

const WOLFSSL_SELFTEST_PATH: &str =
    "arm/kinetis_21/bin/wolfssl_selftest/wolfssl_selftest_debug.bin";

#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_executor_step() {
    let mut proc = ProcessorBuilder::default()
        .with_backend(Backend::Pcode)
        .with_target_program(resolve_test_bin(WOLFSSL_SELFTEST_PATH))
        .with_loader(RawLoader)
        .with_builder(Kinetis21Builder::default())
        .build()
        .unwrap();

    let result = proc.run(13000);
    assert!(result.is_ok());
}

#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_executor_stride_timeout() {
    let mut proc = ProcessorBuilder::default()
        .with_backend(Backend::Pcode)
        .with_target_program(resolve_test_bin(WOLFSSL_SELFTEST_PATH))
        .with_loader(RawLoader)
        .with_builder(Kinetis21Builder::default())
        .build()
        .unwrap();
    const RUN_TIME: Duration = Duration::from_secs(3);

    let start = Instant::now();
    let result = proc.run(RUN_TIME);
    let duration = start.elapsed();
    assert!(result.is_ok());
    assert!(duration >= RUN_TIME);
}
