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
