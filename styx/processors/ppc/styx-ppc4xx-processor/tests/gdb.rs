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

use styx_core::cpu::arch::ppc32::gdb_targets::Ppc4xxTargetDescription;
use styx_core::prelude::*;

use styx_core::util::resolve_test_bin;
use styx_integration_tests::gdb_core_test_suite;

const FREERTOS_PATH: &str = "ppc/ppc405/bin/freertos.bin";

fn build_raw() -> ProcessorBuilder<'static> {
    // create default processor w gdb
    ProcessorBuilder::default()
        .with_builder(styx_ppc4xx_processor::PowerPC405Builder::default())
        .with_ipc_port(IPCPort::any())
}

fn gdb_tests_builder() -> ProcessorBuilder<'static> {
    let test_bin_path = resolve_test_bin(FREERTOS_PATH);
    let loader_yaml = format!(
        r#"
        - !FileRaw
            # gdb_core_test_suite requires that the file be loaded at 0x0.
            base: 0x0
            file: {}
            perms: !AllowAll
        - !RegisterImmediate
            # adjusted start value, address of _start when based at 0x0
            register: pc
            value: 0x20c4
"#,
        test_bin_path
    );
    build_raw()
        .with_loader(ParameterizedLoader)
        .with_input_bytes(loader_yaml.as_bytes().to_owned().into())
}

// - Bytes must be loaded at 0x0 (maybe it should read at pc)
// - Pc must be set by loader, the input here will not set pc, it's simply a value to check
// - watchpoint must be far enough away from entry to allow harness/client to connect before hitting (not 100% sure on the reason)
gdb_core_test_suite!(
    "pc",
    FREERTOS_PATH,
    0x20c4,
    0x20d0,
    0x20dc,
    0xFFFFFEB4,
    Ppc4xxTargetDescription,
    gdb_tests_builder,
);
