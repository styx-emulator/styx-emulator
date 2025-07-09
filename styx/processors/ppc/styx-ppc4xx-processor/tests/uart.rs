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
use styx_core::prelude::*;
use styx_integration_tests::uart_integration::uart_test;
use styx_ppc4xx_processor::PowerPC405Builder;

const UART_TEST_PATH: &str = "ppc/ppc405/bin/uart_test.bin";

#[test]
pub fn test_uart() {
    // styx_util::logging::init_logging();
    let loader_yaml = format!(
        r#"
        - !FileRaw
            base: 0xfff00000
            file: {}
            # Permissions for the allocated memory. Valid permissions are ReadOnly,
            # WriteOnly, ExecuteOnly, ReadWrite, ReadExecute and AllowAll.
            perms: !AllowAll
        - !RegisterImmediate
            # Register to be loaded with a value.
            register: pc
            # Immediate value to load into the register.
            value: 0xfffffffc
"#,
        resolve_test_bin(UART_TEST_PATH)
    );
    let processor = ProcessorBuilder::default()
        .with_loader(ParameterizedLoader)
        .with_input_bytes(loader_yaml.as_bytes().to_owned().into())
        .with_builder(PowerPC405Builder::default());

    uart_test(processor, 0);
}
