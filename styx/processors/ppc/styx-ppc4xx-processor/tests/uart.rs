// SPDX-License-Identifier: BSD-2-Clause
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
