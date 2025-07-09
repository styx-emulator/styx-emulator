// SPDX-License-Identifier: BSD-2-Clause
use styx_core::prelude::*;
use styx_integration_tests::uart_integration::uart_test;
use styx_kinetis21_processor::Kinetis21Builder;

const UART_TEST_PATH: &str = "arm/kinetis_21/bin/uart_test/uart_test_debug.bin";

#[test]
#[cfg_attr(miri, ignore)]
fn test_uart() {
    let builder = ProcessorBuilder::default()
        .with_backend(Backend::Pcode)
        .with_target_program(resolve_test_bin(UART_TEST_PATH))
        .with_loader(RawLoader)
        .with_builder(Kinetis21Builder::default());

    uart_test(builder, 5);
}
