// SPDX-License-Identifier: BSD-2-Clause

use styx_core::arch::ppc32::Ppc32Variants;
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
            file: {test_bin_path}
            perms: !AllowAll
        - !RegisterImmediate
            # adjusted start value, address of _start when based at 0x0
            register: pc
            value: 0x20c4
"#
    );
    build_raw()
        .with_loader(ParameterizedLoader::default())
        .with_input_bytes(loader_yaml.as_bytes().to_owned().into())
}

// see documentation of the test suite for all requirements of
// test environment (there are many :D)
gdb_core_test_suite!(
    "pc",
    FREERTOS_PATH,
    0x20c4,
    0x20d0,
    0x20dc,
    0xFFFFFF54,
    Ppc4xxTargetDescription,
    Ppc32Variants::Ppc405,
    gdb_tests_builder,
);
