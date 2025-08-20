// SPDX-License-Identifier: BSD-2-Clause
use std::sync::Arc;

use styx_emulator::{
    errors::UnknownError,
    peripheral_clients::uart::UartClient,
    prelude::{logging::init_logging, resolve_test_bin, Forever},
};
use styx_uconf::{
    realize_unified, realize_unified_config, ProcessorComponentsStore, UnifiedConfig,
};

const MANY_OPTIONS_CONFIG: &str = r#"
        version: 1
        processors:
        - name: Test Processor
          processor: ppc_4xx
          backend: Pcode
          executor:
              id: default
          port: 0
          program:
          - !MemoryRegion
              # Base address for the region.
              base: 0x100000
              # Size for the region.
              size: 0x800000
              # Permissions for the region. See above for valid permission options.
              perms: !ReadWrite
          - !MemoryRegion
              base: 0x1000000
              size: 0x2000000
              perms: !AllowAll
          - !RegisterImmediate
              # Register to be loaded with a value.
              register: pc
              # Immediate value to load into the register.
              value: 0x1000
          - !RegisterMemoryAddress
              # Register to be loaded with a value.
              register: r4
              # Address from which to load the register value.
              address: 0x40000
          - !EnvironmentStateVariable
              # Define a processor-specific environment state variable.
              - derp
              - 0xF00BA8
        "#;

#[test]
fn test_many_options() -> Result<(), UnknownError> {
    let config: UnifiedConfig = serde_yaml::from_str(MANY_OPTIONS_CONFIG).unwrap();
    let components = ProcessorComponentsStore::new();
    let mut builder = realize_unified_config(&config, &components)?;
    let _ = builder.pop().unwrap().build()?;
    Ok(())
}

#[test]
fn test_many_options_build() -> Result<(), UnknownError> {
    let mut builder = realize_unified(MANY_OPTIONS_CONFIG)?;
    let _ = builder.pop().unwrap().build()?;
    Ok(())
}

/// port of the ppc4xx freertos test with a yaml spec
#[test]
fn test_freertos_hello() -> Result<(), UnknownError> {
    init_logging();
    use std::net::TcpStream;

    const FREERTOS_HELLO_PATH: &str = "arm/kinetis_21/bin/freertos_hello/freertos_hello_debug.bin";
    let yaml = format!(
        r#"
        version: 1
        processors:
        - name: FreeRTOS Test Processor
          processor: arm_kinetis21
          backend: Pcode
          executor:
              id: default
          port: 1337
          program:
          - !FileRaw
              base: 0x0
              file: {}
              perms: !AllowAll
        "#,
        resolve_test_bin(FREERTOS_HELLO_PATH)
    );

    let mut builder = realize_unified(yaml)?;
    let mut processor = builder.pop().unwrap().build()?;

    let ipc_port = processor.ipc_port();
    println!("Trying to connect...");

    loop {
        match TcpStream::connect(format!("127.0.0.1:{ipc_port}")) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }

    let uart_client = Arc::new(UartClient::new(
        format!("http://127.0.0.1:{ipc_port}"),
        Some(5),
    ));
    println!("Connected!");

    std::thread::spawn(move || {
        processor.run(Forever).unwrap();
    });

    // wait for hello world uart message
    let data = uart_client.recv(14, None);

    // check that we got the correct message
    assert_eq!(&data, "Hello world.\r\n".as_bytes());

    // cleanup processor
    println!("Aborting");
    Ok(())
}
