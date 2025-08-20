// SPDX-License-Identifier: BSD-2-Clause
use std::{
    net::TcpStream,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use styx_core::{
    loader::ElfLoader,
    peripheral_clients::spi::SPISimpleClient,
    prelude::{ProcessorBuilder, *},
    util::{self, logging::init_logging},
};
use styx_devices::{adc::ADS7866, eeprom::AT25HP512};
use styx_stm32f107_processor::Stm32f107Builder;

/// Test firmware reads from virtualized ADC and writes to virtualized EEPROM over SPI.
#[test]
fn test_spi_combined() -> Result<(), UnknownError> {
    init_logging();
    let target_program = util::resolve_test_bin("arm/stm32f107/bin/spi_combined/main.elf");
    let mut proc = ProcessorBuilder::default()
        .with_ipc_port(IPCPort::any())
        .with_backend(Backend::Pcode)
        .with_loader(ElfLoader::default())
        .with_target_program(target_program)
        .with_builder(Stm32f107Builder)
        .build()?;

    let port = proc.ipc_port();
    let eeprom = Arc::new(Mutex::new(AT25HP512::new()));
    let thread_eeprom = eeprom.clone();

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();

    // thread with eeprom and adc
    std::thread::spawn(move || {
        loop {
            match TcpStream::connect(format!("127.0.0.1:{port}")) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        let adc = ADS7866::new();
        // Spi port 1 (port 2 in target code/headers)
        let client = SPISimpleClient::new(format!("http://127.0.0.1:{port}"), 1);
        client.connect_device(adc);

        // Spi port 0 (port 1 in target code/headers)
        let client = SPISimpleClient::new(format!("http://127.0.0.1:{port}"), 0);
        client.connect_device(thread_eeprom);
        while !thread_stop.load(atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    let res = proc.run(200000).unwrap();
    println!("processor done");
    stop.store(true, atomic::Ordering::SeqCst);
    assert!(!res.is_fatal());

    let eeprom_ref = eeprom.lock().unwrap();

    // check if address 0x100 of the eeprom has a nonzero value
    // i.e. did the processor write to it
    let data = eeprom_ref.memory.read(0x100).be().u16()?;
    assert!(data > 0);

    // check that the eeprom internal address was not left at zero
    // in my testing this value is about 350 but it is not consistent
    assert!(eeprom_ref.address() > 0);
    Ok(())
}
