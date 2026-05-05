// SPDX-License-Identifier: BSD-2-Clause

#![cfg(feature = "hexagon-tests")]
#![cfg(not(feature = "disable-hexagon-tests"))] // hack for when using `--all-features`

use crate::runner::{setup_load_hexagon, HexagonBinaryType};
use crate::{devices::tester::Tester, CHANNEL_SIZE};
use log::info;
use std::sync::{Arc, Mutex};
use std::thread;
use styx_emulator::cpu::TargetExitReason;
use styx_emulator::prelude::logging::init_logging;
use styx_emulator::prelude::styx_async::sync::broadcast;
use styx_emulator::prelude::Forever;
use styx_hexagon_testdata::TestData;

#[allow(unused)]
fn test_qemu_hexagon_testing_unittests(test: TestData) {
    init_logging();

    let device = Tester::default();

    // Semihosting channel
    let (tx, mut rx) = broadcast::channel(CHANNEL_SIZE);
    let mut proc = setup_load_hexagon(
        HexagonBinaryType::BinaryData(test.bytes()),
        // No debug
        None,
        &device,
        Arc::new(tx),
    )
    .expect("couldn't setup_load_hexagon");

    let output_buffer = Arc::new(Mutex::new(String::new()));
    let output_buffer_thread = output_buffer.clone();

    // Start thread that gets TX output and puts it in a shared buffer
    thread::spawn(move || {
        while let Ok(chr) = rx.blocking_recv() {
            let mut obuf = output_buffer_thread
                .lock()
                .expect("couldn't get output buffer mutex");
            obuf.push(chr as char);
        }
    });

    // This blocks, so retrieving the semihosting buffer populated
    // in the second thread after this is okay since by then the process
    // will have exited
    let res = proc.run(Forever).expect("Proc did not run properly");
    assert_eq!(res.exit_reason, TargetExitReason::HostStopRequest);

    let obuf = output_buffer
        .lock()
        .expect("couldn't get output buffer mutex");

    info!("Output from test was: {obuf}");

    // Check if the last line of the test reads "PASS"
    assert_eq!(obuf.trim().rsplit("\n").nth(0), Some("PASS"));
}
