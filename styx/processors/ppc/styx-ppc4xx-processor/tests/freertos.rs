// SPDX-License-Identifier: BSD-2-Clause
use std::sync::Arc;
use std::time::Duration;
use styx_core::cpu::arch::ppc32::Ppc32Register;

use styx_core::hooks::StyxHook;
use styx_core::prelude::log::debug;
use styx_core::prelude::ProcessorBuilder;
use styx_core::prelude::*;
use styx_core::util::logging::init_logging;
use styx_core::util::resolve_test_bin;
use styx_ppc4xx_processor::PowerPC405Builder;
use tracing::info;

const FREERTOS_PATH: &str = "ppc/ppc405/bin/freertos.bin";

/// Tracks test status.
struct Test {
    name: String,
    status: TestStatus,
}

enum TestStatus {
    Failure,
    Nothing,
    Success,
}
impl Default for TestStatus {
    fn default() -> Self {
        Self::Nothing
    }
}

impl Test {
    fn new(name: impl AsRef<str>) -> Self {
        Test {
            name: name.as_ref().to_owned(),
            status: Default::default(),
        }
    }

    /// Moves status to success unless a failure has occurred.
    fn succeed(&mut self) {
        let name = &self.name;
        self.status = match self.status {
            TestStatus::Nothing => {
                info!("{name} succeeded");
                TestStatus::Success
            }
            TestStatus::Success => TestStatus::Success,
            TestStatus::Failure => TestStatus::Failure,
        };
    }

    /// Moves status to success failure.
    fn fail(&mut self) {
        let name = &self.name;
        self.status = match self.status {
            TestStatus::Nothing | TestStatus::Success => {
                info!("{name} failed");
                TestStatus::Failure
            }
            TestStatus::Failure => TestStatus::Failure,
        };
    }

    /// Did this test succeed and have no failures?
    fn succeeded(&self) -> bool {
        match self.status {
            TestStatus::Success => true,
            TestStatus::Failure | TestStatus::Nothing => false,
        }
    }
}

/// Tests system using a build of FreeRTOS.
///
/// Currently checks for success in the math task and that the LED task gets
/// scheduled after its delay.
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_freertos() {
    init_logging();
    /// Hit when math task checks.
    const MATH_CHECK: u64 = 0xfff06b8c;
    /// Hit after LEDs are
    const LED_RUN: u64 = 0xfff05de8;
    /// After checks have run, return stored in r3.
    /// 0 = bad
    const CHECK_DONE: u64 = 0xfff0253c;
    /// pxCurrentTCB memory location, pointer to current task struct
    const PX_CURRENT_TCB: u64 = 0xfff0ff24u64;

    let test_bin_path = resolve_test_bin(FREERTOS_PATH);
    let loader_yaml = format!(
        r#"
        - !FileRaw
            base: 0xfff00000
            file: {test_bin_path}
            perms: !AllowAll
        - !RegisterImmediate
            register: pc
            value: 0xfffffffc
"#
    );

    let mut processor = ProcessorBuilder::default()
        .with_loader(ParameterizedLoader::default())
        .with_builder(PowerPC405Builder::default())
        .with_input_bytes(loader_yaml.as_bytes().into())
        .build()
        .unwrap();

    {
        processor
            .add_hook(StyxHook::MemoryWrite(
                (PX_CURRENT_TCB..=PX_CURRENT_TCB).into(),
                Box::new(move |_cpu: CoreHandle, _address, _size, data: &[u8]| {
                    let value = u32::from_be_bytes(data.try_into().unwrap());
                    let name_ptr = value + 0x34;
                    let name = _cpu.mmu.data().read(name_ptr as u64).vec(0x14).unwrap();
                    let str = String::from_utf8(name).unwrap();
                    info!("PX_CURRENT_TCB task {str}");

                    Ok(())
                }),
            ))
            .unwrap();
    }

    let math_succeed = Arc::new(Mutex::new(Test::new("Math")));
    {
        let math_succeed = math_succeed.clone();
        processor
            .add_hook(StyxHook::Code(
                (MATH_CHECK..=MATH_CHECK).into(),
                Box::new(move |cpu: CoreHandle| {
                    let cr = cpu.cpu.read_register::<u32>(Ppc32Register::Cr7).unwrap();
                    debug!("cr: 0x{cr:X}");
                    let equal = cr & 0x2 > 0;

                    if equal {
                        math_succeed.lock().unwrap().succeed();
                    } else {
                        math_succeed.lock().unwrap().fail();
                        panic!()
                    }
                    Ok(())
                }),
            ))
            .unwrap();
    }

    let led_succeed = Arc::new(Mutex::new(Test::new("Led")));
    {
        let led_succeed = led_succeed.clone();
        processor
            .add_hook(StyxHook::Code(
                (LED_RUN..=LED_RUN).into(),
                Box::new(move |_cpu: CoreHandle| {
                    led_succeed.lock().unwrap().succeed();
                    _cpu.cpu.stop();
                    Ok(())
                }),
            ))
            .unwrap();
    }

    let check_done = Arc::new(Mutex::new(Test::new("Final Check")));
    {
        let check_done = check_done.clone();
        processor
            .add_hook(StyxHook::Code(
                (CHECK_DONE..=CHECK_DONE).into(),
                Box::new(move |cpu: CoreHandle| {
                    check_done.lock().unwrap().succeed();
                    cpu.cpu.stop();
                    Ok(())
                }),
            ))
            .unwrap()
    };

    processor.run(Duration::from_secs(300)).unwrap();

    // cleanup processor
    println!("Aborting");

    assert!(math_succeed.lock().unwrap().succeeded());
    assert!(led_succeed.lock().unwrap().succeeded());
    // assert!(check_done.lock().unwrap().succeeded());
}
