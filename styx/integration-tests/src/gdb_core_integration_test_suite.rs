// SPDX-License-Identifier: BSD-2-Clause
/// Given a series of inputs, generate a test suite to exercise gdb plugin functionality for a
/// provided styx processor
///
/// As input this macro requires (in order)
/// - a `&'static str` name of the `pc` register according to gdb
/// - a `&'static str` name of the test program (relative to the `data/testbins` path)
/// - `u64` the start address of the test program
/// - `u64` an address to put 1 breakpoint
/// - `u64` an address to put another breakpoint
/// - `u64` an address to put one watchpoint (gdb clients clear all on trigger, so only need 1)
/// - the concrete type of the gdb support type for that architecture variant (e.g.
///   `Ppc4xxTargetDescription`)
/// - function that returns the ProcessorBuilder of the processor under test
///
/// Requirements:
///
/// - Test file must be loaded at 0x0 so that the read_memory check succeeds
/// - Pc must be set by loader, the input "entry address" here will not set pc, it's simply a value
///   to check the instantiated pc
/// - the watchpoint must be far enough away from entry to allow harness/client to connect before
///   hitting
///
#[macro_export]
macro_rules! gdb_core_test_suite {
    ($pc_register:expr_2021,
     $test_bin_path:expr_2021,
     $start_address:expr_2021,
     $bp_one:expr_2021,
     $bp_two:expr_2021,
     $wp_one:expr_2021,
     $test_target_description_type:tt,
     $gdb_test_processor:ident,
     ) => {
        mod gdb_core_integration {
            use super::*;

            const PC_REGISTER: &'static str = $pc_register;
            const TEST_BIN_PATH: &'static str = $test_bin_path;
            const START_ADDRESS: u64 = $start_address;
            const BP_ONE: u64 = $bp_one;
            const BP_TWO: u64 = $bp_two;
            const WP_ONE: u64 = $wp_one;
            type GdbTestTargetDescriptionType = $test_target_description_type;

            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdbserver_and_client_can_setup() {
                let _harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
            }

            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_get_registers() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                assert_eq!(START_ADDRESS, *registers.get(PC_REGISTER).unwrap());
            }

            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_set_register() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();
                assert_eq!(
                    START_ADDRESS,
                    *registers.get(PC_REGISTER).unwrap(),
                    "initial pc not correct"
                );

                // now set pc
                harness
                    .set_register(PC_REGISTER.to_owned(), 0x41414140)
                    .unwrap();

                let registers = harness.list_registers().unwrap();

                assert_eq!(
                    0x41414140,
                    *registers.get(PC_REGISTER).unwrap(),
                    "resulting pc not correct"
                );
            }

            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_read_memory() {
                let blink_flash = resolve_test_bin(TEST_BIN_PATH);
                let valid_data = std::fs::read(blink_flash).unwrap();
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let data = harness.read_memory(0, 0x100).unwrap();
                tracing::debug!(?data);
                assert_eq!(valid_data[..0x100], data);
            }

            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_write_memory() {
                let blink_flash = resolve_test_bin(TEST_BIN_PATH);
                let valid_data = std::fs::read(blink_flash).unwrap();
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let data = harness.read_memory(0, 0x100).unwrap();
                tracing::debug!(?data);
                assert_eq!(valid_data[..0x100], data);

                // write data
                let data_to_write = vec![0xa5; 0x100];
                harness.write_memory(0x0, &data_to_write).unwrap();

                // make sure that we get back the new data
                let data = harness.read_memory(0, 0x100).unwrap();
                tracing::debug!(?data);
                assert_eq!(data_to_write, data);
            }

            // test can add breakpoint while at same address and list it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_breakpoint_at_same_address() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = START_ADDRESS;
                assert_eq!(address, *registers.get(PC_REGISTER).unwrap());

                let breakpoint = harness.add_breakpoint(address).unwrap();

                let output = harness.list_breakpoints().unwrap();
                assert_eq!((breakpoint.number, address), *output.first().unwrap());
            }

            // test can add breakpoint while at different address and list it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_breakpoint_at_diff_address() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                let breakpoint = harness.add_breakpoint(address).unwrap();

                let output = harness.list_breakpoints().unwrap();
                assert_eq!((breakpoint.number, address), *output.first().unwrap());
            }

            // test can add breakpoint and run into it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_breakpoint_and_hit() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint = harness.add_breakpoint(address).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint.number, bp_id);
                assert_eq!(address, current_pc);
            }

            // test can add breakpoint and remove it while at same address
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_breakpoint_and_hit_then_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint = harness.add_breakpoint(address).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint.number, bp_id);
                assert_eq!(address, current_pc);

                // now delete the breakpoint
                harness.remove_breakpoint(bp_id).unwrap();

                // breakpoint should no longer exist
                let output = harness.list_breakpoints().unwrap();
                assert_eq!(false, output.contains(&(breakpoint.number, address)));
            }

            // test can add breakpoint and remove it while at different address
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_breakpoint_hit_move_then_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint = harness.add_breakpoint(address).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint.number, bp_id);
                assert_eq!(address, current_pc);

                // now step before removing the breakpoint
                let current_pc = harness.step_instruction().unwrap();
                assert_ne!(address, current_pc);

                // now delete the breakpoint
                harness.remove_breakpoint(bp_id).unwrap();

                // breakpoint should no longer exist
                let output = harness.list_breakpoints().unwrap();
                assert_eq!(false, output.contains(&(breakpoint.number, address)));
            }

            // test can add breakpoint and `si` out of it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_breakpoint_hit_then_si() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint = harness.add_breakpoint(address).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint.number, bp_id);
                assert_eq!(address, current_pc);

                // now step out of the breakpoint
                let current_pc = harness.step_instruction().unwrap();
                assert_ne!(address, current_pc);
            }

            // test can add breakpoint and `ni` out of it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_breakpoint_hit_then_ni() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint = harness.add_breakpoint(address).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint.number, bp_id);
                assert_eq!(address, current_pc);

                // now step out of the breakpoint
                let current_pc = harness.next_instruction().unwrap();
                assert_ne!(address, current_pc);
            }

            // test can add breakpoint and continue out of it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_breakpoint_hit_then_continue() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint = harness.add_breakpoint(address).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint.number, bp_id);
                assert_eq!(address, current_pc);

                // now continue out of the breakpoint
                harness.gdb_continue().unwrap();

                // NOTE that currently things are broken so we can't actually verify that
                // pc has changed, because gdbstub doesn't take the interrupt char
                // std::thread::sleep(std::time::Duration::from_millis(500));
                // _ = harness.exec_interrupt();
                // _ = harness.wait_for_stop_reason();

                // // make sure pc actually moved
                // let registers = harness.list_registers().unwrap();
                // let current_pc = *registers.get(PC_REGISTER).unwrap();
                // assert_ne!(address, current_pc);
            }

            // test can add two breakpoints and run into both
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_two_breakpoints_and_hit_both() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address_one = BP_ONE;
                let address_two = BP_TWO;
                assert_ne!(address_one, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint_one = harness.add_breakpoint(address_one).unwrap();
                let breakpoint_two = harness.add_breakpoint(address_two).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                // make sure we're stopped at the first breakpoint
                assert_eq!(breakpoint_one.number, bp_id);
                assert_eq!(address_one, current_pc);

                // now continue into the next breakpoint
                harness.gdb_continue().unwrap();

                std::thread::sleep(std::time::Duration::from_millis(200));
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint_two.number, bp_id);
                assert_eq!(address_two, current_pc);
            }

            // test can add two breakpoints and remove both
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_two_breakpoints_run_then_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address_one = BP_ONE;
                let address_two = BP_TWO;
                assert_ne!(address_one, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint_one = harness.add_breakpoint(address_one).unwrap();
                let breakpoint_two = harness.add_breakpoint(address_two).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                // make sure we're stopped at the first breakpoint
                assert_eq!(breakpoint_one.number, bp_id);
                assert_eq!(address_one, current_pc);

                // now continue into the next breakpoint
                harness.gdb_continue().unwrap();

                std::thread::sleep(std::time::Duration::from_millis(200));
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint_two.number, bp_id);
                assert_eq!(address_two, current_pc);

                harness.remove_breakpoint(breakpoint_one.number).unwrap();
                harness.remove_breakpoint(breakpoint_two.number).unwrap();
                let breakpoints = harness.list_breakpoints().unwrap();

                assert!(!breakpoints
                    .iter()
                    .any(|(id, _)| *id == breakpoint_one.number));
                assert!(!breakpoints
                    .iter()
                    .any(|(id, _)| *id == breakpoint_two.number));
            }

            // test can add two breakpoints, run into first, and remove 2nd
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_two_breakpoints_hit_first_then_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address_one = BP_ONE;
                let address_two = BP_TWO;
                assert_ne!(address_one, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint_one = harness.add_breakpoint(address_one).unwrap();
                let breakpoint_two = harness.add_breakpoint(address_two).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                // make sure we're stopped at the first breakpoint
                assert_eq!(breakpoint_one.number, bp_id);
                assert_eq!(address_one, current_pc);

                // remove the breakpoints
                harness.remove_breakpoint(breakpoint_one.number).unwrap();
                harness.remove_breakpoint(breakpoint_two.number).unwrap();
                let breakpoints = harness.list_breakpoints().unwrap();

                assert!(!breakpoints
                    .iter()
                    .any(|(id, _)| *id == breakpoint_one.number));
                assert!(!breakpoints
                    .iter()
                    .any(|(id, _)| *id == breakpoint_two.number));
            }

            // test can add two breakpoints, run into second, and remove first
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_two_breakpoints_hit_second_then_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address_one = BP_ONE;
                let address_two = BP_TWO;
                assert_ne!(address_one, *registers.get(PC_REGISTER).unwrap());

                // set breakpoint at address
                let breakpoint_one = harness.add_breakpoint(address_one).unwrap();
                let breakpoint_two = harness.add_breakpoint(address_two).unwrap();

                // now continue into the breakpoint
                harness.gdb_continue().unwrap();
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                // make sure we're stopped at the first breakpoint
                assert_eq!(breakpoint_one.number, bp_id);
                assert_eq!(address_one, current_pc);

                // now continue into the next breakpoint
                harness.gdb_continue().unwrap();

                std::thread::sleep(std::time::Duration::from_millis(200));
                // get the stop reason from gdb
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let bp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Breakpoint { number } => number,
                    _ => panic!("Did not stop due to breakpoint"),
                };
                let registers = harness.list_registers().unwrap();
                let current_pc = *registers.get(PC_REGISTER).unwrap();

                assert_eq!(breakpoint_two.number, bp_id);
                assert_eq!(address_two, current_pc);

                // remove the breakpoints
                harness.remove_breakpoint(breakpoint_one.number).unwrap();
                harness.remove_breakpoint(breakpoint_two.number).unwrap();
                let breakpoints = harness.list_breakpoints().unwrap();

                assert!(!breakpoints
                    .iter()
                    .any(|(id, _)| *id == breakpoint_one.number));
                assert!(!breakpoints
                    .iter()
                    .any(|(id, _)| *id == breakpoint_two.number));
            }

            // test can add watchpoint and list it @ sane address
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_at_same_address() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = START_ADDRESS;
                assert_eq!(address, *registers.get(PC_REGISTER).unwrap());

                let watchpoint_id = harness.add_watchpoint(address).unwrap();

                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));
            }

            // test can add watchpoint and list it @ diff address
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_at_diff_address() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                let watchpoint_id = harness.add_watchpoint(address).unwrap();

                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));
            }

            // test can remove watchpoint @ same address
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_same_address_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = START_ADDRESS;
                assert_eq!(address, *registers.get(PC_REGISTER).unwrap());

                // add watchpoint
                let watchpoint_id = harness.add_watchpoint(address).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));

                // now remove watchpoint
                harness.remove_watchpoint(watchpoint_id).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert_eq!(false, watchpoints.contains(&watchpoint_id));
            }

            // test can remove watchpoint @ diff address
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_diff_address_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());
                let registers = harness.list_registers().unwrap();

                let address = BP_ONE;
                assert_ne!(address, *registers.get(PC_REGISTER).unwrap());

                // add watchpoint
                let watchpoint_id = harness.add_watchpoint(address).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));

                // now remove watchpoint
                harness.remove_watchpoint(watchpoint_id).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert_eq!(false, watchpoints.contains(&watchpoint_id));
            }

            // test can run into watchpoint
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_and_hit() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());

                // add watchpoint
                let watchpoint_id = harness.add_watchpoint(WP_ONE).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));

                // hit watchpoint
                harness.gdb_continue().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is watchpoint we created
                // - watchpoint id is watchpoint's id
                let wp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Watchpoint { number } => number,
                    _ => panic!("Did not stop due to watchpoint"),
                };
                assert_eq!(watchpoint_id, wp_id);
            }

            // test can run into watchpoint and remove it while stopped at it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_and_hit_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());

                // add watchpoint
                let watchpoint_id = harness.add_watchpoint(WP_ONE).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));

                // hit watchpoint
                harness.gdb_continue().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let wp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Watchpoint { number } => number,
                    _ => panic!("Did not stop due to watchpoint"),
                };
                assert_eq!(watchpoint_id, wp_id);

                // now remove watchpoint
                harness.remove_watchpoint(watchpoint_id).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert_eq!(false, watchpoints.contains(&watchpoint_id));
            }

            // test can run into watchpoint and `si` out of it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_and_hit_si() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());

                // add watchpoint
                let watchpoint_id = harness.add_watchpoint(WP_ONE).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));

                // hit watchpoint
                harness.gdb_continue().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let wp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Watchpoint { number } => number,
                    _ => panic!("Did not stop due to watchpoint"),
                };
                assert_eq!(watchpoint_id, wp_id);

                // get pc
                let registers = harness.list_registers().unwrap();
                let old_pc = *registers.get(PC_REGISTER).unwrap();

                // now step out of the watchpoint
                let current_pc = harness.step_instruction().unwrap();
                assert_ne!(old_pc, current_pc);
            }

            // test can run into watchpoint and `ni` out of it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_and_hit_ni() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());

                // add watchpoint
                let watchpoint_id = harness.add_watchpoint(WP_ONE).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));

                // hit watchpoint
                harness.gdb_continue().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let wp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Watchpoint { number } => number,
                    _ => panic!("Did not stop due to watchpoint"),
                };
                assert_eq!(watchpoint_id, wp_id);

                // get pc
                let registers = harness.list_registers().unwrap();
                let old_pc = *registers.get(PC_REGISTER).unwrap();

                // now step out of the watchpoint
                let current_pc = harness.next_instruction().unwrap();
                assert_ne!(old_pc, current_pc);
            }

            // test can run into watchpoint and remove it after exiting it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_and_hit_move_remove() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());

                // add watchpoint
                let watchpoint_id = harness.add_watchpoint(WP_ONE).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));

                // hit watchpoint
                harness.gdb_continue().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let wp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Watchpoint { number } => number,
                    _ => panic!("Did not stop due to watchpoint"),
                };
                assert_eq!(watchpoint_id, wp_id);

                // get pc
                let registers = harness.list_registers().unwrap();
                let old_pc = *registers.get(PC_REGISTER).unwrap();

                // now step out of the watchpoint
                let current_pc = harness.step_instruction().unwrap();
                assert_ne!(old_pc, current_pc);

                // now remove watchpoint
                harness.remove_watchpoint(watchpoint_id).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert_eq!(false, watchpoints.contains(&watchpoint_id));
            }

            // test can run into watchpoint and continue out of it
            #[test]
            #[cfg_attr(miri, ignore)]
            #[cfg_attr(asan, ignore)]
            fn test_gdb_add_watchpoint_and_hit_continue() {
                let harness =
                    ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder::<
                        GdbTestTargetDescriptionType,
                    >($gdb_test_processor());

                // add watchpoint
                let watchpoint_id = harness.add_watchpoint(WP_ONE).unwrap();
                let watchpoints: Vec<i64> = harness.list_watchpoints().unwrap();
                assert!(watchpoints.contains(&watchpoint_id));

                // hit watchpoint
                harness.gdb_continue().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
                let stop_reason = harness.wait_for_stop_reason().unwrap();

                // assert that:
                // - stop reason is breakpoint we created
                // - current address is our breakpoint's address
                let wp_id = match stop_reason {
                    ::gdbmi::status::StopReason::Watchpoint { number } => number,
                    _ => panic!("Did not stop due to watchpoint"),
                };
                assert_eq!(watchpoint_id, wp_id);

                // now step out of the watchpoint
                let _ = harness.gdb_continue().unwrap();
            }
        }
    };
}
