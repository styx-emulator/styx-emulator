// SPDX-License-Identifier: BSD-2-Clause
//! Testing harness for the gdb plugin and `gdb-multiarch`
//!
use std::collections::HashMap;
use std::process::Stdio;
use std::thread::JoinHandle;

use gdbmi::breakpoint::Breakpoint;
use gdbmi::raw::ResultResponse;
use gdbmi::status::{Status, StopReason, Stopped};
use gdbmi::{Gdb, TimeoutError};
use std::fmt::Write;
use std::num::ParseIntError;
use styx_core::prelude::*;
use styx_plugins::gdb::{GdbExecutor, GdbPluginParams};

use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::runtime::Runtime;
use tracing::{debug, error, trace};

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum GdbHarnessError {
    #[error("Got invalid hex chars in data: `{0}`")]
    BadHexChars(ParseIntError),
    #[error("gdbmi lib failed: `{0}`")]
    GdbMI(gdbmi::Error),
    #[error("`{0}` is not a valid register")]
    InvalidRegisterName(String),
    #[error("Got a NotifyResponse instead of a ResultResponse")]
    NotifyInsteadOfResult,
    #[error("Timeout for {0} expired")]
    TimeoutExpiration(TimeoutError),
}

impl From<ParseIntError> for GdbHarnessError {
    fn from(value: ParseIntError) -> Self {
        Self::BadHexChars(value)
    }
}

impl From<gdbmi::TimeoutError> for GdbHarnessError {
    fn from(value: gdbmi::TimeoutError) -> Self {
        Self::TimeoutExpiration(value)
    }
}

impl From<gdbmi::Error> for GdbHarnessError {
    fn from(value: gdbmi::Error) -> Self {
        Self::GdbMI(value)
    }
}

const GDB_MULTIARCH: &str = "gdb-multiarch";
const GDB: &str = "gdb";
/// Determine the path to the `gdb-multiarch` binary
///
/// Determines which gdb binary to use baased on the archetectues available.
/// If `gdb-multiarch` is available, it will be used. Otherwise, the default
/// gdb binary will be used. If the architecture list is not long, a warning
/// message will be printed.
fn determine_gdb_binary() -> &'static str {
    // check if gdb-multiarch is available, if so, use it
    if std::process::Command::new(GDB_MULTIARCH)
        .output()
        .ok()
        .is_some()
    {
        return GDB_MULTIARCH;
    }

    // gdb-multiarch not available, check if there is
    // 1. a `gdb` in the path
    // 2. the `gdb` has aa long list of supported archs (probably not the greatest
    //    assumption to make but #YOLO -- we'll say it implies built with `--enable-targets=all`)
    //
    // We do this by executing `set architecture` with no specific architecure and
    // checking the output. If the output is long, we'll assume its a full list of
    // supported archs.
    if let Ok(output) = std::process::Command::new(GDB)
        .arg("--interpreter=mi3")
        .arg("-q")
        .arg("-nx")
        .arg("-ex")
        .arg("set architecture")
        .arg("-ex")
        .arg("quit")
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let targets = output_str
            .lines()
            .flat_map(|line| line.split_whitespace())
            .collect::<Vec<&str>>();
        if targets.len() > 20 {
            return GDB;
        }
    }

    // if we get here, we want to panic so people know that we need multiarch support
    // from a gdb binary to continue
    error!("No gdb binary found with multiarch support. Please install `gdb-multiarch` or a gdb binary with multiarch support");
    panic!("No gdb binary found with multiarch support. Please install `gdb-multiarch` or a gdb binary with multiarch support");
}

fn create_gdb_multiarch_process(port: u16, runtime: Runtime) -> BlockingGdbClient {
    let gdb_binary = determine_gdb_binary();
    let gdb: Gdb = runtime.block_on(async {
        let process: Child = Command::new(gdb_binary)
            .arg("-q")
            .arg("--interpreter=mi3")
            .arg("-nh")
            .arg("-nx")
            .arg("-ex")
            .arg(format!("target remote :{}", port))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        Gdb::new(process, DEFAULT_TIMEOUT)
    });

    BlockingGdbClient::new(Arc::new(gdb), runtime)
}

/// Blocking wrapper around the tokio heavy [`Gdb`]
pub struct BlockingGdbClient {
    inner: Arc<Gdb>,
    runtime: Runtime,
}

impl BlockingGdbClient {
    pub fn new(client: Arc<Gdb>, runtime: Runtime) -> Self {
        Self {
            inner: client,
            runtime,
        }
    }

    pub fn read_memory(&self, base_address: u64, size: u32) -> Result<Vec<u8>, GdbHarnessError> {
        let inner = self.inner.clone();

        let resp: ResultResponse = self
            .runtime
            .block_on(async {
                inner
                    .raw_cmd(&format!(
                        "-data-read-memory-bytes {} {}",
                        base_address, size
                    ))
                    .await
            })?
            .expect_result()?;

        resp.expect_msg_is("done")?;

        // turn the response into the string of hex chars
        let hex_chars = resp
            .expect_payload()?
            .remove_expect("memory")?
            .expect_list()?[0]
            .clone()
            .expect_dict()?
            .remove_expect("contents")?
            .expect_string()?;

        let hex_data = decode_hex(&hex_chars)?;
        trace!(?hex_data);
        Ok(hex_data)
    }

    pub fn write_memory(&self, base_address: u64, data: &[u8]) -> Result<(), GdbHarnessError> {
        let inner = self.inner.clone();

        let hex_data = encode_hex(data);

        let resp: ResultResponse = self
            .runtime
            .block_on(async {
                inner
                    .raw_cmd(&format!(
                        "-data-write-memory-bytes {} {}",
                        base_address, hex_data
                    ))
                    .await
            })?
            .expect_result()?;

        debug!(?resp);
        resp.expect_msg_is("done")?;

        Ok(())
    }

    pub fn set_register(&self, register: String, value: u64) -> Result<(), GdbHarnessError> {
        let inner = self.inner.clone();

        // first get the register names
        let resp: ResultResponse = self
            .runtime
            .block_on(async { inner.raw_cmd("-data-list-register-names").await })?
            .expect_result()?;

        // make sure we actually get a "command complete" resp
        resp.expect_msg_is("done")?;

        // list [ String ]
        let register_names: Vec<String> = resp
            .expect_payload()?
            .remove_expect("register-names")?
            .expect_list()?
            .iter()
            .map(|x| x.clone().expect_string().unwrap())
            .collect();

        // make sure its a valid register name
        if !register_names.contains(&register) {
            return Err(GdbHarnessError::InvalidRegisterName(register));
        }

        // set value
        let resp: ResultResponse = self
            .runtime
            .block_on(async {
                inner
                    .raw_console_cmd(&format!("set ${} = {}", register, value))
                    .await
            })?
            .expect_result()?;

        debug!(?resp);

        // make sure it executed
        resp.expect_msg_is("done")?;

        Ok(())
    }

    pub fn add_watchpoint(&self, address: u64) -> Result<i64, GdbHarnessError> {
        let inner = self.inner.clone();

        let resp: ResultResponse = self
            .runtime
            .block_on(async { inner.raw_cmd(&format!("-break-watch *{address}")).await })?
            .expect_result()?;

        resp.expect_msg_is("done")?;

        let mut wp_data = resp.expect_payload()?;
        debug!(?wp_data);

        // get the watchpoint number
        let number = wp_data
            .remove_expect("wpt")?
            .expect_dict()?
            .remove_expect("number")?
            .expect_signed()?;

        Ok(number)
    }

    pub fn remove_watchpoint(&self, watchpoint_id: i64) -> Result<(), GdbHarnessError> {
        self.remove_breakpoint(watchpoint_id)
    }

    pub fn list_watchpoints(&self) -> Result<Vec<i64>, GdbHarnessError> {
        let inner = self.inner.clone();

        // remove the bp
        let resp: ResultResponse = self
            .runtime
            .block_on(async { inner.raw_cmd("-break-list").await })?
            .expect_result()?;

        // make sure it was a success
        resp.expect_msg_is("done")?;

        debug!(?resp);

        // get the list of (id, address)
        let output: Vec<i64> = resp
            .expect_payload()?
            .remove_expect("BreakpointTable")?
            .expect_dict()?
            .remove_expect("body")?
            .expect_list()?
            .iter()
            .filter_map(|d| {
                let mut dict_body = d.clone().expect_dict().unwrap();
                let is_watchpoint = dict_body
                    .remove_expect("type")
                    .unwrap()
                    .expect_string()
                    .unwrap()
                    .cmp(&"hw watchpoint".to_owned())
                    .is_eq();

                if !is_watchpoint {
                    return None;
                }

                let bp_id_value = dict_body
                    .remove_expect("number")
                    .unwrap()
                    .expect_string()
                    .unwrap()
                    .parse::<i64>()
                    .unwrap();

                Some(bp_id_value)
            })
            .collect();

        Ok(output)
    }

    pub fn add_breakpoint(&self, address: u64) -> Result<Breakpoint, GdbHarnessError> {
        let inner = self.inner.clone();

        let resp = self
            .runtime
            .block_on(async { inner.break_insert_address(address).await })?;

        Ok(resp)
    }

    pub fn remove_breakpoint(&self, bp_id: i64) -> Result<(), GdbHarnessError> {
        let inner = self.inner.clone();

        // remove the bp
        let resp: ResultResponse = self
            .runtime
            .block_on(async { inner.raw_cmd(&format!("-break-delete {}", bp_id)).await })?
            .expect_result()?;

        // make sure it was a success
        resp.expect_msg_is("done")?;

        Ok(())
    }

    pub fn list_breakpoints(&self) -> Result<Vec<(i64, u64)>, GdbHarnessError> {
        let inner = self.inner.clone();

        // remove the bp
        let resp: ResultResponse = self
            .runtime
            .block_on(async { inner.raw_cmd("-break-list").await })?
            .expect_result()?;

        // make sure it was a success
        resp.expect_msg_is("done")?;

        debug!(?resp);

        // get the list of (id, address)
        let output: Vec<(i64, u64)> = resp
            .expect_payload()?
            .remove_expect("BreakpointTable")?
            .expect_dict()?
            .remove_expect("body")?
            .expect_list()?
            .iter()
            .filter_map(|d| {
                let mut dict_body = d.clone().expect_dict().unwrap();
                let is_breakpoint = dict_body
                    .remove_expect("type")
                    .unwrap()
                    .expect_string()
                    .unwrap()
                    .cmp(&"breakpoint".to_owned())
                    .is_eq();

                if !is_breakpoint {
                    return None;
                }

                let address_value = dict_body
                    .remove_expect("addr")
                    .unwrap()
                    .expect_hex()
                    .unwrap();
                let bp_id_value = dict_body
                    .remove_expect("number")
                    .unwrap()
                    .expect_string()
                    .unwrap()
                    .parse::<i64>()
                    .unwrap();

                Some((bp_id_value, address_value))
            })
            .collect();

        Ok(output)
    }

    pub fn get_registers(&self) -> Result<HashMap<String, u64>, GdbHarnessError> {
        let inner = self.inner.clone();

        // first get the register names
        let resp: ResultResponse = self
            .runtime
            .block_on(async { inner.raw_cmd("-data-list-register-names").await })?
            .expect_result()?;

        // make sure we actually get a "command complete" resp
        resp.expect_msg_is("done")?;

        // list [ String ]
        let ordered_register_names: Vec<String> = resp
            .expect_payload()?
            .remove_expect("register-names")?
            .expect_list()?
            .iter()
            .map(|x| x.clone().expect_string().unwrap())
            .collect();

        // now get the register values
        let resp: ResultResponse = self
            .runtime
            .block_on(async { inner.raw_cmd("-data-list-register-values x").await })?
            .expect_result()?;

        // make sure we actually get a "command complete" resp
        resp.expect_msg_is("done")?;

        // list[ Dict<decimal register number, hex register value>]
        let ordered_register_values: Vec<(usize, u64)> = resp
            .expect_payload()?
            .remove_expect("register-values")?
            .expect_list()?
            .iter_mut()
            .map(|d| {
                let mut dict = d.clone().expect_dict().unwrap();
                let number = dict
                    .remove_expect("number")
                    .unwrap()
                    .expect_number()
                    .unwrap() as usize;
                let value = dict.remove_expect("value").unwrap().expect_hex().unwrap();

                (number, value)
            })
            .collect();

        // add all the register values into a register_map, getting
        // the register name by index into the ordered_register_names
        let register_map: HashMap<String, u64> =
            HashMap::from_iter(ordered_register_values.iter().map(|(idx, value)| {
                let key = ordered_register_names[*idx].clone();
                (key, *value)
            }));

        Ok(register_map)
    }

    pub fn quit(&self) -> Result<(), GdbHarnessError> {
        let inner = self.inner.clone();
        let _dont_care = self
            .runtime
            .block_on(async move { inner.raw_cmd("-gdb-exit").await })?;
        Ok(())
    }

    pub fn gdb_continue(&self) -> Result<(), GdbHarnessError> {
        let inner = self.inner.clone();

        self.runtime
            .block_on(async move { inner.exec_continue().await })?;

        Ok(())
    }

    fn inner_insn_await_stopped_status(&self) -> Result<Stopped, GdbHarnessError> {
        let inner = self.inner.clone();

        // sleep bc the gdb client is pretty racey atm
        std::thread::sleep(std::time::Duration::from_millis(100));
        _ = self.wait_for_stop_reason()?;

        Ok(self.runtime.block_on(async {
            inner
                .await_stopped(Some(std::time::Duration::from_millis(500)))
                .await
        })?)
    }

    pub fn step_instruction(&self) -> Result<u64, GdbHarnessError> {
        let inner = self.inner.clone();

        self.runtime
            .block_on(async { inner.exec_step_instruction().await })?;

        // now get current pc
        let status = self.inner_insn_await_stopped_status()?;

        Ok(status.address.0)
    }

    pub fn next_instruction(&self) -> Result<u64, GdbHarnessError> {
        let inner = self.inner.clone();

        self.runtime
            .block_on(async { inner.exec_next_instruction().await })?;

        // now get current pc
        let status = self.inner_insn_await_stopped_status()?;

        Ok(status.address.0)
    }

    pub fn wait_for_stop(&self) -> Result<Stopped, GdbHarnessError> {
        let inner = self.inner.clone();

        let stop_reason = self.runtime.block_on(async {
            inner
                .await_stopped(Some(std::time::Duration::from_millis(500)))
                .await
        })?;

        Ok(stop_reason)
    }

    fn check_for_stop_reason(&self) -> Result<Option<StopReason>, GdbHarnessError> {
        let inner = self.inner.clone();

        let stopped = self.runtime.block_on(async {
            inner
                .await_stopped(Some(std::time::Duration::from_millis(500)))
                .await
        })?;

        Ok(stopped.reason)
    }
    pub fn wait_for_stop_reason(&self) -> Result<StopReason, GdbHarnessError> {
        let mut stop_reason = None;
        while stop_reason.is_none() {
            match self.check_for_stop_reason() {
                Ok(stopped) => stop_reason = stopped,
                Err(e) => match e {
                    GdbHarnessError::TimeoutExpiration(_) => continue,
                    _ => Err(e)?,
                },
            }
        }

        Ok(stop_reason.unwrap())
    }

    pub fn gdb_status(&self) -> Result<Status, GdbHarnessError> {
        let inner = self.inner.clone();

        let curr_status = self.runtime.block_on(async { inner.status().await })?;

        Ok(curr_status)
    }

    pub fn exec_interrupt(&self) -> Result<(), GdbHarnessError> {
        let inner = self.inner.clone();

        // ignore timeout errors here since its most likely going to take a sec
        _ = self
            .runtime
            .block_on(async { inner.exec_interrupt().await });

        Ok(())
    }

    /// Sets the client to big endian mode.
    pub fn set_endian_big(&self) -> Result<(), GdbHarnessError> {
        let inner = self.inner.clone();

        self.runtime
            .block_on(async { inner.raw_console_cmd("set endian big").await })?;

        Ok(())
    }
}

pub struct GdbHarness {
    gdb_client: BlockingGdbClient,
    /// Handle for thread spawned to run the processor.
    _processor_handle: JoinHandle<()>,
}

impl GdbHarness {
    pub fn from_processor_builder<GdbSupport>(builder: ProcessorBuilder) -> Self
    where
        GdbSupport: gdbstub::arch::Arch + 'static + std::fmt::Debug,
        GdbSupport::Registers: styx_core::cpu::arch::GdbRegistersHelper,
        GdbSupport::RegId: styx_core::cpu::arch::GdbArchIdSupportTrait,
    {
        // create gdb plugin with port 0
        let gdb_plugin =
            GdbExecutor::<GdbSupport>::new(GdbPluginParams::tcp("127.0.0.1", 0, false)).unwrap();

        // get assigned port (doesn't happen until processor starts) todo
        let port = gdb_plugin.port();

        let mut processor = builder
            // .with_executor()
            .with_executor(gdb_plugin)
            .with_ipc_port(0)
            .build()
            .unwrap();

        // spawn the processor in a blocking thread
        let runtime = Runtime::new().unwrap();
        let endian = processor.core.cpu.endian();
        let proc_handle = std::thread::spawn(move || {
            processor.run(Forever).unwrap();
        });

        // create gdb process
        let gdb_process = create_gdb_multiarch_process(port, runtime);
        if endian.is_big() {
            gdb_process.set_endian_big().unwrap();
        }

        // now create object
        Self {
            gdb_client: gdb_process,
            _processor_handle: proc_handle,
        }
    }

    pub fn list_registers(&self) -> Result<HashMap<String, u64>, GdbHarnessError> {
        self.gdb_client.get_registers()
    }

    pub fn set_register(&self, register: String, value: u64) -> Result<(), GdbHarnessError> {
        self.gdb_client.set_register(register, value)
    }

    pub fn read_memory(&self, base_address: u64, size: u32) -> Result<Vec<u8>, GdbHarnessError> {
        let data = self.gdb_client.read_memory(base_address, size)?;
        debug!("Harness got `{}` bytes of data back from gdb", data.len());
        Ok(data)
    }

    pub fn write_memory(&self, base_address: u64, data: &[u8]) -> Result<(), GdbHarnessError> {
        self.gdb_client.write_memory(base_address, data)
    }

    pub fn add_watchpoint(&self, address: u64) -> Result<i64, GdbHarnessError> {
        self.gdb_client.add_watchpoint(address)
    }

    pub fn remove_watchpoint(&self, watchpoint_id: i64) -> Result<(), GdbHarnessError> {
        self.gdb_client.remove_watchpoint(watchpoint_id)
    }

    pub fn list_watchpoints(&self) -> Result<Vec<i64>, GdbHarnessError> {
        self.gdb_client.list_watchpoints()
    }

    pub fn add_breakpoint(&self, address: u64) -> Result<Breakpoint, GdbHarnessError> {
        self.gdb_client.add_breakpoint(address)
    }

    pub fn remove_breakpoint(&self, breakpoint_id: i64) -> Result<(), GdbHarnessError> {
        self.gdb_client.remove_breakpoint(breakpoint_id)
    }

    pub fn list_breakpoints(&self) -> Result<Vec<(i64, u64)>, GdbHarnessError> {
        self.gdb_client.list_breakpoints()
    }

    pub fn gdb_continue(&self) -> Result<(), GdbHarnessError> {
        self.gdb_client.gdb_continue()
    }

    pub fn gdb_status(&self) -> Result<Status, GdbHarnessError> {
        self.gdb_client.gdb_status()
    }

    pub fn wait_for_stop_reason(&self) -> Result<StopReason, GdbHarnessError> {
        self.gdb_client.wait_for_stop_reason()
    }

    pub fn wait_for_stop(&self) -> Result<Stopped, GdbHarnessError> {
        self.gdb_client.wait_for_stop()
    }

    pub fn step_instruction(&self) -> Result<u64, GdbHarnessError> {
        self.gdb_client.step_instruction()
    }

    pub fn next_instruction(&self) -> Result<u64, GdbHarnessError> {
        self.gdb_client.next_instruction()
    }

    pub fn exec_interrupt(&self) -> Result<(), GdbHarnessError> {
        self.gdb_client.exec_interrupt()
    }
}
