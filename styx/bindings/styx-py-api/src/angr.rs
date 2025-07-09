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
use crate::util::module_system::ModuleSystem;
use log::debug;
use log::error;
use log::info;
use pyo3::exceptions::PyAssertionError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyString};
use std::collections::HashMap;
use styx_emulator::core::cpu::arch::{u40, u80};
use styx_emulator::hooks::HookToken;
use styx_emulator::prelude::*;
use styx_emulator::sync::{Arc, Mutex};

pyo3::import_exception!(angr.errors, SimConcreteRegisterError);

#[derive(Default)]
struct Watchpoint {
    read: Option<HookToken>,
    write: Option<HookToken>,
}

#[derive(Default)]
struct SymbionTargetData {
    breakpoints: HashMap<u64, HookToken>,
    watchpoints: HashMap<u64, Watchpoint>,
}

/// The symbion backend implementation.
///
/// This is compiled to be used from the python runtime
#[pyclass(module = "angr")]
pub struct StyxConcreteTargetBackend {
    processor: SyncProcessor,
    data: SymbionTargetData,
}

impl StyxConcreteTargetBackend {
    // TODO: eval what is left
    // /// The only way to get an instance of a backend.
    // ///
    // /// target: the processor backend that should be used
    // ///
    // /// firmware_path: the path to the binary to be loaded
    // #[inline]
    // pub fn new(
    //     target: Target,
    //     firmware_path: String,
    //     gdb_backend: bool,
    //     ipc_port: u16,
    // ) -> Result<Self, String> {
    //     // TODO: remove this log-init
    //     use std::env;
    //     env::set_var(
    //         "RUST_LOG",
    //         env::var("RUST_LOG").unwrap_or_else(|_| "debug".to_string()),
    //     );
    //     info!("rust_log: {:?}", env::var("RUST_LOG").unwrap());

    //     let plugin = SymbionTargetData::default();
    //     let processor = Self::create_processor(&target, firmware_path, gdb_backend, ipc_port)?;

    //     Ok(Self {
    //         processor,
    //         data: plugin,
    //     })
    // }

    // fn create_processor(
    //     target: &Target,
    //     firmware_path: impl Into<String>,
    //     gdb_backend: bool,
    //     ipc_port: u16,
    // ) -> Result<Arc<dyn ProcessorCommon>, String> {
    //     static LOG_LOCK: OnceLock<()> = OnceLock::new();
    //     LOG_LOCK.get_or_init(|| {
    //         styx_util::logging::init_logging();
    //     });

    //     let builder = ProcessorBuilder::default()
    //         .with_endian(ArchEndian::LittleEndian)
    //         .with_target_program(firmware_path.into())
    //         .with_loader(RawLoader)
    //         .with_variant(ArmVariants::ArmCortexM3)
    //         .with_plugin(StyxTracePlugin::default())
    //         .with_ipc_port(ipc_port);
    //     let builder = if gdb_backend {
    //         let executor = Executor::new_unlimited(
    //                 Arc::new(
    //                     GdbExecutor::<ArmCoreDescription>::new(GdbPluginParams::tcp("0.0.0.0", 9999, true))
    //                 )
    //         );
    //         builder.with_executor(executor)
    //     } else {
    //         builder.with_executor(Executor::default())
    //     };

    //     let proc: Arc<dyn ProcessorCommon> = match target {
    //         Target::Stm32f107 => builder.build::<Stm32f107Cpu>(),
    //         _ => unimplemented!(),
    //     }
    //     .map_err(|e| format!("unable to create processor: {e}"))?;

    //     let callback = |cpu: CpuBackend| {
    //         println!("executing {:x}", cpu.pc().unwrap());
    //     };
    //     let region = proc.cpu().memory_manager().unwrap();
    //     let hook = styx_emulator::core::cpu::hooks::StyxHook::Code {
    //         start: region.min_address().unwrap(),
    //         end: region.max_address().unwrap(),
    //         callback: Box::new(callback),
    //     };
    //     proc.add_hook(hook).unwrap();

    //     Ok(proc)
    // }
}

type PyAddr = u64;
type PyRegisters<'py> = Bound<'py, PyDict>; // name -> integer value

#[pymethods]
impl StyxConcreteTargetBackend {
    #[new]
    #[pyo3(signature=(cpu, **kwargs))]
    pub fn py_new(
        cpu: PyRef<crate::processor::Processor>,
        #[allow(unused)] kwargs: Option<&Bound<PyDict>>,
    ) -> PyResult<Self> {
        Ok(Self {
            processor: cpu.clone(),
            data: Default::default(),
        })
    }

    /// Reading from memory of the target
    ///
    /// May return Err(angr.errors.ConcreteMemoryError)
    #[pyo3(signature=(address, nbytes, **_kwargs))]
    pub fn read_memory<'py>(
        &self,
        py: Python<'py>,
        address: PyAddr,
        nbytes: u32,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let buf = self
            .processor
            .access(move |core| core.mmu.data().read(address).vec(nbytes as usize))
            .map_err(|e| PyAssertionError::new_err(format!("unable to write memory: {e}")))?;
        debug!("read_memory: addr={address:X} size={nbytes} bytes={buf:X?}");
        Ok(PyBytes::new(py, buf.as_slice()))
    }

    /// Writing to memory of the target
    ///
    /// may return Err(ConcreteMemoryError)
    #[pyo3(signature=(address, value, **_kwargs))]
    pub fn write_memory<'py>(
        &self,
        _py: Python<'py>,
        address: PyAddr,
        value: Bound<'py, PyString>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        info!("write_memory: {address:X} {value:?}");
        let value = value.to_cow()?;
        error!("writing {value:?}");
        //self.processor.cpu().write_memory(address, )
        todo!()
    }

    /// Reads a register from the target
    ///
    /// may return Err(angr.errors.ConcreteMemoryError)
    #[pyo3(signature=(register, **_kwargs))]
    pub fn read_register<'py>(
        &self,
        _py: Python<'py>,
        register: Bound<'py, PyString>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<u128> {
        let reg_name = register.to_cow()?;
        let registers = self.processor.architecture().registers().registers();
        let register = registers
            .iter()
            .find(|reg| reg.name().eq_ignore_ascii_case(&reg_name));
        let Some(register) = register else {
            debug!("register {reg_name:?} did not exist");
            return Err(SimConcreteRegisterError::new_err("register does not exist"));
        };
        let value = read_register_value(&self.processor, register);
        debug!("read {value:X} from {reg_name:?}");
        Ok(value)
    }

    /// Writes a register to the target
    ///
    /// may return Err(angr.errors.ConcreteRegisterError)
    #[pyo3(signature=(register_, value, **_kwargs))]
    pub fn write_register<'py>(
        &self,
        _py: Python<'py>,
        register_: Bound<'py, PyString>,
        value: u128,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let reg_name = register_.to_cow()?;
        let registers = self.processor.architecture().registers().registers();
        let register = registers
            .iter()
            .find(|reg| reg.name().eq_ignore_ascii_case(&reg_name));
        let Some(register) = register else {
            debug!("unable to write register {register_:?}, does not exist");
            return Err(SimConcreteRegisterError::new_err("register does not exist"));
        };
        debug!("write_register: {register_:?} {value:X}");
        write_register_value(&self.processor, register, value);
        Ok(())
    }

    /// Reads the entire register file from the concrete target
    ///
    /// This is primarily to facilitate state transitions and debugging interfaces
    ///
    /// Many targets have a batch register reading function to enable this, as a performance optimization
    #[pyo3(signature=(**_kwargs))]
    pub fn read_all_registers<'py>(
        &self,
        py: Python<'py>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<PyRegisters<'py>> /* name -> integer value */ {
        debug!("read all register");
        let out = PyDict::new(py);
        for reg in self.processor.architecture().registers().registers() {
            let value = read_register_value(&self.processor, &reg);
            out.set_item(reg.name(), value)?;
        }
        Ok(out)
    }

    /// Writes the entire register file to the concrete target
    #[pyo3(signature=(values, **_kwargs))]
    pub fn write_all_registers<'py>(
        &self,
        _py: Python<'py>,
        values: PyRegisters<'py>, // name -> integer value
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        debug!("write_all_registers: {values:?}");
        for (key, value) in values.iter() {
            let regname = Bound::<PyString>::extract_bound(&key)?;
            let value = u128::extract_bound(&value)?;

            let reg_name = regname.to_cow()?;
            let registers = self.processor.architecture().registers().registers();
            let register = registers
                .iter()
                .find(|reg| reg.name().eq_ignore_ascii_case(&reg_name));
            let Some(register) = register else {
                return Err(SimConcreteRegisterError::new_err("register does not exist"));
            };
            write_register_value(&self.processor, register, value);
        }
        Ok(())
    }

    /// Inserts a breakpoint
    ///
    /// May return Err(angr.errors.ConcreteBreakpointError)
    #[pyo3(signature=(address, **_kwargs))]
    pub fn set_breakpoint(
        &mut self,
        _py: Python<'_>,
        address: PyAddr,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        if let std::collections::hash_map::Entry::Vacant(entry) =
            self.data.breakpoints.entry(address)
        {
            let callback = |cpu: styx_emulator::prelude::CpuBackend| {
                cpu.stop().unwrap();
            };
            let hook = styx_emulator::hooks::StyxHook::Code(address.into(), Box::new(callback));
            let token = self.processor.add_hook(hook).unwrap(); // TODO: error handling
            entry.insert(token);
            debug!("set breakpoint at {address:X}");
        }
        Ok(())
    }

    /// Removes a breakpoint
    ///
    /// May return Err(anger.errors.ConcreteBreakpointError)
    #[pyo3(signature=(address, **_kwargs))]
    fn remove_breakpoint(
        &mut self,
        _py: Python<'_>,
        address: PyAddr,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        if let Some(hook_token) = self.data.breakpoints.remove(&address) {
            self.processor.delete_hook(hook_token).unwrap();
            debug!("unset breakpoint at {address:X}");
        }
        Ok(())
    }

    /// Sets a watchpoint
    ///
    /// May return Err(anger.errors.ConcreteBreakpointError)
    #[pyo3(signature=(address, **kwargs))]
    fn set_watchpoint(
        &mut self,
        _py: Python<'_>,
        address: PyAddr,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let read = kwargs_get::<bool>(kwargs, "read", || false)?;
        let write = kwargs_get::<bool>(kwargs, "write", || false)?;
        let entry = self.data.watchpoints.entry(address).or_default();

        if read && entry.read.is_none() {
            let callback = |cpu: CpuBackend, _addr: u64, _size: u32, _data: &mut [u8]| {
                cpu.stop().unwrap();
            };
            let hook = styx_emulator::hooks::StyxHook::MemRead {
                start: address,
                end: address,
                callback: Box::new(callback),
            };
            let token = self.processor.add_hook(hook).unwrap();
            entry.read = Some(token);
        }

        if write && entry.write.is_none() {
            let callback = |cpu: CpuBackend, _addr: u64, _size: u32, _data: &[u8]| {
                cpu.stop().unwrap();
            };
            let hook = styx_emulator::hooks::StyxHook::MemWrite {
                start: address,
                end: address,
                callback: Box::new(callback),
            };
            let token = self.processor.add_hook(hook).unwrap();
            entry.write = Some(token);
        }

        Ok(())
    }

    /// Removes a watchpoint
    #[pyo3(signature=(address, **_kwargs))]
    fn remove_watchpoint(
        &mut self,
        _py: Python<'_>,
        address: PyAddr,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        if let Some(watchpoint) = self.data.watchpoints.remove(&address) {
            watchpoint
                .read
                .map(|token| self.processor.delete_hook(token))
                .transpose()
                .unwrap();
            watchpoint
                .write
                .map(|token| self.processor.delete_hook(token))
                .transpose()
                .unwrap();
        }
        Ok(())
    }

    fn get_mappings(&self, py: Python<'_>) -> PyResult<Vec<PyObject>> {
        let regions = self.processor.memory_regions().unwrap();
        let mut out = Vec::new();
        for (base, size, perms) in regions {
            let start_addr = base;
            let end_addr = (base + size) - 1;
            let offset = 0; // no address randomization?

            let mut perm_string = ['-'; 4];
            if perms.contains(styx_emulator::prelude::MemoryPermissions::READ) {
                perm_string[0] = 'r';
            }
            if perms.contains(styx_emulator::prelude::MemoryPermissions::WRITE) {
                perm_string[1] = 'w';
            }
            if perms.contains(styx_emulator::prelude::MemoryPermissions::EXEC) {
                perm_string[2] = 'x';
            }
            // todo: [3] = 'p',
            let name = format!("region:{}:{}:{}", start_addr, end_addr, perms);

            let item = PyModule::import(py, "angr_targets.memory_map")?
                .getattr("MemoryMap")?
                .call1((start_addr, end_addr, offset, name, perm_string))?;
            out.push(item.into());
        }

        Ok(out)
    }

    fn reset(&mut self, py: Python<'_>, halt: bool) -> PyResult<()> {
        if halt {
            self.processor.pause().unwrap();
            while !matches!(
                self.processor.processor_state(),
                styx_emulator::prelude::ProcessorState::Shutdown
                    | styx_emulator::prelude::ProcessorState::Paused
            ) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        } else if self.is_running(py) {
            return Err(PyAssertionError::new_err("machine must be stopped"));
        }
        for (_, hook) in self.data.breakpoints.drain() {
            self.processor.delete_hook(hook).unwrap();
        }
        for (_, hook) in self.data.watchpoints.drain() {
            hook.read
                .map(|token| self.processor.delete_hook(token))
                .transpose()
                .unwrap();
            hook.write
                .map(|token| self.processor.delete_hook(token))
                .transpose()
                .unwrap();
        }
        Ok(())
    }

    fn step(_me: PyRef<Self>, _py: Python<'_>) -> PyResult<()> {
        unimplemented!("TODO: processor needs a way to set number of instructions to exec");
        // let proc = me.processor.clone();
        // drop(me);
        // py.allow_threads(move || {
        //     proc.cpu()
        //         .start(Duration::MAX, 1u64)
        //         .map_err(|e| PyAssertionError::new_err(format!("{e}")))?;
        //     Ok(())
        // })
    }

    fn run(me: PyRef<Self>, py: Python<'_>) -> PyResult<()> {
        let proc = me.processor.clone();
        drop(me);
        py.allow_threads(move || {
            proc.start()
                .map_err(|e| PyAssertionError::new_err(format!("{e}")))
        })
    }

    fn is_running(&self, _py: Python<'_>) -> bool {
        let state = self.processor.processor_state();
        matches!(state, styx_emulator::prelude::ProcessorState::Running)
    }

    // TODO: maybe this should be shutdown
    fn stop(&self, _py: Python<'_>) -> PyResult<()> {
        self.processor
            .pause()
            .map_err(|e| PyAssertionError::new_err((format!("unable to stop machine: {}", e),)))
    }

    fn wait_for_running(&self, _py: Python<'_>) -> PyResult<()> {
        self.processor.async_start().unwrap();
        while !matches!(
            self.processor.processor_state(),
            styx_emulator::prelude::ProcessorState::Running
        ) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }

    fn wait_for_halt(&self, _py: Python<'_>) -> PyResult<()> {
        self.processor.async_start().unwrap();
        while !matches!(
            self.processor.processor_state(),
            styx_emulator::prelude::ProcessorState::Shutdown
                | styx_emulator::prelude::ProcessorState::Paused
        ) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }

    #[pyo3(signature=(which=None))]
    fn wait_for_breakpoint(&self, py: Python<'_>, which: Option<PyAddr>) -> PyResult<()> {
        let Some(which) = which else {
            self.wait_for_halt(py)?;
            return Ok(());
        };
        while self.processor.pc().unwrap() != which {
            self.processor.async_start().unwrap();
            while !matches!(
                self.processor.processor_state(),
                styx_emulator::prelude::ProcessorState::Shutdown
                    | styx_emulator::prelude::ProcessorState::Paused
            ) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        Ok(())
    }
}

#[allow(unused)]
fn kwargs_try_get<'py, T: FromPyObject<'py>>(
    kwargs: &Bound<'py, PyDict>,
    key: &str,
) -> PyResult<Option<T>> {
    match kwargs.get_item(key) {
        Ok(Some(v)) => <T as FromPyObject>::extract_bound(&v).map(Some),
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

fn kwargs_get<'py, T: FromPyObject<'py>>(
    kwargs: Option<&Bound<'py, PyDict>>,
    key: &str,
    default: impl FnOnce() -> T,
) -> PyResult<T> {
    let Some(kwargs) = kwargs else {
        return Ok(default());
    };
    let Some(value) = kwargs.get_item(key)? else {
        return Ok(default());
    };
    <T as FromPyObject>::extract_bound(&value)
}

fn read_register_value(
    cpu: &Processor,
    register: &styx_emulator::core::cpu::arch::CpuRegister,
) -> u128 {
    match register.register_value_enum() {
        styx_emulator::core::cpu::arch::RegisterValue::u8(_) => {
            let value = cpu
                .read_register::<u8>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u16(_) => {
            let value = cpu
                .read_register::<u16>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u32(_) => {
            let value = cpu
                .read_register::<u32>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u40(_) => {
            let value = cpu
                .read_register::<u40>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u64(_) => {
            let value = cpu
                .read_register::<u64>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u80(_) => {
            let value = cpu
                .read_register::<u80>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u128(_) => cpu
            .read_register::<u128>(register.variant())
            .expect("we already checked that this register existed"),
        styx_emulator::core::cpu::arch::RegisterValue::ArmSpecial(_) => {
            todo!()
        }
    }
}

fn write_register_value(
    cpu: &Processor,
    register: &styx_emulator::core::cpu::arch::CpuRegister,
    value: u128,
) {
    use styx_emulator::core::cpu::arch::RegisterValue;
    match register.register_value_enum() {
        RegisterValue::u8(_) => {
            let value: u8 = value.try_into().unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        RegisterValue::u16(_) => {
            let value: u16 = value.try_into().unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        RegisterValue::u32(_) => {
            let value: u32 = value.try_into().unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        RegisterValue::u40(_) => {
            let value: u64 = value.try_into().unwrap();
            let value: u40 = u40::try_new(value).unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        RegisterValue::u64(_) => {
            let value: u64 = value.try_into().unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        RegisterValue::u80(_) => {
            let value: u80 = u80::try_new(value).unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        RegisterValue::u128(_) => {
            let value: u128 = value;
            cpu.write_register(register.variant(), value).unwrap();
        }
        RegisterValue::ArmSpecial(_) => todo!(),
    }
}

pub(crate) fn register(m: &mut ModuleSystem) -> PyResult<()> {
    m.register("angr", |m| {
        m.add_class::<StyxConcreteTargetBackend>()?;
        Ok(())
    })?;
    Ok(())
}
