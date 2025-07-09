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
use pyo3::prelude::Py;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::*;
use pyo3_stub_gen::{PyStubType, TypeInfo};
use std::collections::HashSet;
use styx_emulator::prelude as styx;

// is this horrible
// hack to extend CoreHandle lifetime
fn lifetime_expand(handle: styx::CoreHandle<'_>) -> styx::CoreHandle<'static> {
    unsafe { std::mem::transmute(handle) }
}

pub fn get_range(start: u64, end: u64) -> styx::AddressRange {
    (start..=end).into()
}

#[gen_stub_pyclass]
#[pyclass(module = "cpu.hooks")]
pub struct HookToken(pub styx_emulator::hooks::HookToken);

macro_rules! hook_xmacro {
    ($x:ident $($t:tt)*) => {
        $x! {
            Code() -> (): () {
                start: u64,
                end: u64,
            };
            Block(addr: u64: u64, size: u32: u32) -> (): ();
            MemoryWrite(addr: u64: u64, size: u32: u32, data: ::pyo3::prelude::Py<::pyo3::types::PyBytes>: &[u8]) -> (): ()  {
                start: u64,
                end: u64,
            };
            MemoryRead(addr: u64: u64, size: u32: u32, data: ::pyo3::prelude::Py<::pyo3::types::PyBytes>: &mut [u8]) -> (): () {
                start: u64,
                end: u64,
            };
            Interrupt(intno: i32: i32) -> (): ();
            InvalidInstruction() -> bool: styx_emulator::hooks::Resolution;
            ProtectionFault(addr: u64: u64, size: u32: u32, region_perms: $crate::cpu::MemoryPermissions: styx::MemoryPermissions, fault_data: $crate::cpu::MemFaultData: styx::MemFaultData) ->  bool: styx_emulator::hooks::Resolution {
                start: u64,
                end: u64,
            };
            UnmappedFault(addr: u64: u64, size: u32: u32, fault_data: $crate::cpu::MemFaultData: styx::MemFaultData) -> bool: styx_emulator::hooks::Resolution {
                start: u64,
                end: u64,
            };
            $($t:tt)*
        }
    }
}

pub(crate) use hook_xmacro;

use crate::cpu::{MemFaultData, MemoryPermissions};

macro_rules! define_hooks {
    (
        $(
            $name:ident( $($an:ident: $at:ty: $att:ty),* $(,)? ) $(-> $rt:ty: $rtt:ty)? $({
                $($pn:ident: $pt:ty),* $(,)?
            })?
        ;)*
    ) => {
        $(
            ::paste::paste! {
                #[gen_stub_pyclass]
                #[pyclass(module = "cpu.hooks")]
                #[derive(Clone)]
                pub struct [< $name Hook >] {
                    $( $($pn: $pt,)*)?
                    callback: std::sync::Arc<PyObject>,
                }

                #[gen_stub_pymethods]
                #[pymethods]
                impl [< $name Hook >] {
                    #[new]
                    pub fn py_new($($($pn:$pt,)*)? callback: PyObject) -> Self {
                        Self {
                            $($($pn,)*)?
                            callback: std::sync::Arc::new(callback),
                        }
                    }
                }

                impl styx_emulator::hooks::[< $name Hook >] for [< $name Hook >] {
                    fn call(&mut self, proc: styx_emulator::hooks::CoreHandle, $($an: $att,)*) -> Result<$($rtt)?, styx_emulator::prelude::UnknownError>{
                        let cpu_backend = $crate::cpu::ProcessorCore::new(lifetime_expand(proc));
                        let res = Python::with_gil(|py| {
                            use ::pyo3::conversion::FromPyObject;
                            let result = self.callback.call1(py, (cpu_backend, $(convert_arg(py, $an)?),*))?;
                            let res: PyResult<$($rt)?> = convert(py, result);
                            res
                        }).unwrap();

                        Ok(res.into())
                    }
                }

                impl From<&'_ [< $name Hook >]> for styx_emulator::hooks::StyxHook {
                    fn from(hook: &[< $name Hook >]) -> Self {
                        Self::$name (
                            $( get_range($( hook.$pn,)*), )?
                            Box::new(hook.clone())
                        )
                    }
                }

                #[gen_stub_pyclass]
                #[pyclass(module = "cpu.hooks")]
                #[derive(Clone)]
                pub struct [< $name DataHook >] {
                    $( $($pn: $pt,)* )?
                    callback: std::sync::Arc<PyObject>,
                    userdata: std::sync::Arc<PyObject>,
                }

                #[gen_stub_pymethods]
                #[pymethods]
                impl [< $name DataHook >] {
                    #[new]
                    pub fn py_new($($($pn:$pt,)*)? callback: PyObject, userdata: PyObject) -> Self {
                        Self {
                            $($($pn,)*)?
                            callback: std::sync::Arc::new(callback),
                            userdata: std::sync::Arc::new(userdata),
                        }
                    }
                }

                impl styx_emulator::hooks::[< $name Hook >] for [< $name DataHook >] {
                    fn call(&mut self, proc: styx_emulator::hooks::CoreHandle, $($an: $att,)*) -> Result<$($rtt)?, styx_emulator::prelude::UnknownError>{
                        let cpu_backend = $crate::cpu::ProcessorCore::new(lifetime_expand(proc));
                        let res = Python::with_gil(|py| {
                            use ::pyo3::conversion::FromPyObject;
                            let result = self.callback.call1(py, (cpu_backend, $(convert_arg(py, $an)?,)* self.userdata.as_ref().clone()))?;
                            let res: PyResult<$($rt)?> = convert(py, result);
                            res
                        }).unwrap();

                        Ok(res.into())
                    }
                }

                impl From<&'_ [< $name DataHook >]> for styx_emulator::hooks::StyxHook {
                    fn from(hook: &[< $name DataHook >]) -> Self {
                        Self::$name (
                            $( get_range($( hook.$pn,)*), )?
                            Box::new(hook.clone())
                        )
                    }
                }
            }
        )*

        ::paste::paste! {
            #[derive(FromPyObject)]
            pub enum Hook<'py> {
                $(
                    $name(Bound<'py, [< $name Hook >]>),
                    [< $name Data >](Bound<'py, [< $name DataHook >]>),
                )*
            }

            pyo3_stub_gen::impl_stub_type!(
                Hook<'_> = $(
                    [< $name Hook >] | [< $name DataHook >]
                ) | *
            );

            impl<'py> From<Hook<'py>> for styx_emulator::hooks::StyxHook {
                fn from(value: Hook<'py>) -> Self {
                    match value {
                        $(
                            Hook::$name(hook) => From::from(&*Bound::borrow(&hook)),
                            Hook::[< $name Data >](hook) => From::from(&*Bound::borrow(&hook)),
                        )*
                    }
                }
            }
        }

        ::paste::paste! {
            pub(crate) fn register(m: &mut crate::util::module_system::ModuleSystem) -> PyResult<()> {
                m.register("cpu.hooks", |m| {
                    $(
                        m.add_class::<[< $name Hook >]>()?;
                        m.add_class::<[< $name DataHook >]>()?;
                    )*
                    Ok(())
                })?;
                Ok(())
            }
        }
    };
}

hook_xmacro!(define_hooks);

trait Convert<'py>: Sized + 'py {
    fn convert(py: Python<'py>, value: PyObject) -> PyResult<Self>;
}
fn convert<'py, C: Convert<'py> + 'py>(py: Python<'py>, value: PyObject) -> PyResult<C> {
    C::convert(py, value)
}

impl<'py> Convert<'py> for () {
    fn convert(_: Python<'py>, _: PyObject) -> PyResult<Self> {
        Ok(())
    }
}

impl<'py> Convert<'py> for bool {
    fn convert(py: Python, value: PyObject) -> PyResult<Self> {
        value.extract(py)
    }
}

trait ConvertArg<'py, T: 'py> {
    fn convert_arg(self, py: Python<'py>) -> PyResult<T>;
}

fn convert_arg<'py, A, B>(py: Python<'py>, a: A) -> PyResult<B>
where
    A: ConvertArg<'py, B>,
    B: 'py,
{
    a.convert_arg(py)
}

impl<'py> ConvertArg<'py, u32> for u32 {
    fn convert_arg(self, _py: Python<'py>) -> PyResult<u32> {
        Ok(self)
    }
}

impl<'py> ConvertArg<'py, u64> for u64 {
    fn convert_arg(self, _py: Python<'py>) -> PyResult<u64> {
        Ok(self)
    }
}

impl<'py> ConvertArg<'py, i32> for i32 {
    fn convert_arg(self, _py: Python<'py>) -> PyResult<i32> {
        Ok(self)
    }
}

impl<'py> ConvertArg<'py, Bound<'py, ::pyo3::types::PyBytes>> for &'_ [u8] {
    fn convert_arg(self, py: Python<'py>) -> PyResult<Bound<'py, ::pyo3::types::PyBytes>> {
        Ok(::pyo3::types::PyBytes::new(py, self))
    }
}

impl<'py> ConvertArg<'py, Bound<'py, ::pyo3::types::PyBytes>> for &'_ mut [u8] {
    fn convert_arg(self, py: Python<'py>) -> PyResult<Bound<'py, ::pyo3::types::PyBytes>> {
        Ok(::pyo3::types::PyBytes::new(py, &*self))
    }
}

impl<'py> ConvertArg<'py, Bound<'py, MemFaultData>> for styx::MemFaultData<'_> {
    fn convert_arg(self, py: Python<'py>) -> PyResult<Bound<'py, MemFaultData>> {
        let data: MemFaultData = self.into();
        Bound::new(py, data)
    }
}

impl<'py> ConvertArg<'py, Bound<'py, MemoryPermissions>> for styx::MemoryPermissions {
    fn convert_arg(self, py: Python<'py>) -> PyResult<Bound<'py, MemoryPermissions>> {
        let data: MemoryPermissions = self.into();
        Bound::new(py, data)
    }
}
