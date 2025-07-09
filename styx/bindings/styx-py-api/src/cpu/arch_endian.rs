// SPDX-License-Identifier: BSD-2-Clause
use pyo3::pyclass;
use pyo3_stub_gen::derive::*;
use styx_emulator::core::macros::enum_mirror;

/// The order of bytes within a word of data
#[enum_mirror(styx_emulator::core::cpu::ArchEndian)]
#[derive(PartialEq, Clone, Copy)]
#[gen_stub_pyclass_enum]
#[pyclass(eq, module = "cpu")]
pub enum ArchEndian {
    /// The MSB is the rightmost bit
    BigEndian,
    /// The MSB is the leftmost bit
    LittleEndian,
}
