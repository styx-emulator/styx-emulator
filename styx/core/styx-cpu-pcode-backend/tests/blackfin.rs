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
#![cfg(feature = "arch_bfin")]

use arbitrary_int::u40;
use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{
    arch::blackfin::{BlackfinRegister, BlackfinVariants},
    Arch, ArchEndian,
};
use styx_processor::cpu::CpuBackendExt;

/// Test writing to A0/A1 and reading from ANx/ANw.
#[cfg_attr(miri, ignore)]
#[test]
fn test_accumulator_read_write() {
    let mut backend = PcodeBackend::new_engine(
        Arch::Blackfin,
        BlackfinVariants::Bf512,
        ArchEndian::LittleEndian,
    );

    backend
        .write_register(BlackfinRegister::A0, u40::new(0x6613371337u64))
        .unwrap();
    backend
        .write_register(BlackfinRegister::A1, u40::new(0x33DEADBEEFu64))
        .unwrap();

    assert_eq!(
        0x66u32,
        backend.read_register::<u32>(BlackfinRegister::A0x).unwrap()
    );
    assert_eq!(
        0x33u32,
        backend.read_register::<u32>(BlackfinRegister::A1x).unwrap()
    );

    assert_eq!(
        0x13371337u32,
        backend.read_register::<u32>(BlackfinRegister::A0w).unwrap()
    );
    assert_eq!(
        0xDEADBEEFu32,
        backend.read_register::<u32>(BlackfinRegister::A1w).unwrap()
    );
}
