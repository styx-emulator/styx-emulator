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

//! These tests assert the behavior of executing instructions at pc=u64:MAX.
//!
//! The expected behavior is that the CPU errors gracefully and does not panic.

use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{Arch, ArchEndian};
use styx_errors::UnknownError;
use styx_processor::{
    cpu::CpuBackend,
    event_controller::EventController,
    memory::{helpers::WriteExt, MemoryPermissions, Mmu},
};
use styx_util::logging::init_logging;

#[cfg(feature = "arch_ppc")]
#[test]
fn test_pc_overflow_ppc32() -> Result<(), UnknownError> {
    use styx_cpu_type::arch::ppc32::Ppc32Variants;

    init_logging();
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    cpu.set_pc(u64::MAX - 3)?;
    mmu.memory_map(u64::MAX - 0xFFF, 0x1000, MemoryPermissions::all())?;
    mmu.code()
        .write(u64::MAX - 3)
        .bytes(&[0x60, 0x00, 0x00, 0x00])?; // powerpc code for NOP

    let res = cpu.execute(&mut mmu, &mut ev, 1);
    // this should not panic and instead return an error
    assert!(res.is_err());

    Ok(())
}

#[cfg(feature = "arch_arm")]
#[test]
fn test_pc_overflow_arm_tmode() -> Result<(), UnknownError> {
    use styx_cpu_type::arch::arm::ArmVariants;

    init_logging();
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu = PcodeBackend::new_engine(
        Arch::Arm,
        ArmVariants::ArmCortexM4,
        ArchEndian::LittleEndian,
    );

    cpu.set_pc(u64::MAX)?;
    mmu.memory_map(u64::MAX - 0xFFF, 0x1000, MemoryPermissions::all())?;
    mmu.code().write(u64::MAX - 1).bytes(&[0xC0, 0x46])?; // arm t-mode code for NOP

    let res = cpu.execute(&mut mmu, &mut ev, 1);
    // this should not panic and instead return an error
    assert!(res.is_err());

    Ok(())
}

#[cfg(feature = "arch_arm")]
#[test]
fn test_pc_overflow_arm_normal() -> Result<(), UnknownError> {
    use styx_cpu_type::arch::arm::ArmVariants;

    init_logging();
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu = PcodeBackend::new_engine(
        Arch::Arm,
        ArmVariants::ArmCortexA7,
        ArchEndian::LittleEndian,
    );

    cpu.set_pc(u64::MAX - 3)?;
    mmu.memory_map(u64::MAX - 0xFFF, 0x1000, MemoryPermissions::all())?;
    mmu.code()
        .write(u64::MAX - 3)
        .bytes(&[0x00, 0x00, 0x00, 0x00])?; // arm code for NOP

    let res = cpu.execute(&mut mmu, &mut ev, 1);
    // this should not panic and instead return an error
    assert!(res.is_err());

    Ok(())
}

#[cfg(feature = "arch_bfin")]
#[test]
fn test_pc_overflow_bfin() -> Result<(), UnknownError> {
    use styx_cpu_type::arch::blackfin::BlackfinVariants;

    init_logging();
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu = PcodeBackend::new_engine(
        Arch::Blackfin,
        BlackfinVariants::Bf512,
        ArchEndian::LittleEndian,
    );

    cpu.set_pc(u64::MAX - 1)?;
    mmu.memory_map(u64::MAX - 0xFFF, 0x1000, MemoryPermissions::all())?;
    mmu.code().write(u64::MAX - 1).bytes(&[0x00, 0x00])?; // bfin code for NOP (at least in our sla spec)

    let res = cpu.execute(&mut mmu, &mut ev, 1);
    // this should not panic and instead return an error
    assert!(res.is_err());

    Ok(())
}
