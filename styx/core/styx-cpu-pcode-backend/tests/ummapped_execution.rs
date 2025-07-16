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
//! Various tests for when execution hits regions that are unmapped or don't have permissions.

use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{arch::ppc32::Ppc32Variants, Arch, ArchEndian, TargetExitReason};
use styx_processor::{
    cpu::{CpuBackend, ExecutionReport},
    event_controller::EventController,
    memory::{helpers::WriteExt, memory_region::MemoryRegion, MemoryPermissions, Mmu},
};

/// Execution when starting in unmapped memory should throw a descriptive error.
#[test]
fn test_unmapped_execution() {
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    mmu.add_memory_region(MemoryRegion::new(0x0, 0x1000, MemoryPermissions::all()).unwrap())
        .unwrap();
    // start unmapped
    cpu.set_pc(0x2000).unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 1000).unwrap();
    println!("cpu execution res: {res:?}");
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::UnmappedMemoryFetch, 0)
    );
}

/// Execution when starting in mapped memory should throw read the mapped memory until it goes
/// unmapped. If execution then goes into unmapped on the next instruction then it should error
/// again.
#[test]
fn test_goes_unmapped_execution() {
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();

    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    mmu.add_memory_region(MemoryRegion::new(0x0, 0x1000, MemoryPermissions::all()).unwrap())
        .unwrap();

    // start mapped
    cpu.set_pc(0xFFC).unwrap();
    mmu.code()
        .write(0xFFC)
        .bytes(&[0x38, 0x80, 0x00, 0x04]) // valid ppc32 code
        .unwrap();

    // 1 instruction should be mapped
    let res = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    println!("res: {res:?}");

    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::InstructionCountComplete, 1)
    );

    // start mapped
    // 1 instruction should be mapped, 2nd instruction is not
    cpu.set_pc(0xFFC).unwrap();
    let res = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    println!("cpu execution res: {res:?}");
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::UnmappedMemoryFetch, 1)
    );
}

/// Execution when starting in memory with no permissions should error. Currently this only applies
/// to memory with no permissions, the execute permission is not checked.
#[test]
fn test_no_permission_execution() {
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();

    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    mmu.add_memory_region(MemoryRegion::new(0x0, 0x1000, MemoryPermissions::all()).unwrap())
        .unwrap();
    mmu.add_memory_region(MemoryRegion::new(0x1000, 0x1000, MemoryPermissions::empty()).unwrap())
        .unwrap();

    // start with no permission region
    cpu.set_pc(0x1000).unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 1000).unwrap();
    println!("cpu execution res: {res:?}");
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::ProtectedMemoryFetch, 0)
    );
}

/// Execution when starting in memory with permissions but bleeds into a region with no permission
/// should read as much as possible before stopping, like mapped/unmapped execution. This does not
/// work currently because the MmuOpError is not descriptive enough to tell us how many bytes is we
/// read with permissions before failing (i.e. a permission equivalent to GoesUnmapped).
#[ignore]
#[test]
fn test_goes_no_permission_execution() {
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();

    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    mmu.add_memory_region(MemoryRegion::new(0x0, 0x1000, MemoryPermissions::all()).unwrap())
        .unwrap();
    mmu.add_memory_region(MemoryRegion::new(0x1000, 0x1000, MemoryPermissions::empty()).unwrap())
        .unwrap();

    cpu.set_pc(0xFFC).unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::InstructionCountComplete, 1)
    );
}
