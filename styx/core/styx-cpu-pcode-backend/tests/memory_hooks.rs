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
use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{arch::ppc32::Ppc32Variants, Arch, ArchEndian, TargetExitReason};
use styx_processor::{
    cpu::{CpuBackend, ExecutionReport},
    event_controller::EventController,
    hooks::{CoreHandle, Hookable, StyxHook},
    memory::{
        helpers::{ReadExt, WriteExt},
        memory_region::MemoryRegion,
        MemoryPermissions, Mmu,
    },
};

/// Tests behavior of the memory read hook on a big endian arch in the pcode backend.
///
/// Ensures hook arguments and read data mutability are ensured.
#[test]
fn test_memory_read_hook_be() {
    let objdump = "
       0:	3c 60 00 00 	lis     r3,0
       4:	60 63 10 00 	ori     r3,r3,4096
       8:	80 83 00 00 	lwz     r4,0(r3)
   ";

    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    let code_bytes = styx_util::parse_objdump(objdump).unwrap();

    // code region
    mmu.add_memory_region(MemoryRegion::new(0, 0x10000, MemoryPermissions::all()).unwrap())
        .unwrap();

    mmu.write_code(0x0, &code_bytes).unwrap();
    mmu.data().write(0x1000).be().value(0xCAFEBABEu32).unwrap();

    let read_hook = |_core: CoreHandle, addr: u64, size: u32, data: &mut [u8]| {
        assert_eq!(data, &[0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(addr, 0x1000);
        assert_eq!(size, 4);
        assert_eq!(size, data.len() as u32);
        data[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        Ok(())
    };
    cpu.add_hook(StyxHook::memory_read(0x1000, read_hook))
        .unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 3).unwrap();

    println!("execution result: {res:?}");

    let assert_addr = mmu.data().read(0x1000).be().u32().unwrap();
    assert_eq!(assert_addr, 0xDEADBEEF);
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::InstructionCountComplete, 3)
    );
}
