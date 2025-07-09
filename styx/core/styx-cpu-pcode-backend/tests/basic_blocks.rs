// SPDX-License-Identifier: BSD-2-Clause
use std::sync::atomic::{AtomicU32, Ordering};

use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::TargetExitReason;
use styx_cpu_type::{arch::ppc32::Ppc32Variants, Arch, ArchEndian};
use styx_errors::UnknownError;
use styx_processor::cpu::{CpuBackend, ExecutionReport};
use styx_processor::hooks::{CoreHandle, Hookable, StyxHook};
use styx_processor::memory::helpers::WriteExt;
use styx_processor::memory::MemoryPermissions;
use styx_processor::{event_controller::EventController, memory::Mmu};
use styx_util::logging::init_logging;

/// Test the triggering of basic blocks in the pcode backend.
///
/// A simple infinite loop is run. The hooks are checked for correct address, size, and number of
/// executions.
#[test]
fn test_basic_block_hook() -> Result<(), UnknownError> {
    init_logging();
    let objdump = "
     0:	3c 60 00 00 	lis     r3,0
     4:	60 63 10 00 	ori     r3,r3,4096
     8:	3c 80 00 00 	lis     r4,0
     c:	60 84 13 37 	ori     r4,r4,4919
    10:	90 83 00 00 	stw     r4,0(r3)
    14:	4b ff ff ec 	b       0 <start>
   ";

    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    let code_bytes = styx_util::parse_objdump(objdump)?;
    mmu.memory_map(0, 0x10000, MemoryPermissions::all())?;
    mmu.code().write(0).bytes(&code_bytes)?;
    cpu.set_pc(0)?;

    let value: &'static _ = Box::leak(Box::new(AtomicU32::new(0)));

    cpu.add_hook(StyxHook::block(|_core: CoreHandle, addr, size| {
        value.fetch_add(1, Ordering::Relaxed);
        assert_eq!(addr, 0);
        assert_eq!(size, 0x18);
        Ok(())
    }))?;

    let res = cpu.execute(&mut mmu, &mut ev, 6 * 1000)?;
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::InstructionCountComplete, 6000)
    );
    // not 1000 because the first execution is NOT a basic block (we didn't branch to it)
    assert_eq!(value.load(Ordering::Relaxed), 999);

    Ok(())
}
