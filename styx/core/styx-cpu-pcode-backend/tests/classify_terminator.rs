// SPDX-License-Identifier: BSD-2-Clause

use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{arch::ppc32::Ppc32Variants, Arch, ArchEndian};
use styx_processor::cpu::{
    classify_block_terminator, ControlFlowType, CpuBackend, InstructionClass,
};
use styx_processor::event_controller::EventController;
use styx_processor::memory::helpers::WriteExt;
use styx_processor::memory::memory_region::MemoryRegion;
use styx_processor::memory::{MemoryPermissions, Mmu};

/// PPC is big-endian; instruction words are written in big-endian byte order
fn setup() -> (Mmu, EventController, PcodeBackend) {
    let mmu =
        Mmu::with_regions([MemoryRegion::new(0, 0x10000, MemoryPermissions::all()).unwrap()]);
    let ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);
    cpu.set_pc(0).unwrap();
    (mmu, ev, cpu)
}

#[test]
fn classify_block_terminator_ppc() {
    let (mut mmu, mut ev, mut cpu) = setup();

    // b .   — unconditional branch (0x48000000)
    mmu.code().write(0x00).bytes(&[0x48, 0x00, 0x00, 0x00]).unwrap();
    // bl .  — branch and link == function call (0x48000001)
    mmu.code().write(0x10).bytes(&[0x48, 0x00, 0x00, 0x01]).unwrap();
    // blr   — branch to link register == function return (0x4e800020)
    mmu.code().write(0x20).bytes(&[0x4e, 0x80, 0x00, 0x20]).unwrap();
    // add r3, r3, r4 — a non-branching instruction (0x7c632214)
    mmu.code().write(0x30).bytes(&[0x7c, 0x63, 0x22, 0x14]).unwrap();

    assert_eq!(
        classify_block_terminator(&mut cpu, 0x00, 4, &mut mmu, &mut ev).flow,
        ControlFlowType::Branch,
        "`b` should classify as an intra-procedural branch"
    );

    // `bl .` is a direct call, so its static target is extracted
    //
    // here the instruction's own address, 0x10 (displacement 0)
    let call = classify_block_terminator(&mut cpu, 0x10, 4, &mut mmu, &mut ev);
    assert_eq!(call.flow, ControlFlowType::Call, "`bl` should classify as a call");
    assert_eq!(call.target, Some(0x10), "direct call target should be extracted");

    let ret = classify_block_terminator(&mut cpu, 0x20, 4, &mut mmu, &mut ev);
    assert_eq!(ret.flow, ControlFlowType::Return, "`blr` should classify as a return");
    assert_eq!(ret.target, None, "an indirect return has no static target");

    assert_eq!(
        classify_block_terminator(&mut cpu, 0x30, 4, &mut mmu, &mut ev).flow,
        ControlFlowType::Fallthrough,
        "a non-branching block should classify as fallthrough"
    );
}

#[test]
fn classify_instruction_ppc() {
    let (mut mmu, mut ev, mut cpu) = setup();

    // bl .                       — call (0x48000001)
    mmu.code().write(0x00).bytes(&[0x48, 0x00, 0x00, 0x01]).unwrap();
    // blr                        — return (0x4e800020)
    mmu.code().write(0x10).bytes(&[0x4e, 0x80, 0x00, 0x20]).unwrap();
    // lwz r4, 0(r3)              — load (0x80830000)
    mmu.code().write(0x20).bytes(&[0x80, 0x83, 0x00, 0x00]).unwrap();
    // stw r4, 0(r3)              — store (0x90830000)
    mmu.code().write(0x30).bytes(&[0x90, 0x83, 0x00, 0x00]).unwrap();
    // add r3, r3, r4             — other (0x7c632214)
    mmu.code().write(0x40).bytes(&[0x7c, 0x63, 0x22, 0x14]).unwrap();
    // cmpwi cr0, r3, 5           — compare, best-effort (0x2c030005)
    mmu.code().write(0x50).bytes(&[0x2c, 0x03, 0x00, 0x05]).unwrap();

    let class = |cpu: &mut PcodeBackend, mmu: &mut Mmu, ev: &mut EventController, addr| {
        let info = cpu.classify_instruction(addr, mmu, ev);
        assert_eq!(info.length, 4, "PPC instructions are 4 bytes");
        info.class
    };

    assert_eq!(class(&mut cpu, &mut mmu, &mut ev, 0x00), InstructionClass::Call);
    assert_eq!(class(&mut cpu, &mut mmu, &mut ev, 0x10), InstructionClass::Return);
    assert_eq!(class(&mut cpu, &mut mmu, &mut ev, 0x20), InstructionClass::Load);
    assert_eq!(class(&mut cpu, &mut mmu, &mut ev, 0x30), InstructionClass::Store);
    assert_eq!(class(&mut cpu, &mut mmu, &mut ev, 0x40), InstructionClass::Other);
    // best-effort: a hardware compare lowers to comparison pcode ops
    assert_eq!(class(&mut cpu, &mut mmu, &mut ev, 0x50), InstructionClass::Compare);
}



