// SPDX-License-Identifier: BSD-2-Clause

use std::str::FromStr;

use log::info;
use styx_errors::anyhow::Context;
use styx_pcode::{
    pcode::{SpaceName, VarnodeData},
    sla::SlaUserOps,
};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::ArchSpecBuilder,
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    HexagonPcodeBackend, PCodeStateChange,
};

/// Handle memw_phys instruction, see 11.9.2 "Load from physical address"
/// for more information.
#[derive(Debug)]
pub struct MemHandler {}

impl<T: CpuBackend> CallOtherCallback<T> for MemHandler {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let reg_s = &inputs[0];
        let reg_t = &inputs[1];

        let output = output
            .as_ref()
            .expect("memw_phys does not have an output register");

        assert_eq!(reg_s.space, SpaceName::Register);
        assert_eq!(reg_t.space, SpaceName::Register);

        let rs = cpu
            .read(reg_s)
            .with_context(|| "couldn't read Rs in memw_phys")?
            .to_u64()
            .with_context(|| "Rs is over 64 bits in memw_phys")?;
        let rt = cpu
            .read(reg_t)
            .with_context(|| "couldn't read Rt in memw_phys")?
            .to_u64()
            .with_context(|| "Rt is over 64 bits in memw_phys")?;

        assert_eq!(output.space, SpaceName::Register);
        assert_eq!(output.size, 4);

        // 11.9.2 "load from physical address"
        // Physical addresses in Hexagon are 36 bits,
        // and chunks of these bits are passed in with two registers,
        // so we have to read these registers, mask them, and string these.
        //
        // Specifically, Rt's lower 25 bits should be bits 10 to 35 in the
        // memory address, and Rs's lower 11 bits should be bits 0 to 10
        // in the memory address. The below mask and shift reflects this.
        //
        // It doesn't seem to be worth using a bitfield for this because
        // the "rest" of each of these registers aren't used for anything
        // else during this instruction.
        let input = (rs & 0x7ff) | (rt << 11);

        info!(
            "memw_phys reading from {input:x}, rs {rs:x} rt {rt:x} at pc {:x?}",
            cpu.pc()
        );

        let output_data = mmu
            .read_u32_le_phys_data(input)
            .with_context(|| "couldn't read from physical memory location")?;

        info!("memw_phys read {output_data:x}");

        cpu.write(output, output_data.into())
            .with_context(|| "couldn't write physical memory value to register")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

// NOTE: there is no locking right now, as Styx only supports singlecore.
// FIXME: multicore.
//
// Both the slaspec implementations will need to be reworked when we
// get multicore, since we will then need a global lock across cores
#[derive(Debug)]
struct MemLockedHandler {}

impl<T: CpuBackend> CallOtherCallback<T> for MemLockedHandler {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // According to our SLASPEC
        // input 0 is Rs
        // input 1 is Rt
        //
        // output is the predicate (Pd)

        let rs = &inputs[0];
        let rs_val = cpu
            .read(rs)
            .with_context(|| "couldn't read memory address in Rs for mem_locked store")?
            .to_u64()
            .with_context(|| "couldn't convert Rs mem addr to u64")?;

        let rt = &inputs[1];
        let rt_val = cpu
            .read(rt)
            .with_context(|| "couldn't read value of Rt in mem_locked store")?;
        let rt_u64 = rt_val
            .to_u64()
            .with_context(|| "couldn't convert Rd write value to u64")?;

        match rt_val.size() {
            4 => mmu.write_u32_le_virt_data(rs_val, rt_u64 as u32, cpu),
            8 => mmu.write_u64_le_virt_data(rs_val, rt_u64, cpu),
            _ => unreachable!("invalid mem_locked size: rt_val is not 4 bytes or 8 bytes"),
        }
        .with_context(|| "couldn't write Rt to *Rs")?;

        let pd = output.with_context(|| "couldn't unwrap predicate output of mem_locked store")?;
        cpu.write(pd, 1u32.into())
            .with_context(|| "couldn't write Pd in mem_locked store")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_mem_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::MemwPhys, MemHandler {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::MemwLocked, MemLockedHandler {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::MemdLocked, MemLockedHandler {})
        .unwrap();
}
