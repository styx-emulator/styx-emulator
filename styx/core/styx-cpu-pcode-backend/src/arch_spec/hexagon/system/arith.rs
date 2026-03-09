// SPDX-License-Identifier: BSD-2-Clause
//! These aren't system instructions, but I guess they can be accelerated by farming them out to Rust.
//! And I guess analysis doesn't matter as much for this?
use derive_more::FromStr;
use log::trace;
use styx_errors::anyhow::Context;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::{ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    memory::sized_value::SizedValue,
    PCodeStateChange,
};

/// 11.10.2 XTYPE BIT - count leading ones
/// Implemented with a callother.
#[derive(Debug)]
pub struct Cl1Handler {}

impl<T: CpuBackend> CallOtherCallback<T> for Cl1Handler {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // According to 11.10.2 XTYPE BIT in the Hexagon manual,
        // the source register can either be 32 or 64 bits, so
        // we want to write our function to handle both accordingly.

        let rs = &inputs[0];
        let rd = output.with_context(|| "couldn't read Rd for cl1")?;

        let rs_sized_val = cpu.read(rs).with_context(|| "couldn't read Rs for cl1")?;
        let rs_u64 = rs_sized_val
            .to_u64()
            .with_context(|| "couldn't cast Rs as u32 for cl1")?;

        // Knowing that the varnode Rs may either be 32 or 64 bits,
        // to make the "count leading ones" work universally,
        // we want to ensure that the MSB for the 32 bit value is now
        // the MSB for a 64 bit value so we can use the same leading_ones
        // method irregardless of whether the input varnode was 32 or 64 bits.
        //
        // Therefore we shift left by 32 in the 32-bit case and shift left by
        // zero in the 64-bit case.
        let shift_amt = 64 - (rs_sized_val.size() * 8);
        let shifted_rs_u64 = rs_u64 << shift_amt;

        let leading_ones = shifted_rs_u64.leading_ones();
        cpu.write(rd, leading_ones.into())
            .with_context(|| "couldn't write leading ones into Rd for cl1")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// 11.10.2 Bit reverse instruction
///
/// Reverses the order of bits.
/// This callother is also used in various other loads and stores;
/// see hexagon.slaspec for more information.
#[derive(Debug)]
pub struct BrevHandler {}
impl<T: CpuBackend> CallOtherCallback<T> for BrevHandler {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let rs = &inputs[0];
        let output = output.with_context(|| "brev doesn't have output")?;
        let rs_val = cpu
            .read(rs)
            .with_context(|| "couldn't read Rs(s) for brev")?;
        let rs_64 = rs_val
            .to_u64()
            .with_context(|| "couldn't convert Rs(s) to u64")?;

        // Quick sanity check in each branch: ensure that output is the same size as the
        // input. Again, according to 11.10.2 the brev instruction can use both
        // 32 and 64-bit inputs/outputs, but they should be consistent. To avoid
        // footguns, the check is enforced for other locations where the brev callother
        // is used.
        let rs_rev = if rs_val.size() == 8 {
            assert_eq!(output.size, 8);
            trace!("64-bit brev {:64b} {:64b}", rs_64, rs_64.reverse_bits());
            SizedValue::from_u64(rs_64.reverse_bits(), 8)
        } else if rs_val.size() == 4 {
            assert_eq!(output.size, 4);
            trace!(
                "32-bit brev {:032b} {:032b}",
                rs_64 as u32,
                (rs_64 as u32).reverse_bits()
            );
            SizedValue::from_u64((rs_64 as u32).reverse_bits() as u64, 4)
        } else {
            panic!()
        };

        cpu.write(output, rs_rev)
            .with_context(|| "couldn't write reversed bits into Rd for brev")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_arith_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Cl1, Cl1Handler {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Brev, BrevHandler {})
        .unwrap();
}
