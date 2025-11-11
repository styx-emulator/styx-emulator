// SPDX-License-Identifier: BSD-2-Clause
//! These aren't system instructions, but I guess they can be accelerated by farming them out to Rust.
//! And I guess analysis doesn't matter as much for this?
use derive_more::FromStr;
use log::{debug, info};
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
        let rs = &inputs[0];
        let rd = output.with_context(|| "couldn't read Rd for cl1")?;

        // We actually have no idea how big this is, so we will just shift
        let rs_sized_val = cpu.read(rs).with_context(|| "couldn't read Rs for cl1")?;
        let rs_u64 = rs_sized_val
            .to_u64()
            .with_context(|| "couldn't cast Rs as u32 for cl1")?;

        let shift_amt = 64 - (rs_sized_val.size() * 8);
        let shifted_rs_u64 = rs_u64 << shift_amt;

        let leading_ones = shifted_rs_u64.leading_ones() as u32;
        cpu.write(rd, leading_ones.into())
            .with_context(|| "couldn't write leading ones into Rd for cl1")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

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

        let rs_rev = if rs_val.size() == 8 {
            info!("brev {:64b} {:64b}", rs_64, rs_64.reverse_bits());
            SizedValue::from_u64(rs_64.reverse_bits(), 8)
        } else if rs_val.size() == 4 {
            info!(
                "brev {:032b} {:032b}",
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
