// SPDX-License-Identifier: BSD-2-Clause
use derive_more::FromStr;
use log::trace;
use styx_cpu_type::arch::hexagon::HexagonRegister;
use styx_pcode::{
    pcode::{SpaceName, VarnodeData},
    sla::SlaUserOps,
};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    memory::Mmu,
};

use crate::{
    arch_spec::{hexagon::system::regs::Ssr, ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};

#[derive(Debug)]
pub struct InterruptGenericStub {
    from: &'static str,
}

#[derive(Debug)]
pub struct Trap0Handler;
impl<T: CpuBackend> CallOtherCallback<T> for Trap0Handler {
    fn handle(
        &mut self,
        backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        assert_eq!(inputs.len(), 1);
        // Exception number
        let exc_no_vn = &inputs[0];

        // See section 11.9.3 (trap), for more details
        // Always an immediate
        assert_eq!(exc_no_vn.space, SpaceName::Constant);

        // The immediate is always 1 byte/8 bits, but
        // is set as a 32-bit value in the P-Code
        let exc_no = u8::try_from(exc_no_vn.offset).expect("the trap offset must be within 8 bits");

        // According to 11.9.3, we also need to set the "CAUSE" field
        // of the SSR register
        let ssr =
            Ssr::new_with_raw_value(backend.read_register::<u32>(HexagonRegister::Ssr).unwrap())
                .with_cause(exc_no);
        backend
            .write_register(HexagonRegister::Ssr, ssr.raw_value())
            .unwrap();

        trace!(
            "trap0 with exception {exc_no}, ssr is {:x}",
            ssr.raw_value()
        );

        Ok(PCodeStateChange::DelayedInterrupt(exc_no as i32))
    }
}

impl<T: CpuBackend> CallOtherCallback<T> for InterruptGenericStub {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        unimplemented!("interrupt related stub called for {}", self.from);
    }
}

pub fn add_interrupt_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Trap0, Trap0Handler)
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Trap1,
            InterruptGenericStub { from: "trap1" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Rte, InterruptGenericStub { from: "rte" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Swi, InterruptGenericStub { from: "swi" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Cswi, InterruptGenericStub { from: "cswi" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Ciad, InterruptGenericStub { from: "ciad" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Siad, InterruptGenericStub { from: "siad" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Iassignr,
            InterruptGenericStub { from: "iassignr" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Iassignw,
            InterruptGenericStub { from: "iassignw" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Nmi, InterruptGenericStub { from: "nmi" })
        .unwrap();
}
