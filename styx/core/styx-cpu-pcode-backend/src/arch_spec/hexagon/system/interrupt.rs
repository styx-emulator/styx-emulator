// SPDX-License-Identifier: BSD-2-Clause
use derive_more::FromStr;
use log::trace;
use styx_cpu_type::arch::hexagon::{register_fields::Ssr, HexagonRegister};
use styx_errors::anyhow::Context;
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
    arch_spec::{ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};

#[derive(Debug)]
pub struct InterruptGenericStub {
    from: &'static str,
}

/// Look at <https://github.com/quic/qemu/blob/hex-next/target/hexagon/cpu_bits.h>
#[repr(i32)]
#[allow(unused)]
pub enum InterruptType {
    None = -1,
    Reset = 0,
    Imprecise = 1,
    Precise = 0x2,
    TlbMissX = 0x4,
    TlbMissRw = 0x6,
    Trap0 = 0x8,
    Trap1 = 0x9,
    Fptrap = 0xb,
    Debug = 0xc,
    Int0 = 0x10,
    Int1 = 0x11,
    Int2 = 0x12,
    Int3 = 0x13,
    Int4 = 0x14,
    Int5 = 0x15,
    Int6 = 0x16,
    Int7 = 0x17,
    Int8 = 0x18,
    Int9 = 0x19,
    IntA = 0x1a,
    IntB = 0x1b,
    IntC = 0x1c,
    IntD = 0x1d,
    IntE = 0x1e,
    IntF = 0x1f,
}

/// Trap instruction, see 11.9.3 Trap.
///
/// Also see implementation in QUIC QEMU, branch hex-next
/// specifically target/hexagon/hexswi.c, specifically
/// hexagon_cpu_do_interrupt. Also see fTRAP macro
/// in target/hexagon/macros.h.
///
/// Also see do_raise_exception and hexagon_raise_exception_err
/// in target/hexagon/op_helper.c.
///
/// FIXME: multicore (delayed interrupt may need changing)
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
        let exc_no = u8::try_from(exc_no_vn.offset)
            .with_context(|| "the trap offset must be within 8 bits")?;

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

        Ok(PCodeStateChange::DelayedInterrupt(
            InterruptType::Trap0 as i32,
        ))
    }
}

/// Clear pending interrupts - see section 11.9.2 "Clear pending interrupts"
/// FIXME: multicore (just double check there are no effects to handle)
#[derive(Debug)]
pub struct CswiHandler;
impl<T: CpuBackend> CallOtherCallback<T> for CswiHandler {
    /// Implement "Clear pending interrupts."
    ///
    /// For some reason, the QEMU implementation (hex_interrupt.c and registers bitfields in branch hex-next)
    /// seem to define the mask to clear the lower 16 bits of the pending interrupts register,
    /// even though the mask is defined in the manual 11.9.2 "Clear Pending Interrupts" to be
    /// 32 bits.
    ///
    /// Other branches, such as bcain/tlb_obj, seem to define a separate register IPEND and IAD
    /// as 32-bit registers. These registers come towards the end of the defined list of registers.
    ///
    /// In 11.9.2 "System control register transfer," however, the registers IPEND and IAD
    /// are defined separately as 32-bit values, but in the same place where both QEMU branches
    /// define IPENDAD and VID1, respectively. We have chosen to move IPEND and IAD to the end of
    /// the register map and not use them.
    fn handle(
        &mut self,
        backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        assert_eq!(inputs.len(), 1);

        let rs = backend
            .read(&inputs[0])
            .with_context(|| "couldn't read cswi register argument value")?
            .to_u64()
            .with_context(|| "couldn't unwrap mask")? as u32;

        let ipend_value = backend
            .read_register::<u32>(HexagonRegister::Ipend)
            .with_context(|| "couldn't read IPEND register")?;
        let ipend_cleared = ipend_value & !rs;

        backend
            .write_register(HexagonRegister::Ipend, ipend_cleared)
            .with_context(|| "couldn't clear specified bits of IPEND register")?;

        trace!("cswi: rs {rs:x} ipend_old {ipend_value:x} ipend_after {ipend_cleared:x}",);

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// Clear interrupt auto disbale - see section 11.9.2 "Clear interrupt auto disbale"
/// FIXME: multicore (just double check there are no effects to handle)
#[derive(Debug)]
pub struct CiadHandler;
impl<T: CpuBackend> CallOtherCallback<T> for CiadHandler {
    /// Implement CIAD (clear interrupt auto disable)
    /// NOTE: the implementation of this may change when we implement the interrupt controller.
    ///
    /// See [CswiHandler::handle], the same note about implementation applies here.
    fn handle(
        &mut self,
        backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        assert_eq!(inputs.len(), 1);

        let rs = backend
            .read(&inputs[0])
            .with_context(|| "couldn't read ciad register argument value")?
            .to_u64()
            .with_context(|| "couldn't unwrap mask")? as u32;

        let iad_value = backend
            .read_register::<u32>(HexagonRegister::Iad)
            .with_context(|| "couldn't read IAD register")?;

        let iad_cleared = iad_value & !rs;

        backend
            .write_register(HexagonRegister::Iad, iad_cleared)
            .with_context(|| "couldn't clear specified bits of IAD register")?;

        trace!("ciad: rs {rs:x} iad_old {iad_value:x} after {iad_cleared:x}",);

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// Return from exception - 11.9.2
#[derive(Debug)]
pub struct RteHandler;
impl<T: CpuBackend> CallOtherCallback<T> for RteHandler {
    /// Implement RTE (return from exception)
    fn handle(
        &mut self,
        backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let elr = backend
            .read_register::<u32>(HexagonRegister::Elr)
            .with_context(|| "couldn't read elr for rte")?;
        let ssr = Ssr::new_with_raw_value(
            backend
                .read_register::<u32>(HexagonRegister::Ssr)
                .with_context(|| "couldn't read ssr for rte")?,
        )
        .with_ex(false);

        backend
            .write_register(HexagonRegister::Ssr, ssr.raw_value())
            .with_context(|| "couldn't write ssr with cleared ex for rte")?;

        Ok(PCodeStateChange::InstructionAbsolute(elr as u64))
    }
}

/// Raise NMI on threads - 11.9.2
/// FIXME: multicore
#[derive(Debug)]
pub struct NmiHandler;
impl<T: CpuBackend> CallOtherCallback<T> for NmiHandler {
    /// Implement NMI on threads
    ///
    /// Since Styx only supports single-core emulation,
    /// this is currently only implemented for one core.
    /// The instruction handler with panic with the
    /// unimplemented! directive if the input to nmi
    /// has hardware thread 0's bit set to zero and
    /// other hardware threads' bits set to 1.
    fn handle(
        &mut self,
        backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let rs = &inputs[0];
        let rs_val = backend
            .read(rs)
            .with_context(|| "couldn't read Rs for nmi")?
            .to_u64()
            .with_context(|| "couldn't turn Rs to u32 for nmi")?;

        // FIXME: multicore
        // we only have one thread, so this suffices.
        //
        // In the case, we do not have to NMI on thread 0
        // and since we are running on thread 0 since Styx only
        // supports one core, we are done.
        if rs_val & 1 == 0 {
            trace!("nmi({rs_val:x}) called");
            Ok(PCodeStateChange::Fallthrough)
        }
        // Some other thread should be sent an nmi,
        // but Styx doesn't support multicore yet.
        else {
            unimplemented!("nmi({rs_val:x}) called");
        }
    }
}

impl<T: CpuBackend> CallOtherCallback<T> for InterruptGenericStub {
    fn handle(
        &mut self,
        backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        unimplemented!(
            "interrupt related stub called for {} pc {:x?}",
            self.from,
            backend.pc()
        );
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
        .add_handler_other_sla(HexagonUserOps::Rte, RteHandler {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Swi, InterruptGenericStub { from: "swi" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Cswi, CswiHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Ciad, CiadHandler)
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
        .add_handler_other_sla(HexagonUserOps::Nmi, NmiHandler {})
        .unwrap();
}
