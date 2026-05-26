// SPDX-License-Identifier: BSD-2-Clause

use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    str::FromStr,
    sync::{Arc, Mutex},
};

use log::info;
use styx_errors::{anyhow::Context, UnknownError};
use styx_pcode::{
    pcode::{SpaceName, VarnodeData},
    sla::SlaUserOps,
};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{
    cpu::CpuBackend,
    event_controller::EventController,
    memory::{AtomicMmuOpError, Load, Mmu, StoreConditionalResult, TlbTranslateError},
};

use crate::{
    arch_spec::ArchSpecBuilder,
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    memory::sized_value::SizedValue,
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

#[derive(Debug)]
struct MemLoadlinkedHandler {
    llsc_map: Arc<Mutex<BTreeMap<u64, Load>>>,
    size: usize,
}

impl<T: CpuBackend + 'static> CallOtherCallback<T> for MemLoadlinkedHandler {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // First input is address. Output is the value
        // WARN: NOTE: TODO: Need to makes sure this works with page faulting.
        let addr = u64::from(
            cpu.read(&inputs[0])
                .with_context(|| "couldn't get address to load-linked from")?
                .to_u64()
                .with_context(|| "couldn't convert load link address to u64")?,
        );
        info!("size of load linked is {:?} pc {:x?}", self.size, cpu.pc());

        match mmu.virt_load_linked_data(addr, self.size, cpu) {
            Ok(load_value) => {
                let mut llsc = self.llsc_map.lock().expect("couldn't lock llsc map");

                // Now write to output varnode
                let sized_value_write =
                    SizedValue::from_le_bytes(&load_value.data()).resize(self.size as u8);
                let output = output.with_context(|| "expected an output varnode for load link")?;

                // Make sure the value we're writing is the same size the output
                assert_eq!(sized_value_write.size() as usize, output.size as usize);
                info!(
                    "load value is {:x?}, sized value is {:x?}",
                    &load_value, sized_value_write
                );

                cpu.write(output, sized_value_write)
                    .with_context(|| "couldn't write load link to output register")?;

                // Keep it in the LLSC list
                llsc.insert(addr, load_value);

                Ok(PCodeStateChange::Fallthrough)
            }
            // This should handle page faults.
            Err(AtomicMmuOpError::TlbTranslateError(TlbTranslateError::Exception(exc))) => {
                Ok(PCodeStateChange::Exception(exc as i32))
            }
            Err(e) => Err(CallOtherHandleError::Other(e.into())),
        }
    }
}

// NOTE: there is no locking right now, as Styx only supports singlecore.
// FIXME: multicore.
//
// Both the slaspec implementations will need to be reworked when we
// get multicore, since we will then need a global lock across cores
#[derive(Debug)]
struct MemLockedHandler {
    llsc_map: Arc<Mutex<BTreeMap<u64, Load>>>,
}

impl<T: CpuBackend + 'static> CallOtherCallback<T> for MemLockedHandler {
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

        // Look up load information for store conditional

        // Predicate result of our operation
        let mut llsc_map = self.llsc_map.lock().expect("couldn't lock LLSC map");
        let store_result = match llsc_map.remove(&rs_val) {
            Some(load) => {
                info!(
                    "pc {:x?} load {load:x?} virt {:x} bytes {:x?}",
                    cpu.pc(),
                    rs_val,
                    &(rt_u64 as u32).to_le_bytes()
                );
                let res = match rt_val.size() {
                    4 => mmu.virt_store_conditional_data(
                        rs_val,
                        load,
                        &(rt_u64 as u32).to_le_bytes(),
                        cpu,
                    ),
                    8 => mmu.virt_store_conditional_data(rs_val, load, &rt_u64.to_le_bytes(), cpu),
                    _ => unreachable!("invalid mem_locked size: rt_val is not 4 bytes or 8 bytes"),
                }
                .with_context(|| "couldn't write Rt to *Rs")?;

                info!("res {res:?}");

                match res {
                    StoreConditionalResult::Success => true,
                    StoreConditionalResult::Failure => false,
                }
            }
            // There was no previous load conditional that occurred on this thread.
            None => false,
        };

        info!("store conditional result {store_result}");
        let pd = output.with_context(|| "couldn't unwrap predicate output of mem_locked store")?;
        cpu.write(pd, (store_result as u8).into())
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

    let llsc_map = Arc::new(Mutex::new(BTreeMap::new()));

    // Load linked
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::MemwLoadlinked,
            MemLoadlinkedHandler {
                llsc_map: llsc_map.clone(),
                size: 4,
            },
        )
        .unwrap();
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::MemdLoadlinked,
            MemLoadlinkedHandler {
                llsc_map: llsc_map.clone(),
                size: 8,
            },
        )
        .unwrap();

    // Store conditional
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::MemwLocked,
            MemLockedHandler {
                llsc_map: llsc_map.clone(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::MemdLocked,
            MemLockedHandler {
                llsc_map: llsc_map.clone(),
            },
        )
        .unwrap();
}
