// SPDX-License-Identifier: BSD-2-Clause
use super::{
    call_other::{self},
    hooks::HookManager,
    memory::space_manager::SpaceManager,
    Bool, Float, Int, PCodeStateChange, PcodeType, SInt,
};
use crate::{
    call_other::{CallOtherCpu, CallOtherManager},
    hooks::HasHookManager,
    memory::{
        sized_value::SizedValue,
        space::SpaceError,
        space_manager::{HasSpaceManager, MmuSpaceOps, VarnodeError},
    },
    pcode_gen::HasPcodeGenerator,
    HasConfig, DEFAULT_REG_ALLOCATION, FALSE,
};
use log::trace;
use smallvec::SmallVec;
use styx_errors::anyhow::anyhow;
use styx_pcode::pcode::{Opcode, Pcode, SpaceId, SpaceName, VarnodeData};
use styx_processor::{
    core::{Exception, HandleExceptionAction},
    cpu::CpuBackend,
    event_controller::EventController,
    hooks::MemFaultData,
    memory::{MemoryOperationError, Mmu, MmuOpError},
};

pub(crate) trait PcodeHelpers {
    fn get_input(&self, input: usize) -> &VarnodeData;
    fn get_output(&self) -> &VarnodeData;
    fn get_input_constant(&self, input: usize) -> &VarnodeData;
}

impl PcodeHelpers for Pcode {
    #[inline]
    fn get_input(&self, input: usize) -> &VarnodeData {
        self.inputs
            .get(input)
            .unwrap_or_else(|| panic!("pcode missing input {input}"))
    }

    #[inline]
    fn get_input_constant(&self, input: usize) -> &VarnodeData {
        let varnode = self.get_input(input);

        debug_assert_eq!(varnode.space, SpaceName::Constant);

        varnode
    }

    #[inline]
    fn get_output(&self) -> &VarnodeData {
        self.output.as_ref().expect("pcode missing output")
    }
}

#[derive(Debug, PartialEq)]
enum PCodeStateChangeInner<'a> {
    CallOther(u64, &'a [VarnodeData], Option<&'a VarnodeData>),
    State(PCodeStateChange),
}

impl<'a> From<PCodeStateChange> for PCodeStateChangeInner<'a> {
    fn from(value: PCodeStateChange) -> Self {
        PCodeStateChangeInner::State(value)
    }
}

pub fn execute_pcode<
    T: CpuBackend
        + HasSpaceManager
        + HasHookManager
        + HasPcodeGenerator<InnerCpuBackend = T>
        + HasConfig
        + MmuSpaceOps
        + CallOtherCpu<T>
        + 'static,
>(
    pcode: &Pcode,
    cpu: &mut T,
    mmu: &mut Mmu,
    ev: &mut EventController,
    call_other_manager: &mut CallOtherManager<T>,
    isa_pc: u64,
    regs_written: &mut SmallVec<[VarnodeData; DEFAULT_REG_ALLOCATION]>,
) -> PCodeStateChange {
    let s = execute_pcode_inner(pcode, cpu, mmu, ev);

    // Allows it to get dropped after this
    {
        let outvar = &pcode.output;
        if let Some(outvar_unwrap) = outvar {
            if outvar_unwrap.space == SpaceName::Register {
                regs_written.push(outvar_unwrap.clone())
            }
        }
    }

    match s {
        PCodeStateChangeInner::CallOther(call_other_op, varnode_datas, varnode_data) => {
            let result_output = CallOtherManager::trigger(
                cpu,
                call_other_manager,
                isa_pc,
                mmu,
                ev,
                call_other_op,
                varnode_datas,
                varnode_data,
            );

            match result_output {
                Ok(pcode_state_change) => pcode_state_change,
                Err(err) => match err {
                    call_other::CallOtherTriggerError::CallOtherHandleError(err) => {
                        panic!("Call other error: {err:?}");
                    }
                    call_other::CallOtherTriggerError::HandleDoesNotExist(_) => {
                        PCodeStateChange::Fallthrough
                    }
                },
            }
        }
        PCodeStateChangeInner::State(pcode_state_change) => pcode_state_change,
    }
}

fn execute_pcode_inner<
    'a,
    B: CpuBackend
        + HasSpaceManager
        + HasHookManager
        + HasPcodeGenerator<InnerCpuBackend = B>
        + HasConfig
        + MmuSpaceOps
        + 'static,
>(
    pcode: &'a Pcode,
    cpu: &mut B,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> PCodeStateChangeInner<'a> {
    match pcode.opcode {
        Opcode::Copy => unary_typed::<Int, Int, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);

            v0
        }),
        Opcode::Load => {
            let space_input = pcode.get_input(0);
            let pointer_offset_input = pcode.get_input(1);
            let output_varnode = pcode.get_output();

            let space_id = cpu
                .get_value_mmu(mmu, space_input)
                .unwrap()
                .to_u64()
                .unwrap();

            let load_space_name = cpu
                .space_manager()
                .get_space_name(&SpaceId::from(space_id))
                .unwrap()
                .clone();

            let ptr_offset = cpu.get_value_mmu(mmu, pointer_offset_input).unwrap();
            trace!("Loading from {load_space_name:?}+0x{ptr_offset:08X}");

            let load_address = ptr_offset.to_u64().unwrap();
            let load_size = output_varnode.size;
            let ptr_varnode = VarnodeData {
                space: load_space_name.clone(),
                offset: load_address,
                size: output_varnode.size,
            };

            let result = SpaceManager::read_hooked(cpu, mmu, ev, &ptr_varnode);
            let fixed_result = match result {
                Ok(ptr_value) => Ok(ptr_value),
                Err(VarnodeError::SpaceError(SpaceError::MemoryError(
                    MmuOpError::PhysicalMemoryError(
                        MemoryOperationError::InvalidRegionPermissions { have, need: _ },
                    ),
                ))) => {
                    let ex = cpu
                        .config()
                        .exception
                        .handle_exception(Exception::ProtectedMemoryRead);
                    match ex {
                        HandleExceptionAction::Pause(target_exit_reason) => {
                            Err(PCodeStateChange::Exit(target_exit_reason))
                        }
                        HandleExceptionAction::TargetHandle(target_exit_reason) => {
                            let is_fixed = HookManager::trigger_protection_fault_hook(
                                cpu,
                                mmu,
                                ev,
                                load_address,
                                load_size,
                                have,
                                MemFaultData::Read,
                            )
                            .unwrap();
                            if is_fixed.fixed() {
                                let result = SpaceManager::read_hooked(cpu, mmu, ev, &ptr_varnode);

                                result.map_err(|_| PCodeStateChange::Exit(target_exit_reason))
                            } else {
                                Err(PCodeStateChange::Exit(target_exit_reason))
                            }
                        }
                    }
                }
                Err(VarnodeError::SpaceError(SpaceError::MemoryError(
                    MmuOpError::PhysicalMemoryError(MemoryOperationError::UnmappedMemory(_)),
                ))) => {
                    let ex = cpu
                        .config()
                        .exception
                        .handle_exception(Exception::UnmappedMemoryRead);
                    match ex {
                        HandleExceptionAction::Pause(target_exit_reason) => {
                            Err(PCodeStateChange::Exit(target_exit_reason))
                        }
                        HandleExceptionAction::TargetHandle(target_exit_reason) => {
                            let is_fixed = HookManager::trigger_unmapped_fault_hook(
                                cpu,
                                mmu,
                                ev,
                                load_address,
                                load_size,
                                MemFaultData::Read,
                            )
                            .unwrap();
                            if is_fixed.fixed() {
                                let result = SpaceManager::read_hooked(cpu, mmu, ev, &ptr_varnode);

                                result.map_err(|_| PCodeStateChange::Exit(target_exit_reason))
                            } else {
                                Err(PCodeStateChange::Exit(target_exit_reason))
                            }
                        }
                    }
                }
                Err(VarnodeError::SpaceError(SpaceError::MemoryError(
                    MmuOpError::TlbException(exception_number),
                ))) => Err(PCodeStateChange::Exception(exception_number)),

                Err(e) => panic!("unexpected varnode error \n{e:?}"),
            };

            match fixed_result {
                Ok(ptr_value) => {
                    trace!("Loaded 0x{ptr_value:X}");

                    cpu.set_value_mmu(mmu, output_varnode, ptr_value).unwrap();
                    PCodeStateChange::Fallthrough.into()
                }
                Err(state_change) => state_change.into(),
            }
        }
        Opcode::Store => {
            let space_id_input = pcode.get_input(0);
            let pointer_offset_varnode = pcode.get_input(1);
            let write_value_varnode = pcode.get_input(2);

            let space_id = cpu
                .space_manager()
                .read(space_id_input)
                .unwrap()
                .to_u64()
                .unwrap();

            let store_space_name = cpu
                .space_manager()
                .get_space_name(&SpaceId::from(space_id))
                .ok_or(anyhow!("bad"))
                .unwrap()
                .clone();
            let ptr_offset = cpu.get_value_mmu(mmu, pointer_offset_varnode).unwrap();

            let value_to_write = cpu.get_value_mmu(mmu, write_value_varnode).unwrap();
            trace!("Storing 0x{value_to_write:X} to {store_space_name:?}+0x{ptr_offset:08X}");

            let store_address = ptr_offset.to_u64().unwrap();
            let store_size = write_value_varnode.size;
            let ptr_varnode = VarnodeData {
                space: store_space_name.clone(),
                offset: store_address,
                size: store_size,
            };

            let result = SpaceManager::write_hooked(cpu, mmu, ev, &ptr_varnode, value_to_write);
            match result {
                Ok(_) => PCodeStateChange::Fallthrough.into(),
                Err(VarnodeError::SpaceError(SpaceError::MemoryError(
                    MmuOpError::PhysicalMemoryError(
                        MemoryOperationError::InvalidRegionPermissions { have, need: _ },
                    ),
                ))) => {
                    let ex = cpu
                        .config()
                        .exception
                        .handle_exception(Exception::ProtectedMemoryWrite);
                    match ex {
                        HandleExceptionAction::Pause(target_exit_reason) => {
                            PCodeStateChange::Exit(target_exit_reason).into()
                        }
                        HandleExceptionAction::TargetHandle(target_exit_reason) => {
                            let mut buf = vec![0u8; write_value_varnode.size as usize];
                            cpu.read_chunk_mmu(
                                mmu,
                                &write_value_varnode.space,
                                write_value_varnode.offset,
                                &mut buf,
                            )
                            .unwrap();
                            let is_fixed = HookManager::trigger_protection_fault_hook(
                                cpu,
                                mmu,
                                ev,
                                store_address,
                                store_size,
                                have,
                                MemFaultData::Write { data: &buf },
                            )
                            .unwrap();
                            if is_fixed.fixed() {
                                let result = SpaceManager::write_hooked(
                                    cpu,
                                    mmu,
                                    ev,
                                    &ptr_varnode,
                                    value_to_write,
                                );

                                result
                                    .map(|_| PCodeStateChange::Fallthrough)
                                    .unwrap_or_else(|_| PCodeStateChange::Exit(target_exit_reason))
                                    .into()
                            } else {
                                PCodeStateChange::Exit(target_exit_reason).into()
                            }
                        }
                    }
                }
                Err(VarnodeError::SpaceError(SpaceError::MemoryError(
                    MmuOpError::PhysicalMemoryError(MemoryOperationError::UnmappedMemory(_)),
                ))) => {
                    let ex = cpu
                        .config()
                        .exception
                        .handle_exception(Exception::UnmappedMemoryWrite);
                    match ex {
                        HandleExceptionAction::Pause(target_exit_reason) => {
                            PCodeStateChange::Exit(target_exit_reason).into()
                        }
                        HandleExceptionAction::TargetHandle(target_exit_reason) => {
                            let mut buf = vec![0u8; write_value_varnode.size as usize];
                            cpu.read_chunk_mmu(
                                mmu,
                                &write_value_varnode.space,
                                write_value_varnode.offset,
                                &mut buf,
                            )
                            .unwrap();
                            let is_fixed = HookManager::trigger_unmapped_fault_hook(
                                cpu,
                                mmu,
                                ev,
                                store_address,
                                store_size,
                                MemFaultData::Write { data: &buf },
                            )
                            .unwrap();
                            if is_fixed.fixed() {
                                let result = SpaceManager::write_hooked(
                                    cpu,
                                    mmu,
                                    ev,
                                    &ptr_varnode,
                                    value_to_write,
                                );

                                result
                                    .map(|_| PCodeStateChange::Fallthrough)
                                    .unwrap_or_else(|_| PCodeStateChange::Exit(target_exit_reason))
                                    .into()
                            } else {
                                PCodeStateChange::Exit(target_exit_reason).into()
                            }
                        }
                    }
                }
                Err(VarnodeError::SpaceError(SpaceError::MemoryError(
                    MmuOpError::TlbException(exception_number),
                ))) => PCodeStateChange::Exception(exception_number).into(),

                Err(e) => panic!("unexpected varnode error \n{e:?}"),
            }
        }
        Opcode::Branch | Opcode::Call => {
            // within raw pcode, branch and call have the same semantics
            let dest = pcode.get_input(0);
            // pcode relative jump
            if dest.space == SpaceName::Constant {
                let offset: SInt = cpu.get_value_mmu(mmu, dest).unwrap().into();
                trace!("Branch: pcode relative jump with offset {offset:?}");
                PCodeStateChange::PCodeRelative(offset.value() as i64).into()
            }
            // absolute instruction jump
            else {
                trace!("Branch: absolute jump to 0x{:x}", dest.offset);
                PCodeStateChange::InstructionAbsolute(dest.offset).into()
            }
        }
        Opcode::CBranch => {
            let condition = pcode.get_input(1);

            if cpu
                .get_value_mmu(mmu, condition)
                .unwrap()
                .to_u128()
                .unwrap()
                == 0
            {
                trace!("Branch not taken.");
                return PCodeStateChange::Fallthrough.into();
            }

            let dest = pcode.get_input(0);
            // pcode relative jump
            if dest.space == SpaceName::Constant {
                let offset: SInt = cpu.get_value_mmu(mmu, dest).unwrap().into();
                trace!("Branch: pcode relative jump with offset {offset:?}");
                PCodeStateChange::PCodeRelative(offset.value() as i64).into()
            }
            // absolute instruction jump
            else {
                trace!("CBranch absolute jump to 0x{:x}", dest.offset);
                PCodeStateChange::InstructionAbsolute(dest.offset).into()
            }
        }
        Opcode::BranchInd | Opcode::CallInd | Opcode::Return => {
            let dest = pcode.get_input(0);

            let dest_addr = cpu.get_value_mmu(mmu, dest).unwrap().to_u128().unwrap();

            trace!("Indirect jump to 0x{dest_addr:x}");
            PCodeStateChange::InstructionAbsolute(dest_addr as u64).into()
        }
        Opcode::CallOther => {
            let call_other_op = cpu
                .space_manager()
                .read(pcode.get_input(0))
                .unwrap()
                .to_u64()
                .unwrap();

            PCodeStateChangeInner::CallOther(
                call_other_op,
                &pcode.inputs[1..],
                pcode.output.as_ref(),
            )

            // let result_output = CallOtherManager::trigger(
            //     cpu,
            //     call_other_op,
            //     &pcode.inputs[1..],
            //     pcode.output.as_ref(),
            // );

            // match result_output {
            //     Ok(pcode_state_change) => pcode_state_change,
            //     Err(err) => match err {
            //         call_other::CallOtherTriggerError::CallOtherHandleError(err) => {
            //             panic!("Call other error: {err:?}");
            //         }
            //         call_other::CallOtherTriggerError::HandleDoesNotExist(_) => {
            //             PCodeStateChange::Fallthrough
            //         }
            //     },
            // }
        }
        Opcode::IntEqual => binary_typed::<Int, Int, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(os, 1);
            Bool(v0.value() == v1.value())
        }),
        Opcode::IntNotEqual => {
            binary_typed::<Int, Int, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);
                Bool(v0.value() != v1.value())
            })
        }
        Opcode::IntSLess => {
            binary_typed::<SInt, SInt, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);
                Bool(v0.value() < v1.value())
            })
        }
        Opcode::IntSLessEqual => {
            binary_typed::<SInt, SInt, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);
                Bool(v0.value() <= v1.value())
            })
        }
        Opcode::IntLess => binary_typed::<Int, Int, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(os, 1);
            Bool(v0.value() < v1.value())
        }),
        Opcode::IntLessEqual => {
            binary_typed::<Int, Int, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);
                Bool(v0.value() <= v1.value())
            })
        }
        Opcode::IntZExt => unary_typed::<Int, Int, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert!(os as u8 > v0.size());
            SizedValue::from_u128(v0.value(), os as u8).into()
        }),
        Opcode::IntSExt => unary_typed::<SInt, SInt, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert!(os as u8 > v0.size());
            let shift_amount = 64 - v0.size() * 8;
            SizedValue::from_u128(
                ((v0.value() << shift_amount) >> shift_amount) as u128,
                os as u8,
            )
            .into()
        }),
        Opcode::IntAdd => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(
                v0.value().wrapping_add(v1.value()) & get_mask(v0.size()),
                v0.size(),
            )
            .into()
        }),
        Opcode::IntSub => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(
                v0.value().wrapping_sub(v1.value()) & get_mask(v0.size()),
                v0.size(),
            )
            .into()
        }),
        Opcode::IntCarry => binary_typed::<Int, Int, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(os, 1);

            let size = v0.size();
            let v0 = v0.value();
            let v1 = v1.value();

            Bool(v0 > (v0.wrapping_add(v1) & get_mask(size)))
        }),
        Opcode::IntSCarry => {
            // if inputs have the same sign, but output has a different sign then carry occurred
            binary_typed::<SInt, SInt, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);

                let size = v0.size();
                let v0 = v0.value();
                let v1 = v1.value();

                let res = v0.wrapping_add(v1);

                let s1 = (v0 >> ((8 * size) - 1)) & 1;
                let s2 = (v1 >> ((8 * size) - 1)) & 1;
                let so = (res >> ((8 * size) - 1)) & 1;

                Bool((s1 ^ s2 ^ 1) & (s1 ^ so) > 0)
            })
        }
        Opcode::IntSBorrow => {
            // if input1 and output have different signs but input2 and output have the same sign then borrow occurred
            binary_typed::<SInt, SInt, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);

                let size = v0.size();
                let v0 = v0.value();
                let v1 = v1.value();

                let res = v0.wrapping_sub(v1);

                let s1 = (v0 >> ((8 * size) - 1)) & 1;
                let s2 = (v1 >> ((8 * size) - 1)) & 1;
                let so = (res >> ((8 * size) - 1)) & 1;

                Bool((s1 ^ so) & (s2 ^ so ^ 1) > 0)
            })
        }
        Opcode::Int2Comp => unary_typed::<Int, Int, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128((!v0.value()).wrapping_add(1), v0.size()).into()
        }),

        Opcode::IntNegate => unary_typed::<Int, Int, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(!v0.value(), v0.size()).into()
        }),
        Opcode::IntXor => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(v0.value() ^ v1.value(), v0.size()).into()
        }),
        Opcode::IntAnd => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(v0.value() & v1.value(), v0.size()).into()
        }),
        Opcode::IntOr => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(v0.value() | v1.value(), v0.size()).into()
        }),
        Opcode::IntLeft => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size() as u32, os);

            SizedValue::from_u128(
                v0.value()
                    .checked_shl(v1.value().try_into().unwrap())
                    .unwrap_or(0),
                v0.size(),
            )
            .into()
        }),
        Opcode::IntRight => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(
                v0.value()
                    .checked_shr(v1.value().try_into().unwrap())
                    .unwrap_or(0),
                v0.size(),
            )
            .into()
        }),
        Opcode::IntSRight => {
            binary_typed::<SInt, Int, SInt, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size() as u32, os);
                let res = v0
                    .value()
                    .checked_shr(v1.value().try_into().unwrap())
                    .unwrap_or_else(|| if v0.value() < 0 { -1 } else { 0 });
                SizedValue::from_u128(res as u128, v0.size()).into()
            })
        }
        Opcode::IntMult => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(
                v0.value().wrapping_mul(v1.value()) & get_mask(v0.size()),
                v0.size(),
            )
            .into()
        }),
        Opcode::IntDiv => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(v0.size() as u32, os);
            if v1.value() == 0 {
                return SizedValue::from_u128(0, v0.size()).into();
            }

            SizedValue::from_u128(v0.value() / v1.value(), v0.size()).into()
        }),
        Opcode::IntSDiv => {
            binary_typed::<SInt, SInt, SInt, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(v0.size() as u32, os);
                if v1.value() == 0 {
                    return SizedValue::from_u128(0, v0.size()).into();
                }

                SizedValue::from_u128((v0.value() / v1.value()) as u128, v0.size()).into()
            })
        }
        Opcode::IntRem => binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), v1.size());
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_u128(v0.value() % v1.value(), v0.size()).into()
        }),
        Opcode::IntSRem => {
            binary_typed::<SInt, SInt, SInt, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(v0.size() as u32, os);
                SizedValue::from_u128((v0.value() % v1.value()) as u128, v0.size()).into()
            })
        }
        Opcode::BoolNegate => unary_typed::<Bool, Bool, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size(), 1);
            debug_assert_eq!(os, 1);
            Bool(!v0.0)
        }),
        Opcode::BoolXor => {
            binary_typed::<Bool, Bool, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), 1);
                debug_assert_eq!(v1.size(), 1);
                debug_assert_eq!(os, 1);
                (v0.0 != v1.0).into()
            })
        }
        Opcode::BoolAnd => {
            binary_typed::<Bool, Bool, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), 1);
                debug_assert_eq!(v1.size(), 1);
                debug_assert_eq!(os, 1);
                (v0.0 && v1.0).into()
            })
        }
        Opcode::BoolOr => binary_typed::<Bool, Bool, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
            debug_assert_eq!(v0.size(), 1);
            debug_assert_eq!(v1.size(), 1);
            debug_assert_eq!(os, 1);
            Bool(v0.0 | v1.0)
        }),
        Opcode::FloatEqual => {
            binary_typed::<Float, Float, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);
                if v0.value().is_nan() || v1.value().is_nan() {
                    return FALSE;
                }

                Bool(v0.value() == v1.value())
            })
        }
        Opcode::FloatNotEqual => {
            binary_typed::<Float, Float, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);
                if v0.value().is_nan() || v1.value().is_nan() {
                    return FALSE;
                }

                Bool(v0.value() != v1.value())
            })
        }
        Opcode::FloatLess => {
            binary_typed::<Float, Float, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);
                if v0.value().is_nan() || v1.value().is_nan() {
                    return FALSE;
                }

                Bool(v0.value() < v1.value())
            })
        }
        Opcode::FloatLessEqual => {
            binary_typed::<Float, Float, Bool, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(os, 1);
                if v0.value().is_nan() || v1.value().is_nan() {
                    return FALSE;
                }

                Bool(v0.value() <= v1.value())
            })
        }
        Opcode::FloatNan => unary_typed::<Float, Bool, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(os, 1);
            Bool(v0.value().is_nan())
        }),
        Opcode::FloatAdd => {
            binary_typed::<Float, Float, Float, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(v0.size() as u32, os);
                SizedValue::from_f64(v0.value() + v1.value(), v0.size()).into()
            })
        }
        Opcode::FloatDiv => {
            binary_typed::<Float, Float, Float, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(v0.size() as u32, os);
                SizedValue::from_f64(v0.value() / v1.value(), v0.size()).into()
            })
        }
        Opcode::FloatMult => {
            binary_typed::<Float, Float, Float, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(v0.size() as u32, os);
                SizedValue::from_f64(v0.value() * v1.value(), v0.size()).into()
            })
        }
        Opcode::FloatSub => {
            binary_typed::<Float, Float, Float, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size(), v1.size());
                debug_assert_eq!(v0.size() as u32, os);
                SizedValue::from_f64(v0.value() - v1.value(), v0.size()).into()
            })
        }
        Opcode::FloatNeg => unary_typed::<Float, Float, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_f64(-v0.value(), v0.size()).into()
        }),
        Opcode::FloatAbs => unary_typed::<Float, Float, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_f64(v0.value().abs(), v0.size()).into()
        }),
        Opcode::FloatSqrt => unary_typed::<Float, Float, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_f64(v0.value().sqrt(), v0.size()).into()
        }),
        Opcode::FloatInt2Float => {
            unary_typed::<SInt, Float, _>(pcode, cpu, mmu, ev, |v0, out_size| {
                SizedValue::from_f64(v0.value() as f64, out_size.try_into().unwrap()).into()
            })
        }
        Opcode::FloatFloat2Float => {
            unary_typed::<Float, Float, _>(pcode, cpu, mmu, ev, |v0, out_size| {
                debug_assert_ne!(v0.size(), out_size as u8);
                SizedValue::from_f64(v0.value(), out_size.try_into().unwrap()).into()
            })
        }
        Opcode::FloatTrunc => unary_typed::<Float, SInt, _>(pcode, cpu, mmu, ev, |v0, os| {
            match os {
                1 => SizedValue::from_u64(v0.value() as i8 as u64, os.try_into().unwrap()),
                2 => SizedValue::from_u64(v0.value() as i16 as u64, os.try_into().unwrap()),
                4 => SizedValue::from_u64(v0.value() as i32 as u64, os.try_into().unwrap()),
                8 => SizedValue::from_u64(v0.value() as i64 as u64, os.try_into().unwrap()),
                _ => unreachable!(),
            }
            .into()
        }),
        Opcode::FloatCeil => unary_typed::<Float, Float, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_f64(v0.value().ceil(), v0.size()).into()
        }),
        Opcode::FloatFloor => unary_typed::<Float, Float, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_f64(v0.value().floor(), v0.size()).into()
        }),
        Opcode::FloatRound => unary_typed::<Float, Float, _>(pcode, cpu, mmu, ev, |v0, os| {
            debug_assert_eq!(v0.size() as u32, os);
            SizedValue::from_f64(v0.value().round(), v0.size()).into()
        }),
        Opcode::PopCount => unary_typed::<Int, Int, _>(pcode, cpu, mmu, ev, |v0, result_size| {
            SizedValue::from_u128(
                v0.value().count_ones() as u128,
                result_size.try_into().unwrap(),
            )
            .into()
        }),
        Opcode::LZCount => unary_typed::<Int, Int, _>(pcode, cpu, mmu, ev, |v0, result_size| {
            SizedValue::from_u128(
                (v0.value().leading_zeros() - (128 - (v0.size() * 8)) as u32) as u128,
                result_size.try_into().unwrap(),
            )
            .into()
        }),
        Opcode::Piece => {
            // concat(v0,v1)
            binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                debug_assert_eq!(v0.size() + v1.size(), os as u8);
                let v1_size = v1.size();

                SizedValue::from_u128((v0.value() << (v1_size as u128 * 8)) | v1.value(), os as u8)
                    .into()
            })
        }
        Opcode::SubPiece => {
            // we need to verify that this implementation is correct: "This is a truncation
            // operator that understands the endianess of the data. Input1 indicates the number
            // of least significant bytes of input0 to be thrown away. Output is then filled
            // with any remaining bytes of input0 up to the size of output. If the size of
            // output is smaller than the size of input0 plus the constant input1, then the
            // additional most significant bytes of input0 will also be truncated.""
            binary_typed::<Int, Int, Int, _>(pcode, cpu, mmu, ev, |v0, v1, os| {
                SizedValue::from_u128(v0.value() >> (v1.value() * 8), os as u8).into()
            })
        }
        Opcode::Insert => {
            let v0 = pcode.get_input(0);
            let v1 = pcode.get_input(1);
            let position = pcode.get_input_constant(2);
            let size = pcode.get_input_constant(3);
            let out = pcode.get_output();

            debug_assert_eq!(v0.size, out.size);

            let bit_pos = cpu.get_value_mmu(mmu, position).unwrap().to_u128().unwrap();
            let num_bits = cpu.get_value_mmu(mmu, size).unwrap().to_u128().unwrap();

            let mask = 2_u128.pow(num_bits as u32) - 1;

            let to_insert =
                (cpu.get_value_mmu(mmu, v1).unwrap().to_u128().unwrap() & mask) << num_bits;
            let mask = !(mask << bit_pos);

            let res = (cpu.get_value_mmu(mmu, v0).unwrap().to_u128().unwrap() & mask) | to_insert;

            cpu.space_manager()
                .write(out, SizedValue::from_u128(res, out.size as u8))
                .unwrap();

            PCodeStateChange::Fallthrough.into()
        }
        Opcode::Extract => {
            let v0 = pcode.get_input(0);
            let position = pcode.get_input_constant(1);
            let size = pcode.get_input_constant(2);
            let out = pcode.get_output();

            let mut res = cpu.get_value_mmu(mmu, v0).unwrap().to_u128().unwrap();

            res >>= cpu.get_value_mmu(mmu, position).unwrap().to_u128().unwrap();
            let mask =
                2_u128.pow(cpu.get_value_mmu(mmu, size).unwrap().to_u128().unwrap() as u32) - 1;

            res &= mask;

            cpu.space_manager()
                .write(out, SizedValue::from_u128(res, out.size as u8))
                .unwrap();

            PCodeStateChange::Fallthrough.into()
        }
        Opcode::Indirect => {
            // I'm pretty sure this implementation is correct for our use case
            unary_typed::<Int, Int, _>(pcode, cpu, mmu, ev, |v0, _| v0)
        }
        // everything below here should probably be fine to leave unimplemented (at least for now, maybe forever)
        // psuedo pcode ops
        Opcode::CPoolRef => unimplemented!(),
        Opcode::New => unimplemented!(),
        // High level pcode ops
        Opcode::MultiEqual => unimplemented!(),
        Opcode::Cast => unimplemented!(),
        Opcode::PtrAdd => unimplemented!(),
        Opcode::PtrSub => unimplemented!(),
        Opcode::SegmentOp => unimplemented!(),

        // misc
        Opcode::Max => unimplemented!(),
    }
}

fn unary_typed_inner<
    V0: PcodeType,
    O: PcodeType,
    C: CpuBackend
        + HasSpaceManager
        + HasHookManager
        + HasPcodeGenerator<InnerCpuBackend = C>
        + HasConfig
        + MmuSpaceOps
        + 'static,
>(
    pcode: &Pcode,
    cpu: &mut C,
    mmu: &mut Mmu,
    ev: &mut EventController,
    f: impl FnOnce(V0, u32) -> O,
) -> PCodeStateChange {
    let v0 = pcode.get_input(0);
    let output = pcode.get_output();
    // let v0_value = space_manager.read_mmu(mmu, v0).unwrap().into();
    let v0_value = SpaceManager::read_hooked_register(cpu, mmu, ev, v0)
        .unwrap()
        .into();
    let output_value = f(v0_value, output.size);

    SpaceManager::write_hooked_register(cpu, mmu, ev, output, output_value.into()).unwrap();
    trace!(
        "Unary op {:?}: {v0_value:?} -> {output_value:?}",
        pcode.opcode
    );
    PCodeStateChange::Fallthrough
}
fn unary_typed<
    'a,
    V0: PcodeType,
    O: PcodeType,
    C: CpuBackend
        + HasSpaceManager
        + HasHookManager
        + HasPcodeGenerator<InnerCpuBackend = C>
        + HasConfig
        + MmuSpaceOps
        + 'static,
>(
    pcode: &'a Pcode,
    cpu: &mut C,
    mmu: &mut Mmu,
    ev: &mut EventController,
    f: impl FnOnce(V0, u32) -> O,
) -> PCodeStateChangeInner<'a> {
    unary_typed_inner(pcode, cpu, mmu, ev, f).into()
}

fn binary_typed_inner<
    V0: PcodeType,
    V1: PcodeType,
    O: PcodeType,
    C: CpuBackend
        + HasSpaceManager
        + HasHookManager
        + HasPcodeGenerator<InnerCpuBackend = C>
        + HasConfig
        + MmuSpaceOps
        + 'static,
>(
    pcode: &Pcode,
    cpu: &mut C,
    mmu: &mut Mmu,
    ev: &mut EventController,
    f: impl FnOnce(V0, V1, u32) -> O,
) -> PCodeStateChange {
    let v0 = pcode.get_input(0);
    let v1 = pcode.get_input(1);
    let output = pcode.get_output();
    // let v0_value = space_manager.read_mmu(mmu, v0).unwrap().into();
    let v0_value = SpaceManager::read_hooked_register(cpu, mmu, ev, v0)
        .unwrap()
        .into();
    // let v1_value = space_manager.read_mmu(mmu, v1).unwrap().into();
    let v1_value = SpaceManager::read_hooked_register(cpu, mmu, ev, v1)
        .unwrap()
        .into();
    let output_value = f(v0_value, v1_value, output.size);

    SpaceManager::write_hooked_register(cpu, mmu, ev, output, output_value.into()).unwrap();
    trace!(
        "Binary op {:?}: {v0_value:?}, {v1_value:?} -> {output_value:?}",
        pcode.opcode
    );
    PCodeStateChange::Fallthrough
}

fn binary_typed<
    'a,
    V0: PcodeType,
    V1: PcodeType,
    O: PcodeType,
    C: CpuBackend
        + HasSpaceManager
        + HasHookManager
        + HasPcodeGenerator<InnerCpuBackend = C>
        + HasConfig
        + MmuSpaceOps
        + 'static,
>(
    pcode: &'a Pcode,
    cpu: &mut C,
    mmu: &mut Mmu,
    ev: &mut EventController,
    f: impl FnOnce(V0, V1, u32) -> O,
) -> PCodeStateChangeInner<'a> {
    binary_typed_inner(pcode, cpu, mmu, ev, f).into()
}

#[inline]
fn get_mask(size: u8) -> u128 {
    if size == 0 {
        0
    } else if size >= 16 {
        u128::MAX
    } else {
        (1u128 << (size * 8)) - 1
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        execute_pcode::{execute_pcode_inner, PcodeHelpers},
        memory::sized_value::SizedValue,
        Bool, PCodeStateChange, PcodeBackend,
    };
    use styx_cpu_type::arch::arm::ArmVariants;
    use styx_pcode::pcode::{Opcode, Pcode, SpaceName, VarnodeData};
    use styx_processor::{
        event_controller::{DummyEventController, EventController},
        memory::Mmu,
    };

    use super::*;

    use test_case::test_case;

    #[test_case(0, 0x00000000000000000000000000000000; "zero bytes")]
    #[test_case(1, 0x000000000000000000000000000000FF; "one byte")]
    #[test_case(2, 0x00000000000000000000000000000FFFF; "two bytes")]
    #[test_case(3, 0x0000000000000000000000000000FFFFFF; "three bytes")]
    #[test_case(4, 0x000000000000000000000000000FFFFFFFF; "four bytes")]
    #[test_case(8, 0x00000000000000000FFFFFFFFFFFFFFFF; "eight bytes")]
    #[test_case(15, 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF; "fifteen bytes")]
    #[test_case(16, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF; "sixteen bytes")]
    #[test_case(17, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF; "seventeen bytes - overflow")]
    #[test_case(255, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF; "max u8 value")]
    fn test_get_mask(size: u8, expected: u128) {
        assert_eq!(get_mask(size), expected);
    }

    #[test_case(
        Opcode::Copy,
        SizedValue::from_u128(0xAB, 1),
        SizedValue::from_u128(0xAB, 1)
    )]
    #[test_case(
        Opcode::PopCount,
        SizedValue::from_u128(0, 4),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::PopCount,
        SizedValue::from_u128(0xFFFFFFFF, 4),
        SizedValue::from_u128(32, 1)
    )]
    #[test_case(
        Opcode::LZCount,
        SizedValue::from_u128(0, 4),
        SizedValue::from_u128(32, 1)
    )]
    #[test_case(
        Opcode::LZCount,
        SizedValue::from_u128(0xFFFFFFFF, 4),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::LZCount,
        SizedValue::from_u128(0x0000F000, 4),
        SizedValue::from_u128(16, 1)
    )]
    #[test_case(
        Opcode::IntZExt,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(0x00FF, 2)
    )]
    #[test_case(
        Opcode::IntSExt,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(0xFFFF, 2)
    )]
    #[test_case(
        Opcode::IntSExt,
        SizedValue::from_u128(0x0F, 1),
        SizedValue::from_u128(0x000F, 2)
    )]
    #[test_case(Opcode::Int2Comp, SizedValue::from_u128(-10_i64 as u128, 1), SizedValue::from_u128(10, 1))]
    #[test_case(Opcode::Int2Comp, SizedValue::from_u128(10, 1), SizedValue::from_u128(-10_i64 as u128, 1))]
    #[test_case(Opcode::Int2Comp, SizedValue::from_u128(0, 1), SizedValue::from_u128(0_i64 as u128, 1))]
    #[test_case(
        Opcode::IntNegate,
        SizedValue::from_u128(0x55, 1),
        SizedValue::from_u128(0xAA, 1)
    )]
    #[test_case(Opcode::BoolNegate, Bool(false).into(), Bool(true).into())]
    #[test_case(Opcode::BoolNegate, Bool(true).into(), Bool(false).into())]
    #[test_case(Opcode::FloatNeg, SizedValue::from_f64(10.5, 4), SizedValue::from_f64(-10.5, 4))]
    #[test_case(Opcode::FloatNeg, SizedValue::from_f64(f64::NAN, 8), SizedValue::from_f64(-f64::NAN, 8))]
    #[test_case(Opcode::FloatAbs, SizedValue::from_f64(-10.5, 4), SizedValue::from_f64(10.5, 4))]
    #[test_case(
        Opcode::FloatAbs,
        SizedValue::from_f64(11.5, 4),
        SizedValue::from_f64(11.5, 4)
    )]
    #[test_case(Opcode::FloatAbs, SizedValue::from_f64(-f64::NAN, 8), SizedValue::from_f64(f64::NAN, 8))]
    #[test_case(
        Opcode::FloatSqrt,
        SizedValue::from_f64(9.0, 4),
        SizedValue::from_f64(3.0, 4)
    )]
    #[test_case(
        Opcode::FloatSqrt,
        SizedValue::from_f64(f64::NAN, 8),
        SizedValue::from_f64(f64::NAN, 8)
    )]
    #[test_case(
        Opcode::FloatCeil,
        SizedValue::from_f64(1.2, 4),
        SizedValue::from_f64(2.0, 4)
    )]
    #[test_case(Opcode::FloatCeil, SizedValue::from_f64(-1.2, 4), SizedValue::from_f64(-1.0, 4))]
    #[test_case(
        Opcode::FloatCeil,
        SizedValue::from_f64(f64::NAN, 8),
        SizedValue::from_f64(f64::NAN, 8)
    )]
    #[test_case(
        Opcode::FloatFloor,
        SizedValue::from_f64(1.2, 4),
        SizedValue::from_f64(1.0, 4)
    )]
    #[test_case(Opcode::FloatFloor, SizedValue::from_f64(-1.2, 4), SizedValue::from_f64(-2.0, 4))]
    #[test_case(
        Opcode::FloatFloor,
        SizedValue::from_f64(f64::NAN, 8),
        SizedValue::from_f64(f64::NAN, 8)
    )]
    #[test_case(
        Opcode::FloatRound,
        SizedValue::from_f64(1.2, 4),
        SizedValue::from_f64(1.0, 4)
    )]
    #[test_case(
        Opcode::FloatRound,
        SizedValue::from_f64(1.9, 4),
        SizedValue::from_f64(2.0, 4)
    )]
    #[test_case(
        Opcode::FloatRound,
        SizedValue::from_f64(f64::NAN, 8),
        SizedValue::from_f64(f64::NAN, 8)
    )]
    #[test_case(Opcode::FloatNan, SizedValue::from_f64(1.2, 4), Bool(false).into())]
    #[test_case(Opcode::FloatNan, SizedValue::from_f64(f64::NAN, 8), Bool(true).into())]
    #[test_case(Opcode::FloatInt2Float, SizedValue::from_u128(-25_i64 as u128, 4), SizedValue::from_f64(-25.0, 8))]
    #[test_case(
        Opcode::FloatFloat2Float,
        SizedValue::from_f64(9.0, 4),
        SizedValue::from_f64(9.0, 8)
    )]
    #[test_case(
        Opcode::FloatFloat2Float,
        SizedValue::from_f64(f64::NAN, 8),
        SizedValue::from_f64(f64::NAN, 4)
    )]
    #[test_case(Opcode::FloatTrunc, SizedValue::from_f64(-25.5, 4), SizedValue::from_u128(-25_i64 as u128, 1))]
    #[test_case(
        Opcode::FloatTrunc,
        SizedValue::from_f64(25.5, 4),
        SizedValue::from_u128(25, 2)
    )]
    #[test_case(
        Opcode::Indirect,
        SizedValue::from_u128(0xCAFEBABE, 4),
        SizedValue::from_u128(0xCAFEBABE, 4)
    )]
    fn test_unary_operators(opcode: Opcode, input: SizedValue, expected_output: SizedValue) {
        let mut mmu = Mmu::default();
        let mut evt = EventController::new(Box::new(DummyEventController::default()));

        let mut cpu = PcodeBackend::new_engine(
            styx_cpu_type::Arch::Arm,
            ArmVariants::ArmCortexM4,
            styx_cpu_type::ArchEndian::LittleEndian,
        );

        let output_varnode = VarnodeData {
            space: SpaceName::Unique,
            offset: input.size() as u64,
            size: expected_output.size() as u32,
        };

        let pcode = Pcode {
            opcode,
            inputs: vec![VarnodeData {
                space: SpaceName::Unique,
                offset: 0,
                size: input.size() as u32,
            }]
            .into(),
            output: Some(output_varnode),
        };

        cpu.space_manager.write(pcode.get_input(0), input).unwrap();

        execute_pcode_inner::<PcodeBackend>(&pcode, &mut cpu, &mut mmu, &mut evt);

        let result = cpu.get_value_mmu(&mut mmu, pcode.get_output()).unwrap();
        assert_eq!(result, expected_output);
    }

    #[test_case(Opcode::IntEqual, SizedValue::from_u128(1, 4), SizedValue::from_u128(0, 4), Bool(false).into())]
    #[test_case(Opcode::IntEqual, SizedValue::from_u128(1, 4), SizedValue::from_u128(1, 4), Bool(true).into())]
    #[test_case(Opcode::IntNotEqual, SizedValue::from_u128(1, 4), SizedValue::from_u128(0, 4), Bool(true).into())]
    #[test_case(Opcode::IntNotEqual, SizedValue::from_u128(1, 4), SizedValue::from_u128(1, 4), Bool(false).into())]
    #[test_case(Opcode::IntLess, SizedValue::from_u128(1, 4), SizedValue::from_u128(1, 4), Bool(false).into())]
    #[test_case(Opcode::IntLess, SizedValue::from_u128(0, 4), SizedValue::from_u128(1, 4), Bool(true).into())]
    #[test_case(Opcode::IntSLess, SizedValue::from_u128(-15_i64 as u128, 4), SizedValue::from_u128(-16_i64 as u128, 4), Bool(false).into())]
    #[test_case(Opcode::IntSLess, SizedValue::from_u128(-100_i64 as u128, 4), SizedValue::from_u128(10, 4), Bool(true).into())]
    #[test_case(Opcode::IntLessEqual, SizedValue::from_u128(1, 4), SizedValue::from_u128(0, 4), Bool(false).into())]
    #[test_case(Opcode::IntLessEqual, SizedValue::from_u128(1, 4), SizedValue::from_u128(1, 4), Bool(true).into())]
    #[test_case(Opcode::IntLessEqual, SizedValue::from_u128(1, 4), SizedValue::from_u128(2, 4), Bool(true).into())]
    #[test_case(Opcode::IntSLessEqual, SizedValue::from_u128(-15_i64 as u128, 4), SizedValue::from_u128(-16_i64 as u128, 4), Bool(false).into())]
    #[test_case(Opcode::IntSLessEqual, SizedValue::from_u128(-100_i64 as u128, 4), SizedValue::from_u128(-100_i64 as u128, 4), Bool(true).into())]
    #[test_case(Opcode::IntSLessEqual, SizedValue::from_u128(-100_i64 as u128, 4), SizedValue::from_u128(10, 4), Bool(true).into())]
    #[test_case(
        Opcode::IntAdd,
        SizedValue::from_u128(10, 4),
        SizedValue::from_u128(15, 4),
        SizedValue::from_u128(25, 4)
    )]
    #[test_case(
        Opcode::IntAdd,
        SizedValue::from_u128(255, 1),
        SizedValue::from_u128(1, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::IntSub,
        SizedValue::from_u128(10, 4),
        SizedValue::from_u128(1, 4),
        SizedValue::from_u128(9, 4)
    )]
    #[test_case(Opcode::IntSub, SizedValue::from_u128(-10_i64 as u128, 2), SizedValue::from_u128(1, 2), SizedValue::from_u128(-11_i64 as u128, 2))]
    #[test_case(Opcode::IntCarry, SizedValue::from_u128(254, 1), SizedValue::from_u128(1, 1), Bool(false).into())]
    #[test_case(Opcode::IntCarry, SizedValue::from_u128(255, 1), SizedValue::from_u128(1, 1), Bool(true).into())]
    #[test_case(Opcode::IntSCarry, SizedValue::from_u128(126_i64 as u128, 1), SizedValue::from_u128(1, 1), Bool(false).into())]
    #[test_case(Opcode::IntSCarry, SizedValue::from_u128(127_i64 as u128, 1), SizedValue::from_u128(1, 1), Bool(true).into())]
    #[test_case(Opcode::IntSCarry, SizedValue::from_u128(-128_i64 as u128, 1), SizedValue::from_u128(-1_i64 as u128, 1), Bool(true).into())]
    #[test_case(Opcode::IntSBorrow, SizedValue::from_u128(-127_i64 as u128, 1), SizedValue::from_u128(1, 1), Bool(false).into())]
    #[test_case(Opcode::IntSBorrow, SizedValue::from_u128(127_i64 as u128, 1), SizedValue::from_u128(-1_i64 as u128, 1), Bool(true).into())]
    #[test_case(Opcode::IntSBorrow, SizedValue::from_u128(-128_i64 as u128, 1), SizedValue::from_u128(1_i64 as u128, 1), Bool(true).into())]
    #[test_case(
        Opcode::IntXor,
        SizedValue::from_u128(0x55, 1),
        SizedValue::from_u128(0xAA, 1),
        SizedValue::from_u128(0xFF, 1)
    )]
    #[test_case(
        Opcode::IntAnd,
        SizedValue::from_u128(0x55, 1),
        SizedValue::from_u128(0xAA, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::IntOr,
        SizedValue::from_u128(0x55, 1),
        SizedValue::from_u128(0xAB, 1),
        SizedValue::from_u128(255, 1)
    )]
    #[test_case(
        Opcode::IntLeft,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(8, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::IntLeft,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(7, 1),
        SizedValue::from_u128(0x80, 1)
    )]
    #[test_case(
        Opcode::IntLeft,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(9, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::IntRight,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(8, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::IntRight,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(7, 1),
        SizedValue::from_u128(1, 1)
    )]
    #[test_case(
        Opcode::IntRight,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(10, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(Opcode::IntSRight, SizedValue::from_u128(-100_i64 as u128, 1), SizedValue::from_u128(1, 1), SizedValue::from_u128(-50_i64 as u128, 1))]
    #[test_case(
        Opcode::IntSRight,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(8, 1),
        SizedValue::from_u128(0xFF, 1)
    )]
    #[test_case(
        Opcode::IntSRight,
        SizedValue::from_u128(20, 1),
        SizedValue::from_u128(10, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(Opcode::IntSRight, SizedValue::from_u128(-20_i64 as u128, 1), SizedValue::from_u128(10, 1), SizedValue::from_u128(-1_i64 as u128, 1))]
    #[test_case(
        Opcode::IntMult,
        SizedValue::from_u128(10, 1),
        SizedValue::from_u128(12, 1),
        SizedValue::from_u128(120, 1)
    )]
    #[test_case(Opcode::IntMult, SizedValue::from_u128(-5_i64 as u128, 1), SizedValue::from_u128(8, 1), SizedValue::from_u128(-40_i64 as u128, 1))]
    #[test_case(Opcode::IntMult, SizedValue::from_u128(200, 1), SizedValue::from_u128(2, 1), SizedValue::from_u128(400 % 256, 1))]
    #[test_case(
        Opcode::IntDiv,
        SizedValue::from_u128(10, 1),
        SizedValue::from_u128(2, 1),
        SizedValue::from_u128(5, 1)
    )]
    #[test_case(
        Opcode::IntDiv,
        SizedValue::from_u128(10, 1),
        SizedValue::from_u128(4, 1),
        SizedValue::from_u128(2, 1)
    )]
    #[test_case(
        Opcode::IntDiv,
        SizedValue::from_u128(1, 1),
        SizedValue::from_u128(0, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::IntRem,
        SizedValue::from_u128(10, 1),
        SizedValue::from_u128(10, 1),
        SizedValue::from_u128(0, 1)
    )]
    #[test_case(
        Opcode::IntRem,
        SizedValue::from_u128(10, 1),
        SizedValue::from_u128(3, 1),
        SizedValue::from_u128(1, 1)
    )]
    #[test_case(Opcode::IntSDiv, SizedValue::from_u128(-10_i64 as u128, 1), SizedValue::from_u128(2, 1), SizedValue::from_u128(-5_i64 as u128, 1))]
    #[test_case(Opcode::IntSDiv, SizedValue::from_u128(-10_i64 as u128, 1), SizedValue::from_u128(4, 1), SizedValue::from_u128(-2_i64 as u128, 1))]
    #[test_case(Opcode::IntSDiv, SizedValue::from_u128(-1_i64 as u128, 1), SizedValue::from_u128(0, 1), SizedValue::from_u128(0, 1))]
    #[test_case(Opcode::IntSRem, SizedValue::from_u128(-10_i64 as u128, 1), SizedValue::from_u128(10, 1), SizedValue::from_u128(0, 1))]
    #[test_case(Opcode::IntSRem, SizedValue::from_u128(-10_i64 as u128, 1), SizedValue::from_u128(3, 1), SizedValue::from_u128(-1_i64 as u128, 1))]
    #[test_case(Opcode::BoolXor, Bool(false).into(), Bool(false).into(), Bool(false).into())]
    #[test_case(Opcode::BoolXor, Bool(false).into(), Bool(true).into(), Bool(true).into())]
    #[test_case(Opcode::BoolXor, Bool(true).into(), Bool(false).into(), Bool(true).into())]
    #[test_case(Opcode::BoolXor, Bool(true).into(), Bool(true).into(), Bool(false).into())]
    #[test_case(Opcode::BoolAnd, Bool(false).into(), Bool(false).into(), Bool(false).into())]
    #[test_case(Opcode::BoolAnd, Bool(false).into(), Bool(true).into(), Bool(false).into())]
    #[test_case(Opcode::BoolAnd, Bool(true).into(), Bool(false).into(), Bool(false).into())]
    #[test_case(Opcode::BoolAnd, Bool(true).into(), Bool(true).into(), Bool(true).into())]
    #[test_case(Opcode::BoolOr, Bool(false).into(), Bool(false).into(), Bool(false).into())]
    #[test_case(Opcode::BoolOr, Bool(false).into(), Bool(true).into(), Bool(true).into())]
    #[test_case(Opcode::BoolOr, Bool(true).into(), Bool(false).into(), Bool(true).into())]
    #[test_case(Opcode::BoolOr, Bool(true).into(), Bool(true).into(), Bool(true).into())]
    #[test_case(Opcode::FloatEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(0.5, 4), Bool(false).into())]
    #[test_case(Opcode::FloatEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(1.5, 4), Bool(true).into())]
    #[test_case(Opcode::FloatEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(f64::NAN, 4), Bool(false).into())]
    #[test_case(Opcode::FloatNotEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(0.5, 4), Bool(true).into())]
    #[test_case(Opcode::FloatNotEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(1.5, 4), Bool(false).into())]
    #[test_case(Opcode::FloatNotEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(f64::NAN, 4), Bool(false).into())]
    #[test_case(Opcode::FloatLess, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(0.5, 4), Bool(false).into())]
    #[test_case(Opcode::FloatLess, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(1.6, 4), Bool(true).into())]
    #[test_case(Opcode::FloatLess, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(f64::NAN, 4), Bool(false).into())]
    #[test_case(Opcode::FloatLessEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(0.5, 4), Bool(false).into())]
    #[test_case(Opcode::FloatLessEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(1.5, 4), Bool(true).into())]
    #[test_case(Opcode::FloatLessEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(1.6, 4), Bool(true).into())]
    #[test_case(Opcode::FloatLessEqual, SizedValue::from_f64(1.5, 4), SizedValue::from_f64(f64::NAN, 4), Bool(false).into())]
    #[test_case(
        Opcode::FloatAdd,
        SizedValue::from_f64(10.0, 4),
        SizedValue::from_f64(15.0, 4),
        SizedValue::from_f64(25.0, 4)
    )]
    #[test_case(
        Opcode::FloatAdd,
        SizedValue::from_f64(10.0, 4),
        SizedValue::from_f64(f64::NAN, 4),
        SizedValue::from_f64(f64::NAN, 4)
    )]
    #[test_case(Opcode::FloatSub, SizedValue::from_f64(10.0, 4), SizedValue::from_f64(15.0, 4), SizedValue::from_f64(-5.0, 4))]
    #[test_case(
        Opcode::FloatSub,
        SizedValue::from_f64(10.0, 4),
        SizedValue::from_f64(f64::NAN, 4),
        SizedValue::from_f64(f64::NAN, 4)
    )]
    #[test_case(
        Opcode::FloatMult,
        SizedValue::from_f64(10.0, 4),
        SizedValue::from_f64(15.0, 4),
        SizedValue::from_f64(150.0, 4)
    )]
    #[test_case(
        Opcode::FloatMult,
        SizedValue::from_f64(10.0, 4),
        SizedValue::from_f64(f64::NAN, 4),
        SizedValue::from_f64(f64::NAN, 4)
    )]
    #[test_case(
        Opcode::FloatDiv,
        SizedValue::from_f64(15.0, 4),
        SizedValue::from_f64(5.0, 4),
        SizedValue::from_f64(3.0, 4)
    )]
    #[test_case(
        Opcode::FloatDiv,
        SizedValue::from_f64(10.0, 4),
        SizedValue::from_f64(f64::NAN, 4),
        SizedValue::from_f64(f64::NAN, 4)
    )]
    #[test_case(
        Opcode::Piece,
        SizedValue::from_u128(0xFF, 1),
        SizedValue::from_u128(0xAA, 1),
        SizedValue::from_u128(0xFFAA, 2)
    )]
    #[test_case(
        Opcode::SubPiece,
        SizedValue::from_u128(0xFFAA, 2),
        SizedValue::from_u128(1, 1),
        SizedValue::from_u128(0xFF, 1)
    )]
    #[test_case(
        Opcode::SubPiece,
        SizedValue::from_u128(0xAABBCC, 3),
        SizedValue::from_u128(1, 1),
        SizedValue::from_u128(0xBB, 1)
    )]
    fn test_binary_operators(
        opcode: Opcode,
        input1: SizedValue,
        input2: SizedValue,
        expected_output: SizedValue,
    ) {
        let mut mmu = Mmu::default();
        let mut evt = EventController::new(Box::new(DummyEventController::default()));

        let mut cpu = PcodeBackend::new_engine(
            styx_cpu_type::Arch::Arm,
            ArmVariants::ArmCortexM4,
            styx_cpu_type::ArchEndian::LittleEndian,
        );

        let output_varnode = VarnodeData {
            space: SpaceName::Unique,
            offset: (input1.size() + input2.size()) as u64,
            size: expected_output.size() as u32,
        };

        let pcode = Pcode {
            opcode,
            inputs: vec![
                VarnodeData {
                    space: SpaceName::Unique,
                    offset: 0,
                    size: input1.size() as u32,
                },
                VarnodeData {
                    space: SpaceName::Unique,
                    offset: input1.size() as u64,
                    size: input2.size() as u32,
                },
            ]
            .into(),
            output: Some(output_varnode),
        };

        cpu.space_manager.write(pcode.get_input(0), input1).unwrap();
        cpu.space_manager.write(pcode.get_input(1), input2).unwrap();

        execute_pcode_inner::<PcodeBackend>(&pcode, &mut cpu, &mut mmu, &mut evt);

        let result = cpu.get_value_mmu(&mut mmu, pcode.get_output()).unwrap();
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_extract() {
        let mut mmu = Mmu::default();
        let mut evt = EventController::new(Box::new(DummyEventController::default()));

        let mut cpu = PcodeBackend::new_engine(
            styx_cpu_type::Arch::Arm,
            ArmVariants::ArmCortexM4,
            styx_cpu_type::ArchEndian::LittleEndian,
        );

        let v0 = VarnodeData {
            space: SpaceName::Unique,
            offset: 0,
            size: 4,
        };
        cpu.space_manager
            .write(&v0, SizedValue::from_u128(0xFFFFBABEFFFF, 4))
            .unwrap();

        let pos = VarnodeData {
            space: SpaceName::Constant,
            offset: 16,
            size: 4,
        };
        let size = VarnodeData {
            space: SpaceName::Constant,
            offset: 16,
            size: 4,
        };
        let out = VarnodeData {
            space: SpaceName::Unique,
            offset: 4,
            size: 4,
        };

        // should extract BABE from 0xFFFF_BABE_FFFF
        let inst = Pcode {
            opcode: Opcode::Extract,
            inputs: vec![v0, pos, size].into(),
            output: Some(out),
        };

        execute_pcode_inner::<PcodeBackend>(&inst, &mut cpu, &mut mmu, &mut evt);

        let result = cpu.get_value_mmu(&mut mmu, inst.get_output()).unwrap();
        assert_eq!(result.to_u128().unwrap(), 0xBABE);
    }

    #[test]
    fn test_insert() {
        let mut mmu = Mmu::default();
        let mut evt = EventController::new(Box::new(DummyEventController::default()));

        let mut cpu = PcodeBackend::new_engine(
            styx_cpu_type::Arch::Arm,
            ArmVariants::ArmCortexM4,
            styx_cpu_type::ArchEndian::LittleEndian,
        );

        let v0 = VarnodeData {
            space: SpaceName::Unique,
            offset: 0,
            size: 8,
        };
        cpu.space_manager
            .write(&v0, SizedValue::from_u128(0xFFFFFFFFFFFF, 8))
            .unwrap();

        let v1 = VarnodeData {
            space: SpaceName::Unique,
            offset: 8,
            size: 8,
        };
        cpu.space_manager
            .write(&v1, SizedValue::from_u128(0xBABE, 8))
            .unwrap();

        let pos = VarnodeData {
            space: SpaceName::Constant,
            offset: 16,
            size: 4,
        };
        let size = VarnodeData {
            space: SpaceName::Constant,
            offset: 16,
            size: 4,
        };
        let out = VarnodeData {
            space: SpaceName::Unique,
            offset: 16,
            size: 8,
        };

        // should insert BABE into 0xFFFF_FFFF_FFFF resulting in 0xFFFFBABEFFFF
        let inst = Pcode {
            opcode: Opcode::Insert,
            inputs: vec![v0, v1, pos, size].into(),
            output: Some(out),
        };

        execute_pcode_inner::<PcodeBackend>(&inst, &mut cpu, &mut mmu, &mut evt);

        let result = cpu.get_value_mmu(&mut mmu, inst.get_output()).unwrap();
        assert_eq!(result.to_u128().unwrap(), 0xFFFFBABEFFFF);
    }

    #[test]
    fn test_control_flow_operators() {
        let mut mmu = Mmu::default();
        let mut evt = EventController::new(Box::new(DummyEventController::default()));

        let mut cpu = PcodeBackend::new_engine(
            styx_cpu_type::Arch::Arm,
            ArmVariants::ArmCortexM4,
            styx_cpu_type::ArchEndian::LittleEndian,
        );

        // BRANCH/CALL
        let target = VarnodeData {
            space: SpaceName::Constant,
            offset: -2_i64 as u64,
            size: 4,
        };
        let inst = Pcode {
            opcode: Opcode::Branch,
            inputs: vec![target].into(),
            output: None,
        };
        let state = execute_pcode_inner::<PcodeBackend>(&inst, &mut cpu, &mut mmu, &mut evt);
        assert_eq!(state, PCodeStateChange::PCodeRelative(-2).into());

        let target = VarnodeData {
            space: SpaceName::Ram,
            offset: 0xCAFEBABE,
            size: 4,
        };
        let inst = Pcode {
            opcode: Opcode::Branch,
            inputs: vec![target].into(),
            output: None,
        };
        let state = execute_pcode_inner::<PcodeBackend>(&inst, &mut cpu, &mut mmu, &mut evt);
        assert_eq!(
            state,
            PCodeStateChange::InstructionAbsolute(0xCAFEBABE).into()
        );

        // CBRANCH
        let t: SizedValue = Bool(true).into();
        let f: SizedValue = Bool(false).into();
        let condition = VarnodeData {
            space: SpaceName::Unique,
            offset: 0,
            size: 1,
        };
        cpu.space_manager.write(&condition, t).unwrap();
        let target = VarnodeData {
            space: SpaceName::Constant,
            offset: -2_i64 as u64,
            size: 4,
        };
        let inst = Pcode {
            opcode: Opcode::CBranch,
            inputs: vec![target, condition].into(),
            output: None,
        };
        let state = execute_pcode_inner::<PcodeBackend>(&inst, &mut cpu, &mut mmu, &mut evt);

        assert_eq!(state, PCodeStateChange::PCodeRelative(-2).into());

        let target = VarnodeData {
            space: SpaceName::Ram,
            offset: 0xCAFEBABE,
            size: 4,
        };
        let condition = VarnodeData {
            space: SpaceName::Unique,
            offset: 0,
            size: 1,
        };
        let inst = Pcode {
            opcode: Opcode::CBranch,
            inputs: vec![target, condition].into(),
            output: None,
        };
        let state = execute_pcode_inner::<PcodeBackend>(&inst, &mut cpu, &mut mmu, &mut evt);

        assert_eq!(
            state,
            PCodeStateChange::InstructionAbsolute(0xCAFEBABE).into()
        );

        let condition = VarnodeData {
            space: SpaceName::Unique,
            offset: 0,
            size: 1,
        };
        cpu.space_manager.write(&condition, f).unwrap();
        let state = execute_pcode_inner::<PcodeBackend>(&inst, &mut cpu, &mut mmu, &mut evt);
        assert_eq!(state, PCodeStateChange::Fallthrough.into());

        // BRANCH_IND/CALL_IND/RETURN
        let target = VarnodeData {
            space: SpaceName::Unique,
            offset: 0,
            size: 4,
        };
        let addr = SizedValue::from_u128(0xBEEFBEEF, 4);
        cpu.space_manager.write(&target, addr).unwrap();

        let inst = Pcode {
            opcode: Opcode::BranchInd,
            inputs: vec![target].into(),
            output: None,
        };
        let state = execute_pcode_inner::<PcodeBackend>(&inst, &mut cpu, &mut mmu, &mut evt);

        assert_eq!(
            state,
            PCodeStateChange::InstructionAbsolute(0xBEEFBEEF).into()
        );
    }
}
