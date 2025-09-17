// SPDX-License-Identifier: BSD-2-Clause
use arbitrary_int::*;
use bitbybit::{bitenum, bitfield};
use log::trace;

use crate::arch_spec::hexagon::backend::{GeneralHexagonInstruction, Iclass};

//
// These only represent the 12 bits _after_ the parse bits, as we have experimentally
// determined that these are the only bits required to determine whether or not an instruction
// contains a new-value instruction.
//
// All bitfields here are 26 bits, representing the 12 bits before the Parse field
// and the 14 bits after the Parse field and before the ICLASS field. (see 11.7.2 for an
// example of what this looks like). As such, the bit indexes seen here are representative
// of if bits 0-13 and bits 16-27 were spliced together.
//
// Experimentally, by looking at all instruction classes,
// we determined these are the only with dot-new
// instruction classes, and also we found the instruction
// subtypes of these classes that indicate dot-new instructions.
//
// All information in this file comes from sections 11.3, 11.4, 11.5, 11.7, and 11.8.

/// ICLASS 0011
#[bitfield(u26)]
#[derive(Debug)]
struct IclassLoadStoreInstruction {
    // This field is actually 3 bits, but the lowest bit is resreved.
    // See
    #[bits(1..=2, r)]
    nv_reg_offset: u2,
    // NOTE: this isn't actually defined in the spec, but it seems to follow
    // the load/store conditional/gp iclass's subtype, even though it's
    // not labelled
    #[bits(19..=21, r)]
    iclass_subtype: Option<IclassConditionalGPLoadStoreType>,
}

/// ICLASS 1010
#[bitfield(u26)]
#[derive(Debug)]
struct IclassStoreInstruction {
    #[bits(20..=22, r)]
    iclass_subtype: Option<IclassStoreType>,
    #[bits(9..=10, r)]
    nv_reg_offset: u2,
}

#[bitenum(u3, exhaustive = false)]
#[derive(Debug)]
pub enum IclassStoreType {
    Dotnew = 0b110,
}

/// ICLASS 0100
#[bitfield(u26)]
#[derive(Debug)]
struct IclassConditionalGPLoadStoreInstruction {
    // Immediate is split across these bits,
    // some bits before Parse, and two bits
    // later (`imm_hi_5`).
    #[bits(9..=10, r)]
    nv_reg_offset: u2,
    #[bits(19..=21,r)]
    iclass_subtype: Option<IclassConditionalGPLoadStoreType>,
}

#[bitenum(u3, exhaustive = false)]
#[derive(Debug)]
pub enum IclassConditionalGPLoadStoreType {
    Dotnew = 0b101,
}

/// ICLASS 0010 - jump
#[bitfield(u26)]
#[derive(Debug)]
struct IclassNewValueJump {
    #[bits(15..=16, r)]
    nv_reg_offset: u2,
}

/// Check hexagon instruction to see if it references a dot-new register.
///
/// Since dot-new registers are encoded using offsets from the producing location,
/// (eg. the new-value register to be used here is the output register from 2 instructions
/// ago), we return the offset from the dot-new instruction to the producing location.
///
/// See section 10.10 for more information. This information is then
/// used to find the actual general-purpose register number corresponding
/// to this offset. That general-purpose register number is passed as a
/// context option to Sleigh, which uses that register when generating
/// the P-codes for this instruction.
///
/// This dance is required since Sleigh doesn't have lookbehind, making it
/// difficult for the processor module to look at the specified offset
/// and determine the register output at that point.
///
/// Returns None if not a dot-new instruction.
pub fn parse_dotnew(insn: GeneralHexagonInstruction) -> Option<u32> {
    let iclass = insn.nonduplex_iclass();
    match iclass {
        // 0b0011
        Iclass::IclassLoadStore => {
            let reserved_field = IclassLoadStoreInstruction::new_with_raw_value(insn.reserved());
            trace!("dotnew: iclass load store, reserved field is {reserved_field:x?}");

            match reserved_field.iclass_subtype() {
                Ok(IclassConditionalGPLoadStoreType::Dotnew) => {
                    Some(reserved_field.nv_reg_offset().into())
                }
                _ => None,
            }
        }

        // 0b0100
        Iclass::IclassConditionalGPLoadStore => {
            let reserved_field =
                IclassConditionalGPLoadStoreInstruction::new_with_raw_value(insn.reserved());
            trace!(
                "dotnew: iclass conditional/gp load/store, reserved field is {reserved_field:x?}"
            );
            trace!(
                "dotnew: iclass subtype {:x?}",
                reserved_field.iclass_subtype()
            );

            match reserved_field.iclass_subtype() {
                Ok(IclassConditionalGPLoadStoreType::Dotnew) => {
                    Some(reserved_field.nv_reg_offset().into())
                }
                _ => None,
            }
        }

        // 0b1010
        Iclass::IclassStore => {
            let reserved_field = IclassStoreInstruction::new_with_raw_value(insn.reserved());
            trace!("dotnew: iclass store, reserved field is {reserved_field:x?}");

            match reserved_field.iclass_subtype() {
                Ok(IclassStoreType::Dotnew) => Some(reserved_field.nv_reg_offset().into()),
                _ => None,
            }
        }
        // 0b0010 - this Jump class is only used for new-value registers
        Iclass::Jump2 => {
            let reserved_field = IclassNewValueJump::new_with_raw_value(insn.reserved());
            trace!("dotnew: iclass new-value jump, reserved field is {reserved_field:x?}");

            Some(reserved_field.nv_reg_offset().into())
        }
        _ => None,
    }
}
