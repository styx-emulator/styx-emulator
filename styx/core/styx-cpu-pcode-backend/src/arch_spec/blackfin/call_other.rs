// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_type::arch::blackfin::BlackfinRegister;
use styx_pcode::pcode::VarnodeData;

use log::debug;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    memory::{helpers::ReadExt, Mmu},
};

use crate::{
    call_other::{CallOtherCallback, CallOtherHandleError},
    memory::{sized_value::SizedValue, space_manager::SpaceManager},
    PCodeStateChange, PcodeBackend,
};

/// `RAISE` instruction. Latches asynchronous interrupt.
#[derive(Debug)]
pub struct RaiseHandler;
impl CallOtherCallback for RaiseHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let space_manager = &backend.space_manager;
        let interrupt_argument = space_manager
            .read(inputs.first().unwrap())
            .unwrap()
            .to_u64()
            .unwrap();

        debug!("Raise called with interrupt {interrupt_argument}");

        Ok(PCodeStateChange::DelayedInterrupt(
            interrupt_argument as i32,
        ))
    }
}

/// `EXCPT` instruction. Latches synchronous exception.
#[derive(Debug)]
pub struct ExcptHandler;
impl CallOtherCallback for ExcptHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        _output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let parameter_varnode = inputs.first().expect("expected parameter for excpt call");
        let interrupt_number = backend
            .space_manager
            .read(parameter_varnode)
            .unwrap()
            .to_u64()
            .unwrap() as i32;

        Ok(PCodeStateChange::DelayedInterrupt(interrupt_number))
    }
}

#[derive(Debug)]
pub struct CSyncHandler;
impl CallOtherCallback for CSyncHandler {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // this is a nop in our case because we don't do any speculative execution and
        // so synchronization isn't necessary.
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct SSyncHandler;
impl CallOtherCallback for SSyncHandler {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // this is a nop in our case because we don't do any speculative execution and
        // so synchronization isn't necessary.
        Ok(PCodeStateChange::Fallthrough)
    }
}

/// DEPOSIT has 2 args, background and foreground
/// the foreground has 3 fields in it
///     nnnn nnnn nnnn nnnn xxxp pppp xxxL LLLL
///     where:
///         n = foreground bit field (16 bits)
///         p = intended position of foreground bit field LSB in dest_reg (valid range 0 through 31)
///         L = length of foreground bit field (valid range 0 through 31, values >=16 clamped at 16)
///
/// The operation writes the foreground bit field of length L over the background bit
/// field with the foreground LSB located at bit p of the background.
fn do_deposit(sign_extend: bool, background: u32, foreground: u32) -> u32 {
    let size = (foreground & 0x1F).clamp(0, 16);
    let pos = (foreground & 0x1F00) >> 8;

    // a mask starting from p with size L
    let field_mask = (2_u32.pow(size) - 1) << pos;

    let foreground_bits = ((foreground >> 16) << pos) & field_mask;

    let mut background_field = background;
    background_field &= !field_mask;
    background_field |= foreground_bits;

    if sign_extend {
        let start_pos = (size + pos).clamp(0, 32);
        let last_bit_pos = start_pos.saturating_sub(1);
        let shift_amount = 32 - start_pos;
        // if msb of inserted field is 0, clear remaining bits
        // else set remaining bits
        let shift_mask = ((2_u64.pow(shift_amount) - 1) << start_pos) as u32;

        if ((background_field >> last_bit_pos) & 1) > 0 {
            // last bit is 1, set all remaining bits
            background_field |= shift_mask;
        } else {
            background_field &= !shift_mask;
        }
    }

    background_field
}

#[derive(Debug)]
pub struct DepositXHandler;
impl CallOtherCallback for DepositXHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // we should get 2 input args and an output
        debug_assert_eq!(inputs.len(), 2);
        debug_assert!(output.is_some());

        let space_manager = &mut backend.space_manager;

        let reg1 = space_manager
            .read(inputs.first().unwrap())
            .unwrap()
            .to_u64()
            .unwrap() as u32;
        let reg2 = space_manager
            .read(inputs.get(1).unwrap())
            .unwrap()
            .to_u64()
            .unwrap() as u32;

        let res = do_deposit(true, reg1, reg2);

        let out_varnode = output.unwrap();
        space_manager
            .write(
                out_varnode,
                SizedValue::from_u64(res as u64, out_varnode.size as u8),
            )
            .unwrap();

        // handle flags
        backend
            .write_register(BlackfinRegister::AC0flag, 0_u8)
            .unwrap();
        backend
            .write_register(BlackfinRegister::Vflag, 0_u8)
            .unwrap();
        // set AZ flag if result is 0
        if res == 0 {
            backend
                .write_register(BlackfinRegister::AZflag, 1_u8)
                .unwrap();
        } else {
            backend
                .write_register(BlackfinRegister::AZflag, 0_u8)
                .unwrap();
        }
        // set AN flag if result is negative
        if res >> 31 > 0 {
            backend
                .write_register(BlackfinRegister::ANflag, 1_u8)
                .unwrap();
        } else {
            backend
                .write_register(BlackfinRegister::ANflag, 0_u8)
                .unwrap();
        }
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
/// Handler for the DEPOSIT instruction
///
/// This instruction affects status bits as follows.
/// - AZ is set if result is zero; cleared if nonzero.
/// - AN is set if result is negative; cleared if non-negative.
/// - AC0 is cleared.
/// - V is cleared.
///
pub struct DepositHandler;
impl CallOtherCallback for DepositHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // we should get 2 input args and an output
        debug_assert_eq!(inputs.len(), 2);
        debug_assert!(output.is_some());

        let space_manager = &mut backend.space_manager;

        let reg1 = space_manager
            .read(inputs.first().unwrap())
            .unwrap()
            .to_u64()
            .unwrap() as u32;
        let reg2 = space_manager
            .read(inputs.get(1).unwrap())
            .unwrap()
            .to_u64()
            .unwrap() as u32;

        let res = do_deposit(false, reg1, reg2);

        let out_varnode = output.unwrap();
        space_manager
            .write(
                out_varnode,
                SizedValue::from_u64(res as u64, out_varnode.size as u8),
            )
            .unwrap();

        // handle flags
        backend
            .write_register(BlackfinRegister::AC0flag, 0_u8)
            .unwrap();
        backend
            .write_register(BlackfinRegister::Vflag, 0_u8)
            .unwrap();
        // set AZ flag if result is 0
        if res == 0 {
            backend
                .write_register(BlackfinRegister::AZflag, 1_u8)
                .unwrap();
        } else {
            backend
                .write_register(BlackfinRegister::AZflag, 0_u8)
                .unwrap();
        }
        // set AN flag if result is negative
        if res >> 31 > 0 {
            backend
                .write_register(BlackfinRegister::ANflag, 1_u8)
                .unwrap();
        } else {
            backend
                .write_register(BlackfinRegister::ANflag, 0_u8)
                .unwrap();
        }
        Ok(PCodeStateChange::Fallthrough)
    }
}
#[derive(Debug)]
/// Handler for the DIVS instruction.
/// DIVS ( dividend_register, divisor_register ), R7 - R0 are valid operand registers
///
/// The counterpart to DIVQ, used to initialize state
///
/// Process:
/// - Sets the ASTAT.AQ bit depending on the signs of the operands
/// - Left shifts the dividend by 1
/// - Updates the LSB of the dividend according to the AQ bit
pub struct DivSHandler;
impl CallOtherCallback for DivSHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // we should have 2 input varnodes (dividend_register, divisor_register) and 0 output varnodes
        debug_assert!(inputs.len() == 2);
        debug_assert!(output.is_none());

        let dividend = inputs.first().unwrap();
        let divisor = inputs.get(1).unwrap();

        let mut dividend_value = backend
            .space_manager
            .read(dividend)
            .unwrap()
            .to_u64()
            .unwrap() as u32;
        let divisor_value = backend
            .space_manager
            .read(divisor)
            .unwrap()
            .to_u64()
            .unwrap() as u16;

        let r: u16 = (dividend_value >> 16) as u16;

        // compute the AQ bit
        let aq = (r ^ divisor_value) >> 15;

        // write AQ result into the ASTAT register
        let astat = backend
            .read_register::<u32>(BlackfinRegister::ASTAT)
            .unwrap()
            & !(1 << 6);
        backend
            .write_register(BlackfinRegister::ASTAT, astat | (aq << 6) as u32)
            .unwrap();

        // update dividend and write it back
        dividend_value <<= 1;
        dividend_value |= aq as u32;
        dividend_value = (dividend_value & 0x1FFFF) | ((r as u32) << 17);
        backend
            .space_manager
            .write(
                dividend,
                SizedValue::from_u64(dividend_value as u64, dividend.size as u8),
            )
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
/// Handler for the DIVQ instruction.
/// DIVQ ( dividend_register, divisor_register ), R7 - R0 are valid operand registers
///
/// The counterpart to the DIVS instruction, used as part of the conditional add-subtract division algorithm.
///
/// Process:
/// - Either add or subtract the divisor from the dividend based on the ASTAT.AQ status bit.
///     - AQ = 1 for addition, AQ = 0 for subtraction
/// - Set ASTAT.AQ = dividend_MSB XOR divisor_MSB (where dividend is 32 bits and divisor is 16 bits)
/// - Left shift the dividend 1 bit
/// - Copy ~ASTAT.AQ into the LSB of the dividend.
pub struct DivQHandler;
impl CallOtherCallback for DivQHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // we should have 2 input varnodes (dividend_register, divisor_register) and 0 output varnodes
        debug_assert!(inputs.len() == 2);
        debug_assert!(output.is_none());

        // get the current AQ bit value
        let astat = backend
            .read_register::<u32>(BlackfinRegister::ASTAT)
            .unwrap();
        let aq = astat & (1 << 6) > 0;

        let dividend = inputs.first().unwrap();
        let divisor = inputs.get(1).unwrap();

        let mut dividend_value = backend
            .space_manager
            .read(dividend)
            .unwrap()
            .to_u64()
            .unwrap() as u32;
        let divisor_value = backend
            .space_manager
            .read(divisor)
            .unwrap()
            .to_u64()
            .unwrap() as u16;

        // perform addition or subtraction depending on the state of ASTAT.AQ
        let af: u16 = (dividend_value >> 16) as u16;
        let r = if aq {
            divisor_value.wrapping_add(af)
        } else {
            af.wrapping_sub(divisor_value)
        };

        // compute the new AQ value
        let new_aq = (r ^ divisor_value) >> 15;

        // update dividend value
        dividend_value <<= 1;
        if new_aq > 0 {
            dividend_value &= !1;
        } else {
            dividend_value |= 1;
        }

        dividend_value = (dividend_value & 0x1FFFF) | ((r as u32) << 17);

        // write back new ASTAT register with updated AQ bit
        if new_aq > 0 {
            backend
                .write_register(BlackfinRegister::ASTAT, astat | (1 << 6))
                .unwrap();
        } else {
            backend
                .write_register(BlackfinRegister::ASTAT, astat & !(1 << 6))
                .unwrap();
        }

        // write out new dividend value
        backend
            .space_manager
            .write(
                dividend,
                SizedValue::from_u64(dividend_value as u64, dividend.size as u8),
            )
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
/// Handler for MAC userop. This is NOT multiply and accumulate. It is multiply and store. E.g. A0 =
/// R1.L * R0.L.
///
/// There is one input (the product result) and one output (the accumulator store). The input
/// varnode is 16-bit and the output varnode is 64-bit but the actual accumulator register is
/// 40-bit.
///
/// There are also different modes to treat the values as fractions, integers, etc. TODO: NOT
/// HANDLED.
///
/// (fu)
/// Unsigned integer. Multiply 16.0 x 16.0 to produce 32.0 format data. Perform no shift
/// correction. Zero extend the result to 40.0 format before passing it to the Accumulator.
/// Saturate the Accumulator after copying or accumulating to maintain 40.0 precision.
/// In either case, the resulting hexadecimal range is minimum 0x00 0000 0000 through
/// maximum 0xFF FFFF FFFF.
pub struct MultiplyAccumulatorHandler;
impl CallOtherCallback for MultiplyAccumulatorHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let space_manager = &backend.space_manager;
        let multiply_result = space_manager
            .read(inputs.first().unwrap())
            .unwrap()
            .to_u64()
            .unwrap();

        // zero extended
        backend
            .space_manager
            .write(output.unwrap(), SizedValue::from_u64(multiply_result, 8))
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// Counts the number of sign bits from the input
///
/// Blackfin Processor Programming Reference 15-87
///
/// The Sign Bit instruction returns the number of sign bits in a number, and can be used in
/// conjunction with a shift to normalize numbers. This instruction can operate on 16-bit, 32-bit,
/// or 40-bit input numbers.
///
/// • For a 16-bit input, Sign Bit returns the number of leading sign bits minus one, which is in
/// the range 0 through 15. There are no special cases. An input of all zeros returns +15 (all sign
/// bits), and an input of all ones also returns +15.
///
/// • For a 32-bit input, Sign Bit returns the number of leading sign bits minus one, which is in
/// the range 0 through 31. An input of all zeros or all ones returns +31 (all sign bits).
///
/// • For a 40-bit Accumulator input, Sign Bit returns the number of leading sign bits minus 9,
/// which is in the range –8 through +31. A negative number is returned when the result in the
/// Accumulator has expanded into the extension bits; the corresponding normalization will shift the
/// result down to a 32-bit quantity (losing precision). An input of all zeros or all ones returns
/// +31.
#[derive(Debug)]
pub struct SignBitsHandler;
impl CallOtherCallback for SignBitsHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let sized_number = backend.space_manager.read(inputs.first().unwrap()).unwrap();
        let number = sized_number.to_u64().unwrap();

        let bytes_in_number = sized_number.size();
        let signed_bits = match bytes_in_number {
            2 | 4 => {
                // 16-bit and 32-bit registers
                let bits_in_number = (bytes_in_number * 8) - 1;
                let signed_bit_count = calculate_sign_bits(bits_in_number as u32, number);
                signed_bit_count - 1 // as per the reference manual, should never be neg
            }
            8 => {
                // actually 40 bit accumulator
                let bits_in_number = 39;
                let signed_bit_count = calculate_sign_bits(bits_in_number, number);

                signed_bit_count - 9 // as per the reference manual, can be neg
            }
            _ => panic!("unsupported input size"),
        };

        let output = output.unwrap();
        let output_value = SizedValue::from_u64(signed_bits as u64, output.size as u8);
        backend.space_manager.write(output, output_value).unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// Calculates the number of sign bits in `number`, assuming an arbitrary number of bits in the
/// number given by `bits_in_number`.
///
/// The number of sign bits is the number of bits that are sign extended to match the sign bit.
fn calculate_sign_bits(bits_in_number: u32, number: u64) -> i8 {
    let mut signed_bit_count = 0;
    while bits_in_number <= signed_bit_count
        && ((number >> (bits_in_number - signed_bit_count)) & 1) == (number >> bits_in_number)
    {
        signed_bit_count += 1;
    }

    signed_bit_count as i8
}

/// This implementation just adds each of the source registers and copies the result to the
/// destination register.
///
/// dest = src_reg_0 +|+ src_reg_1
///
/// The Vector Add / Subtract instruction simultaneously adds and/or sub- tracts two pairs of
/// registered numbers. It then stores the results of each operation into a separate 32-bit data
/// register or 16-bit half register, according to the syntax used. The destination register for
/// each of the quad or dual versions must be unique
#[derive(Debug)]
pub struct VecAddHandler;
impl CallOtherCallback for VecAddHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let src1_varnode = inputs.first().unwrap();
        let src1_value = backend
            .space_manager
            .read(src1_varnode)
            .unwrap()
            .to_u64()
            .unwrap();
        let src2_varnode = inputs.get(1).unwrap();
        let src2_value = backend
            .space_manager
            .read(src2_varnode)
            .unwrap()
            .to_u64()
            .unwrap();

        let output_value = src1_value.saturating_add(src2_value);

        let output_varnode = output.unwrap();
        let output_sized = SizedValue::from_u64(output_value, output_varnode.size as u8);

        backend
            .space_manager
            .write(output_varnode, output_sized)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct VecSubHandler;
impl CallOtherCallback for VecSubHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let src1_varnode = inputs.first().unwrap();
        let src1_value = backend
            .space_manager
            .read(src1_varnode)
            .unwrap()
            .to_u64()
            .unwrap();
        let src2_varnode = inputs.get(1).unwrap();
        let src2_value = backend
            .space_manager
            .read(src2_varnode)
            .unwrap()
            .to_u64()
            .unwrap();

        let output_value = src1_value.saturating_sub(src2_value);

        let output_varnode = output.unwrap();
        let output_sized = SizedValue::from_u64(output_value, output_varnode.size as u8);

        backend
            .space_manager
            .write(output_varnode, output_sized)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// This should probably do some saturating or something...
#[derive(Debug)]
pub struct MoveHandler;
impl CallOtherCallback for MoveHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let src_varnode = inputs.first().unwrap();
        let src_value = backend
            .space_manager
            .read(src_varnode)
            .unwrap()
            .to_u64()
            .unwrap();

        let output_value = src_value;

        let output_varnode = output.unwrap();
        let output_sized = SizedValue::from_u64(output_value, output_varnode.size as u8);

        backend
            .space_manager
            .write(output_varnode, output_sized)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct MinHandler;
impl CallOtherCallback for MinHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let src1_varnode = inputs.first().unwrap();
        let src2_varnode = inputs.get(1).unwrap();
        let output_varnode = output.unwrap();
        debug_assert_eq!(src1_varnode.size, output_varnode.size);
        debug_assert_eq!(src2_varnode.size, output_varnode.size);

        let src1_value = backend
            .space_manager
            .read(src1_varnode)
            .unwrap()
            .to_u64()
            .unwrap();
        let src2_value = backend
            .space_manager
            .read(src2_varnode)
            .unwrap()
            .to_u64()
            .unwrap();

        let output_value = src1_value.min(src2_value);

        let output_sized = SizedValue::from_u64(output_value, output_varnode.size as u8);

        backend
            .space_manager
            .write(output_varnode, output_sized)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// Used to extract length and position from pattern register. See [extract_generic()] for more
/// info.
#[bitfield_struct::bitfield(u16)]
struct Pattern {
    #[bits(5)]
    length: u8,

    #[bits(3)]
    __: u8,

    #[bits(5)]
    position: u8,

    #[bits(3)]
    __: u8,
}

/// Extracts a specified number of bits from a scene, based on a pattern.
///
/// These are terms from the blackfin documentation:
///
/// Scene is the 32 bit field we are extracing bits from.
///
/// Pattern takes the following form:
///
/// ```ignore
///  15.......8  7........0
/// -------------------------
/// | xxxP PPPP | xxxL LLLL |
/// -------------------------
/// ```
///
/// Where:
/// - P = position of pattern bit field LSB in scene_reg (valid range 0 through 31)
/// - L = length of pattern bit field (valid range 0 through 31)
///
/// If (p + L) > 32: In the zero-extended and sign-extended versions of the instruction, the
/// architecture assumes that all bits to the left of the scene_reg are zero.
///
/// Sign extension affects the bits in the destination register (return value).
///
fn extract_generic(
    space_manager: &SpaceManager,
    scene: &VarnodeData,
    pattern: &VarnodeData,
    sign_extend: bool,
) -> u32 {
    let scene = space_manager.read(scene).unwrap().to_u64().unwrap() as u32;
    let pattern = space_manager.read(pattern).unwrap().to_u64().unwrap() as u16;
    let pattern = Pattern::from_bits(pattern);

    let bottom_bits_mask = (1 << pattern.length()) - 1;
    let result = (scene >> pattern.position()) & bottom_bits_mask;
    if sign_extend {
        let sign_bit = result >> (pattern.length() - 1);
        if sign_bit == 1 {
            let top_bits_mask = !bottom_bits_mask;
            top_bits_mask | result
        } else {
            result
        }
    } else {
        result
    }
}

/// `EXTRACT (Z)` Extract zero-extended.
///
/// See [extract_generic()] for info on extraction.
#[derive(Debug)]
pub struct ExtractZ;
impl CallOtherCallback for ExtractZ {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let src1_varnode = inputs.first().unwrap();
        let src2_varnode = inputs.get(1).unwrap();
        let output_varnode = output.unwrap();

        let output_value =
            extract_generic(&backend.space_manager, src1_varnode, src2_varnode, false) as u64;

        let output_sized = SizedValue::from_u64(output_value, output_varnode.size as u8);

        backend
            .space_manager
            .write(output_varnode, output_sized)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// `EXTRACT (X)` Extract sign extended.
///
/// See [extract_generic()] for info on extraction.
#[derive(Debug)]
pub struct ExtractX;
impl CallOtherCallback for ExtractX {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let src1_varnode = inputs.first().unwrap();
        let src2_varnode = inputs.get(1).unwrap();
        let output_varnode = output.unwrap();

        let output_value =
            extract_generic(&backend.space_manager, src1_varnode, src2_varnode, true) as u64;

        let output_sized = SizedValue::from_u64(output_value, output_varnode.size as u8);

        backend
            .space_manager
            .write(output_varnode, output_sized)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// Convert 1.15 and 0.16 fractional format values to 64 bit floating point
/// signed: true  -> input in 1.15 fractional format
///         false -> input in 0.16 fractional format
/// For more on the fractional format, see Blackfin Processor Programming
/// Reference sections 1-16 and 2-4
fn fmt_frac_16(val: u16, signed: bool) -> f64 {
    let mut acc: f64 = 0.0;
    for x in 0..0x10 {
        if x == 0 && signed {
            acc -= if (val & 0x8000) != 0 { 1.0 } else { 0.0 };
        } else {
            acc += if (val & (1 << (15 - x))) != 0 {
                f64::powf(2.0, -((if signed { x } else { x + 1 }) as f64))
            } else {
                0.0
            }
        }
    }
    acc
}

/// Convert 1.31 and 0.32 fractional format values to 64 bit floating point
/// signed: true  -> input in 1.31 fractional format
///         false -> input in 0.32 fractional format
/// For more on the fractional format, see Blackfin Processor Programming
/// Reference sections 1-16 and 2-4
#[allow(dead_code)]
fn fmt_frac_32(val: u32, signed: bool) -> f64 {
    let mut acc: f64 = 0.0;
    for x in 0..0x20 {
        if x == 0 && signed {
            acc -= if (val & 0x80000000) != 0 { 1.0 } else { 0.0 };
        } else {
            acc += if (val & (1 << (31 - x))) != 0 {
                f64::powf(2.0, -((if signed { x } else { x + 1 }) as f64))
            } else {
                0.0
            }
        }
    }
    acc
}

/// Convert 64 bit floating point values to 1.15 and 0.16 fractional format
/// signed: true  -> output in 1.15 fractional format
///         false -> output in 0.16 fractional format
/// For more on the fractional format, see Blackfin Processor Programming
/// Reference sections 1-16 and 2-4
#[allow(dead_code)]
fn fmt_hex_16(val: f64, signed: bool) -> u16 {
    let mut val = val;
    let mut res = 0.0;
    let frac = if signed {
        0x8000u16 as f64
    } else {
        0x10000u32 as f64
    };

    if signed && (val < 0.0) {
        res += 0x8000u16 as f64;
        val += 1.0;
    }

    (res + (val * frac)) as u16
}

/// Convert 64 bit floating point values to 1.31 and 0.32 fractional format
/// signed: true  -> output in 1.31 fractional format
///         false -> output in 0.32 fractional format
/// For more on the fractional format, see Blackfin Processor Programming
/// Reference sections 1-16 and 2-4
fn fmt_hex_32(val: f64, signed: bool) -> u32 {
    let mut val = val;
    let mut res = 0.0;
    let frac = if signed {
        0x80000000u32 as f64
    } else {
        0x100000000u64 as f64
    };

    if signed && (val < 0.0) {
        res += 0x80000000u32 as f64;
        val += 1.0;
    }

    (res + (val * frac)) as u32
}

#[cfg(test)]
mod frac_math_tests {
    use super::*;

    #[test]
    fn test_fmt_frac_hex_16() {
        // Full coverage of signed and unsigned values, 0x0000 -> 0xFFFF
        assert_eq!(fmt_frac_16(0, true), 0.0);
        assert_eq!(fmt_frac_16(0, false), 0.0);

        for x in 1..=u16::MAX {
            let fval_signed = fmt_frac_16(x, true);
            let fval_unsigned = fmt_frac_16(x, false);

            assert_ne!(fval_signed, 0.0);
            assert_ne!(fval_unsigned, 0.0);

            assert_eq!(x, fmt_hex_16(fval_signed, true));
            assert_eq!(x, fmt_hex_16(fval_unsigned, false));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // TODO: own runner? this is very slow
    fn test_fmt_frac_hex_32() {
        // Coverage for start, middle, and end of 32 bit signed and unsigned
        // ranges, including the positive to negative shift for signed values
        assert_eq!(fmt_hex_32(0.0, true), 0);
        assert_eq!(fmt_hex_32(0.0, false), 0);

        for x_small in 1..=0xFFFF {
            let fval_small_signed = fmt_frac_32(x_small, true);
            let fval_small_unsigned = fmt_frac_32(x_small, false);

            let x_medium = x_small + 0x7FFF0000;
            let fval_medium_signed = fmt_frac_32(x_medium, true);
            let fval_medium_unsigned = fmt_frac_32(x_medium, false);

            let x_large = x_small + 0xFFFF0000;
            let fval_large_signed = fmt_frac_32(x_large, true);
            let fval_large_unsigned = fmt_frac_32(x_large, false);

            assert_ne!(fval_small_signed, 0.0);
            assert_ne!(fval_small_unsigned, 0.0);
            assert_eq!(fmt_hex_32(fval_small_signed, true), x_small);
            assert_eq!(fmt_hex_32(fval_small_unsigned, false), x_small);

            assert_ne!(fval_medium_signed, 0.0);
            assert_ne!(fval_medium_unsigned, 0.0);
            assert_eq!(fmt_hex_32(fval_medium_signed, true), x_medium);
            assert_eq!(fmt_hex_32(fval_medium_unsigned, false), x_medium);

            assert_ne!(fval_large_signed, 0.0);
            assert_ne!(fval_large_unsigned, 0.0);
            assert_eq!(fmt_hex_32(fval_large_signed, true), x_large);
            assert_eq!(fmt_hex_32(fval_large_unsigned, false), x_large);
        }
    }
}

enum MulKind {
    Def = 0,
    S2Rnd = 1,
    T = 2,
    W32 = 3,
    Fu = 4,
    Tfu = 6,
    Is = 8,
    Iss2 = 9,
    Ih = 11,
    Iu = 12,
}

fn extract_mul_kind(val: u8) -> Option<MulKind> {
    if val == (MulKind::Def as u8) {
        Some(MulKind::Def)
    } else if val == (MulKind::S2Rnd as u8) {
        Some(MulKind::S2Rnd)
    } else if val == (MulKind::T as u8) {
        Some(MulKind::T)
    } else if val == (MulKind::W32 as u8) {
        Some(MulKind::W32)
    } else if val == (MulKind::Fu as u8) {
        Some(MulKind::Fu)
    } else if val == (MulKind::Tfu as u8) {
        Some(MulKind::Tfu)
    } else if val == (MulKind::Is as u8) {
        Some(MulKind::Is)
    } else if val == (MulKind::Iss2 as u8) {
        Some(MulKind::Iss2)
    } else if val == (MulKind::Ih as u8) {
        Some(MulKind::Ih)
    } else if val == (MulKind::Iu as u8) {
        Some(MulKind::Iu)
    } else {
        None
    }
}

enum MulMode {
    Single = 0,
    Mixed = 1,
}

fn extract_mul_mode(val: u8, acc: &Accumulator) -> Option<MulMode> {
    // Mixed only applies to MAC1
    match acc {
        Accumulator::A0 => Some(MulMode::Single),
        Accumulator::A1 => {
            if val == (MulMode::Single as u8) {
                Some(MulMode::Single)
            } else if val == (MulMode::Mixed as u8) {
                Some(MulMode::Mixed)
            } else {
                None
            }
        }
    }
}

enum PassthroughMode {
    Equal = 0,
    PlusEqual = 1,
    MinusEqual = 2,
}

fn extract_passthrough_mode(acc: &Accumulator, buf: &[u8]) -> Option<PassthroughMode> {
    let val = match acc {
        Accumulator::A0 => (buf[3] & 0x18) >> 3, // xop01112
        Accumulator::A1 => buf[0] & 0x03,        //op10001
    };

    if val == (PassthroughMode::Equal as u8) {
        Some(PassthroughMode::Equal)
    } else if val == (PassthroughMode::PlusEqual as u8) {
        Some(PassthroughMode::PlusEqual)
    } else if val == (PassthroughMode::MinusEqual as u8) {
        Some(PassthroughMode::MinusEqual)
    } else {
        None
    }
}

enum Accumulator {
    A0 = 0,
    A1 = 1,
}

fn extract_accumulator(val: u8) -> Option<Accumulator> {
    if val == (Accumulator::A0 as u8) {
        Some(Accumulator::A0)
    } else if val == (Accumulator::A1 as u8) {
        Some(Accumulator::A1)
    } else {
        None
    }
}

fn adjust_product_plus_equal(
    product: &u32,
    accumulator_value: &u64,
    mul_mode: &MulMode,
    mul_kind: &MulKind,
) -> Option<u64> {
    let prod = *product;
    let prod_s = fmt_frac_32(prod, true);
    let prod_u = fmt_frac_32(prod, false);
    let acc = *accumulator_value;
    let acc_s = fmt_frac_32(acc as u32, true);
    let acc_u = fmt_frac_32(acc as u32, false);
    let sum_s = prod_s + acc_s;
    let sum_u = prod_u + acc_u;
    match mul_kind {
        MulKind::Def => {
            if sum_s >= 1.0 {
                Some((0x7FFFFFFF - prod) as u64)
            } else if sum_s <= -1.0 {
                Some((0xFFFFFFFF - prod) as u64)
            } else {
                Some(prod as u64)
            }
        }
        MulKind::S2Rnd => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::T => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::W32 => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Fu => match mul_mode {
            MulMode::Single => {
                if sum_u >= 1.0 {
                    Some((0xFFFFFFFF - prod) as u64)
                } else {
                    Some(prod as u64)
                }
            }
            MulMode::Mixed => {
                if sum_s >= 1.0 {
                    Some((0x7FFFFFFF - prod) as u64)
                } else if sum_s <= -1.0 {
                    Some((0xFFFFFFFF - prod) as u64)
                } else {
                    Some(prod as u64)
                }
            }
        },
        MulKind::Tfu => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Is => Some(prod as u64),
        MulKind::Iss2 => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Ih => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Iu => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
    }
}

fn adjust_product_minus_equal(
    product: &u32,
    accumulator_value: &u64,
    mul_mode: &MulMode,
    mul_kind: &MulKind,
) -> Option<u64> {
    let prod = *product;
    let prod_s = fmt_frac_32(prod, true);
    let prod_u = fmt_frac_32(prod, false);
    let acc = *accumulator_value;
    let acc_s = fmt_frac_32(acc as u32, true);
    let acc_u = fmt_frac_32(acc as u32, false);
    let diff_s = acc_s - prod_s;
    let diff_u = acc_u - prod_u;
    match mul_kind {
        MulKind::Def => {
            if diff_s >= 1.0 || diff_s <= -1.0 {
                None // Fix this
            } else {
                Some(prod as u64)
            }
        }
        MulKind::S2Rnd => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::T => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::W32 => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Fu => match mul_mode {
            MulMode::Single => {
                if diff_u < 0.0 {
                    Some(acc)
                } else {
                    Some(prod as u64)
                }
            }
            MulMode::Mixed => {
                if diff_s >= 1.0 || diff_s <= -1.0 {
                    None // Fix this
                } else {
                    Some(prod as u64)
                }
            }
        },
        MulKind::Tfu => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Is => Some(prod as u64),
        MulKind::Iss2 => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Ih => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Iu => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
    }
}

fn adjust_product(
    product: &u32,
    accumulator_value: &u64,
    passthrough_mode: &PassthroughMode,
    mul_mode: &MulMode,
    mul_kind: &MulKind,
) -> Option<u64> {
    match passthrough_mode {
        PassthroughMode::Equal => Some(*product as u64),
        PassthroughMode::PlusEqual => {
            adjust_product_plus_equal(product, accumulator_value, mul_mode, mul_kind)
        }
        PassthroughMode::MinusEqual => {
            adjust_product_minus_equal(product, accumulator_value, mul_mode, mul_kind)
        }
    }
}

fn mac_mul(op1: u16, op2: u16, mul_kind: &MulKind, mul_mode: &MulMode) -> Option<u32> {
    // Quick docs dump refresher on how mixed mode works:
    //
    // "Mixed mode multiply (valid only for MAC1). When issued in a fraction
    // mode instruction (with Default, FU, T, TFU, or S2RND mode), multiply 1.15
    // * 0.16 to produce 1.31 results.  When issued in an integer mode
    // instruction (with IS, ISS2, or IH mode), multiply 16.0 * 16.0 (signed *
    // unsigned) to produce 32.0 results.  No shift correction in either case.
    // Src_reg_0 is the signed operand and Src_reg_1 is the unsigned operand.
    // Accumulation and extraction proceed according to the other mode selection
    // or Default."                   - Blackfin Processor Programming Reference

    match mul_kind {
        MulKind::Def => match mul_mode {
            MulMode::Single => Some(fmt_hex_32(
                fmt_frac_16(op1, true) * fmt_frac_16(op2, true),
                true,
            )),
            MulMode::Mixed => Some(fmt_hex_32(
                fmt_frac_16(op1, true) * fmt_frac_16(op2, false),
                true,
            )),
        },
        MulKind::S2Rnd => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::T => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::W32 => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Fu => match mul_mode {
            // Critical Mode
            MulMode::Single => Some(fmt_hex_32(
                fmt_frac_16(op1, false) * fmt_frac_16(op2, false),
                false,
            )),
            MulMode::Mixed => Some(fmt_hex_32(
                fmt_frac_16(op1, true) * fmt_frac_16(op2, false),
                true,
            )),
        },
        MulKind::Tfu => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Is => match mul_mode {
            MulMode::Single => Some(((op1 as i16 as i32) * (op2 as i16 as i32)) as u32),
            MulMode::Mixed => {
                let negative = (op1 as i16) < 0;
                let src1 = (if negative { -(op1 as i16) } else { op1 as i16 }) as u32;
                Some((((src1 * (op2 as u32)) as i32) * (if negative { -1 } else { 1 })) as u32)
            }
        },
        MulKind::Iss2 => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Ih => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
        MulKind::Iu => match mul_mode {
            MulMode::Single => None,
            MulMode::Mixed => None,
        },
    }
}

/// Print register state and MAC results
///
/// Example output:
///
/// ┌ Registers @ PC = 0x1518 ────────────────┐
/// │A0 0xDFAF1740               R0 0xD136459D│
/// │A1 0xF0BBA999 P1 0xF0BBA999 R1 0xF0BBA999│
/// │              P2 0xF0BBA999 R2 0x71145679│
/// │              P3 0xF0BBA999 R3 0xDD010007│
/// │              P4 0xF0BBA999 R4 0xEDDC1569│
/// │                            R5 0xF0BBA999│
/// │                            R6 0x00E3D01D│
/// │                            R7 0xF0BBA999│
/// └─────────────────────────────────────────┘
/// A0 += MAC(0xd01d, 0xf0bb) yields:
/// Product:
///     3283301679 (int),
///     0xc3b3352f (hex),
///     -0.4710935135371983 (signed),
///     0.7644532432314008 (unsigned)
/// Adjusted Product:
///     1011665616 (int),
///     0x3c4ccad0 (hex),
///     0.471093513071537 (signed),
///     0.2355467565357685 (unsigned)
#[allow(clippy::too_many_arguments)]
fn debug_mac_print(
    backend: &mut PcodeBackend,
    src1_value: &u64,
    src2_value: &u64,
    product: &u32,
    adjusted_product: &u64,
    accumulator: &Accumulator,
    passthrough_mode: &PassthroughMode,
    mul_mode: &MulMode,
) {
    eprintln!(
        "┌ Registers @ PC = 0x{:04X} ────────────────┐",
        backend.pc().unwrap()
    );
    eprintln!(
        "│A0 {:#010X}               R0 {:#010X}│",
        backend.read_register::<u32>(BlackfinRegister::A0w).unwrap(),
        backend.read_register::<u32>(BlackfinRegister::R0).unwrap()
    );
    eprintln!(
        "│A1 {:#010X} P1 {:#010X} R1 {:#010X}│",
        backend.read_register::<u32>(BlackfinRegister::A1w).unwrap(),
        backend.read_register::<u32>(BlackfinRegister::P1).unwrap(),
        backend.read_register::<u32>(BlackfinRegister::R1).unwrap()
    );
    eprintln!(
        "│              P2 {:#010X} R2 {:#010X}│",
        backend.read_register::<u32>(BlackfinRegister::P2).unwrap(),
        backend.read_register::<u32>(BlackfinRegister::R2).unwrap()
    );
    eprintln!(
        "│              P3 {:#010X} R3 {:#010X}│",
        backend.read_register::<u32>(BlackfinRegister::P3).unwrap(),
        backend.read_register::<u32>(BlackfinRegister::R3).unwrap()
    );
    eprintln!(
        "│              P4 {:#010X} R4 {:#010X}│",
        backend.read_register::<u32>(BlackfinRegister::P4).unwrap(),
        backend.read_register::<u32>(BlackfinRegister::R4).unwrap()
    );
    eprintln!(
        "│                            R5 {:#010X}│",
        backend.read_register::<u32>(BlackfinRegister::R5).unwrap()
    );
    eprintln!(
        "│                            R6 {:#010X}│",
        backend.read_register::<u32>(BlackfinRegister::R6).unwrap()
    );
    eprintln!(
        "│                            R7 {:#010X}│",
        backend.read_register::<u32>(BlackfinRegister::R7).unwrap()
    );
    eprintln!("└─────────────────────────────────────────┘");
    match accumulator {
        Accumulator::A0 => eprint!("A0"),
        Accumulator::A1 => eprint!("A1"),
    };
    match passthrough_mode {
        PassthroughMode::Equal => eprint!(" = "),
        PassthroughMode::PlusEqual => eprint!(" += "),
        PassthroughMode::MinusEqual => eprint!(" -= "),
    };
    eprint!("MAC({src1_value:#06x}, {src2_value:#06x}) ");
    match mul_mode {
        MulMode::Single => (),
        MulMode::Mixed => eprint!("(M) "),
    };
    eprintln!("yields:");
    eprintln!(
        "\tProduct:\n\t\t{} (int),\n\t\t{:#010x} (hex),\n\t\t{} (signed),\n\t\t{} (unsigned)",
        product,
        product,
        fmt_frac_32(*product, true),
        fmt_frac_32(*product, false)
    );
    if *product as u64 == *adjusted_product {
        eprintln!("\tNo adjustment!");
    } else {
        eprintln!(
            "\tAdjusted Product:\n\t\t{} (int),\n\t\t{:#010x} (hex),\n\t\t{} (signed),\n\t\t{} (unsigned)",
            *adjusted_product,
            *adjusted_product,
            fmt_frac_32((*adjusted_product & 0xFFFFFFFF) as u32, true),
            fmt_frac_32((*adjusted_product & 0xFFFFFFFF) as u32, false)
        );
    }
}

/// Handler for the MAC instruction.
#[derive(Debug)]
pub struct MacHandler;
impl CallOtherCallback for MacHandler {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert!(inputs.len() == 3);
        debug_assert!(output.is_some());

        let src1_varnode = inputs.first().unwrap();
        let src2_varnode = inputs.get(1).unwrap();
        let accumulator_varnode = inputs.get(2).unwrap();

        let output_varnode = output.unwrap();

        let src1_value = backend
            .space_manager
            .read(src1_varnode)
            .unwrap()
            .to_u64()
            .unwrap();
        let src2_value = backend
            .space_manager
            .read(src2_varnode)
            .unwrap()
            .to_u64()
            .unwrap();

        let accumulator = extract_accumulator(
            backend
                .space_manager
                .read(accumulator_varnode)
                .unwrap()
                .to_u64()
                .unwrap() as u8,
        )
        .unwrap();

        let accumulator_value = match accumulator {
            Accumulator::A0 => backend.read_register::<u32>(BlackfinRegister::A0w).unwrap() as u64,
            Accumulator::A1 => backend.read_register::<u32>(BlackfinRegister::A1w).unwrap() as u64,
        };

        // A quick refresher on instruction byte layout for sleigh tokens
        //
        // inst(16)              inst2(16)
        // buf[0]     buf[1]     buf[2]     buf[3]
        // [........] [........] [........] [........]
        //  76543210   FEDCBA98   76543210   FEDCBA98
        //
        // For example, to extract uimm7 = (4,8) from the inst(16) token
        // let val = ((buf[1] & 0x1) << 4) + ((buf[0] & 0xF0) >> 4);

        // Extract multiplication mode from the first two instructions bytes
        let mut buf = [0u8; 4];
        _mmu.code()
            .read(backend.pc().unwrap())
            .bytes(&mut buf)
            .unwrap();

        let mm04 = (buf[0] & 0x10) >> 4;
        let mmod0508 = ((buf[0] & 0x20) >> 5)
            + ((buf[0] & 0x40) >> 5)
            + ((buf[0] & 0x80) >> 5)
            + ((buf[1] & 0x01) << 3);

        let passthrough_mode = extract_passthrough_mode(&accumulator, &buf).unwrap();
        let mul_mode = extract_mul_mode(mm04, &accumulator).unwrap();
        let mul_kind = extract_mul_kind(mmod0508).unwrap();
        let product = mac_mul(src1_value as u16, src2_value as u16, &mul_kind, &mul_mode).unwrap();
        let adjusted_product = adjust_product(
            &product,
            &accumulator_value,
            &passthrough_mode,
            &mul_mode,
            &mul_kind,
        )
        .unwrap();

        debug_mac_print(
            backend,
            &src1_value,
            &src2_value,
            &product,
            &adjusted_product,
            &accumulator,
            &passthrough_mode,
            &mul_mode,
        );

        let output_sized = SizedValue::from_u64(adjusted_product, output_varnode.size as u8);

        backend
            .space_manager
            .write(output_varnode, output_sized)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}
