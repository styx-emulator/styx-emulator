// SPDX-License-Identifier: BSD-2-Clause
use half::f16;

use crate::{call_other::CallOtherCallback, memory::sized_value::SizedValue, PCodeStateChange};

#[derive(Debug, Default)]
/// Floating-point minimum number (vector):
/// This instruction compares corresponding vector elements in the two source
/// SIMD&FP registers, writes the smaller of the two floating-point values into a
/// vector, and writes the vector to the destination SIMD&FP register.
///
/// Floating-point minimum number (scalar):
/// This instruction compares the first and second source SIMD&FP register values,
/// and writes the smaller of the two floating-point values to the destination
/// SIMD&FP register.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_fminnm(Vn.T, Vm.T, width)` or `Rd = NEON_fminnm(Rn, Rm)`
///
/// `T = {4H, 8H, 2S, 4S, 2D}`
/// `width = {2, 4, 8}`
///
/// Implementation:
///
/// The scalar implementation is just a simple FP compare, the vector implementation
/// iterates over each pair of floats in the vectors and does a compare for each.
pub struct NeonFminnmCallother;
impl CallOtherCallback for NeonFminnmCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let out: u128 = if inputs.len() == 3 {
            // vector
            let element_width = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as usize;

            let vec1_data = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
            let vec2_data = cpu.read(&inputs[1]).unwrap().to_u128().unwrap();

            match element_width {
                2 => {
                    const NUM_ELEMENTS: usize = 8;

                    let mut vec1: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };

                    for i in 0..NUM_ELEMENTS {
                        vec1[i] = vec1[i].min(vec2[i]);
                    }

                    unsafe { std::mem::transmute::<[f16; NUM_ELEMENTS], u128>(vec1) }
                }
                4 => {
                    const NUM_ELEMENTS: usize = 4;

                    let mut vec1: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };

                    for i in 0..NUM_ELEMENTS {
                        vec1[i] = vec1[i].min(vec2[i]);
                    }

                    unsafe { std::mem::transmute::<[f32; NUM_ELEMENTS], u128>(vec1) }
                }
                8 => {
                    const NUM_ELEMENTS: usize = 2;

                    let mut vec1: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };

                    for i in 0..NUM_ELEMENTS {
                        vec1[i] = vec1[i].min(vec2[i]);
                    }

                    unsafe { std::mem::transmute::<[f64; NUM_ELEMENTS], u128>(vec1) }
                }
                _ => unreachable!(
                    "valid vector element widths are 2,4,8 got: {}",
                    element_width
                ),
            }
        } else if inputs.len() == 2 {
            // scalar
            match inputs[0].size {
                2 => {
                    let input1 = cpu.read(&inputs[0]).unwrap().to_f16().unwrap();
                    let input2 = cpu.read(&inputs[1]).unwrap().to_f16().unwrap();

                    input1.min(input2).to_bits() as u128
                }
                4 => {
                    let input1 = cpu.read(&inputs[0]).unwrap().to_f32().unwrap();
                    let input2 = cpu.read(&inputs[1]).unwrap().to_f32().unwrap();

                    input1.min(input2).to_bits() as u128
                }
                8 => {
                    let input1 = cpu.read(&inputs[0]).unwrap().to_f64().unwrap();
                    let input2 = cpu.read(&inputs[1]).unwrap().to_f64().unwrap();

                    input1.min(input2).to_bits() as u128
                }
                _ => unreachable!("valid float widths are 2,4,8 got: {}", inputs[0].size),
            }
        } else {
            unreachable!("NEON_fminnm expects 2 or 3 arguments, got {}", inputs.len());
        };

        let output_varnode = output.unwrap();
        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Floating-point compare greater than (vector):
///
/// This instruction reads each floating-point value in the first source SIMD&FP
/// register and if the value is greater than the corresponding floating-point value
/// in the second source SIMD&FP register sets every bit of the corresponding vector
/// element in the destination SIMD&FP register to one, otherwise sets every bit of
/// the corresponding vector element in the destination SIMD&FP register to zero.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_fcmgt(Vn.T, Vm.T, width)` or `Rd = NEON_fcmgt(Rn, Rm)`
///
/// `T = {4H, 8H, 2S, 4S, 2D}`
/// `width = {2, 4, 8}`
///
/// Implementation:
///
/// Convert to array, do comparison, then convert back.
pub struct NeonFcmgtCallother;
impl CallOtherCallback for NeonFcmgtCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let out: u128 = if inputs.len() == 3 {
            // vector
            let element_width = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as usize;

            let vec1_data = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
            let vec2_data = cpu.read(&inputs[1]).unwrap().to_u128().unwrap();

            match element_width {
                2 => {
                    const NUM_ELEMENTS: usize = 8;

                    let vec1: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u16; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec1[i] > vec2[i] {
                            out_vec[i] = 0xFFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u16; NUM_ELEMENTS], u128>(out_vec) }
                }
                4 => {
                    const NUM_ELEMENTS: usize = 4;

                    let vec1: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u32; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec1[i] > vec2[i] {
                            out_vec[i] = 0xFFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u32; NUM_ELEMENTS], u128>(out_vec) }
                }
                8 => {
                    const NUM_ELEMENTS: usize = 2;

                    let vec1: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u64; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec1[i] > vec2[i] {
                            out_vec[i] = 0xFFFF_FFFF_FFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u64; NUM_ELEMENTS], u128>(out_vec) }
                }
                _ => unreachable!(
                    "valid vector element widths are 2,4,8 got: {}",
                    element_width
                ),
            }
        } else if inputs.len() == 2 {
            // scalar
            let input1 = cpu.read(&inputs[0]).unwrap().to_f64().unwrap();
            let input2 = cpu.read(&inputs[1]).unwrap().to_f64().unwrap();

            if input1 > input2 {
                match inputs[0].size {
                    2 => 0xFFFF_u128,
                    4 => 0xFFFF_FFFF_u128,
                    8 => 0xFFFF_FFFF_FFFF_FFFF_u128,
                    _ => unreachable!("valid FP sizes are 2,4,8 got: {}", inputs[0].size),
                }
            } else {
                0
            }
        } else {
            unreachable!("NEON_fcmgt expects 2 or 3 arguments, got {}", inputs.len());
        };

        let output_varnode = output.unwrap();
        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Floating-point Compare Greater than or Equal (vector):
///
/// This instruction reads each floating-point value in the first source SIMD and
/// FP register and if the value is greater than or equal to the corresponding
/// floating-point value in the second source SIMD/FP register sets every bit
/// of the corresponding vector element in the destination SIMD/FP register
/// to one, otherwise sets every bit of the corresponding vector element in the
/// destination SIMD/FP register to zero.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_fcmge(Vn.T, Vm.T, width)` or `Rd = NEON_fcmge(Rn, Rm)`
///
/// `T = {4H, 8H, 2S, 4S, 2D}`
/// `width = {2, 4, 8}`
///
/// Implementation:
///
/// Convert to array, do comparison, then convert back.
pub struct NeonFcmgeCallother;
impl CallOtherCallback for NeonFcmgeCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let out: u128 = if inputs.len() == 3 {
            // vector
            let element_width = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as usize;

            let vec1_data = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
            let vec2_data = cpu.read(&inputs[1]).unwrap().to_u128().unwrap();

            match element_width {
                2 => {
                    const NUM_ELEMENTS: usize = 8;

                    let vec1: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u16; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec1[i] >= vec2[i] {
                            out_vec[i] = 0xFFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u16; NUM_ELEMENTS], u128>(out_vec) }
                }
                4 => {
                    const NUM_ELEMENTS: usize = 4;

                    let vec1: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u32; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..4 {
                        if vec1[i] >= vec2[i] {
                            out_vec[i] = 0xFFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u32; 4], u128>(out_vec) }
                }
                8 => {
                    const NUM_ELEMENTS: usize = 2;

                    let vec1: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u64; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec1[i] >= vec2[i] {
                            out_vec[i] = 0xFFFF_FFFF_FFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u64; NUM_ELEMENTS], u128>(out_vec) }
                }
                _ => unreachable!(
                    "valid vector element widths are 2,4,8 got: {}",
                    element_width
                ),
            }
        } else if inputs.len() == 2 {
            // scalar
            let input1 = cpu.read(&inputs[0]).unwrap().to_f64().unwrap();
            let input2 = cpu.read(&inputs[1]).unwrap().to_f64().unwrap();

            if input1 >= input2 {
                match inputs[0].size {
                    2 => 0xFFFF_u128,
                    4 => 0xFFFF_FFFF_u128,
                    8 => 0xFFFF_FFFF_FFFF_FFFF_u128,
                    _ => unreachable!("valid FP sizes are 2,4,8 got: {}", inputs[0].size),
                }
            } else {
                0
            }
        } else {
            unreachable!("NEON_fcmge expects 2 or 3 arguments, got {}", inputs.len());
        };

        let output_varnode = output.unwrap();
        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Floating-point Compare Less than zero (vector):
///
/// This instruction reads each floating-point value in the source SIMD/FP
/// register and if the value is less than zero sets every bit of the
/// corresponding vector element in the destination SIMD/FP register to
/// one, otherwise sets every bit of the corresponding vector element in the
/// destination SIMD/FP register to zero.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_fcmlt(Vn.T, 0, width)` or `Rd = NEON_fcmlt(Rn, 0)`
///
/// `T = {4H, 8H, 2S, 4S, 2D}`
/// `width = {2, 4, 8}`
///
/// Implementation:
///
/// Convert to array, do comparison, then convert back.
pub struct NeonFcmltCallother;
impl CallOtherCallback for NeonFcmltCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let out: u128 = if inputs.len() == 3 {
            // vector
            let element_width = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as usize;

            let vec_data = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();

            match element_width {
                2 => {
                    const NUM_ELEMENTS: usize = 8;

                    let vec: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec_data) };
                    let mut out_vec: [u16; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec[i] < f16::ZERO {
                            out_vec[i] = 0xFFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u16; NUM_ELEMENTS], u128>(out_vec) }
                }
                4 => {
                    const NUM_ELEMENTS: usize = 4;

                    let vec: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec_data) };
                    let mut out_vec: [u32; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec[i] < 0.0 {
                            out_vec[i] = 0xFFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u32; NUM_ELEMENTS], u128>(out_vec) }
                }
                8 => {
                    const NUM_ELEMENTS: usize = 2;

                    let vec: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec_data) };
                    let mut out_vec: [u64; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec[i] < 0.0 {
                            out_vec[i] = 0xFFFF_FFFF_FFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u64; NUM_ELEMENTS], u128>(out_vec) }
                }
                _ => unreachable!(
                    "valid vector element widths are 2,4,8 got: {}",
                    element_width
                ),
            }
        } else if inputs.len() == 2 {
            // scalar
            let input1 = cpu.read(&inputs[0]).unwrap().to_f64().unwrap();

            if input1 < 0.0 {
                match inputs[0].size {
                    2 => 0xFFFF_u128,
                    4 => 0xFFFF_FFFF_u128,
                    8 => 0xFFFF_FFFF_FFFF_FFFF_u128,
                    _ => unreachable!("valid FP sizes are 2,4,8 got: {}", inputs[0].size),
                }
            } else {
                0
            }
        } else {
            unreachable!("NEON_fcmlt expects 2 or 3 arguments, got {}", inputs.len());
        };

        let output_varnode = output.unwrap();
        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Floating-point Compare Less than or Equal to zero (vector):
///
/// This instruction reads each floating-point value in the source SIMD and
/// FP register and if the value is less than or equal to zero sets every
/// bit of the corresponding vector element in the destination SIMD and
/// FP register to one, otherwise sets every bit of the corresponding
/// vector element in the destination SIMD/FP register to zero.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_fcmle(Vn.T, 0, width)` or `Rd = NEON_fcmle(Rn, 0)`
///
/// `T = {4H, 8H, 2S, 4S, 2D}`
/// `width = {2, 4, 8}`
///
/// Implementation:
///
/// Convert to array, do comparison, then convert back.
pub struct NeonFcmleCallother;
impl CallOtherCallback for NeonFcmleCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let out: u128 = if inputs.len() == 3 {
            // vector
            let element_width = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as usize;

            let vec_data = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();

            match element_width {
                2 => {
                    const NUM_ELEMENTS: usize = 8;

                    let vec: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec_data) };
                    let mut out_vec: [u16; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec[i] <= f16::ZERO {
                            out_vec[i] = 0xFFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u16; NUM_ELEMENTS], u128>(out_vec) }
                }
                4 => {
                    const NUM_ELEMENTS: usize = 4;

                    let vec: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec_data) };
                    let mut out_vec: [u32; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec[i] <= 0.0 {
                            out_vec[i] = 0xFFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u32; NUM_ELEMENTS], u128>(out_vec) }
                }
                8 => {
                    const NUM_ELEMENTS: usize = 2;

                    let vec: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec_data) };
                    let mut out_vec: [u64; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec[i] <= 0.0 {
                            out_vec[i] = 0xFFFF_FFFF_FFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u64; NUM_ELEMENTS], u128>(out_vec) }
                }
                _ => unreachable!(
                    "valid vector element widths are 2,4,8 got: {}",
                    element_width
                ),
            }
        } else if inputs.len() == 2 {
            // scalar
            let input1 = cpu.read(&inputs[0]).unwrap().to_f64().unwrap();

            if input1 <= 0.0 {
                match inputs[0].size {
                    2 => 0xFFFF_u128,
                    4 => 0xFFFF_FFFF_u128,
                    8 => 0xFFFF_FFFF_FFFF_FFFF_u128,
                    _ => unreachable!("valid FP sizes are 2,4,8 got: {}", inputs[0].size),
                }
            } else {
                0
            }
        } else {
            unreachable!("NEON_fcmle expects 2 or 3 arguments, got {}", inputs.len());
        };

        let output_varnode = output.unwrap();
        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Floating-point Compare Equal (vector):
///
/// This instruction compares each floating-point value from the first
/// source SIMD/FP register, with the corresponding floating-point
/// value from the second source SIMD/FP register, and if the
/// comparison is equal sets every bit of the corresponding vector element
/// in the destination SIMD/FP register to one, otherwise sets every
/// bit of the corresponding vector element in the destination SIMD and
/// FP register to zero.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_fcmeq(Vn.T, Vm.T, width)` or `Rd = NEON_fcmeq(Rn, Rm)`
///
/// `T = {4H, 8H, 2S, 4S, 2D}`
/// `width = {2, 4, 8}`
///
/// Implementation:
///
/// Convert to array, do comparison, then convert back.
pub struct NeonFcmeqCallother;
impl CallOtherCallback for NeonFcmeqCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let out: u128 = if inputs.len() == 3 {
            // vector
            let element_width = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as usize;

            let vec1_data = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
            let vec2_data = cpu.read(&inputs[1]).unwrap().to_u128().unwrap();

            match element_width {
                2 => {
                    const NUM_ELEMENTS: usize = 8;

                    let vec1: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f16; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u16; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec1[i] == vec2[i] {
                            out_vec[i] = 0xFFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u16; NUM_ELEMENTS], u128>(out_vec) }
                }
                4 => {
                    const NUM_ELEMENTS: usize = 4;

                    let vec1: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f32; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u32; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec1[i] == vec2[i] {
                            out_vec[i] = 0xFFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u32; NUM_ELEMENTS], u128>(out_vec) }
                }
                8 => {
                    const NUM_ELEMENTS: usize = 2;

                    let vec1: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec1_data) };
                    let vec2: [f64; NUM_ELEMENTS] = unsafe { std::mem::transmute(vec2_data) };
                    let mut out_vec: [u64; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vec1[i] == vec2[i] {
                            out_vec[i] = 0xFFFF_FFFF_FFFF_FFFF;
                        }
                    }

                    unsafe { std::mem::transmute::<[u64; NUM_ELEMENTS], u128>(out_vec) }
                }
                _ => unreachable!(
                    "valid vector element widths are 2,4,8 got: {}",
                    element_width
                ),
            }
        } else if inputs.len() == 2 {
            // scalar
            let input1 = cpu.read(&inputs[0]).unwrap().to_f64().unwrap();
            let input2 = cpu.read(&inputs[1]).unwrap().to_f64().unwrap();

            if input1 == input2 {
                match inputs[0].size {
                    2 => 0xFFFF_u128,
                    4 => 0xFFFF_FFFF_u128,
                    8 => 0xFFFF_FFFF_FFFF_FFFF_u128,
                    _ => unreachable!("valid FP sizes are 2,4,8 got: {}", inputs[0].size),
                }
            } else {
                0
            }
        } else {
            unreachable!("NEON_fcmeq expects 2 or 3 arguments, got {}", inputs.len());
        };

        let output_varnode = output.unwrap();
        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Compare bitwise Test bits nonzero (vector):
///
/// This instruction reads each vector element in the first source SIMD
/// and FP register, performs an AND with the corresponding vector
/// element in the second source SIMD/FP register, and if the result
/// is not zero, sets every bit of the corresponding vector element in
/// the destination SIMD/FP register to one, otherwise sets every
/// bit of the corresponding vector element in the destination SIMD
/// and FP register to zero.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_cmtst(Vn.T, Vm.T, width)`
/// or `Rd = NEON_cmtst(Rn, Rm)`
///
/// `T = {8B, 16B, 4H, 8H, 2S, 4S, 2D}`
/// `width = {1, 2, 4, 8}`
///
/// Implementation:
///
/// For the vector case we convert the inputs to vectors according to the width argument, then do the comparison per element.
///
/// The scalar case is a simple integer comparison.
pub struct NeonCmtestCallother;
impl CallOtherCallback for NeonCmtestCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let rn = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
        let rm = cpu.read(&inputs[1]).unwrap().to_u128().unwrap();

        let out: u128 = if inputs.len() == 3 {
            let element_width = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as usize;

            match element_width {
                1 => {
                    const NUM_ELEMENTS: usize = 16;

                    let vn: [u8; NUM_ELEMENTS] = rn.to_ne_bytes();
                    let vm: [u8; NUM_ELEMENTS] = rm.to_ne_bytes();
                    let mut vd: [u8; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vn[i] & vm[i] != 0 {
                            vd[i] = 0xFF_u8;
                        }
                    }

                    u128::from_ne_bytes(vd)
                }
                2 => {
                    const NUM_ELEMENTS: usize = 8;

                    let vn: [u16; NUM_ELEMENTS] = unsafe { std::mem::transmute(rn) };
                    let vm: [u16; NUM_ELEMENTS] = unsafe { std::mem::transmute(rm) };
                    let mut vd: [u16; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vn[i] & vm[i] != 0 {
                            vd[i] = 0xFFFF_u16;
                        }
                    }

                    unsafe { std::mem::transmute::<[u16; NUM_ELEMENTS], u128>(vd) }
                }
                4 => {
                    const NUM_ELEMENTS: usize = 4;

                    let vn: [u32; NUM_ELEMENTS] = unsafe { std::mem::transmute(rn) };
                    let vm: [u32; NUM_ELEMENTS] = unsafe { std::mem::transmute(rm) };
                    let mut vd: [u32; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vn[i] & vm[i] != 0 {
                            vd[i] = 0xFFFF_FFFF_u32;
                        }
                    }

                    unsafe { std::mem::transmute::<[u32; NUM_ELEMENTS], u128>(vd) }
                }
                8 => {
                    const NUM_ELEMENTS: usize = 2;

                    let vn: [u64; NUM_ELEMENTS] = unsafe { std::mem::transmute(rn) };
                    let vm: [u64; NUM_ELEMENTS] = unsafe { std::mem::transmute(rm) };
                    let mut vd: [u64; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                    for i in 0..NUM_ELEMENTS {
                        if vn[i] & vm[i] != 0 {
                            vd[i] = 0xFFFF_FFFF_FFFF_FFFF_u64;
                        }
                    }

                    unsafe { std::mem::transmute::<[u64; NUM_ELEMENTS], u128>(vd) }
                }
                _ => unreachable!(
                    "valid vector element widths are 1,2,4,8 got: {}",
                    element_width
                ),
            }
        } else if inputs.len() == 2 {
            if rn & rm != 0 {
                0xFFFF_FFFF_FFFF_FFFF
            } else {
                0
            }
        } else {
            unreachable!("NEON_cmtst expects 2 or 3 arguments, got {}", inputs.len())
        };

        let output_varnode = output.unwrap();
        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Reverse elements in 64-bit doublewords (vector):
///
/// This instruction reverses the order of 8-bit, 16-bit, or 32-bit
/// elements in each doubleword of the vector in the source SIMD and
/// FP register, places the results into a vector, and writes the
/// vector to the destination SIMD/FP register.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_rev64(Vn.T, width)`
///
/// `T = {8B, 16B, 4H, 8H, 2S, 4S}`
/// `width = {1, 2, 4}`
///
/// Implementation:
///
/// We first convert the input into an array, and then use XOR tricks to
/// reverse the ordering of elements in each 64 bit chunk.
///
/// Example with 4x4 vector:
///
/// `initial_indices = [0,1,2,3]`
///
/// `reversed = [0^1, 1^1, 2^1, 3^1] = [1, 0, 3, 2]`
pub struct NeonRev64Callother;
impl CallOtherCallback for NeonRev64Callother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let input_data = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
        let element_width = cpu.read(&inputs[1]).unwrap().to_u128().unwrap() as usize;

        let out: u128 = match element_width {
            1 => {
                const NUM_ELEMENTS: usize = 16;

                let input_vec: [u8; NUM_ELEMENTS] = input_data.to_ne_bytes();
                let mut output_vec: [u8; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                for i in 0..NUM_ELEMENTS {
                    output_vec[i ^ 0x7] = input_vec[i];
                }

                u128::from_ne_bytes(output_vec)
            }
            2 => {
                const NUM_ELEMENTS: usize = 8;

                let input_vec: [u16; NUM_ELEMENTS] = unsafe { std::mem::transmute(input_data) };
                let mut output_vec: [u16; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                for i in 0..NUM_ELEMENTS {
                    output_vec[i ^ 0x3] = input_vec[i];
                }

                unsafe { std::mem::transmute::<[u16; NUM_ELEMENTS], u128>(output_vec) }
            }
            4 => {
                const NUM_ELEMENTS: usize = 4;

                let input_vec: [u32; NUM_ELEMENTS] = unsafe { std::mem::transmute(input_data) };
                let mut output_vec: [u32; NUM_ELEMENTS] = [0; NUM_ELEMENTS];

                for i in 0..NUM_ELEMENTS {
                    output_vec[i ^ 0x1] = input_vec[i];
                }

                unsafe { std::mem::transmute::<[u32; NUM_ELEMENTS], u128>(output_vec) }
            }
            _ => unreachable!(
                "valid vector element widths are 1,2,4 got: {}",
                element_width
            ),
        };

        let output_varnode = output.unwrap();
        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Bitwise Insert if False:
///
/// This instruction inserts each bit from the first source SIMD
/// and FP register into the destination SIMD/FP register if
/// the corresponding bit of the second source SIMD/FP register
/// is 0, otherwise leaves the bit in the destination register
/// unchanged.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_bif(Vd.T, Vn.T, Vm.T, width)`
///
/// `T = {8B, 16B}`
/// `width = 1`
///
/// Implementation:
///
/// This operation is equivalent to Vd = (Vn & ~Vm) | (Vd & Vm)
pub struct NeonBifCallother;
impl CallOtherCallback for NeonBifCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let vd = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
        let vn = cpu.read(&inputs[1]).unwrap().to_u128().unwrap();
        let vm = cpu.read(&inputs[2]).unwrap().to_u128().unwrap();

        let out = (vn & !vm) | (vd & vm);

        let output_varnode = output.unwrap();

        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Bitwise Insert if True:
///
/// This instruction inserts each bit from the first source SIMD
/// and FP register into the SIMD/FP destination register if
/// the corresponding bit of the second source SIMD/FP
/// register is 1, otherwise leaves the bit in the destination
/// register unchanged.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_bit(Vd.T, Vn.T, Vm.T, width)`
///
/// `T = {8B, 16B}`
/// `width = 1`
///
/// Implementation:
///
/// This operation is equivalent to Vd = (Vn & Vm) | (Vd & ~Vm)
pub struct NeonBitCallother;
impl CallOtherCallback for NeonBitCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let vd = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
        let vn = cpu.read(&inputs[1]).unwrap().to_u128().unwrap();
        let vm = cpu.read(&inputs[2]).unwrap().to_u128().unwrap();

        let out = (vn & vm) | (vd & !vm);

        let output_varnode = output.unwrap();

        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Bitwise Select:
///
/// This instruction sets each bit in the destination SIMD/FP
/// register to the corresponding bit from the first source SIMD
/// and FP register when the original destination bit was 1,
/// otherwise from the second source SIMD/FP register.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_bsl(Vd.T, Vn.T, Vm.T, width)`
///
/// `T = {8B, 16B}`
/// `width = 1`
///
/// Implementation:
///
/// This operation is equivalent to Vd = (Vd & Vn) | (!Vd & Vm)
pub struct NeonBslCallother;
impl CallOtherCallback for NeonBslCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let vd = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
        let vn = cpu.read(&inputs[1]).unwrap().to_u128().unwrap();
        let vm = cpu.read(&inputs[2]).unwrap().to_u128().unwrap();

        let out = (vd & vn) | (!vd & vm);

        let output_varnode = output.unwrap();

        cpu.write(
            output_varnode,
            SizedValue::from_u128(out, output_varnode.size as u8),
        )
        .unwrap();
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Add across Vector:
///
/// This instruction adds every vector element in the source SIMD and
/// FP register together, and writes the scalar result to the
/// destination SIMD/FP register.
///
/// Sleigh Usage:
///
/// `Rd = NEON_addv(Vn.T, width)`
///
/// `T = {8B, 16B, 4H, 8H}`
/// `width = {1, 2}`
///
/// Implementation:
///
/// We convert input into an array depending on the width argument, then
/// sum all of the array elements using wrapping operators.
///
/// Safety:
///
/// We only transmute between standard integer types so this will always
/// be safe.
pub struct NeonAddvCallother;
impl CallOtherCallback for NeonAddvCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<crate::PCodeStateChange, crate::call_other::CallOtherHandleError> {
        let vec_data = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
        let element_width = cpu.read(&inputs[1]).unwrap().to_u128().unwrap() as usize;
        let output_varnode = output.unwrap();

        let out: SizedValue = match element_width {
            // 8 bit elements, B
            1 => {
                let data: [u8; 16] = vec_data.to_ne_bytes();
                let mut sum: u8 = 0;
                for elem in data {
                    sum = sum.wrapping_add(elem);
                }
                SizedValue::from_u128(sum as u128, output_varnode.size as u8)
            }
            // halfword elements, H
            2 => {
                let data: [u16; 8] = unsafe { std::mem::transmute(vec_data) };
                let mut sum: u16 = 0;
                for elem in data {
                    sum = sum.wrapping_add(elem);
                }
                SizedValue::from_u128(sum as u128, output_varnode.size as u8)
            }
            // single word, S
            4 => {
                let data: [u32; 4] = unsafe { std::mem::transmute(vec_data) };
                let mut sum: u32 = 0;
                for elem in data {
                    sum = sum.wrapping_add(elem);
                }
                SizedValue::from_u128(sum as u128, output_varnode.size as u8)
            }
            // double word
            8 => {
                let data: [u64; 2] = unsafe { std::mem::transmute(vec_data) };
                let mut sum: u64 = 0;
                for elem in data {
                    sum = sum.wrapping_add(elem);
                }
                SizedValue::from_u128(sum as u128, output_varnode.size as u8)
            }
            _ => unreachable!("not a valid width specifier"),
        };

        cpu.write(output_varnode, out).unwrap();
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug, Default)]
/// Population Count per byte:
///
/// This instruction counts the number of bits that have a value of
/// one in each vector element in the source SIMD/FP register,
/// places the result into a vector, and writes the vector to the
/// destination SIMD/FP register.
///
/// Sleigh Usage:
///
/// `Vd.T = NEON_cnt(Vn, width)`
///
/// `T = {8B, 16B}`
/// `width = 1`
///
/// Implementation:
///
/// We convert the input into an array of bytes, and do the popcount operation on each element.
pub struct NeonCntCallother;
impl CallOtherCallback for NeonCntCallother {
    fn handle(
        &mut self,
        cpu: &mut crate::PcodeBackend,
        _mmu: &mut styx_processor::memory::Mmu,
        _ev: &mut styx_processor::event_controller::EventController,
        inputs: &[styx_pcode::pcode::VarnodeData],
        output: Option<&styx_pcode::pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, crate::call_other::CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 2);
        debug_assert!(output.is_some());

        let input_varnode = &inputs[0];
        let output_varnode = output.unwrap();

        let mut vec: [u8; 16] = cpu
            .read(input_varnode)
            .unwrap()
            .to_u128()
            .unwrap()
            .to_ne_bytes();

        for element in vec.iter_mut() {
            *element = (*element).count_ones() as u8;
        }

        let out = SizedValue::from_u128(u128::from_ne_bytes(vec), output_varnode.size as u8);
        cpu.write(output_varnode, out).unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}
