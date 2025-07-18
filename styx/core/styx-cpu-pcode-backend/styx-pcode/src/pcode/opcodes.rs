// SPDX-License-Identifier: BSD-2-Clause
use num_derive::FromPrimitive;

/// P-code Opcode.
#[derive(Debug, FromPrimitive, PartialEq, Eq, Clone, Copy)]
pub enum Opcode {
    ///< Copy one operand to another
    Copy = 1,
    ///< Load from a pointer into a specified address space
    Load = 2,
    ///< Store at a pointer into a specified address space
    Store = 3,
    ///< Always branch
    Branch = 4,
    ///< Conditional branch
    CBranch = 5,
    ///< Indirect branch (jumptable)
    BranchInd = 6,
    ///< Call to an absolute address
    Call = 7,
    ///< Call through an indirect address
    CallInd = 8,
    ///< User-defined operation
    CallOther = 9,
    ///< Return from subroutine
    Return = 10,
    // Integer/bit operations
    ///< Integer comparison, equality (==)
    IntEqual = 11,
    ///< Integer comparison, in-equality (!=)
    IntNotEqual = 12,
    ///< Integer comparison, signed less-than (<)
    IntSLess = 13,
    ///< Integer comparison, signed less-than-or-equal (<=)
    IntSLessEqual = 14,
    ///< Integer comparison, unsigned less-than (<)
    IntLess = 15,
    // This also indicates a borrow on unsigned substraction
    ///< Integer comparison, unsigned less-than-or-equal (<=)
    IntLessEqual = 16,
    ///< Zero extension
    IntZExt = 17,
    ///< Sign extension
    IntSExt = 18,
    ///< Addition, signed or unsigned (+)
    IntAdd = 19,
    ///< Subtraction, signed or unsigned (-)
    IntSub = 20,
    ///< Test for unsigned carry
    IntCarry = 21,
    ///< Test for signed carry
    IntSCarry = 22,
    ///< Test for signed borrow
    IntSBorrow = 23,
    ///< Twos complement
    Int2Comp = 24,
    ///< Logical/bitwise negation (~)
    IntNegate = 25,
    ///< Logical/bitwise exclusive-or (^)
    IntXor = 26,
    ///< Logical/bitwise and (&)
    IntAnd = 27,
    ///< Logical/bitwise or (|)
    IntOr = 28,
    ///< Left shift (<<)
    IntLeft = 29,
    ///< Right shift, logical (>>)
    IntRight = 30,
    ///< Right shift, arithmetic (>>)
    IntSRight = 31,
    ///< Integer multiplication, signed and unsigned (*)
    IntMult = 32,
    ///< Integer division, unsigned (/)
    IntDiv = 33,
    ///< Integer division, signed (/)
    IntSDiv = 34,
    ///< Remainder/modulo, unsigned (%)
    IntRem = 35,
    ///< Remainder/modulo, signed (%)
    IntSRem = 36,
    ///< Boolean negate (!)
    BoolNegate = 37,
    ///< Boolean exclusive-or (^^)
    BoolXor = 38,
    ///< Boolean and (&&)
    BoolAnd = 39,
    ///< Boolean or (||)
    BoolOr = 40,
    // Floating point operations
    ///< Floating-point comparison, equality (==)
    FloatEqual = 41,
    ///< Floating-point comparison, in-equality (!=)
    FloatNotEqual = 42,
    ///< Floating-point comparison, less-than (<)
    FloatLess = 43,
    ///< Floating-point comparison, less-than-or-equal (<=)
    FloatLessEqual = 44,
    // Slot 45 is currently unused
    ///< Not-a-number test (NaN)
    FloatNan = 46,
    ///< Floating-point addition (+)
    FloatAdd = 47,
    ///< Floating-point division (/)
    FloatDiv = 48,
    ///< Floating-point multiplication (*)
    FloatMult = 49,
    ///< Floating-point subtraction (-)
    FloatSub = 50,
    ///< Floating-point negation (-)
    FloatNeg = 51,
    ///< Floating-point absolute value (abs)
    FloatAbs = 52,
    ///< Floating-point square root (sqrt)
    FloatSqrt = 53,
    ///< Convert an integer to a floating-point
    FloatInt2Float = 54,
    ///< Convert between different floating-point sizes
    FloatFloat2Float = 55,
    ///< Round towards zero
    FloatTrunc = 56,
    ///< Round towards +infinity
    FloatCeil = 57,
    ///< Round towards -infinity
    FloatFloor = 58,
    ///< Round towards nearest
    FloatRound = 59,
    // Internal opcodes for simplification. Not
    // typically generated in a direct translation.

    // Data-flow operations
    ///< Phi-node operator
    MultiEqual = 60,
    ///< Copy with an indirect effect
    Indirect = 61,
    ///< Concatenate
    Piece = 62,
    ///< Truncate
    SubPiece = 63,
    ///< Cast from one data-type to another
    Cast = 64,
    ///< Index into an array ([])
    PtrAdd = 65,
    ///< Drill down to a sub-field  (->)
    PtrSub = 66,
    ///< Look-up a \e segmented address
    SegmentOp = 67,
    ///< Recover a value from the \e constant \e pool
    CPoolRef = 68,
    ///< Allocate a new object (new)
    New = 69,
    ///< Insert a bit-range
    Insert = 70,
    ///< Extract a bit-range
    Extract = 71,
    ///< Count the 1-bits
    PopCount = 72,
    ///< Count number of leading zeros
    LZCount = 73,
    ///< Placeholder to indicate the max opcode value
    Max = 74,
}

impl Opcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        num::FromPrimitive::from_u32(val)
    }

    /// Is this op part of the `BRANCH` family where input0 is the location of the next pcode to
    /// execute.
    pub fn is_branch(&self) -> bool {
        matches!(self, Self::Branch | Self::CBranch | Self::Call)
    }

    /// Is this op part of the `BRANCHIND` family where input0 is the offset of the next pcode to
    /// execute.
    pub fn is_branch_indirect(&self) -> bool {
        matches!(self, Self::BranchInd | Self::CallInd | Self::Return)
    }
}
