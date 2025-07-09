// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use core::marker;
#[doc = " Conversions to and from peripheral struts to memory blocks."]
pub trait FromBytes: Sized {
    #[doc = " Copies bytes into a new peripheral struct."]
    #[doc = ""]
    #[doc = " None will be returned if the number of bytes is not correct."]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " The bytes must be a valid representation of the peripheral struct and the registers."]
    unsafe fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let self_size = std::mem::size_of::<Self>();
        if bytes.len() != self_size {
            return None;
        }
        let mut self_uninit = std::mem::MaybeUninit::<Self>::uninit();
        let self_ptr = self_uninit.as_mut_ptr();
        let bytes_ptr = bytes.as_ptr();
        unsafe { std::ptr::copy(bytes_ptr, self_ptr as _, self_size) };
        Some(unsafe { self_uninit.assume_init() })
    }
    #[doc = " Converts a peripheral struct into a byte slice."]
    fn as_bytes_ref(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
#[doc = " Raw register type (`u8`, `u16`, `u32`, ...)"]
pub trait RawReg:
    Copy
    + Default
    + From<bool>
    + core::ops::BitOr<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::BitOrAssign
    + core::ops::BitAndAssign
    + core::ops::Not<Output = Self>
    + core::ops::Shl<u8, Output = Self>
{
    #[doc = " Mask for bits of width `WI`"]
    fn mask<const WI: u8>() -> Self;
    #[doc = " Mask for bits of width 1"]
    fn one() -> Self;
}
macro_rules! raw_reg {
    ($ U : ty , $ size : literal , $ mask : ident) => {
        impl RawReg for $U {
            #[inline(always)]
            fn mask<const WI: u8>() -> Self {
                $mask::<WI>()
            }
            #[inline(always)]
            fn one() -> Self {
                1
            }
        }
        const fn $mask<const WI: u8>() -> $U {
            <$U>::MAX >> ($size - WI)
        }
        impl FieldSpec for $U {
            type Ux = $U;
        }
    };
}
raw_reg!(u8, 8, mask_u8);
raw_reg!(u16, 16, mask_u16);
raw_reg!(u32, 32, mask_u32);
raw_reg!(u64, 64, mask_u64);
#[doc = " Raw register type"]
pub trait RegisterSpec {
    #[doc = " Raw register type (`u8`, `u16`, `u32`, ...)."]
    type Ux: RawReg;
    #[doc = " Offset into peripheral in bytes."]
    const OFFSET: u64;
}
#[doc = " Raw field type"]
pub trait FieldSpec: Sized {
    #[doc = " Raw field type (`u8`, `u16`, `u32`, ...)."]
    type Ux: Copy + PartialEq + From<Self>;
}
#[doc = " Trait implemented by readable registers to enable the `read` method."]
#[doc = ""]
#[doc = " Registers marked with `Writable` can be also be `modify`'ed."]
pub trait Readable: RegisterSpec {}
#[doc = " Trait implemented by writeable registers."]
#[doc = ""]
#[doc = " This enables the  `write`, `write_with_zero` and `reset` methods."]
#[doc = ""]
#[doc = " Registers marked with `Readable` can be also be `modify`'ed."]
pub trait Writable: RegisterSpec {
    #[doc = " Is it safe to write any bits to register"]
    type Safety;
    #[doc = " Specifies the register bits that are not changed if you pass `1` and are changed if you pass `0`"]
    const ZERO_TO_MODIFY_FIELDS_BITMAP: Self::Ux;
    #[doc = " Specifies the register bits that are not changed if you pass `0` and are changed if you pass `1`"]
    const ONE_TO_MODIFY_FIELDS_BITMAP: Self::Ux;
}
#[doc = " Reset value of the register."]
#[doc = ""]
#[doc = " This value is the initial value for the `write` method. It can also be directly written to the"]
#[doc = " register by using the `reset` method."]
pub trait Resettable: RegisterSpec {
    #[doc = " Reset value of the register."]
    const RESET_VALUE: Self::Ux;
    #[doc = " Reset value of the register."]
    #[inline(always)]
    fn reset_value() -> Self::Ux {
        Self::RESET_VALUE
    }
}
#[doc = " This structure provides volatile access to registers."]
#[repr(transparent)]
pub struct Reg<REG: RegisterSpec> {
    register: vcell::VolatileCell<REG::Ux>,
    _marker: marker::PhantomData<REG>,
}
unsafe impl<REG: RegisterSpec> Send for Reg<REG> where REG::Ux: Send {}
impl<REG: RegisterSpec> Reg<REG> {
    #[doc = " Returns the underlying memory address of register."]
    #[doc = ""]
    #[doc = " ```ignore"]
    #[doc = " let reg_ptr = periph.reg.as_ptr();"]
    #[doc = " ```"]
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut REG::Ux {
        self.register.as_ptr()
    }
    #[doc = " Offset into peripheral in bytes."]
    #[inline(always)]
    pub const fn offset() -> u64 {
        REG::OFFSET
    }
    #[doc = " Reads the contents of a register."]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " This register operation occurs from the perspective of the"]
    #[doc = " hardware (allows reads to WO registers) and as such is `unsafe`."]
    #[doc = ""]
    #[doc = " You can read the raw contents of a register by using `bits`:"]
    #[doc = " ```ignore"]
    #[doc = " let bits = periph.reg.sys_read().bits();"]
    #[doc = " ```"]
    #[doc = " or get the content of a particular field of a register:"]
    #[doc = " ```ignore"]
    #[doc = " let reader = periph.reg.sys_read();"]
    #[doc = " let bits = reader.field1().bits();"]
    #[doc = " let flag = reader.field2().bit_is_set();"]
    #[doc = " ```"]
    #[inline(always)]
    pub unsafe fn sys_read(&self) -> R<REG> {
        R {
            bits: self.register.get(),
            _reg: marker::PhantomData,
        }
    }
    #[doc = " Writes bits to a register."]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " This register operation occurs from the perspective of the"]
    #[doc = " hardware (allows writes to RO registers) and as such is `unsafe`."]
    #[doc = ""]
    #[doc = " # NOTE"]
    #[doc = ""]
    #[doc = " Fields not set will be written as `0`."]
    #[doc = ""]
    #[doc = " You can write raw bits into a register:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.sys_write_with_zero(|w| unsafe { w.bits(rawbits) });"]
    #[doc = " ```"]
    #[doc = " or write only the fields you need:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.sys_write_with_zero(|w| w"]
    #[doc = "     .field1().bits(newfield1bits)"]
    #[doc = "     .field2().set_bit()"]
    #[doc = "     .field3().variant(VARIANT)"]
    #[doc = " );"]
    #[doc = " ```"]
    #[doc = " or an alternative way of saying the same:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.sys_write_with_zero(|w| {"]
    #[doc = "     w.field1().bits(newfield1bits);"]
    #[doc = "     w.field2().set_bit();"]
    #[doc = "     w.field3().variant(VARIANT)"]
    #[doc = " });"]
    #[doc = " ```"]
    #[inline(always)]
    pub unsafe fn sys_write_with_zero<F>(&self, f: F)
    where
        F: FnOnce(&mut W<REG>) -> &mut W<REG>,
    {
        self.register.set(
            f(&mut W {
                bits: REG::Ux::default(),
                _reg: marker::PhantomData,
            })
            .bits,
        );
    }
    #[doc = " Modifies the contents of the register by reading and then writing it."]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " This register operation occurs from the perspective of the"]
    #[doc = " hardware (allows reads/writes to WO/RO registers)"]
    #[doc = " and as such is `unsafe`."]
    #[doc = ""]
    #[doc = " E.g. to do a read-modify-write sequence to change parts of a register:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.sys_modify(|r, w| unsafe { w.bits("]
    #[doc = "    r.bits() | 3"]
    #[doc = " ) });"]
    #[doc = " ```"]
    #[doc = " or"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.sys_modify(|_, w| w"]
    #[doc = "     .field1().bits(newfield1bits)"]
    #[doc = "     .field2().set_bit()"]
    #[doc = "     .field3().variant(VARIANT)"]
    #[doc = " );"]
    #[doc = " ```"]
    #[doc = " or an alternative way of saying the same:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.sys_modify(|_, w| {"]
    #[doc = "     w.field1().bits(newfield1bits);"]
    #[doc = "     w.field2().set_bit();"]
    #[doc = "     w.field3().variant(VARIANT)"]
    #[doc = " });"]
    #[doc = " ```"]
    #[doc = " Other fields will have the value they had before the call to `sys_modify`."]
    #[inline(always)]
    pub unsafe fn sys_modify<F>(&self, f: F)
    where
        for<'w> F: FnOnce(&R<REG>, &'w mut W<REG>) -> &'w mut W<REG>,
    {
        let bits = self.register.get();
        self.register.set(
            f(
                &R {
                    bits,
                    _reg: marker::PhantomData,
                },
                &mut W {
                    bits,
                    _reg: marker::PhantomData,
                },
            )
            .bits,
        );
    }
    #[doc = " Clears the register content to 0"]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " This does not obey R/W permissions and is unsafe."]
    #[doc = ""]
    #[doc = " This can be used as an alternative to `sys_reset` when"]
    #[doc = " it is not available."]
    #[inline(always)]
    pub unsafe fn sys_register_clear(&self) {
        self.register.set(REG::Ux::default())
    }
}
impl<REG: Resettable> Reg<REG> {
    #[doc = " Resets the register content to the reset value"]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " This does not obey R/W permissions and is unsafe."]
    #[doc = ""]
    #[doc = " Note that not all registers implement [`Resettable`],"]
    #[doc = " so you may have to use `sys_register_clear()` instead."]
    #[inline(always)]
    pub unsafe fn sys_reset(&self) {
        self.register.set(REG::RESET_VALUE)
    }
}
impl<REG: Readable> Reg<REG> {
    #[doc = " Reads the contents of a `Readable` register."]
    #[doc = ""]
    #[doc = " You can read the raw contents of a register by using `bits`:"]
    #[doc = " ```ignore"]
    #[doc = " let bits = periph.reg.read().bits();"]
    #[doc = " ```"]
    #[doc = " or get the content of a particular field of a register:"]
    #[doc = " ```ignore"]
    #[doc = " let reader = periph.reg.read();"]
    #[doc = " let bits = reader.field1().bits();"]
    #[doc = " let flag = reader.field2().bit_is_set();"]
    #[doc = " ```"]
    #[inline(always)]
    pub fn read(&self) -> R<REG> {
        R {
            bits: self.register.get(),
            _reg: marker::PhantomData,
        }
    }
}
impl<REG: Resettable + Writable> Reg<REG> {
    #[doc = " Writes the reset value to `Writable` register."]
    #[doc = ""]
    #[doc = " Resets the register to its initial state."]
    #[inline(always)]
    pub fn reset(&self) {
        self.register.set(REG::RESET_VALUE)
    }
    #[doc = " Writes bits to a `Writable` register."]
    #[doc = ""]
    #[doc = " You can write raw bits into a register:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.write(|w| unsafe { w.bits(rawbits) });"]
    #[doc = " ```"]
    #[doc = " or write only the fields you need:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.write(|w| w"]
    #[doc = "     .field1().bits(newfield1bits)"]
    #[doc = "     .field2().set_bit()"]
    #[doc = "     .field3().variant(VARIANT)"]
    #[doc = " );"]
    #[doc = " ```"]
    #[doc = " or an alternative way of saying the same:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.write(|w| {"]
    #[doc = "     w.field1().bits(newfield1bits);"]
    #[doc = "     w.field2().set_bit();"]
    #[doc = "     w.field3().variant(VARIANT)"]
    #[doc = " });"]
    #[doc = " ```"]
    #[doc = " In the latter case, other fields will be set to their reset value."]
    #[inline(always)]
    pub fn write<F>(&self, f: F)
    where
        F: FnOnce(&mut W<REG>) -> &mut W<REG>,
    {
        self.register.set(
            f(&mut W {
                bits: REG::RESET_VALUE & !REG::ONE_TO_MODIFY_FIELDS_BITMAP
                    | REG::ZERO_TO_MODIFY_FIELDS_BITMAP,
                _reg: marker::PhantomData,
            })
            .bits,
        );
    }
}
impl<REG: Writable> Reg<REG> {
    #[doc = " Writes 0 to a `Writable` register."]
    #[doc = ""]
    #[doc = " Similar to `write`, but unused bits will contain 0."]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " Unsafe to use with registers which don't allow to write 0."]
    #[inline(always)]
    pub unsafe fn write_with_zero<F>(&self, f: F)
    where
        F: FnOnce(&mut W<REG>) -> &mut W<REG>,
    {
        self.register.set(
            f(&mut W {
                bits: REG::Ux::default(),
                _reg: marker::PhantomData,
            })
            .bits,
        );
    }
}
impl<REG: Readable + Writable> Reg<REG> {
    #[doc = " Modifies the contents of the register by reading and then writing it."]
    #[doc = ""]
    #[doc = " E.g. to do a read-modify-write sequence to change parts of a register:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.modify(|r, w| unsafe { w.bits("]
    #[doc = "    r.bits() | 3"]
    #[doc = " ) });"]
    #[doc = " ```"]
    #[doc = " or"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.modify(|_, w| w"]
    #[doc = "     .field1().bits(newfield1bits)"]
    #[doc = "     .field2().set_bit()"]
    #[doc = "     .field3().variant(VARIANT)"]
    #[doc = " );"]
    #[doc = " ```"]
    #[doc = " or an alternative way of saying the same:"]
    #[doc = " ```ignore"]
    #[doc = " periph.reg.modify(|_, w| {"]
    #[doc = "     w.field1().bits(newfield1bits);"]
    #[doc = "     w.field2().set_bit();"]
    #[doc = "     w.field3().variant(VARIANT)"]
    #[doc = " });"]
    #[doc = " ```"]
    #[doc = " Other fields will have the value they had before the call to `modify`."]
    #[inline(always)]
    pub fn modify<F>(&self, f: F)
    where
        for<'w> F: FnOnce(&R<REG>, &'w mut W<REG>) -> &'w mut W<REG>,
    {
        let bits = self.register.get();
        self.register.set(
            f(
                &R {
                    bits,
                    _reg: marker::PhantomData,
                },
                &mut W {
                    bits: bits & !REG::ONE_TO_MODIFY_FIELDS_BITMAP
                        | REG::ZERO_TO_MODIFY_FIELDS_BITMAP,
                    _reg: marker::PhantomData,
                },
            )
            .bits,
        );
    }
}
#[doc(hidden)]
pub mod raw;
#[doc = " Register reader."]
#[doc = ""]
#[doc = " Result of the `read` methods of registers. Also used as a closure argument in the `modify`"]
#[doc = " method."]
pub type R<REG> = raw::R<REG>;
impl<REG: RegisterSpec> R<REG> {
    #[doc = " Reads raw bits from the register."]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " This is a system hardware level operation that ignores permissions."]
    #[inline(always)]
    pub unsafe fn sys_get(&self) -> REG::Ux {
        self.bits
    }
}
impl<REG: RegisterSpec> R<REG> {
    #[doc = " Reads raw bits from register."]
    #[inline(always)]
    pub const fn bits(&self) -> REG::Ux {
        self.bits
    }
}
impl<REG: RegisterSpec, FI> PartialEq<FI> for R<REG>
where
    REG::Ux: PartialEq,
    FI: Copy,
    REG::Ux: From<FI>,
{
    #[inline(always)]
    fn eq(&self, other: &FI) -> bool {
        self.bits.eq(&REG::Ux::from(*other))
    }
}
#[doc = " Register writer."]
#[doc = ""]
#[doc = " Used as an argument to the closures in the `write` and `modify` methods of the register."]
pub type W<REG> = raw::W<REG>;
impl<REG: RegisterSpec> W<REG> {
    #[doc = " Writes raw bits to the register."]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " This is a system hardware level operation that ignores permissions."]
    #[inline(always)]
    pub unsafe fn sys_set(&mut self, bits: REG::Ux) -> &mut Self {
        self.bits = bits;
        self
    }
}
impl<REG: Writable> W<REG> {
    #[doc = " Writes raw bits to the register."]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " Passing incorrect value can cause undefined behaviour. See reference manual"]
    #[inline(always)]
    pub unsafe fn bits(&mut self, bits: REG::Ux) -> &mut Self {
        self.bits = bits;
        self
    }
}
impl<REG> W<REG>
where
    REG: Writable<Safety = Safe>,
{
    #[doc = " Writes raw bits to the register."]
    #[inline(always)]
    pub fn set(&mut self, bits: REG::Ux) -> &mut Self {
        self.bits = bits;
        self
    }
}
#[doc = " Field reader."]
#[doc = ""]
#[doc = " Result of the `read` methods of fields."]
pub type FieldReader<FI = u8> = raw::FieldReader<FI>;
#[doc = " Bit-wise field reader"]
pub type BitReader<FI = bool> = raw::BitReader<FI>;
impl<FI: FieldSpec> FieldReader<FI> {
    #[doc = " Reads raw bits from field."]
    #[inline(always)]
    pub const fn bits(&self) -> FI::Ux {
        self.bits
    }
}
impl<FI> PartialEq<FI> for FieldReader<FI>
where
    FI: FieldSpec + Copy,
{
    #[inline(always)]
    fn eq(&self, other: &FI) -> bool {
        self.bits.eq(&FI::Ux::from(*other))
    }
}
impl<FI> PartialEq<FI> for BitReader<FI>
where
    FI: Copy,
    bool: From<FI>,
{
    #[inline(always)]
    fn eq(&self, other: &FI) -> bool {
        self.bits.eq(&bool::from(*other))
    }
}
impl<FI> BitReader<FI> {
    #[doc = " Value of the field as raw bits."]
    #[inline(always)]
    pub const fn bit(&self) -> bool {
        self.bits
    }
    #[doc = " Returns `true` if the bit is clear (0)."]
    #[inline(always)]
    pub const fn bit_is_clear(&self) -> bool {
        !self.bit()
    }
    #[doc = " Returns `true` if the bit is set (1)."]
    #[inline(always)]
    pub const fn bit_is_set(&self) -> bool {
        self.bit()
    }
}
#[doc = " Marker for register/field writers which can take any value of specified width"]
pub struct Safe;
#[doc = " You should check that value is allowed to pass to register/field writer marked with this"]
pub struct Unsafe;
#[doc = " Write field Proxy with unsafe `bits`"]
pub type FieldWriter<'a, REG, const WI: u8, FI = u8> = raw::FieldWriter<'a, REG, WI, FI, Unsafe>;
#[doc = " Write field Proxy with safe `bits`"]
pub type FieldWriterSafe<'a, REG, const WI: u8, FI = u8> = raw::FieldWriter<'a, REG, WI, FI, Safe>;
impl<'a, REG, const WI: u8, FI> FieldWriter<'a, REG, WI, FI>
where
    REG: RegisterSpec,
    FI: FieldSpec,
    REG::Ux: From<FI::Ux>,
{
    #[doc = " Field width"]
    pub const WIDTH: u8 = WI;
    #[doc = " Field width"]
    #[inline(always)]
    pub const fn width(&self) -> u8 {
        WI
    }
    #[doc = " Field offset"]
    #[inline(always)]
    pub const fn offset(&self) -> u8 {
        self.o
    }
    #[doc = " Writes raw bits to the field"]
    #[doc = ""]
    #[doc = " # Safety"]
    #[doc = ""]
    #[doc = " Passing incorrect value can cause undefined behaviour. See reference manual"]
    #[inline(always)]
    pub unsafe fn bits(self, value: FI::Ux) -> &'a mut W<REG> {
        self.w.bits &= !(REG::Ux::mask::<WI>() << self.o);
        self.w.bits |= (REG::Ux::from(value) & REG::Ux::mask::<WI>()) << self.o;
        self.w
    }
    #[doc = " Writes `variant` to the field"]
    #[inline(always)]
    pub fn variant(self, variant: FI) -> &'a mut W<REG> {
        unsafe { self.bits(FI::Ux::from(variant)) }
    }
}
impl<'a, REG, const WI: u8, FI> FieldWriterSafe<'a, REG, WI, FI>
where
    REG: RegisterSpec,
    FI: FieldSpec,
    REG::Ux: From<FI::Ux>,
{
    #[doc = " Field width"]
    pub const WIDTH: u8 = WI;
    #[doc = " Field width"]
    #[inline(always)]
    pub const fn width(&self) -> u8 {
        WI
    }
    #[doc = " Field offset"]
    #[inline(always)]
    pub const fn offset(&self) -> u8 {
        self.o
    }
    #[doc = " Writes raw bits to the field"]
    #[inline(always)]
    pub fn bits(self, value: FI::Ux) -> &'a mut W<REG> {
        self.w.bits &= !(REG::Ux::mask::<WI>() << self.o);
        self.w.bits |= (REG::Ux::from(value) & REG::Ux::mask::<WI>()) << self.o;
        self.w
    }
    #[doc = " Writes `variant` to the field"]
    #[inline(always)]
    pub fn variant(self, variant: FI) -> &'a mut W<REG> {
        self.bits(FI::Ux::from(variant))
    }
}
macro_rules! bit_proxy {
    ($ writer : ident , $ mwv : ident) => {
        #[doc(hidden)]
        pub struct $mwv;
        #[doc = " Bit-wise write field proxy"]
        pub type $writer<'a, REG, FI = bool> = raw::BitWriter<'a, REG, FI, $mwv>;
        impl<'a, REG, FI> $writer<'a, REG, FI>
        where
            REG: RegisterSpec,
            bool: From<FI>,
        {
            #[doc = " Field width"]
            pub const WIDTH: u8 = 1;
            #[doc = " Field width"]
            #[inline(always)]
            pub const fn width(&self) -> u8 {
                Self::WIDTH
            }
            #[doc = " Field offset"]
            #[inline(always)]
            pub const fn offset(&self) -> u8 {
                self.o
            }
            #[doc = " Writes bit to the field"]
            #[inline(always)]
            pub fn bit(self, value: bool) -> &'a mut W<REG> {
                self.w.bits &= !(REG::Ux::one() << self.o);
                self.w.bits |= (REG::Ux::from(value) & REG::Ux::one()) << self.o;
                self.w
            }
            #[doc = " Writes `variant` to the field"]
            #[inline(always)]
            pub fn variant(self, variant: FI) -> &'a mut W<REG> {
                self.bit(bool::from(variant))
            }
        }
    };
}
bit_proxy!(BitWriter, BitM);
bit_proxy!(BitWriter1S, Bit1S);
bit_proxy!(BitWriter0C, Bit0C);
bit_proxy!(BitWriter1C, Bit1C);
bit_proxy!(BitWriter0S, Bit0S);
bit_proxy!(BitWriter1T, Bit1T);
bit_proxy!(BitWriter0T, Bit0T);
impl<'a, REG, FI> BitWriter<'a, REG, FI>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    #[doc = " Sets the field bit"]
    #[inline(always)]
    pub fn set_bit(self) -> &'a mut W<REG> {
        self.w.bits |= REG::Ux::one() << self.o;
        self.w
    }
    #[doc = " Clears the field bit"]
    #[inline(always)]
    pub fn clear_bit(self) -> &'a mut W<REG> {
        self.w.bits &= !(REG::Ux::one() << self.o);
        self.w
    }
}
impl<'a, REG, FI> BitWriter1S<'a, REG, FI>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    #[doc = " Sets the field bit"]
    #[inline(always)]
    pub fn set_bit(self) -> &'a mut W<REG> {
        self.w.bits |= REG::Ux::one() << self.o;
        self.w
    }
}
impl<'a, REG, FI> BitWriter0C<'a, REG, FI>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    #[doc = " Clears the field bit"]
    #[inline(always)]
    pub fn clear_bit(self) -> &'a mut W<REG> {
        self.w.bits &= !(REG::Ux::one() << self.o);
        self.w
    }
}
impl<'a, REG, FI> BitWriter1C<'a, REG, FI>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    #[doc = "Clears the field bit by passing one"]
    #[inline(always)]
    pub fn clear_bit_by_one(self) -> &'a mut W<REG> {
        self.w.bits |= REG::Ux::one() << self.o;
        self.w
    }
}
impl<'a, REG, FI> BitWriter0S<'a, REG, FI>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    #[doc = "Sets the field bit by passing zero"]
    #[inline(always)]
    pub fn set_bit_by_zero(self) -> &'a mut W<REG> {
        self.w.bits &= !(REG::Ux::one() << self.o);
        self.w
    }
}
impl<'a, REG, FI> BitWriter1T<'a, REG, FI>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    #[doc = "Toggle the field bit by passing one"]
    #[inline(always)]
    pub fn toggle_bit(self) -> &'a mut W<REG> {
        self.w.bits |= REG::Ux::one() << self.o;
        self.w
    }
}
impl<'a, REG, FI> BitWriter0T<'a, REG, FI>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    #[doc = "Toggle the field bit by passing zero"]
    #[inline(always)]
    pub fn toggle_bit(self) -> &'a mut W<REG> {
        self.w.bits &= !(REG::Ux::one() << self.o);
        self.w
    }
}
