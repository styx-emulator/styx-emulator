// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `iir` reader"]
pub type R = crate::R<IirSpec>;
#[doc = "Register `iir` writer"]
pub type W = crate::W<IirSpec>;
#[doc = "This indicates the highest priority pending interrupt.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Id {
    #[doc = "0: `0`"]
    Modemstat = 0,
    #[doc = "1: `1`"]
    Nointrpending = 1,
    #[doc = "2: `10`"]
    Thrempty = 2,
    #[doc = "4: `100`"]
    Rxdatavailable = 4,
    #[doc = "6: `110`"]
    Rxlinestat = 6,
    #[doc = "12: `1100`"]
    Chartimeout = 12,
}
impl From<Id> for u8 {
    #[inline(always)]
    fn from(variant: Id) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Id {
    type Ux = u8;
}
#[doc = "Field `id` reader - This indicates the highest priority pending interrupt."]
pub type IdR = crate::FieldReader<Id>;
impl IdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Id> {
        match self.bits {
            0 => Some(Id::Modemstat),
            1 => Some(Id::Nointrpending),
            2 => Some(Id::Thrempty),
            4 => Some(Id::Rxdatavailable),
            6 => Some(Id::Rxlinestat),
            12 => Some(Id::Chartimeout),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_modemstat(&self) -> bool {
        *self == Id::Modemstat
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nointrpending(&self) -> bool {
        *self == Id::Nointrpending
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_thrempty(&self) -> bool {
        *self == Id::Thrempty
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_rxdatavailable(&self) -> bool {
        *self == Id::Rxdatavailable
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_rxlinestat(&self) -> bool {
        *self == Id::Rxlinestat
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_chartimeout(&self) -> bool {
        *self == Id::Chartimeout
    }
}
#[doc = "Field `id` writer - This indicates the highest priority pending interrupt."]
pub type IdW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "This is used to indicate whether the FIFO's are enabled or disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Fifoen {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "3: `11`"]
    Enabled = 3,
}
impl From<Fifoen> for u8 {
    #[inline(always)]
    fn from(variant: Fifoen) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Fifoen {
    type Ux = u8;
}
#[doc = "Field `fifoen` reader - This is used to indicate whether the FIFO's are enabled or disabled."]
pub type FifoenR = crate::FieldReader<Fifoen>;
impl FifoenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Fifoen> {
        match self.bits {
            0 => Some(Fifoen::Disabled),
            3 => Some(Fifoen::Enabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Fifoen::Disabled
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Fifoen::Enabled
    }
}
#[doc = "Field `fifoen` writer - This is used to indicate whether the FIFO's are enabled or disabled."]
pub type FifoenW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:3 - This indicates the highest priority pending interrupt."]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 6:7 - This is used to indicate whether the FIFO's are enabled or disabled."]
    #[inline(always)]
    pub fn fifoen(&self) -> FifoenR {
        FifoenR::new(((self.bits >> 6) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - This indicates the highest priority pending interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<IirSpec> {
        IdW::new(self, 0)
    }
    #[doc = "Bits 6:7 - This is used to indicate whether the FIFO's are enabled or disabled."]
    #[inline(always)]
    #[must_use]
    pub fn fifoen(&mut self) -> FifoenW<IirSpec> {
        FifoenW::new(self, 6)
    }
}
#[doc = "Returns interrupt identification and FIFO enable/disable when read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iir::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IirSpec;
impl crate::RegisterSpec for IirSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`iir::R`](R) reader structure"]
impl crate::Readable for IirSpec {}
#[doc = "`reset()` method sets iir to value 0x01"]
impl crate::Resettable for IirSpec {
    const RESET_VALUE: u32 = 0x01;
}
