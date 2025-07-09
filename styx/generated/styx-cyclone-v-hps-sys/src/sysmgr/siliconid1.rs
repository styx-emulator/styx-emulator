// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `siliconid1` reader"]
pub type R = crate::R<Siliconid1Spec>;
#[doc = "Register `siliconid1` writer"]
pub type W = crate::W<Siliconid1Spec>;
#[doc = "Silicon revision number.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Rev {
    #[doc = "1: `1`"]
    Rev1 = 1,
}
impl From<Rev> for u16 {
    #[inline(always)]
    fn from(variant: Rev) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rev {
    type Ux = u16;
}
#[doc = "Field `rev` reader - Silicon revision number."]
pub type RevR = crate::FieldReader<Rev>;
impl RevR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Rev> {
        match self.bits {
            1 => Some(Rev::Rev1),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rev1(&self) -> bool {
        *self == Rev::Rev1
    }
}
#[doc = "Field `rev` writer - Silicon revision number."]
pub type RevW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Silicon ID\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Id {
    #[doc = "0: `0`"]
    HpsCycloneVArriaV = 0,
}
impl From<Id> for u16 {
    #[inline(always)]
    fn from(variant: Id) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Id {
    type Ux = u16;
}
#[doc = "Field `id` reader - Silicon ID"]
pub type IdR = crate::FieldReader<Id>;
impl IdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Id> {
        match self.bits {
            0 => Some(Id::HpsCycloneVArriaV),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_hps_cyclone_v_arria_v(&self) -> bool {
        *self == Id::HpsCycloneVArriaV
    }
}
#[doc = "Field `id` writer - Silicon ID"]
pub type IdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Silicon revision number."]
    #[inline(always)]
    pub fn rev(&self) -> RevR {
        RevR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - Silicon ID"]
    #[inline(always)]
    pub fn id(&self) -> IdR {
        IdR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Silicon revision number."]
    #[inline(always)]
    #[must_use]
    pub fn rev(&mut self) -> RevW<Siliconid1Spec> {
        RevW::new(self, 0)
    }
    #[doc = "Bits 16:31 - Silicon ID"]
    #[inline(always)]
    #[must_use]
    pub fn id(&mut self) -> IdW<Siliconid1Spec> {
        IdW::new(self, 16)
    }
}
#[doc = "Specifies Silicon ID and revision number.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`siliconid1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Siliconid1Spec;
impl crate::RegisterSpec for Siliconid1Spec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`siliconid1::R`](R) reader structure"]
impl crate::Readable for Siliconid1Spec {}
#[doc = "`reset()` method sets siliconid1 to value 0x01"]
impl crate::Resettable for Siliconid1Spec {
    const RESET_VALUE: u32 = 0x01;
}
