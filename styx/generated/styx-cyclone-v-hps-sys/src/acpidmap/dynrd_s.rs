// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dynrd_s` reader"]
pub type R = crate::R<DynrdSSpec>;
#[doc = "Register `dynrd_s` writer"]
pub type W = crate::W<DynrdSSpec>;
#[doc = "Field `user` reader - This value is propagated to SCU as ARUSERS."]
pub type UserR = crate::FieldReader;
#[doc = "Field `user` writer - This value is propagated to SCU as ARUSERS."]
pub type UserW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `page` reader - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageR = crate::FieldReader;
#[doc = "Field `page` writer - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 4:8 - This value is propagated to SCU as ARUSERS."]
    #[inline(always)]
    pub fn user(&self) -> UserR {
        UserR::new(((self.bits >> 4) & 0x1f) as u8)
    }
    #[doc = "Bits 12:13 - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    pub fn page(&self) -> PageR {
        PageR::new(((self.bits >> 12) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 4:8 - This value is propagated to SCU as ARUSERS."]
    #[inline(always)]
    #[must_use]
    pub fn user(&mut self) -> UserW<DynrdSSpec> {
        UserW::new(self, 4)
    }
    #[doc = "Bits 12:13 - ARADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    #[must_use]
    pub fn page(&mut self) -> PageW<DynrdSSpec> {
        PageW::new(self, 12)
    }
}
#[doc = "The Read AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dynrd_s::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DynrdSSpec;
impl crate::RegisterSpec for DynrdSSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`dynrd_s::R`](R) reader structure"]
impl crate::Readable for DynrdSSpec {}
#[doc = "`reset()` method sets dynrd_s to value 0"]
impl crate::Resettable for DynrdSSpec {
    const RESET_VALUE: u32 = 0;
}
