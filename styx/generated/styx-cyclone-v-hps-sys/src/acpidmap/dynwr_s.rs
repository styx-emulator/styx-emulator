// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dynwr_s` reader"]
pub type R = crate::R<DynwrSSpec>;
#[doc = "Register `dynwr_s` writer"]
pub type W = crate::W<DynwrSSpec>;
#[doc = "Field `user` reader - This value is propagated to SCU as AWUSERS."]
pub type UserR = crate::FieldReader;
#[doc = "Field `user` writer - This value is propagated to SCU as AWUSERS."]
pub type UserW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `page` reader - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageR = crate::FieldReader;
#[doc = "Field `page` writer - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
pub type PageW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 4:8 - This value is propagated to SCU as AWUSERS."]
    #[inline(always)]
    pub fn user(&self) -> UserR {
        UserR::new(((self.bits >> 4) & 0x1f) as u8)
    }
    #[doc = "Bits 12:13 - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    pub fn page(&self) -> PageR {
        PageR::new(((self.bits >> 12) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 4:8 - This value is propagated to SCU as AWUSERS."]
    #[inline(always)]
    #[must_use]
    pub fn user(&mut self) -> UserW<DynwrSSpec> {
        UserW::new(self, 4)
    }
    #[doc = "Bits 12:13 - AWADDR remap to 1st, 2nd, 3rd, or 4th 1GB memory region."]
    #[inline(always)]
    #[must_use]
    pub fn page(&mut self) -> PageW<DynwrSSpec> {
        PageW::new(self, 12)
    }
}
#[doc = "The Write AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dynwr_s::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DynwrSSpec;
impl crate::RegisterSpec for DynwrSSpec {
    type Ux = u32;
    const OFFSET: u64 = 92u64;
}
#[doc = "`read()` method returns [`dynwr_s::R`](R) reader structure"]
impl crate::Readable for DynwrSSpec {}
#[doc = "`reset()` method sets dynwr_s to value 0"]
impl crate::Resettable for DynwrSSpec {
    const RESET_VALUE: u32 = 0;
}
