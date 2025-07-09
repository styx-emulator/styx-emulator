// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMACHRBAR` reader"]
pub type R = crate::R<DmachrbarSpec>;
#[doc = "Register `DMACHRBAR` writer"]
pub type W = crate::W<DmachrbarSpec>;
#[doc = "Field `HRBAP` reader - HRBAP"]
pub type HrbapR = crate::FieldReader<u32>;
#[doc = "Field `HRBAP` writer - HRBAP"]
pub type HrbapW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - HRBAP"]
    #[inline(always)]
    pub fn hrbap(&self) -> HrbapR {
        HrbapR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - HRBAP"]
    #[inline(always)]
    #[must_use]
    pub fn hrbap(&mut self) -> HrbapW<DmachrbarSpec> {
        HrbapW::new(self, 0)
    }
}
#[doc = "Ethernet DMA current host receive buffer address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmachrbar::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmachrbarSpec;
impl crate::RegisterSpec for DmachrbarSpec {
    type Ux = u32;
    const OFFSET: u64 = 84u64;
}
#[doc = "`read()` method returns [`dmachrbar::R`](R) reader structure"]
impl crate::Readable for DmachrbarSpec {}
#[doc = "`reset()` method sets DMACHRBAR to value 0"]
impl crate::Resettable for DmachrbarSpec {
    const RESET_VALUE: u32 = 0;
}
