// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMACHTBAR` reader"]
pub type R = crate::R<DmachtbarSpec>;
#[doc = "Register `DMACHTBAR` writer"]
pub type W = crate::W<DmachtbarSpec>;
#[doc = "Field `HTBAP` reader - HTBAP"]
pub type HtbapR = crate::FieldReader<u32>;
#[doc = "Field `HTBAP` writer - HTBAP"]
pub type HtbapW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - HTBAP"]
    #[inline(always)]
    pub fn htbap(&self) -> HtbapR {
        HtbapR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - HTBAP"]
    #[inline(always)]
    #[must_use]
    pub fn htbap(&mut self) -> HtbapW<DmachtbarSpec> {
        HtbapW::new(self, 0)
    }
}
#[doc = "Ethernet DMA current host transmit buffer address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmachtbar::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmachtbarSpec;
impl crate::RegisterSpec for DmachtbarSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`dmachtbar::R`](R) reader structure"]
impl crate::Readable for DmachtbarSpec {}
#[doc = "`reset()` method sets DMACHTBAR to value 0"]
impl crate::Resettable for DmachtbarSpec {
    const RESET_VALUE: u32 = 0;
}
