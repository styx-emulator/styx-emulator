// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMACHRDR` reader"]
pub type R = crate::R<DmachrdrSpec>;
#[doc = "Register `DMACHRDR` writer"]
pub type W = crate::W<DmachrdrSpec>;
#[doc = "Field `HRDAP` reader - HRDAP"]
pub type HrdapR = crate::FieldReader<u32>;
#[doc = "Field `HRDAP` writer - HRDAP"]
pub type HrdapW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - HRDAP"]
    #[inline(always)]
    pub fn hrdap(&self) -> HrdapR {
        HrdapR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - HRDAP"]
    #[inline(always)]
    #[must_use]
    pub fn hrdap(&mut self) -> HrdapW<DmachrdrSpec> {
        HrdapW::new(self, 0)
    }
}
#[doc = "Ethernet DMA current host receive descriptor register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmachrdr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmachrdrSpec;
impl crate::RegisterSpec for DmachrdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`dmachrdr::R`](R) reader structure"]
impl crate::Readable for DmachrdrSpec {}
#[doc = "`reset()` method sets DMACHRDR to value 0"]
impl crate::Resettable for DmachrdrSpec {
    const RESET_VALUE: u32 = 0;
}
