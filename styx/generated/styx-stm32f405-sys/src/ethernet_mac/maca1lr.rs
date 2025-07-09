// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACA1LR` reader"]
pub type R = crate::R<Maca1lrSpec>;
#[doc = "Register `MACA1LR` writer"]
pub type W = crate::W<Maca1lrSpec>;
#[doc = "Field `MACA1LR` reader - MACA1LR"]
pub type Maca1lrR = crate::FieldReader<u32>;
#[doc = "Field `MACA1LR` writer - MACA1LR"]
pub type Maca1lrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - MACA1LR"]
    #[inline(always)]
    pub fn maca1lr(&self) -> Maca1lrR {
        Maca1lrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - MACA1LR"]
    #[inline(always)]
    #[must_use]
    pub fn maca1lr(&mut self) -> Maca1lrW<Maca1lrSpec> {
        Maca1lrW::new(self, 0)
    }
}
#[doc = "Ethernet MAC address1 low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`maca1lr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`maca1lr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Maca1lrSpec;
impl crate::RegisterSpec for Maca1lrSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`maca1lr::R`](R) reader structure"]
impl crate::Readable for Maca1lrSpec {}
#[doc = "`write(|w| ..)` method takes [`maca1lr::W`](W) writer structure"]
impl crate::Writable for Maca1lrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACA1LR to value 0xffff_ffff"]
impl crate::Resettable for Maca1lrSpec {
    const RESET_VALUE: u32 = 0xffff_ffff;
}
