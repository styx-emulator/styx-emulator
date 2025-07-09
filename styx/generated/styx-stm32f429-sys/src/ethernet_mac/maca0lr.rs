// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACA0LR` reader"]
pub type R = crate::R<Maca0lrSpec>;
#[doc = "Register `MACA0LR` writer"]
pub type W = crate::W<Maca0lrSpec>;
#[doc = "Field `MACA0L` reader - 0"]
pub type Maca0lR = crate::FieldReader<u32>;
#[doc = "Field `MACA0L` writer - 0"]
pub type Maca0lW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - 0"]
    #[inline(always)]
    pub fn maca0l(&self) -> Maca0lR {
        Maca0lR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - 0"]
    #[inline(always)]
    #[must_use]
    pub fn maca0l(&mut self) -> Maca0lW<Maca0lrSpec> {
        Maca0lW::new(self, 0)
    }
}
#[doc = "Ethernet MAC address 0 low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`maca0lr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`maca0lr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Maca0lrSpec;
impl crate::RegisterSpec for Maca0lrSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`maca0lr::R`](R) reader structure"]
impl crate::Readable for Maca0lrSpec {}
#[doc = "`write(|w| ..)` method takes [`maca0lr::W`](W) writer structure"]
impl crate::Writable for Maca0lrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACA0LR to value 0xffff_ffff"]
impl crate::Resettable for Maca0lrSpec {
    const RESET_VALUE: u32 = 0xffff_ffff;
}
