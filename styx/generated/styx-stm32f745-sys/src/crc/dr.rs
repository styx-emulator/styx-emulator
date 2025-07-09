// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DR` reader"]
pub type R = crate::R<DrSpec>;
#[doc = "Register `DR` writer"]
pub type W = crate::W<DrSpec>;
#[doc = "Field `DR` reader - Data Register"]
pub type DrR = crate::FieldReader<u32>;
#[doc = "Field `DR` writer - Data Register"]
pub type DrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Data Register"]
    #[inline(always)]
    pub fn dr(&self) -> DrR {
        DrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Data Register"]
    #[inline(always)]
    #[must_use]
    pub fn dr(&mut self) -> DrW<DrSpec> {
        DrW::new(self, 0)
    }
}
#[doc = "Data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DrSpec;
impl crate::RegisterSpec for DrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`dr::R`](R) reader structure"]
impl crate::Readable for DrSpec {}
#[doc = "`write(|w| ..)` method takes [`dr::W`](W) writer structure"]
impl crate::Writable for DrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DR to value 0xffff_ffff"]
impl crate::Resettable for DrSpec {
    const RESET_VALUE: u32 = 0xffff_ffff;
}
