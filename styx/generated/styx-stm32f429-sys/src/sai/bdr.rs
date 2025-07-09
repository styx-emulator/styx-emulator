// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BDR` reader"]
pub type R = crate::R<BdrSpec>;
#[doc = "Register `BDR` writer"]
pub type W = crate::W<BdrSpec>;
#[doc = "Field `DATA` reader - Data"]
pub type DataR = crate::FieldReader<u32>;
#[doc = "Field `DATA` writer - Data"]
pub type DataW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Data"]
    #[inline(always)]
    pub fn data(&self) -> DataR {
        DataR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Data"]
    #[inline(always)]
    #[must_use]
    pub fn data(&mut self) -> DataW<BdrSpec> {
        DataW::new(self, 0)
    }
}
#[doc = "BData register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bdr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bdr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BdrSpec;
impl crate::RegisterSpec for BdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`bdr::R`](R) reader structure"]
impl crate::Readable for BdrSpec {}
#[doc = "`write(|w| ..)` method takes [`bdr::W`](W) writer structure"]
impl crate::Writable for BdrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BDR to value 0"]
impl crate::Resettable for BdrSpec {
    const RESET_VALUE: u32 = 0;
}
