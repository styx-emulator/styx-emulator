// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BKP14R` reader"]
pub type R = crate::R<Bkp14rSpec>;
#[doc = "Register `BKP14R` writer"]
pub type W = crate::W<Bkp14rSpec>;
#[doc = "Field `BKP` reader - BKP"]
pub type BkpR = crate::FieldReader<u32>;
#[doc = "Field `BKP` writer - BKP"]
pub type BkpW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - BKP"]
    #[inline(always)]
    pub fn bkp(&self) -> BkpR {
        BkpR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - BKP"]
    #[inline(always)]
    #[must_use]
    pub fn bkp(&mut self) -> BkpW<Bkp14rSpec> {
        BkpW::new(self, 0)
    }
}
#[doc = "backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp14r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp14r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Bkp14rSpec;
impl crate::RegisterSpec for Bkp14rSpec {
    type Ux = u32;
    const OFFSET: u64 = 136u64;
}
#[doc = "`read()` method returns [`bkp14r::R`](R) reader structure"]
impl crate::Readable for Bkp14rSpec {}
#[doc = "`write(|w| ..)` method takes [`bkp14r::W`](W) writer structure"]
impl crate::Writable for Bkp14rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BKP14R to value 0"]
impl crate::Resettable for Bkp14rSpec {
    const RESET_VALUE: u32 = 0;
}
