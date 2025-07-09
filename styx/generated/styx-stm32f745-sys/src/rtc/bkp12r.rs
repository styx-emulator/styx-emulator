// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BKP12R` reader"]
pub type R = crate::R<Bkp12rSpec>;
#[doc = "Register `BKP12R` writer"]
pub type W = crate::W<Bkp12rSpec>;
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
    pub fn bkp(&mut self) -> BkpW<Bkp12rSpec> {
        BkpW::new(self, 0)
    }
}
#[doc = "backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp12r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp12r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Bkp12rSpec;
impl crate::RegisterSpec for Bkp12rSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`bkp12r::R`](R) reader structure"]
impl crate::Readable for Bkp12rSpec {}
#[doc = "`write(|w| ..)` method takes [`bkp12r::W`](W) writer structure"]
impl crate::Writable for Bkp12rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BKP12R to value 0"]
impl crate::Resettable for Bkp12rSpec {
    const RESET_VALUE: u32 = 0;
}
