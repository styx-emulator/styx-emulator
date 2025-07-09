// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BKP27R` reader"]
pub type R = crate::R<Bkp27rSpec>;
#[doc = "Register `BKP27R` writer"]
pub type W = crate::W<Bkp27rSpec>;
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
    pub fn bkp(&mut self) -> BkpW<Bkp27rSpec> {
        BkpW::new(self, 0)
    }
}
#[doc = "backup register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bkp27r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bkp27r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Bkp27rSpec;
impl crate::RegisterSpec for Bkp27rSpec {
    type Ux = u32;
    const OFFSET: u64 = 188u64;
}
#[doc = "`read()` method returns [`bkp27r::R`](R) reader structure"]
impl crate::Readable for Bkp27rSpec {}
#[doc = "`write(|w| ..)` method takes [`bkp27r::W`](W) writer structure"]
impl crate::Writable for Bkp27rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BKP27R to value 0"]
impl crate::Resettable for Bkp27rSpec {
    const RESET_VALUE: u32 = 0;
}
