// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ABR` reader"]
pub type R = crate::R<AbrSpec>;
#[doc = "Register `ABR` writer"]
pub type W = crate::W<AbrSpec>;
#[doc = "Field `ALTERNATE` reader - ALTERNATE"]
pub type AlternateR = crate::FieldReader<u32>;
#[doc = "Field `ALTERNATE` writer - ALTERNATE"]
pub type AlternateW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - ALTERNATE"]
    #[inline(always)]
    pub fn alternate(&self) -> AlternateR {
        AlternateR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - ALTERNATE"]
    #[inline(always)]
    #[must_use]
    pub fn alternate(&mut self) -> AlternateW<AbrSpec> {
        AlternateW::new(self, 0)
    }
}
#[doc = "ABR\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`abr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`abr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AbrSpec;
impl crate::RegisterSpec for AbrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`abr::R`](R) reader structure"]
impl crate::Readable for AbrSpec {}
#[doc = "`write(|w| ..)` method takes [`abr::W`](W) writer structure"]
impl crate::Writable for AbrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ABR to value 0"]
impl crate::Resettable for AbrSpec {
    const RESET_VALUE: u32 = 0;
}
