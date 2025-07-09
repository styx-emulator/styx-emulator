// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSGCM1R` reader"]
pub type R = crate::R<Csgcm1rSpec>;
#[doc = "Register `CSGCM1R` writer"]
pub type W = crate::W<Csgcm1rSpec>;
#[doc = "Field `CSGCM1R` reader - CSGCM1R"]
pub type Csgcm1rR = crate::FieldReader<u32>;
#[doc = "Field `CSGCM1R` writer - CSGCM1R"]
pub type Csgcm1rW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSGCM1R"]
    #[inline(always)]
    pub fn csgcm1r(&self) -> Csgcm1rR {
        Csgcm1rR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSGCM1R"]
    #[inline(always)]
    #[must_use]
    pub fn csgcm1r(&mut self) -> Csgcm1rW<Csgcm1rSpec> {
        Csgcm1rW::new(self, 0)
    }
}
#[doc = "context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm1r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm1r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csgcm1rSpec;
impl crate::RegisterSpec for Csgcm1rSpec {
    type Ux = u32;
    const OFFSET: u64 = 116u64;
}
#[doc = "`read()` method returns [`csgcm1r::R`](R) reader structure"]
impl crate::Readable for Csgcm1rSpec {}
#[doc = "`write(|w| ..)` method takes [`csgcm1r::W`](W) writer structure"]
impl crate::Writable for Csgcm1rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSGCM1R to value 0"]
impl crate::Resettable for Csgcm1rSpec {
    const RESET_VALUE: u32 = 0;
}
