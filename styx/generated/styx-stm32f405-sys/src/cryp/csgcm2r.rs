// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSGCM2R` reader"]
pub type R = crate::R<Csgcm2rSpec>;
#[doc = "Register `CSGCM2R` writer"]
pub type W = crate::W<Csgcm2rSpec>;
#[doc = "Field `CSGCM2R` reader - CSGCM2R"]
pub type Csgcm2rR = crate::FieldReader<u32>;
#[doc = "Field `CSGCM2R` writer - CSGCM2R"]
pub type Csgcm2rW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSGCM2R"]
    #[inline(always)]
    pub fn csgcm2r(&self) -> Csgcm2rR {
        Csgcm2rR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSGCM2R"]
    #[inline(always)]
    #[must_use]
    pub fn csgcm2r(&mut self) -> Csgcm2rW<Csgcm2rSpec> {
        Csgcm2rW::new(self, 0)
    }
}
#[doc = "context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm2r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm2r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csgcm2rSpec;
impl crate::RegisterSpec for Csgcm2rSpec {
    type Ux = u32;
    const OFFSET: u64 = 120u64;
}
#[doc = "`read()` method returns [`csgcm2r::R`](R) reader structure"]
impl crate::Readable for Csgcm2rSpec {}
#[doc = "`write(|w| ..)` method takes [`csgcm2r::W`](W) writer structure"]
impl crate::Writable for Csgcm2rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSGCM2R to value 0"]
impl crate::Resettable for Csgcm2rSpec {
    const RESET_VALUE: u32 = 0;
}
