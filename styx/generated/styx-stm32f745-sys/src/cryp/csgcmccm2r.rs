// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSGCMCCM2R` reader"]
pub type R = crate::R<Csgcmccm2rSpec>;
#[doc = "Register `CSGCMCCM2R` writer"]
pub type W = crate::W<Csgcmccm2rSpec>;
#[doc = "Field `CSGCMCCM2R` reader - CSGCMCCM2R"]
pub type Csgcmccm2rR = crate::FieldReader<u32>;
#[doc = "Field `CSGCMCCM2R` writer - CSGCMCCM2R"]
pub type Csgcmccm2rW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSGCMCCM2R"]
    #[inline(always)]
    pub fn csgcmccm2r(&self) -> Csgcmccm2rR {
        Csgcmccm2rR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSGCMCCM2R"]
    #[inline(always)]
    #[must_use]
    pub fn csgcmccm2r(&mut self) -> Csgcmccm2rW<Csgcmccm2rSpec> {
        Csgcmccm2rW::new(self, 0)
    }
}
#[doc = "context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm2r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm2r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csgcmccm2rSpec;
impl crate::RegisterSpec for Csgcmccm2rSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`csgcmccm2r::R`](R) reader structure"]
impl crate::Readable for Csgcmccm2rSpec {}
#[doc = "`write(|w| ..)` method takes [`csgcmccm2r::W`](W) writer structure"]
impl crate::Writable for Csgcmccm2rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSGCMCCM2R to value 0"]
impl crate::Resettable for Csgcmccm2rSpec {
    const RESET_VALUE: u32 = 0;
}
