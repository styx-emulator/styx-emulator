// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSGCMCCM5R` reader"]
pub type R = crate::R<Csgcmccm5rSpec>;
#[doc = "Register `CSGCMCCM5R` writer"]
pub type W = crate::W<Csgcmccm5rSpec>;
#[doc = "Field `CSGCMCCM5R` reader - CSGCMCCM5R"]
pub type Csgcmccm5rR = crate::FieldReader<u32>;
#[doc = "Field `CSGCMCCM5R` writer - CSGCMCCM5R"]
pub type Csgcmccm5rW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSGCMCCM5R"]
    #[inline(always)]
    pub fn csgcmccm5r(&self) -> Csgcmccm5rR {
        Csgcmccm5rR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSGCMCCM5R"]
    #[inline(always)]
    #[must_use]
    pub fn csgcmccm5r(&mut self) -> Csgcmccm5rW<Csgcmccm5rSpec> {
        Csgcmccm5rW::new(self, 0)
    }
}
#[doc = "context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm5r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm5r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csgcmccm5rSpec;
impl crate::RegisterSpec for Csgcmccm5rSpec {
    type Ux = u32;
    const OFFSET: u64 = 100u64;
}
#[doc = "`read()` method returns [`csgcmccm5r::R`](R) reader structure"]
impl crate::Readable for Csgcmccm5rSpec {}
#[doc = "`write(|w| ..)` method takes [`csgcmccm5r::W`](W) writer structure"]
impl crate::Writable for Csgcmccm5rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSGCMCCM5R to value 0"]
impl crate::Resettable for Csgcmccm5rSpec {
    const RESET_VALUE: u32 = 0;
}
