// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSGCM5R` reader"]
pub type R = crate::R<Csgcm5rSpec>;
#[doc = "Register `CSGCM5R` writer"]
pub type W = crate::W<Csgcm5rSpec>;
#[doc = "Field `CSGCM5R` reader - CSGCM5R"]
pub type Csgcm5rR = crate::FieldReader<u32>;
#[doc = "Field `CSGCM5R` writer - CSGCM5R"]
pub type Csgcm5rW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSGCM5R"]
    #[inline(always)]
    pub fn csgcm5r(&self) -> Csgcm5rR {
        Csgcm5rR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSGCM5R"]
    #[inline(always)]
    #[must_use]
    pub fn csgcm5r(&mut self) -> Csgcm5rW<Csgcm5rSpec> {
        Csgcm5rW::new(self, 0)
    }
}
#[doc = "context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm5r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm5r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csgcm5rSpec;
impl crate::RegisterSpec for Csgcm5rSpec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`read()` method returns [`csgcm5r::R`](R) reader structure"]
impl crate::Readable for Csgcm5rSpec {}
#[doc = "`write(|w| ..)` method takes [`csgcm5r::W`](W) writer structure"]
impl crate::Writable for Csgcm5rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSGCM5R to value 0"]
impl crate::Resettable for Csgcm5rSpec {
    const RESET_VALUE: u32 = 0;
}
