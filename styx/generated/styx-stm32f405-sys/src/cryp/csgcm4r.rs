// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSGCM4R` reader"]
pub type R = crate::R<Csgcm4rSpec>;
#[doc = "Register `CSGCM4R` writer"]
pub type W = crate::W<Csgcm4rSpec>;
#[doc = "Field `CSGCM4R` reader - CSGCM4R"]
pub type Csgcm4rR = crate::FieldReader<u32>;
#[doc = "Field `CSGCM4R` writer - CSGCM4R"]
pub type Csgcm4rW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSGCM4R"]
    #[inline(always)]
    pub fn csgcm4r(&self) -> Csgcm4rR {
        Csgcm4rR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSGCM4R"]
    #[inline(always)]
    #[must_use]
    pub fn csgcm4r(&mut self) -> Csgcm4rW<Csgcm4rSpec> {
        Csgcm4rW::new(self, 0)
    }
}
#[doc = "context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm4r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm4r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csgcm4rSpec;
impl crate::RegisterSpec for Csgcm4rSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`csgcm4r::R`](R) reader structure"]
impl crate::Readable for Csgcm4rSpec {}
#[doc = "`write(|w| ..)` method takes [`csgcm4r::W`](W) writer structure"]
impl crate::Writable for Csgcm4rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSGCM4R to value 0"]
impl crate::Resettable for Csgcm4rSpec {
    const RESET_VALUE: u32 = 0;
}
