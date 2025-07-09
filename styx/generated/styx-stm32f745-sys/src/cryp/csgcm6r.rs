// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSGCM6R` reader"]
pub type R = crate::R<Csgcm6rSpec>;
#[doc = "Register `CSGCM6R` writer"]
pub type W = crate::W<Csgcm6rSpec>;
#[doc = "Field `CSGCM6R` reader - CSGCM6R"]
pub type Csgcm6rR = crate::FieldReader<u32>;
#[doc = "Field `CSGCM6R` writer - CSGCM6R"]
pub type Csgcm6rW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSGCM6R"]
    #[inline(always)]
    pub fn csgcm6r(&self) -> Csgcm6rR {
        Csgcm6rR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSGCM6R"]
    #[inline(always)]
    #[must_use]
    pub fn csgcm6r(&mut self) -> Csgcm6rW<Csgcm6rSpec> {
        Csgcm6rW::new(self, 0)
    }
}
#[doc = "context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm6r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm6r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csgcm6rSpec;
impl crate::RegisterSpec for Csgcm6rSpec {
    type Ux = u32;
    const OFFSET: u64 = 136u64;
}
#[doc = "`read()` method returns [`csgcm6r::R`](R) reader structure"]
impl crate::Readable for Csgcm6rSpec {}
#[doc = "`write(|w| ..)` method takes [`csgcm6r::W`](W) writer structure"]
impl crate::Writable for Csgcm6rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSGCM6R to value 0"]
impl crate::Resettable for Csgcm6rSpec {
    const RESET_VALUE: u32 = 0;
}
