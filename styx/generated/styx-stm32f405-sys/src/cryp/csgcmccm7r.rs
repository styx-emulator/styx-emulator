// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSGCMCCM7R` reader"]
pub type R = crate::R<Csgcmccm7rSpec>;
#[doc = "Register `CSGCMCCM7R` writer"]
pub type W = crate::W<Csgcmccm7rSpec>;
#[doc = "Field `CSGCMCCM7R` reader - CSGCMCCM7R"]
pub type Csgcmccm7rR = crate::FieldReader<u32>;
#[doc = "Field `CSGCMCCM7R` writer - CSGCMCCM7R"]
pub type Csgcmccm7rW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSGCMCCM7R"]
    #[inline(always)]
    pub fn csgcmccm7r(&self) -> Csgcmccm7rR {
        Csgcmccm7rR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSGCMCCM7R"]
    #[inline(always)]
    #[must_use]
    pub fn csgcmccm7r(&mut self) -> Csgcmccm7rW<Csgcmccm7rSpec> {
        Csgcmccm7rW::new(self, 0)
    }
}
#[doc = "context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm7r::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm7r::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csgcmccm7rSpec;
impl crate::RegisterSpec for Csgcmccm7rSpec {
    type Ux = u32;
    const OFFSET: u64 = 108u64;
}
#[doc = "`read()` method returns [`csgcmccm7r::R`](R) reader structure"]
impl crate::Readable for Csgcmccm7rSpec {}
#[doc = "`write(|w| ..)` method takes [`csgcmccm7r::W`](W) writer structure"]
impl crate::Writable for Csgcmccm7rSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSGCMCCM7R to value 0"]
impl crate::Resettable for Csgcmccm7rSpec {
    const RESET_VALUE: u32 = 0;
}
