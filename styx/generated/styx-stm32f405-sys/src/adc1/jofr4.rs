// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `JOFR4` reader"]
pub type R = crate::R<Jofr4Spec>;
#[doc = "Register `JOFR4` writer"]
pub type W = crate::W<Jofr4Spec>;
#[doc = "Field `JOFFSET4` reader - Data offset for injected channel x"]
pub type Joffset4R = crate::FieldReader<u16>;
#[doc = "Field `JOFFSET4` writer - Data offset for injected channel x"]
pub type Joffset4W<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Data offset for injected channel x"]
    #[inline(always)]
    pub fn joffset4(&self) -> Joffset4R {
        Joffset4R::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Data offset for injected channel x"]
    #[inline(always)]
    #[must_use]
    pub fn joffset4(&mut self) -> Joffset4W<Jofr4Spec> {
        Joffset4W::new(self, 0)
    }
}
#[doc = "injected channel data offset register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jofr4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jofr4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Jofr4Spec;
impl crate::RegisterSpec for Jofr4Spec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`jofr4::R`](R) reader structure"]
impl crate::Readable for Jofr4Spec {}
#[doc = "`write(|w| ..)` method takes [`jofr4::W`](W) writer structure"]
impl crate::Writable for Jofr4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets JOFR4 to value 0"]
impl crate::Resettable for Jofr4Spec {
    const RESET_VALUE: u32 = 0;
}
