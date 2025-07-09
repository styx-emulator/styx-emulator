// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `JOFR3` reader"]
pub type R = crate::R<Jofr3Spec>;
#[doc = "Register `JOFR3` writer"]
pub type W = crate::W<Jofr3Spec>;
#[doc = "Field `JOFFSET3` reader - Data offset for injected channel x"]
pub type Joffset3R = crate::FieldReader<u16>;
#[doc = "Field `JOFFSET3` writer - Data offset for injected channel x"]
pub type Joffset3W<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Data offset for injected channel x"]
    #[inline(always)]
    pub fn joffset3(&self) -> Joffset3R {
        Joffset3R::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Data offset for injected channel x"]
    #[inline(always)]
    #[must_use]
    pub fn joffset3(&mut self) -> Joffset3W<Jofr3Spec> {
        Joffset3W::new(self, 0)
    }
}
#[doc = "injected channel data offset register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jofr3::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jofr3::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Jofr3Spec;
impl crate::RegisterSpec for Jofr3Spec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`jofr3::R`](R) reader structure"]
impl crate::Readable for Jofr3Spec {}
#[doc = "`write(|w| ..)` method takes [`jofr3::W`](W) writer structure"]
impl crate::Writable for Jofr3Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets JOFR3 to value 0"]
impl crate::Resettable for Jofr3Spec {
    const RESET_VALUE: u32 = 0;
}
