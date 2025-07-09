// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `JOFR2` reader"]
pub type R = crate::R<Jofr2Spec>;
#[doc = "Register `JOFR2` writer"]
pub type W = crate::W<Jofr2Spec>;
#[doc = "Field `JOFFSET2` reader - Data offset for injected channel x"]
pub type Joffset2R = crate::FieldReader<u16>;
#[doc = "Field `JOFFSET2` writer - Data offset for injected channel x"]
pub type Joffset2W<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Data offset for injected channel x"]
    #[inline(always)]
    pub fn joffset2(&self) -> Joffset2R {
        Joffset2R::new((self.bits & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Data offset for injected channel x"]
    #[inline(always)]
    #[must_use]
    pub fn joffset2(&mut self) -> Joffset2W<Jofr2Spec> {
        Joffset2W::new(self, 0)
    }
}
#[doc = "injected channel data offset register x\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`jofr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`jofr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Jofr2Spec;
impl crate::RegisterSpec for Jofr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`jofr2::R`](R) reader structure"]
impl crate::Readable for Jofr2Spec {}
#[doc = "`write(|w| ..)` method takes [`jofr2::W`](W) writer structure"]
impl crate::Writable for Jofr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets JOFR2 to value 0"]
impl crate::Resettable for Jofr2Spec {
    const RESET_VALUE: u32 = 0;
}
