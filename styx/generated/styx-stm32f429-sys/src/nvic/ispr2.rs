// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ISPR2` reader"]
pub type R = crate::R<Ispr2Spec>;
#[doc = "Register `ISPR2` writer"]
pub type W = crate::W<Ispr2Spec>;
#[doc = "Field `SETPEND` reader - SETPEND"]
pub type SetpendR = crate::FieldReader<u32>;
#[doc = "Field `SETPEND` writer - SETPEND"]
pub type SetpendW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - SETPEND"]
    #[inline(always)]
    pub fn setpend(&self) -> SetpendR {
        SetpendR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - SETPEND"]
    #[inline(always)]
    #[must_use]
    pub fn setpend(&mut self) -> SetpendW<Ispr2Spec> {
        SetpendW::new(self, 0)
    }
}
#[doc = "Interrupt Set-Pending Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ispr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ispr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ispr2Spec;
impl crate::RegisterSpec for Ispr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 264u64;
}
#[doc = "`read()` method returns [`ispr2::R`](R) reader structure"]
impl crate::Readable for Ispr2Spec {}
#[doc = "`write(|w| ..)` method takes [`ispr2::W`](W) writer structure"]
impl crate::Writable for Ispr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ISPR2 to value 0"]
impl crate::Resettable for Ispr2Spec {
    const RESET_VALUE: u32 = 0;
}
