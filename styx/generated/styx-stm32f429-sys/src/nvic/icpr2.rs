// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ICPR2` reader"]
pub type R = crate::R<Icpr2Spec>;
#[doc = "Register `ICPR2` writer"]
pub type W = crate::W<Icpr2Spec>;
#[doc = "Field `CLRPEND` reader - CLRPEND"]
pub type ClrpendR = crate::FieldReader<u32>;
#[doc = "Field `CLRPEND` writer - CLRPEND"]
pub type ClrpendW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CLRPEND"]
    #[inline(always)]
    pub fn clrpend(&self) -> ClrpendR {
        ClrpendR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CLRPEND"]
    #[inline(always)]
    #[must_use]
    pub fn clrpend(&mut self) -> ClrpendW<Icpr2Spec> {
        ClrpendW::new(self, 0)
    }
}
#[doc = "Interrupt Clear-Pending Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icpr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icpr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Icpr2Spec;
impl crate::RegisterSpec for Icpr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 392u64;
}
#[doc = "`read()` method returns [`icpr2::R`](R) reader structure"]
impl crate::Readable for Icpr2Spec {}
#[doc = "`write(|w| ..)` method takes [`icpr2::W`](W) writer structure"]
impl crate::Writable for Icpr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ICPR2 to value 0"]
impl crate::Resettable for Icpr2Spec {
    const RESET_VALUE: u32 = 0;
}
