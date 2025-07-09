// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OPTCR1` reader"]
pub type R = crate::R<Optcr1Spec>;
#[doc = "Register `OPTCR1` writer"]
pub type W = crate::W<Optcr1Spec>;
#[doc = "Field `nWRP` reader - Not write protect"]
pub type NWrpR = crate::FieldReader<u16>;
#[doc = "Field `nWRP` writer - Not write protect"]
pub type NWrpW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 16:27 - Not write protect"]
    #[inline(always)]
    pub fn n_wrp(&self) -> NWrpR {
        NWrpR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 16:27 - Not write protect"]
    #[inline(always)]
    #[must_use]
    pub fn n_wrp(&mut self) -> NWrpW<Optcr1Spec> {
        NWrpW::new(self, 16)
    }
}
#[doc = "Flash option control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`optcr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`optcr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Optcr1Spec;
impl crate::RegisterSpec for Optcr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`optcr1::R`](R) reader structure"]
impl crate::Readable for Optcr1Spec {}
#[doc = "`write(|w| ..)` method takes [`optcr1::W`](W) writer structure"]
impl crate::Writable for Optcr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OPTCR1 to value 0x0fff_0000"]
impl crate::Resettable for Optcr1Spec {
    const RESET_VALUE: u32 = 0x0fff_0000;
}
