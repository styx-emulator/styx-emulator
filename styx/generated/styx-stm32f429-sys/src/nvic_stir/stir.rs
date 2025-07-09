// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `STIR` reader"]
pub type R = crate::R<StirSpec>;
#[doc = "Register `STIR` writer"]
pub type W = crate::W<StirSpec>;
#[doc = "Field `INTID` reader - Software generated interrupt ID"]
pub type IntidR = crate::FieldReader<u16>;
#[doc = "Field `INTID` writer - Software generated interrupt ID"]
pub type IntidW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
impl R {
    #[doc = "Bits 0:8 - Software generated interrupt ID"]
    #[inline(always)]
    pub fn intid(&self) -> IntidR {
        IntidR::new((self.bits & 0x01ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:8 - Software generated interrupt ID"]
    #[inline(always)]
    #[must_use]
    pub fn intid(&mut self) -> IntidW<StirSpec> {
        IntidW::new(self, 0)
    }
}
#[doc = "Software trigger interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stir::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stir::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StirSpec;
impl crate::RegisterSpec for StirSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`stir::R`](R) reader structure"]
impl crate::Readable for StirSpec {}
#[doc = "`write(|w| ..)` method takes [`stir::W`](W) writer structure"]
impl crate::Writable for StirSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets STIR to value 0"]
impl crate::Resettable for StirSpec {
    const RESET_VALUE: u32 = 0;
}
