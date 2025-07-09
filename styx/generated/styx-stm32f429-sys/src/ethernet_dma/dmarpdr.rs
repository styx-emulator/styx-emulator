// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMARPDR` reader"]
pub type R = crate::R<DmarpdrSpec>;
#[doc = "Register `DMARPDR` writer"]
pub type W = crate::W<DmarpdrSpec>;
#[doc = "Field `RPD` reader - RPD"]
pub type RpdR = crate::FieldReader<u32>;
#[doc = "Field `RPD` writer - RPD"]
pub type RpdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - RPD"]
    #[inline(always)]
    pub fn rpd(&self) -> RpdR {
        RpdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - RPD"]
    #[inline(always)]
    #[must_use]
    pub fn rpd(&mut self) -> RpdW<DmarpdrSpec> {
        RpdW::new(self, 0)
    }
}
#[doc = "EHERNET DMA receive poll demand register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmarpdr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmarpdr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmarpdrSpec;
impl crate::RegisterSpec for DmarpdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`dmarpdr::R`](R) reader structure"]
impl crate::Readable for DmarpdrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmarpdr::W`](W) writer structure"]
impl crate::Writable for DmarpdrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMARPDR to value 0"]
impl crate::Resettable for DmarpdrSpec {
    const RESET_VALUE: u32 = 0;
}
