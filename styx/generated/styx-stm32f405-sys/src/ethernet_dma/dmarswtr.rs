// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMARSWTR` reader"]
pub type R = crate::R<DmarswtrSpec>;
#[doc = "Register `DMARSWTR` writer"]
pub type W = crate::W<DmarswtrSpec>;
#[doc = "Field `RSWTC` reader - RSWTC"]
pub type RswtcR = crate::FieldReader;
#[doc = "Field `RSWTC` writer - RSWTC"]
pub type RswtcW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - RSWTC"]
    #[inline(always)]
    pub fn rswtc(&self) -> RswtcR {
        RswtcR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - RSWTC"]
    #[inline(always)]
    #[must_use]
    pub fn rswtc(&mut self) -> RswtcW<DmarswtrSpec> {
        RswtcW::new(self, 0)
    }
}
#[doc = "Ethernet DMA receive status watchdog timer register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmarswtr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmarswtr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmarswtrSpec;
impl crate::RegisterSpec for DmarswtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`dmarswtr::R`](R) reader structure"]
impl crate::Readable for DmarswtrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmarswtr::W`](W) writer structure"]
impl crate::Writable for DmarswtrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMARSWTR to value 0"]
impl crate::Resettable for DmarswtrSpec {
    const RESET_VALUE: u32 = 0;
}
