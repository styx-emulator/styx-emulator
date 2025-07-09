// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PTPTSHUR` reader"]
pub type R = crate::R<PtptshurSpec>;
#[doc = "Register `PTPTSHUR` writer"]
pub type W = crate::W<PtptshurSpec>;
#[doc = "Field `TSUS` reader - TSUS"]
pub type TsusR = crate::FieldReader<u32>;
#[doc = "Field `TSUS` writer - TSUS"]
pub type TsusW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - TSUS"]
    #[inline(always)]
    pub fn tsus(&self) -> TsusR {
        TsusR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - TSUS"]
    #[inline(always)]
    #[must_use]
    pub fn tsus(&mut self) -> TsusW<PtptshurSpec> {
        TsusW::new(self, 0)
    }
}
#[doc = "Ethernet PTP time stamp high update register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptshur::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptshur::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptshurSpec;
impl crate::RegisterSpec for PtptshurSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`ptptshur::R`](R) reader structure"]
impl crate::Readable for PtptshurSpec {}
#[doc = "`write(|w| ..)` method takes [`ptptshur::W`](W) writer structure"]
impl crate::Writable for PtptshurSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PTPTSHUR to value 0"]
impl crate::Resettable for PtptshurSpec {
    const RESET_VALUE: u32 = 0;
}
