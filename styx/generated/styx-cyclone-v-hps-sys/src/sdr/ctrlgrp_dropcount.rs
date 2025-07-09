// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dropcount` reader"]
pub type R = crate::R<CtrlgrpDropcountSpec>;
#[doc = "Register `ctrlgrp_dropcount` writer"]
pub type W = crate::W<CtrlgrpDropcountSpec>;
#[doc = "Field `corrdropcount` reader - This gives the count of the number of ECC write back transactions dropped due to the internal FIFO overflowing."]
pub type CorrdropcountR = crate::FieldReader;
#[doc = "Field `corrdropcount` writer - This gives the count of the number of ECC write back transactions dropped due to the internal FIFO overflowing."]
pub type CorrdropcountW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - This gives the count of the number of ECC write back transactions dropped due to the internal FIFO overflowing."]
    #[inline(always)]
    pub fn corrdropcount(&self) -> CorrdropcountR {
        CorrdropcountR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This gives the count of the number of ECC write back transactions dropped due to the internal FIFO overflowing."]
    #[inline(always)]
    #[must_use]
    pub fn corrdropcount(&mut self) -> CorrdropcountW<CtrlgrpDropcountSpec> {
        CorrdropcountW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dropcount::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dropcount::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDropcountSpec;
impl crate::RegisterSpec for CtrlgrpDropcountSpec {
    type Ux = u32;
    const OFFSET: u64 = 20556u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dropcount::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDropcountSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dropcount::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDropcountSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dropcount to value 0"]
impl crate::Resettable for CtrlgrpDropcountSpec {
    const RESET_VALUE: u32 = 0;
}
