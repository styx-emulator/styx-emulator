// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dropaddr` reader"]
pub type R = crate::R<CtrlgrpDropaddrSpec>;
#[doc = "Register `ctrlgrp_dropaddr` writer"]
pub type W = crate::W<CtrlgrpDropaddrSpec>;
#[doc = "Field `corrdropaddr` reader - This register gives the last address which was dropped."]
pub type CorrdropaddrR = crate::FieldReader<u32>;
#[doc = "Field `corrdropaddr` writer - This register gives the last address which was dropped."]
pub type CorrdropaddrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This register gives the last address which was dropped."]
    #[inline(always)]
    pub fn corrdropaddr(&self) -> CorrdropaddrR {
        CorrdropaddrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This register gives the last address which was dropped."]
    #[inline(always)]
    #[must_use]
    pub fn corrdropaddr(&mut self) -> CorrdropaddrW<CtrlgrpDropaddrSpec> {
        CorrdropaddrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dropaddr::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dropaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDropaddrSpec;
impl crate::RegisterSpec for CtrlgrpDropaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20560u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dropaddr::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDropaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dropaddr::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDropaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
