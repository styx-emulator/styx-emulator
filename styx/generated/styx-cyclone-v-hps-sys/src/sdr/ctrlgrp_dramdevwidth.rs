// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dramdevwidth` reader"]
pub type R = crate::R<CtrlgrpDramdevwidthSpec>;
#[doc = "Register `ctrlgrp_dramdevwidth` writer"]
pub type W = crate::W<CtrlgrpDramdevwidthSpec>;
#[doc = "Field `devwidth` reader - This register specifies the width of the physical DRAM chips, for example 8 or 16."]
pub type DevwidthR = crate::FieldReader;
#[doc = "Field `devwidth` writer - This register specifies the width of the physical DRAM chips, for example 8 or 16."]
pub type DevwidthW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - This register specifies the width of the physical DRAM chips, for example 8 or 16."]
    #[inline(always)]
    pub fn devwidth(&self) -> DevwidthR {
        DevwidthR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - This register specifies the width of the physical DRAM chips, for example 8 or 16."]
    #[inline(always)]
    #[must_use]
    pub fn devwidth(&mut self) -> DevwidthW<CtrlgrpDramdevwidthSpec> {
        DevwidthW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramdevwidth::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramdevwidth::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramdevwidthSpec;
impl crate::RegisterSpec for CtrlgrpDramdevwidthSpec {
    type Ux = u32;
    const OFFSET: u64 = 20532u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramdevwidth::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramdevwidthSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramdevwidth::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramdevwidthSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramdevwidth to value 0"]
impl crate::Resettable for CtrlgrpDramdevwidthSpec {
    const RESET_VALUE: u32 = 0;
}
