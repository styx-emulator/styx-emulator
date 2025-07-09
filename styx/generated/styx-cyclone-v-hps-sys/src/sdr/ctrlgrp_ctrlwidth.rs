// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_ctrlwidth` reader"]
pub type R = crate::R<CtrlgrpCtrlwidthSpec>;
#[doc = "Register `ctrlgrp_ctrlwidth` writer"]
pub type W = crate::W<CtrlgrpCtrlwidthSpec>;
#[doc = "Field `ctrlwidth` reader - Specifies controller DRAM interface width, with the following encoding. &amp;quot;00&amp;quot; for 8-bit, &amp;quot;01&amp;quot; for 16-bit (no ECC) or 24-bit (ECC enabled), &amp;quot;10&amp;quot; for 32-bit (no ECC) or 40-bit (ECC enabled). You must also program the dramifwidth register."]
pub type CtrlwidthR = crate::FieldReader;
#[doc = "Field `ctrlwidth` writer - Specifies controller DRAM interface width, with the following encoding. &amp;quot;00&amp;quot; for 8-bit, &amp;quot;01&amp;quot; for 16-bit (no ECC) or 24-bit (ECC enabled), &amp;quot;10&amp;quot; for 32-bit (no ECC) or 40-bit (ECC enabled). You must also program the dramifwidth register."]
pub type CtrlwidthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Specifies controller DRAM interface width, with the following encoding. &amp;quot;00&amp;quot; for 8-bit, &amp;quot;01&amp;quot; for 16-bit (no ECC) or 24-bit (ECC enabled), &amp;quot;10&amp;quot; for 32-bit (no ECC) or 40-bit (ECC enabled). You must also program the dramifwidth register."]
    #[inline(always)]
    pub fn ctrlwidth(&self) -> CtrlwidthR {
        CtrlwidthR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Specifies controller DRAM interface width, with the following encoding. &amp;quot;00&amp;quot; for 8-bit, &amp;quot;01&amp;quot; for 16-bit (no ECC) or 24-bit (ECC enabled), &amp;quot;10&amp;quot; for 32-bit (no ECC) or 40-bit (ECC enabled). You must also program the dramifwidth register."]
    #[inline(always)]
    #[must_use]
    pub fn ctrlwidth(&mut self) -> CtrlwidthW<CtrlgrpCtrlwidthSpec> {
        CtrlwidthW::new(self, 0)
    }
}
#[doc = "This register controls the width of the physical DRAM interface.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_ctrlwidth::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_ctrlwidth::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpCtrlwidthSpec;
impl crate::RegisterSpec for CtrlgrpCtrlwidthSpec {
    type Ux = u32;
    const OFFSET: u64 = 20576u64;
}
#[doc = "`read()` method returns [`ctrlgrp_ctrlwidth::R`](R) reader structure"]
impl crate::Readable for CtrlgrpCtrlwidthSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_ctrlwidth::W`](W) writer structure"]
impl crate::Writable for CtrlgrpCtrlwidthSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_ctrlwidth to value 0"]
impl crate::Resettable for CtrlgrpCtrlwidthSpec {
    const RESET_VALUE: u32 = 0;
}
