// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dramifwidth` reader"]
pub type R = crate::R<CtrlgrpDramifwidthSpec>;
#[doc = "Register `ctrlgrp_dramifwidth` writer"]
pub type W = crate::W<CtrlgrpDramifwidthSpec>;
#[doc = "Field `ifwidth` reader - This register controls the interface width of the SDRAM interface, including any bits used for ECC. For example, for a 32-bit interface with ECC, program this register with 0x28. You must also program the ctrlwidth register."]
pub type IfwidthR = crate::FieldReader;
#[doc = "Field `ifwidth` writer - This register controls the interface width of the SDRAM interface, including any bits used for ECC. For example, for a 32-bit interface with ECC, program this register with 0x28. You must also program the ctrlwidth register."]
pub type IfwidthW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - This register controls the interface width of the SDRAM interface, including any bits used for ECC. For example, for a 32-bit interface with ECC, program this register with 0x28. You must also program the ctrlwidth register."]
    #[inline(always)]
    pub fn ifwidth(&self) -> IfwidthR {
        IfwidthR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This register controls the interface width of the SDRAM interface, including any bits used for ECC. For example, for a 32-bit interface with ECC, program this register with 0x28. You must also program the ctrlwidth register."]
    #[inline(always)]
    #[must_use]
    pub fn ifwidth(&mut self) -> IfwidthW<CtrlgrpDramifwidthSpec> {
        IfwidthW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramifwidth::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramifwidth::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramifwidthSpec;
impl crate::RegisterSpec for CtrlgrpDramifwidthSpec {
    type Ux = u32;
    const OFFSET: u64 = 20528u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramifwidth::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramifwidthSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramifwidth::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramifwidthSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramifwidth to value 0"]
impl crate::Resettable for CtrlgrpDramifwidthSpec {
    const RESET_VALUE: u32 = 0;
}
