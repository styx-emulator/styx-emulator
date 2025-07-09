// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_qoshighpri` reader"]
pub type R = crate::R<CtrlgrpQoshighpriSpec>;
#[doc = "Register `ctrlgrp_qoshighpri` writer"]
pub type W = crate::W<CtrlgrpQoshighpriSpec>;
#[doc = "Field `highpriorityval` reader - This 20 bit field is a 2 bit field for each of the 10 ports. The field used for each port in this register controls the priority used for a port"]
pub type HighpriorityvalR = crate::FieldReader<u32>;
#[doc = "Field `highpriorityval` writer - This 20 bit field is a 2 bit field for each of the 10 ports. The field used for each port in this register controls the priority used for a port"]
pub type HighpriorityvalW<'a, REG> = crate::FieldWriter<'a, REG, 20, u32>;
impl R {
    #[doc = "Bits 0:19 - This 20 bit field is a 2 bit field for each of the 10 ports. The field used for each port in this register controls the priority used for a port"]
    #[inline(always)]
    pub fn highpriorityval(&self) -> HighpriorityvalR {
        HighpriorityvalR::new(self.bits & 0x000f_ffff)
    }
}
impl W {
    #[doc = "Bits 0:19 - This 20 bit field is a 2 bit field for each of the 10 ports. The field used for each port in this register controls the priority used for a port"]
    #[inline(always)]
    #[must_use]
    pub fn highpriorityval(&mut self) -> HighpriorityvalW<CtrlgrpQoshighpriSpec> {
        HighpriorityvalW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_qoshighpri::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_qoshighpri::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpQoshighpriSpec;
impl crate::RegisterSpec for CtrlgrpQoshighpriSpec {
    type Ux = u32;
    const OFFSET: u64 = 20644u64;
}
#[doc = "`read()` method returns [`ctrlgrp_qoshighpri::R`](R) reader structure"]
impl crate::Readable for CtrlgrpQoshighpriSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_qoshighpri::W`](W) writer structure"]
impl crate::Writable for CtrlgrpQoshighpriSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_qoshighpri to value 0"]
impl crate::Resettable for CtrlgrpQoshighpriSpec {
    const RESET_VALUE: u32 = 0;
}
