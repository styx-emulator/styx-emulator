// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_qoslowpri` reader"]
pub type R = crate::R<CtrlgrpQoslowpriSpec>;
#[doc = "Register `ctrlgrp_qoslowpri` writer"]
pub type W = crate::W<CtrlgrpQoslowpriSpec>;
#[doc = "Field `lowpriorityval` reader - This 20 bit field is a 2 bit field for each of the 10 ports. The field used for each port in this register controls the priority used for a port"]
pub type LowpriorityvalR = crate::FieldReader<u32>;
#[doc = "Field `lowpriorityval` writer - This 20 bit field is a 2 bit field for each of the 10 ports. The field used for each port in this register controls the priority used for a port"]
pub type LowpriorityvalW<'a, REG> = crate::FieldWriter<'a, REG, 20, u32>;
impl R {
    #[doc = "Bits 0:19 - This 20 bit field is a 2 bit field for each of the 10 ports. The field used for each port in this register controls the priority used for a port"]
    #[inline(always)]
    pub fn lowpriorityval(&self) -> LowpriorityvalR {
        LowpriorityvalR::new(self.bits & 0x000f_ffff)
    }
}
impl W {
    #[doc = "Bits 0:19 - This 20 bit field is a 2 bit field for each of the 10 ports. The field used for each port in this register controls the priority used for a port"]
    #[inline(always)]
    #[must_use]
    pub fn lowpriorityval(&mut self) -> LowpriorityvalW<CtrlgrpQoslowpriSpec> {
        LowpriorityvalW::new(self, 0)
    }
}
#[doc = "This register controls the mapping of AXI4 QOS received from the FPGA fabric to the internal priority used for traffic prioritization.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_qoslowpri::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_qoslowpri::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpQoslowpriSpec;
impl crate::RegisterSpec for CtrlgrpQoslowpriSpec {
    type Ux = u32;
    const OFFSET: u64 = 20640u64;
}
#[doc = "`read()` method returns [`ctrlgrp_qoslowpri::R`](R) reader structure"]
impl crate::Readable for CtrlgrpQoslowpriSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_qoslowpri::W`](W) writer structure"]
impl crate::Writable for CtrlgrpQoslowpriSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_qoslowpri to value 0"]
impl crate::Resettable for CtrlgrpQoslowpriSpec {
    const RESET_VALUE: u32 = 0;
}
