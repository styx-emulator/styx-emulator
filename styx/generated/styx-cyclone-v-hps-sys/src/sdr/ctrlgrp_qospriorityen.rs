// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_qospriorityen` reader"]
pub type R = crate::R<CtrlgrpQospriorityenSpec>;
#[doc = "Register `ctrlgrp_qospriorityen` writer"]
pub type W = crate::W<CtrlgrpQospriorityenSpec>;
#[doc = "Field `priorityen` reader - This 10 bit field is set to a one to enable QOS usage for a port."]
pub type PriorityenR = crate::FieldReader<u16>;
#[doc = "Field `priorityen` writer - This 10 bit field is set to a one to enable QOS usage for a port."]
pub type PriorityenW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
impl R {
    #[doc = "Bits 0:9 - This 10 bit field is set to a one to enable QOS usage for a port."]
    #[inline(always)]
    pub fn priorityen(&self) -> PriorityenR {
        PriorityenR::new((self.bits & 0x03ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:9 - This 10 bit field is set to a one to enable QOS usage for a port."]
    #[inline(always)]
    #[must_use]
    pub fn priorityen(&mut self) -> PriorityenW<CtrlgrpQospriorityenSpec> {
        PriorityenW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_qospriorityen::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_qospriorityen::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpQospriorityenSpec;
impl crate::RegisterSpec for CtrlgrpQospriorityenSpec {
    type Ux = u32;
    const OFFSET: u64 = 20648u64;
}
#[doc = "`read()` method returns [`ctrlgrp_qospriorityen::R`](R) reader structure"]
impl crate::Readable for CtrlgrpQospriorityenSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_qospriorityen::W`](W) writer structure"]
impl crate::Writable for CtrlgrpQospriorityenSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_qospriorityen to value 0"]
impl crate::Resettable for CtrlgrpQospriorityenSpec {
    const RESET_VALUE: u32 = 0;
}
