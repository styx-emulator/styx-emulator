// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_mppriority` reader"]
pub type R = crate::R<CtrlgrpMpprioritySpec>;
#[doc = "Register `ctrlgrp_mppriority` writer"]
pub type W = crate::W<CtrlgrpMpprioritySpec>;
#[doc = "Field `userpriority` reader - Set absolute user priority of the port. Each port is represented by a 3 bit value, 000=lowest priority, 111=highest priority. Port 0 is bits 2:0. Port number offset corresponds to the control port assignment."]
pub type UserpriorityR = crate::FieldReader<u32>;
#[doc = "Field `userpriority` writer - Set absolute user priority of the port. Each port is represented by a 3 bit value, 000=lowest priority, 111=highest priority. Port 0 is bits 2:0. Port number offset corresponds to the control port assignment."]
pub type UserpriorityW<'a, REG> = crate::FieldWriter<'a, REG, 30, u32>;
impl R {
    #[doc = "Bits 0:29 - Set absolute user priority of the port. Each port is represented by a 3 bit value, 000=lowest priority, 111=highest priority. Port 0 is bits 2:0. Port number offset corresponds to the control port assignment."]
    #[inline(always)]
    pub fn userpriority(&self) -> UserpriorityR {
        UserpriorityR::new(self.bits & 0x3fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:29 - Set absolute user priority of the port. Each port is represented by a 3 bit value, 000=lowest priority, 111=highest priority. Port 0 is bits 2:0. Port number offset corresponds to the control port assignment."]
    #[inline(always)]
    #[must_use]
    pub fn userpriority(&mut self) -> UserpriorityW<CtrlgrpMpprioritySpec> {
        UserpriorityW::new(self, 0)
    }
}
#[doc = "This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mppriority::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mppriority::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpMpprioritySpec;
impl crate::RegisterSpec for CtrlgrpMpprioritySpec {
    type Ux = u32;
    const OFFSET: u64 = 20652u64;
}
#[doc = "`read()` method returns [`ctrlgrp_mppriority::R`](R) reader structure"]
impl crate::Readable for CtrlgrpMpprioritySpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_mppriority::W`](W) writer structure"]
impl crate::Writable for CtrlgrpMpprioritySpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_mppriority to value 0"]
impl crate::Resettable for CtrlgrpMpprioritySpec {
    const RESET_VALUE: u32 = 0;
}
