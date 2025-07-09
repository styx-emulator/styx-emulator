// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `ctrlgrp_remappriority` reader"]
pub type R = crate::R<CtrlgrpRemapprioritySpec>;
#[doc = "Register `ctrlgrp_remappriority` writer"]
pub type W = crate::W<CtrlgrpRemapprioritySpec>;
#[doc = "Field `priorityremap` reader - Set bit N of this register to the value to a one to enable the controller command pool priority bit of a transaction from MPFE priority N"]
pub type PriorityremapR = crate::FieldReader;
#[doc = "Field `priorityremap` writer - Set bit N of this register to the value to a one to enable the controller command pool priority bit of a transaction from MPFE priority N"]
pub type PriorityremapW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Set bit N of this register to the value to a one to enable the controller command pool priority bit of a transaction from MPFE priority N"]
    #[inline(always)]
    pub fn priorityremap(&self) -> PriorityremapR {
        PriorityremapR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Set bit N of this register to the value to a one to enable the controller command pool priority bit of a transaction from MPFE priority N"]
    #[inline(always)]
    #[must_use]
    pub fn priorityremap(&mut self) -> PriorityremapW<CtrlgrpRemapprioritySpec> {
        PriorityremapW::new(self, 0)
    }
}
#[doc = "This register controls the priority for transactions in the controller command pool.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_remappriority::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_remappriority::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpRemapprioritySpec;
impl crate::RegisterSpec for CtrlgrpRemapprioritySpec {
    type Ux = u32;
    const OFFSET: u64 = 20704u64;
}
#[doc = "`read()` method returns [`ctrlgrp_remappriority::R`](R) reader structure"]
impl crate::Readable for CtrlgrpRemapprioritySpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_remappriority::W`](W) writer structure"]
impl crate::Writable for CtrlgrpRemapprioritySpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_remappriority to value 0"]
impl crate::Resettable for CtrlgrpRemapprioritySpec {
    const RESET_VALUE: u32 = 0;
}
