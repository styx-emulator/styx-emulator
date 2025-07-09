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
#[doc = "Register `ctrlgrp_sbecount` reader"]
pub type R = crate::R<CtrlgrpSbecountSpec>;
#[doc = "Register `ctrlgrp_sbecount` writer"]
pub type W = crate::W<CtrlgrpSbecountSpec>;
#[doc = "Field `count` reader - Reports the number of single bit errors that have occurred since the status register counters were last cleared."]
pub type CountR = crate::FieldReader;
#[doc = "Field `count` writer - Reports the number of single bit errors that have occurred since the status register counters were last cleared."]
pub type CountW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Reports the number of single bit errors that have occurred since the status register counters were last cleared."]
    #[inline(always)]
    pub fn count(&self) -> CountR {
        CountR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Reports the number of single bit errors that have occurred since the status register counters were last cleared."]
    #[inline(always)]
    #[must_use]
    pub fn count(&mut self) -> CountW<CtrlgrpSbecountSpec> {
        CountW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_sbecount::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_sbecount::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpSbecountSpec;
impl crate::RegisterSpec for CtrlgrpSbecountSpec {
    type Ux = u32;
    const OFFSET: u64 = 20544u64;
}
#[doc = "`read()` method returns [`ctrlgrp_sbecount::R`](R) reader structure"]
impl crate::Readable for CtrlgrpSbecountSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_sbecount::W`](W) writer structure"]
impl crate::Writable for CtrlgrpSbecountSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_sbecount to value 0"]
impl crate::Resettable for CtrlgrpSbecountSpec {
    const RESET_VALUE: u32 = 0;
}
