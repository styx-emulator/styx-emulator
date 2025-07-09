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
#[doc = "Register `gmacgrp_System_Time_Higher_Word_Seconds` reader"]
pub type R = crate::R<GmacgrpSystemTimeHigherWordSecondsSpec>;
#[doc = "Register `gmacgrp_System_Time_Higher_Word_Seconds` writer"]
pub type W = crate::W<GmacgrpSystemTimeHigherWordSecondsSpec>;
#[doc = "Field `tshwr` reader - This field contains the most significant 16-bits of the timestamp seconds value. The register is directly written to initialize the value. This register is incremented when there is an overflow from the 32-bits of the System Time - Seconds register."]
pub type TshwrR = crate::FieldReader<u16>;
#[doc = "Field `tshwr` writer - This field contains the most significant 16-bits of the timestamp seconds value. The register is directly written to initialize the value. This register is incremented when there is an overflow from the 32-bits of the System Time - Seconds register."]
pub type TshwrW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This field contains the most significant 16-bits of the timestamp seconds value. The register is directly written to initialize the value. This register is incremented when there is an overflow from the 32-bits of the System Time - Seconds register."]
    #[inline(always)]
    pub fn tshwr(&self) -> TshwrR {
        TshwrR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field contains the most significant 16-bits of the timestamp seconds value. The register is directly written to initialize the value. This register is incremented when there is an overflow from the 32-bits of the System Time - Seconds register."]
    #[inline(always)]
    #[must_use]
    pub fn tshwr(&mut self) -> TshwrW<GmacgrpSystemTimeHigherWordSecondsSpec> {
        TshwrW::new(self, 0)
    }
}
#[doc = "System time higher word\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_higher_word_seconds::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_system_time_higher_word_seconds::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpSystemTimeHigherWordSecondsSpec;
impl crate::RegisterSpec for GmacgrpSystemTimeHigherWordSecondsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1828u64;
}
#[doc = "`read()` method returns [`gmacgrp_system_time_higher_word_seconds::R`](R) reader structure"]
impl crate::Readable for GmacgrpSystemTimeHigherWordSecondsSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_system_time_higher_word_seconds::W`](W) writer structure"]
impl crate::Writable for GmacgrpSystemTimeHigherWordSecondsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_System_Time_Higher_Word_Seconds to value 0"]
impl crate::Resettable for GmacgrpSystemTimeHigherWordSecondsSpec {
    const RESET_VALUE: u32 = 0;
}
