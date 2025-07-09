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
#[doc = "Register `gmacgrp_System_Time_Seconds` reader"]
pub type R = crate::R<GmacgrpSystemTimeSecondsSpec>;
#[doc = "Register `gmacgrp_System_Time_Seconds` writer"]
pub type W = crate::W<GmacgrpSystemTimeSecondsSpec>;
#[doc = "Field `tss` reader - The value in this field indicates the current value in seconds of the System Time maintained by the MAC."]
pub type TssR = crate::FieldReader<u32>;
#[doc = "Field `tss` writer - The value in this field indicates the current value in seconds of the System Time maintained by the MAC."]
pub type TssW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - The value in this field indicates the current value in seconds of the System Time maintained by the MAC."]
    #[inline(always)]
    pub fn tss(&self) -> TssR {
        TssR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - The value in this field indicates the current value in seconds of the System Time maintained by the MAC."]
    #[inline(always)]
    #[must_use]
    pub fn tss(&mut self) -> TssW<GmacgrpSystemTimeSecondsSpec> {
        TssW::new(self, 0)
    }
}
#[doc = "The System Time -Seconds register, along with System-TimeNanoseconds register, indicates the current value of the system time maintained by the MAC. Though it is updated on a continuous basis, there is some delay from the actual time because of clock domain transfer latencies (from clk_ptp_ref_i to l3_sp_clk).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_seconds::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpSystemTimeSecondsSpec;
impl crate::RegisterSpec for GmacgrpSystemTimeSecondsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1800u64;
}
#[doc = "`read()` method returns [`gmacgrp_system_time_seconds::R`](R) reader structure"]
impl crate::Readable for GmacgrpSystemTimeSecondsSpec {}
#[doc = "`reset()` method sets gmacgrp_System_Time_Seconds to value 0"]
impl crate::Resettable for GmacgrpSystemTimeSecondsSpec {
    const RESET_VALUE: u32 = 0;
}
