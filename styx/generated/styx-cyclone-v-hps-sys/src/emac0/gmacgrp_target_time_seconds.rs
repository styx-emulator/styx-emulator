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
#[doc = "Register `gmacgrp_Target_Time_Seconds` reader"]
pub type R = crate::R<GmacgrpTargetTimeSecondsSpec>;
#[doc = "Register `gmacgrp_Target_Time_Seconds` writer"]
pub type W = crate::W<GmacgrpTargetTimeSecondsSpec>;
#[doc = "Field `tstr` reader - This register stores the time in seconds. When the timestamp value matches or exceeds both Target Timestamp registers, then based on Bits \\[6:5\\]
of Register 459 (PPS Control Register), the MAC starts or stops the PPS signal output and generates an interrupt (if enabled)."]
pub type TstrR = crate::FieldReader<u32>;
#[doc = "Field `tstr` writer - This register stores the time in seconds. When the timestamp value matches or exceeds both Target Timestamp registers, then based on Bits \\[6:5\\]
of Register 459 (PPS Control Register), the MAC starts or stops the PPS signal output and generates an interrupt (if enabled)."]
pub type TstrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This register stores the time in seconds. When the timestamp value matches or exceeds both Target Timestamp registers, then based on Bits \\[6:5\\]
of Register 459 (PPS Control Register), the MAC starts or stops the PPS signal output and generates an interrupt (if enabled)."]
    #[inline(always)]
    pub fn tstr(&self) -> TstrR {
        TstrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This register stores the time in seconds. When the timestamp value matches or exceeds both Target Timestamp registers, then based on Bits \\[6:5\\]
of Register 459 (PPS Control Register), the MAC starts or stops the PPS signal output and generates an interrupt (if enabled)."]
    #[inline(always)]
    #[must_use]
    pub fn tstr(&mut self) -> TstrW<GmacgrpTargetTimeSecondsSpec> {
        TstrW::new(self, 0)
    }
}
#[doc = "The Target Time Seconds register, along with Target Time Nanoseconds register, is used to schedule an interrupt event (Register 458\\[1\\]
when Advanced Timestamping is enabled; otherwise, TS interrupt bit in Register14\\[9\\]) when the system time exceeds the value programmed in these registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_target_time_seconds::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_target_time_seconds::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTargetTimeSecondsSpec;
impl crate::RegisterSpec for GmacgrpTargetTimeSecondsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1820u64;
}
#[doc = "`read()` method returns [`gmacgrp_target_time_seconds::R`](R) reader structure"]
impl crate::Readable for GmacgrpTargetTimeSecondsSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_target_time_seconds::W`](W) writer structure"]
impl crate::Writable for GmacgrpTargetTimeSecondsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Target_Time_Seconds to value 0"]
impl crate::Resettable for GmacgrpTargetTimeSecondsSpec {
    const RESET_VALUE: u32 = 0;
}
