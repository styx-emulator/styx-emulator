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
#[doc = "Register `hostgrp_haint` reader"]
pub type R = crate::R<HostgrpHaintSpec>;
#[doc = "Register `hostgrp_haint` writer"]
pub type W = crate::W<HostgrpHaintSpec>;
#[doc = "Field `haint` reader - One bit per channel: Bit 0 for Channel 0, bit 15 for Channel 15"]
pub type HaintR = crate::FieldReader<u16>;
#[doc = "Field `haint` writer - One bit per channel: Bit 0 for Channel 0, bit 15 for Channel 15"]
pub type HaintW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - One bit per channel: Bit 0 for Channel 0, bit 15 for Channel 15"]
    #[inline(always)]
    pub fn haint(&self) -> HaintR {
        HaintR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - One bit per channel: Bit 0 for Channel 0, bit 15 for Channel 15"]
    #[inline(always)]
    #[must_use]
    pub fn haint(&mut self) -> HaintW<HostgrpHaintSpec> {
        HaintW::new(self, 0)
    }
}
#[doc = "When a significant event occurs on a channel, the Host All Channels Interrupt register interrupts the application using the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt). There is one interrupt bit per channel, up to a maximum of 16 bits. Bits in this register are set and cleared when the application sets and clears bits in the corresponding Host Channel-n Interrupt register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_haint::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHaintSpec;
impl crate::RegisterSpec for HostgrpHaintSpec {
    type Ux = u32;
    const OFFSET: u64 = 1044u64;
}
#[doc = "`read()` method returns [`hostgrp_haint::R`](R) reader structure"]
impl crate::Readable for HostgrpHaintSpec {}
#[doc = "`reset()` method sets hostgrp_haint to value 0"]
impl crate::Resettable for HostgrpHaintSpec {
    const RESET_VALUE: u32 = 0;
}
