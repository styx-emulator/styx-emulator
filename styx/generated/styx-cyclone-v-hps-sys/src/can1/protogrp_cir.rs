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
#[doc = "Register `protogrp_CIR` reader"]
pub type R = crate::R<ProtogrpCirSpec>;
#[doc = "Register `protogrp_CIR` writer"]
pub type W = crate::W<ProtogrpCirSpec>;
#[doc = "Field `IntId` reader - 0x00 No Message Object interrupt is pending. 0x01-0x80 Number of Message Object which caused the interrupt. 0x81-0xFF unused."]
pub type IntIdR = crate::FieldReader;
#[doc = "Field `IntId` writer - 0x00 No Message Object interrupt is pending. 0x01-0x80 Number of Message Object which caused the interrupt. 0x81-0xFF unused."]
pub type IntIdW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `StatusInt` reader - The Status Interrupt is cleared by reading the Status Register."]
pub type StatusIntR = crate::BitReader;
#[doc = "Field `StatusInt` writer - The Status Interrupt is cleared by reading the Status Register."]
pub type StatusIntW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - 0x00 No Message Object interrupt is pending. 0x01-0x80 Number of Message Object which caused the interrupt. 0x81-0xFF unused."]
    #[inline(always)]
    pub fn int_id(&self) -> IntIdR {
        IntIdR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bit 15 - The Status Interrupt is cleared by reading the Status Register."]
    #[inline(always)]
    pub fn status_int(&self) -> StatusIntR {
        StatusIntR::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - 0x00 No Message Object interrupt is pending. 0x01-0x80 Number of Message Object which caused the interrupt. 0x81-0xFF unused."]
    #[inline(always)]
    #[must_use]
    pub fn int_id(&mut self) -> IntIdW<ProtogrpCirSpec> {
        IntIdW::new(self, 0)
    }
    #[doc = "Bit 15 - The Status Interrupt is cleared by reading the Status Register."]
    #[inline(always)]
    #[must_use]
    pub fn status_int(&mut self) -> StatusIntW<ProtogrpCirSpec> {
        StatusIntW::new(self, 15)
    }
}
#[doc = "If several interrupts are pending, the CAN Interrupt Register will point to the pending interrupt with the highest priority, disregarding their chronological order. An interrupt remains pending until the CPU has cleared it. If IntID is different from 0x00 and CCTRL.MIL is set, the interrupt port CAN_INT_MO is active. The interrupt port remains active until IntID is back to value 0x00 (the cause of the interrupt is reset) or until CCTRL.MIL is reset. If CCTRL.ILE is set and CCTRL.MIL is reseted the Message Object interrupts will be routed to interrupt port CAN_INT_STATUS. The interrupt port remains active until IntID is back to value 0x00 (the cause of the interrupt is reset) or until CCTRL.MIL is set or CCTRL.ILE is reset. The Message Object's interrupt priority decreases with increasing message number. A message interrupt is cleared by clearing the Message Object's IntPnd bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cir::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpCirSpec;
impl crate::RegisterSpec for ProtogrpCirSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`protogrp_cir::R`](R) reader structure"]
impl crate::Readable for ProtogrpCirSpec {}
#[doc = "`reset()` method sets protogrp_CIR to value 0"]
impl crate::Resettable for ProtogrpCirSpec {
    const RESET_VALUE: u32 = 0;
}
