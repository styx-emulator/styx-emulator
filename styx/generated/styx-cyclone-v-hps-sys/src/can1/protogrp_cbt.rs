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
#[doc = "Register `protogrp_CBT` reader"]
pub type R = crate::R<ProtogrpCbtSpec>;
#[doc = "Register `protogrp_CBT` writer"]
pub type W = crate::W<ProtogrpCbtSpec>;
#[doc = "Field `BRP` reader - The value by which the oscillator frequency is divided for generating the bit time quanta. The bit time is built up from a multiple of this quanta. Valid values for the Baud Rate Prescaler are \\[0 .. 63\\]. The actual interpretation by the hardware of this value is such that one more than the value programmed here is used."]
pub type BrpR = crate::FieldReader;
#[doc = "Field `BRP` writer - The value by which the oscillator frequency is divided for generating the bit time quanta. The bit time is built up from a multiple of this quanta. Valid values for the Baud Rate Prescaler are \\[0 .. 63\\]. The actual interpretation by the hardware of this value is such that one more than the value programmed here is used."]
pub type BrpW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `SJW` reader - Valid programmed values are \\[0 .. 3\\]. The actual interpretation by the hardware of this value is such that one more than the value programmed here is used."]
pub type SjwR = crate::FieldReader;
#[doc = "Field `SJW` writer - Valid programmed values are \\[0 .. 3\\]. The actual interpretation by the hardware of this value is such that one more than the value programmed here is used."]
pub type SjwW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TSeg1` reader - Valid values for TSeg1 are \\[1 .. 15\\]."]
pub type Tseg1R = crate::FieldReader;
#[doc = "Field `TSeg1` writer - Valid values for TSeg1 are \\[1 .. 15\\]."]
pub type Tseg1W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TSeg2` reader - Valid values for TSeg2 are \\[0 .. 7\\]."]
pub type Tseg2R = crate::FieldReader;
#[doc = "Field `TSeg2` writer - Valid values for TSeg2 are \\[0 .. 7\\]."]
pub type Tseg2W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `BRPE` reader - By programming BRPE the Baud Rate Prescaler can be extended to values up to 1023. The actual interpretation by the hardware is that one more than the value programmed by BRPE (MSBs) and BRP (LSBs) is used."]
pub type BrpeR = crate::FieldReader;
#[doc = "Field `BRPE` writer - By programming BRPE the Baud Rate Prescaler can be extended to values up to 1023. The actual interpretation by the hardware is that one more than the value programmed by BRPE (MSBs) and BRP (LSBs) is used."]
pub type BrpeW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:5 - The value by which the oscillator frequency is divided for generating the bit time quanta. The bit time is built up from a multiple of this quanta. Valid values for the Baud Rate Prescaler are \\[0 .. 63\\]. The actual interpretation by the hardware of this value is such that one more than the value programmed here is used."]
    #[inline(always)]
    pub fn brp(&self) -> BrpR {
        BrpR::new((self.bits & 0x3f) as u8)
    }
    #[doc = "Bits 6:7 - Valid programmed values are \\[0 .. 3\\]. The actual interpretation by the hardware of this value is such that one more than the value programmed here is used."]
    #[inline(always)]
    pub fn sjw(&self) -> SjwR {
        SjwR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bits 8:11 - Valid values for TSeg1 are \\[1 .. 15\\]."]
    #[inline(always)]
    pub fn tseg1(&self) -> Tseg1R {
        Tseg1R::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bits 12:14 - Valid values for TSeg2 are \\[0 .. 7\\]."]
    #[inline(always)]
    pub fn tseg2(&self) -> Tseg2R {
        Tseg2R::new(((self.bits >> 12) & 7) as u8)
    }
    #[doc = "Bits 16:19 - By programming BRPE the Baud Rate Prescaler can be extended to values up to 1023. The actual interpretation by the hardware is that one more than the value programmed by BRPE (MSBs) and BRP (LSBs) is used."]
    #[inline(always)]
    pub fn brpe(&self) -> BrpeR {
        BrpeR::new(((self.bits >> 16) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - The value by which the oscillator frequency is divided for generating the bit time quanta. The bit time is built up from a multiple of this quanta. Valid values for the Baud Rate Prescaler are \\[0 .. 63\\]. The actual interpretation by the hardware of this value is such that one more than the value programmed here is used."]
    #[inline(always)]
    #[must_use]
    pub fn brp(&mut self) -> BrpW<ProtogrpCbtSpec> {
        BrpW::new(self, 0)
    }
    #[doc = "Bits 6:7 - Valid programmed values are \\[0 .. 3\\]. The actual interpretation by the hardware of this value is such that one more than the value programmed here is used."]
    #[inline(always)]
    #[must_use]
    pub fn sjw(&mut self) -> SjwW<ProtogrpCbtSpec> {
        SjwW::new(self, 6)
    }
    #[doc = "Bits 8:11 - Valid values for TSeg1 are \\[1 .. 15\\]."]
    #[inline(always)]
    #[must_use]
    pub fn tseg1(&mut self) -> Tseg1W<ProtogrpCbtSpec> {
        Tseg1W::new(self, 8)
    }
    #[doc = "Bits 12:14 - Valid values for TSeg2 are \\[0 .. 7\\]."]
    #[inline(always)]
    #[must_use]
    pub fn tseg2(&mut self) -> Tseg2W<ProtogrpCbtSpec> {
        Tseg2W::new(self, 12)
    }
    #[doc = "Bits 16:19 - By programming BRPE the Baud Rate Prescaler can be extended to values up to 1023. The actual interpretation by the hardware is that one more than the value programmed by BRPE (MSBs) and BRP (LSBs) is used."]
    #[inline(always)]
    #[must_use]
    pub fn brpe(&mut self) -> BrpeW<ProtogrpCbtSpec> {
        BrpeW::new(self, 16)
    }
}
#[doc = "This register is only writable if bits CCTRL.CCE and CCTRL.Init are set. The CAN bit time may be programed in the range of \\[4 .. 25\\]
time quanta. The CAN time quantum may be programmed in the range of \\[1 .. 1024\\]
CAN_CLK periods. For details see Application Note 001 \"Configuration of Bit Timing\". The actual interpretation by the hardware of this value is such that one more than the value programmed here is used. TSeg1 is the sum of Prop_Seg and Phase_Seg1. TSeg2 is Phase_Seg2. Therefore the length of the bit time is (programmed values) \\[TSeg1 + TSeg2 + 3\\]
tq or (functional values) \\[Sync_Seg + Prop_Seg + Phase_Seg1 + Phase_Seg2\\]
tq.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cbt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`protogrp_cbt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpCbtSpec;
impl crate::RegisterSpec for ProtogrpCbtSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`protogrp_cbt::R`](R) reader structure"]
impl crate::Readable for ProtogrpCbtSpec {}
#[doc = "`write(|w| ..)` method takes [`protogrp_cbt::W`](W) writer structure"]
impl crate::Writable for ProtogrpCbtSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets protogrp_CBT to value 0x2301"]
impl crate::Resettable for ProtogrpCbtSpec {
    const RESET_VALUE: u32 = 0x2301;
}
