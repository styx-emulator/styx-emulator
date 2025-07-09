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
#[doc = "Register `devgrp_dvbusdis` reader"]
pub type R = crate::R<DevgrpDvbusdisSpec>;
#[doc = "Register `devgrp_dvbusdis` writer"]
pub type W = crate::W<DevgrpDvbusdisSpec>;
#[doc = "Field `dvbusdis` reader - This value equals: VBUS discharge time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30 MHz (16-bit data width) or 60 MHz (8-bit data width). Depending on your VBUS load, this value can need adjustment."]
pub type DvbusdisR = crate::FieldReader<u16>;
#[doc = "Field `dvbusdis` writer - This value equals: VBUS discharge time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30 MHz (16-bit data width) or 60 MHz (8-bit data width). Depending on your VBUS load, this value can need adjustment."]
pub type DvbusdisW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This value equals: VBUS discharge time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30 MHz (16-bit data width) or 60 MHz (8-bit data width). Depending on your VBUS load, this value can need adjustment."]
    #[inline(always)]
    pub fn dvbusdis(&self) -> DvbusdisR {
        DvbusdisR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This value equals: VBUS discharge time in PHY clocks/1,024 The value you use depends whether the PHY is operating at 30 MHz (16-bit data width) or 60 MHz (8-bit data width). Depending on your VBUS load, this value can need adjustment."]
    #[inline(always)]
    #[must_use]
    pub fn dvbusdis(&mut self) -> DvbusdisW<DevgrpDvbusdisSpec> {
        DvbusdisW::new(self, 0)
    }
}
#[doc = "This register specifies the VBUS discharge time after VBUS pulsing during SRP.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dvbusdis::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dvbusdis::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDvbusdisSpec;
impl crate::RegisterSpec for DevgrpDvbusdisSpec {
    type Ux = u32;
    const OFFSET: u64 = 2088u64;
}
#[doc = "`read()` method returns [`devgrp_dvbusdis::R`](R) reader structure"]
impl crate::Readable for DevgrpDvbusdisSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_dvbusdis::W`](W) writer structure"]
impl crate::Writable for DevgrpDvbusdisSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_dvbusdis to value 0x17d7"]
impl crate::Resettable for DevgrpDvbusdisSpec {
    const RESET_VALUE: u32 = 0x17d7;
}
