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
#[doc = "Register `gmacgrp_Layer4_Address1` reader"]
pub type R = crate::R<GmacgrpLayer4Address1Spec>;
#[doc = "Register `gmacgrp_Layer4_Address1` writer"]
pub type W = crate::W<GmacgrpLayer4Address1Spec>;
#[doc = "Field `l4sp1` reader - When Bit 16 (L4PEN1) is reset and Bit 20 (L4DPM1) is set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the TCP Source Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN1) and Bit 20 (L4DPM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the UDP Source Port Number field in the IPv4 or IPv6 frames."]
pub type L4sp1R = crate::FieldReader<u16>;
#[doc = "Field `l4sp1` writer - When Bit 16 (L4PEN1) is reset and Bit 20 (L4DPM1) is set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the TCP Source Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN1) and Bit 20 (L4DPM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the UDP Source Port Number field in the IPv4 or IPv6 frames."]
pub type L4sp1W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `l4dp1` reader - When Bit 16 (L4PEN1) is reset and Bit 20 (L4DPM1) is set in Register 268 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Destination Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN1) and Bit 20 (L4DPM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the UDP Destination Port Number field in the IPv4 or IPv6 frames."]
pub type L4dp1R = crate::FieldReader<u16>;
#[doc = "Field `l4dp1` writer - When Bit 16 (L4PEN1) is reset and Bit 20 (L4DPM1) is set in Register 268 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Destination Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN1) and Bit 20 (L4DPM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the UDP Destination Port Number field in the IPv4 or IPv6 frames."]
pub type L4dp1W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - When Bit 16 (L4PEN1) is reset and Bit 20 (L4DPM1) is set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the TCP Source Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN1) and Bit 20 (L4DPM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the UDP Source Port Number field in the IPv4 or IPv6 frames."]
    #[inline(always)]
    pub fn l4sp1(&self) -> L4sp1R {
        L4sp1R::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - When Bit 16 (L4PEN1) is reset and Bit 20 (L4DPM1) is set in Register 268 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Destination Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN1) and Bit 20 (L4DPM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the UDP Destination Port Number field in the IPv4 or IPv6 frames."]
    #[inline(always)]
    pub fn l4dp1(&self) -> L4dp1R {
        L4dp1R::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - When Bit 16 (L4PEN1) is reset and Bit 20 (L4DPM1) is set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the TCP Source Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN1) and Bit 20 (L4DPM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the UDP Source Port Number field in the IPv4 or IPv6 frames."]
    #[inline(always)]
    #[must_use]
    pub fn l4sp1(&mut self) -> L4sp1W<GmacgrpLayer4Address1Spec> {
        L4sp1W::new(self, 0)
    }
    #[doc = "Bits 16:31 - When Bit 16 (L4PEN1) is reset and Bit 20 (L4DPM1) is set in Register 268 (Layer 3 and Layer 4 Control Register 0), this field contains the value to be matched with the TCP Destination Port Number field in the IPv4 or IPv6 frames. When Bit 16 (L4PEN1) and Bit 20 (L4DPM1) are set in Register 268 (Layer 3 and Layer 4 Control Register 1), this field contains the value to be matched with the UDP Destination Port Number field in the IPv4 or IPv6 frames."]
    #[inline(always)]
    #[must_use]
    pub fn l4dp1(&mut self) -> L4dp1W<GmacgrpLayer4Address1Spec> {
        L4dp1W::new(self, 16)
    }
}
#[doc = "Because the Layer 3 and Layer 4 Address Registers are double-synchronized to the Rx clock domains, then the synchronization is triggered only when Bits\\[31:24\\]
(in little-endian mode) or Bits\\[7:0\\]
(in big-endian mode) of the Layer 3 and Layer 4 Address Registers are written. For proper synchronization updates, you should perform the consecutive writes to the same Layer 3 and Layer 4 Address Registers after at least four clock cycles delay of the destination clock.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_layer4_address1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_layer4_address1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpLayer4Address1Spec;
impl crate::RegisterSpec for GmacgrpLayer4Address1Spec {
    type Ux = u32;
    const OFFSET: u64 = 1076u64;
}
#[doc = "`read()` method returns [`gmacgrp_layer4_address1::R`](R) reader structure"]
impl crate::Readable for GmacgrpLayer4Address1Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_layer4_address1::W`](W) writer structure"]
impl crate::Writable for GmacgrpLayer4Address1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Layer4_Address1 to value 0"]
impl crate::Resettable for GmacgrpLayer4Address1Spec {
    const RESET_VALUE: u32 = 0;
}
