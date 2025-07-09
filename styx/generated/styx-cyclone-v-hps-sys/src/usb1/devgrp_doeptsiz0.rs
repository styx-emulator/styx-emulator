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
#[doc = "Register `devgrp_doeptsiz0` reader"]
pub type R = crate::R<DevgrpDoeptsiz0Spec>;
#[doc = "Register `devgrp_doeptsiz0` writer"]
pub type W = crate::W<DevgrpDoeptsiz0Spec>;
#[doc = "Field `xfersize` reader - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the RxFIFO."]
pub type XfersizeR = crate::FieldReader;
#[doc = "Field `xfersize` writer - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the RxFIFO."]
pub type XfersizeW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `pktcnt` reader - This field is decremented to zero after a packet is written into the RxFIFO."]
pub type PktcntR = crate::BitReader;
#[doc = "Field `pktcnt` writer - This field is decremented to zero after a packet is written into the RxFIFO."]
pub type PktcntW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "SETUP Packet Count (SUPCnt)This field specifies the number of back-to-back SETUP datapackets the endpoint can receive.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Supcnt {
    #[doc = "1: `1`"]
    Onepacket = 1,
    #[doc = "2: `10`"]
    Twopacket = 2,
    #[doc = "3: `11`"]
    Threepacket = 3,
}
impl From<Supcnt> for u8 {
    #[inline(always)]
    fn from(variant: Supcnt) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Supcnt {
    type Ux = u8;
}
#[doc = "Field `supcnt` reader - SETUP Packet Count (SUPCnt)This field specifies the number of back-to-back SETUP datapackets the endpoint can receive."]
pub type SupcntR = crate::FieldReader<Supcnt>;
impl SupcntR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Supcnt> {
        match self.bits {
            1 => Some(Supcnt::Onepacket),
            2 => Some(Supcnt::Twopacket),
            3 => Some(Supcnt::Threepacket),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_onepacket(&self) -> bool {
        *self == Supcnt::Onepacket
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_twopacket(&self) -> bool {
        *self == Supcnt::Twopacket
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_threepacket(&self) -> bool {
        *self == Supcnt::Threepacket
    }
}
#[doc = "Field `supcnt` writer - SETUP Packet Count (SUPCnt)This field specifies the number of back-to-back SETUP datapackets the endpoint can receive."]
pub type SupcntW<'a, REG> = crate::FieldWriter<'a, REG, 2, Supcnt>;
impl<'a, REG> SupcntW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn onepacket(self) -> &'a mut crate::W<REG> {
        self.variant(Supcnt::Onepacket)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn twopacket(self) -> &'a mut crate::W<REG> {
        self.variant(Supcnt::Twopacket)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn threepacket(self) -> &'a mut crate::W<REG> {
        self.variant(Supcnt::Threepacket)
    }
}
impl R {
    #[doc = "Bits 0:6 - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the RxFIFO."]
    #[inline(always)]
    pub fn xfersize(&self) -> XfersizeR {
        XfersizeR::new((self.bits & 0x7f) as u8)
    }
    #[doc = "Bit 19 - This field is decremented to zero after a packet is written into the RxFIFO."]
    #[inline(always)]
    pub fn pktcnt(&self) -> PktcntR {
        PktcntR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bits 29:30 - SETUP Packet Count (SUPCnt)This field specifies the number of back-to-back SETUP datapackets the endpoint can receive."]
    #[inline(always)]
    pub fn supcnt(&self) -> SupcntR {
        SupcntR::new(((self.bits >> 29) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:6 - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the RxFIFO."]
    #[inline(always)]
    #[must_use]
    pub fn xfersize(&mut self) -> XfersizeW<DevgrpDoeptsiz0Spec> {
        XfersizeW::new(self, 0)
    }
    #[doc = "Bit 19 - This field is decremented to zero after a packet is written into the RxFIFO."]
    #[inline(always)]
    #[must_use]
    pub fn pktcnt(&mut self) -> PktcntW<DevgrpDoeptsiz0Spec> {
        PktcntW::new(self, 19)
    }
    #[doc = "Bits 29:30 - SETUP Packet Count (SUPCnt)This field specifies the number of back-to-back SETUP datapackets the endpoint can receive."]
    #[inline(always)]
    #[must_use]
    pub fn supcnt(&mut self) -> SupcntW<DevgrpDoeptsiz0Spec> {
        SupcntW::new(self, 29)
    }
}
#[doc = "The application must modify this register before enabling endpoint 0. Once endpoint 0 is enabled using Endpoint Enable bit of the Device Control Endpoint 0 Control registers (DIEPCTL0.EPEna/DOEPCTL0.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit. Nonzero endpoints use the registers for endpoints 1 to 15. When Scatter/Gather DMA mode is enabled, this register must not be programmed by the application. If the application reads this register when Scatter/Gather DMA mode is enabled, the core returns all zeros.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoeptsiz0Spec;
impl crate::RegisterSpec for DevgrpDoeptsiz0Spec {
    type Ux = u32;
    const OFFSET: u64 = 2832u64;
}
#[doc = "`read()` method returns [`devgrp_doeptsiz0::R`](R) reader structure"]
impl crate::Readable for DevgrpDoeptsiz0Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_doeptsiz0::W`](W) writer structure"]
impl crate::Writable for DevgrpDoeptsiz0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_doeptsiz0 to value 0"]
impl crate::Resettable for DevgrpDoeptsiz0Spec {
    const RESET_VALUE: u32 = 0;
}
