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
#[doc = "Register `devgrp_doeptsiz8` reader"]
pub type R = crate::R<DevgrpDoeptsiz8Spec>;
#[doc = "Register `devgrp_doeptsiz8` writer"]
pub type W = crate::W<DevgrpDoeptsiz8Spec>;
#[doc = "Field `xfersize` reader - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the RxFIFO."]
pub type XfersizeR = crate::FieldReader<u32>;
#[doc = "Field `xfersize` writer - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the RxFIFO."]
pub type XfersizeW<'a, REG> = crate::FieldWriter<'a, REG, 19, u32>;
#[doc = "Field `pktcnt` reader - Indicates the total number of USB packets that constitute the Transfer Size amount of data for endpoint 0.This field is decremented every time a packet (maximum size or short packet) is read from the RxFIFO."]
pub type PktcntR = crate::FieldReader<u16>;
#[doc = "Field `pktcnt` writer - Indicates the total number of USB packets that constitute the Transfer Size amount of data for endpoint 0.This field is decremented every time a packet (maximum size or short packet) is read from the RxFIFO."]
pub type PktcntW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Applies to isochronous OUT endpoints only.This is the data PID received in the last packet for this endpoint. Use datax. Applies to control OUT Endpoints only. Use packetx. This field specifies the number of back-to-back SETUP data packets the endpoint can receive.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rxdpid {
    #[doc = "0: `0`"]
    Data0 = 0,
    #[doc = "1: `1`"]
    Data2packet1 = 1,
    #[doc = "2: `10`"]
    Data1packet2 = 2,
    #[doc = "3: `11`"]
    Mdatapacket3 = 3,
}
impl From<Rxdpid> for u8 {
    #[inline(always)]
    fn from(variant: Rxdpid) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rxdpid {
    type Ux = u8;
}
#[doc = "Field `rxdpid` reader - Applies to isochronous OUT endpoints only.This is the data PID received in the last packet for this endpoint. Use datax. Applies to control OUT Endpoints only. Use packetx. This field specifies the number of back-to-back SETUP data packets the endpoint can receive."]
pub type RxdpidR = crate::FieldReader<Rxdpid>;
impl RxdpidR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxdpid {
        match self.bits {
            0 => Rxdpid::Data0,
            1 => Rxdpid::Data2packet1,
            2 => Rxdpid::Data1packet2,
            3 => Rxdpid::Mdatapacket3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_data0(&self) -> bool {
        *self == Rxdpid::Data0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_data2packet1(&self) -> bool {
        *self == Rxdpid::Data2packet1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_data1packet2(&self) -> bool {
        *self == Rxdpid::Data1packet2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_mdatapacket3(&self) -> bool {
        *self == Rxdpid::Mdatapacket3
    }
}
#[doc = "Field `rxdpid` writer - Applies to isochronous OUT endpoints only.This is the data PID received in the last packet for this endpoint. Use datax. Applies to control OUT Endpoints only. Use packetx. This field specifies the number of back-to-back SETUP data packets the endpoint can receive."]
pub type RxdpidW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:18 - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the RxFIFO."]
    #[inline(always)]
    pub fn xfersize(&self) -> XfersizeR {
        XfersizeR::new(self.bits & 0x0007_ffff)
    }
    #[doc = "Bits 19:28 - Indicates the total number of USB packets that constitute the Transfer Size amount of data for endpoint 0.This field is decremented every time a packet (maximum size or short packet) is read from the RxFIFO."]
    #[inline(always)]
    pub fn pktcnt(&self) -> PktcntR {
        PktcntR::new(((self.bits >> 19) & 0x03ff) as u16)
    }
    #[doc = "Bits 29:30 - Applies to isochronous OUT endpoints only.This is the data PID received in the last packet for this endpoint. Use datax. Applies to control OUT Endpoints only. Use packetx. This field specifies the number of back-to-back SETUP data packets the endpoint can receive."]
    #[inline(always)]
    pub fn rxdpid(&self) -> RxdpidR {
        RxdpidR::new(((self.bits >> 29) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:18 - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the RxFIFO."]
    #[inline(always)]
    #[must_use]
    pub fn xfersize(&mut self) -> XfersizeW<DevgrpDoeptsiz8Spec> {
        XfersizeW::new(self, 0)
    }
    #[doc = "Bits 19:28 - Indicates the total number of USB packets that constitute the Transfer Size amount of data for endpoint 0.This field is decremented every time a packet (maximum size or short packet) is read from the RxFIFO."]
    #[inline(always)]
    #[must_use]
    pub fn pktcnt(&mut self) -> PktcntW<DevgrpDoeptsiz8Spec> {
        PktcntW::new(self, 19)
    }
    #[doc = "Bits 29:30 - Applies to isochronous OUT endpoints only.This is the data PID received in the last packet for this endpoint. Use datax. Applies to control OUT Endpoints only. Use packetx. This field specifies the number of back-to-back SETUP data packets the endpoint can receive."]
    #[inline(always)]
    #[must_use]
    pub fn rxdpid(&mut self) -> RxdpidW<DevgrpDoeptsiz8Spec> {
        RxdpidW::new(self, 29)
    }
}
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz8::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz8::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoeptsiz8Spec;
impl crate::RegisterSpec for DevgrpDoeptsiz8Spec {
    type Ux = u32;
    const OFFSET: u64 = 3088u64;
}
#[doc = "`read()` method returns [`devgrp_doeptsiz8::R`](R) reader structure"]
impl crate::Readable for DevgrpDoeptsiz8Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_doeptsiz8::W`](W) writer structure"]
impl crate::Writable for DevgrpDoeptsiz8Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_doeptsiz8 to value 0"]
impl crate::Resettable for DevgrpDoeptsiz8Spec {
    const RESET_VALUE: u32 = 0;
}
