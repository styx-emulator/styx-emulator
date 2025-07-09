// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_dieptsiz5` reader"]
pub type R = crate::R<DevgrpDieptsiz5Spec>;
#[doc = "Register `devgrp_dieptsiz5` writer"]
pub type W = crate::W<DevgrpDieptsiz5Spec>;
#[doc = "Field `xfersize` reader - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the TxFIFO."]
pub type XfersizeR = crate::FieldReader<u32>;
#[doc = "Field `xfersize` writer - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the TxFIFO."]
pub type XfersizeW<'a, REG> = crate::FieldWriter<'a, REG, 19, u32>;
#[doc = "Field `pktcnt` reader - Indicates the total number of USB packets that constitute the Transfer Size amount of data for endpoint 0.This field is decremented every time a packet (maximum size or short packet) is read from the TxFIFO."]
pub type PktcntR = crate::FieldReader<u16>;
#[doc = "Field `pktcnt` writer - Indicates the total number of USB packets that constitute the Transfer Size amount of data for endpoint 0.This field is decremented every time a packet (maximum size or short packet) is read from the TxFIFO."]
pub type PktcntW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "for periodic IN endpoints, this field indicates the number of packets that must be transmitted per microframe on the USB. The core uses this field to calculate the data PID for isochronous IN endpoints. for non-periodic IN endpoints, this field is valid only in Internal DMA mode. It specifies the number of packets the core must fetchfor an IN endpoint before it switches to the endpoint pointed to by the Next Endpoint field of the Device Endpoint-n Control register (DIEPCTLn.NextEp)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mc {
    #[doc = "1: `1`"]
    Packetone = 1,
    #[doc = "2: `10`"]
    Packettwo = 2,
    #[doc = "3: `11`"]
    Packetthree = 3,
}
impl From<Mc> for u8 {
    #[inline(always)]
    fn from(variant: Mc) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Mc {
    type Ux = u8;
}
#[doc = "Field `mc` reader - for periodic IN endpoints, this field indicates the number of packets that must be transmitted per microframe on the USB. The core uses this field to calculate the data PID for isochronous IN endpoints. for non-periodic IN endpoints, this field is valid only in Internal DMA mode. It specifies the number of packets the core must fetchfor an IN endpoint before it switches to the endpoint pointed to by the Next Endpoint field of the Device Endpoint-n Control register (DIEPCTLn.NextEp)"]
pub type McR = crate::FieldReader<Mc>;
impl McR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Mc> {
        match self.bits {
            1 => Some(Mc::Packetone),
            2 => Some(Mc::Packettwo),
            3 => Some(Mc::Packetthree),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_packetone(&self) -> bool {
        *self == Mc::Packetone
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_packettwo(&self) -> bool {
        *self == Mc::Packettwo
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_packetthree(&self) -> bool {
        *self == Mc::Packetthree
    }
}
#[doc = "Field `mc` writer - for periodic IN endpoints, this field indicates the number of packets that must be transmitted per microframe on the USB. The core uses this field to calculate the data PID for isochronous IN endpoints. for non-periodic IN endpoints, this field is valid only in Internal DMA mode. It specifies the number of packets the core must fetchfor an IN endpoint before it switches to the endpoint pointed to by the Next Endpoint field of the Device Endpoint-n Control register (DIEPCTLn.NextEp)"]
pub type McW<'a, REG> = crate::FieldWriter<'a, REG, 2, Mc>;
impl<'a, REG> McW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn packetone(self) -> &'a mut crate::W<REG> {
        self.variant(Mc::Packetone)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn packettwo(self) -> &'a mut crate::W<REG> {
        self.variant(Mc::Packettwo)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn packetthree(self) -> &'a mut crate::W<REG> {
        self.variant(Mc::Packetthree)
    }
}
impl R {
    #[doc = "Bits 0:18 - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the TxFIFO."]
    #[inline(always)]
    pub fn xfersize(&self) -> XfersizeR {
        XfersizeR::new(self.bits & 0x0007_ffff)
    }
    #[doc = "Bits 19:28 - Indicates the total number of USB packets that constitute the Transfer Size amount of data for endpoint 0.This field is decremented every time a packet (maximum size or short packet) is read from the TxFIFO."]
    #[inline(always)]
    pub fn pktcnt(&self) -> PktcntR {
        PktcntR::new(((self.bits >> 19) & 0x03ff) as u16)
    }
    #[doc = "Bits 29:30 - for periodic IN endpoints, this field indicates the number of packets that must be transmitted per microframe on the USB. The core uses this field to calculate the data PID for isochronous IN endpoints. for non-periodic IN endpoints, this field is valid only in Internal DMA mode. It specifies the number of packets the core must fetchfor an IN endpoint before it switches to the endpoint pointed to by the Next Endpoint field of the Device Endpoint-n Control register (DIEPCTLn.NextEp)"]
    #[inline(always)]
    pub fn mc(&self) -> McR {
        McR::new(((self.bits >> 29) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:18 - Indicates the transfer size in bytes for endpoint 0. The core interrupts the application only after it has exhausted the transfer size amount of data. The transfer size can be Set to the maximum packet size of the endpoint, to be interrupted at the end of each packet. The core decrements this field every time a packet from the external memory is written to the TxFIFO."]
    #[inline(always)]
    #[must_use]
    pub fn xfersize(&mut self) -> XfersizeW<DevgrpDieptsiz5Spec> {
        XfersizeW::new(self, 0)
    }
    #[doc = "Bits 19:28 - Indicates the total number of USB packets that constitute the Transfer Size amount of data for endpoint 0.This field is decremented every time a packet (maximum size or short packet) is read from the TxFIFO."]
    #[inline(always)]
    #[must_use]
    pub fn pktcnt(&mut self) -> PktcntW<DevgrpDieptsiz5Spec> {
        PktcntW::new(self, 19)
    }
    #[doc = "Bits 29:30 - for periodic IN endpoints, this field indicates the number of packets that must be transmitted per microframe on the USB. The core uses this field to calculate the data PID for isochronous IN endpoints. for non-periodic IN endpoints, this field is valid only in Internal DMA mode. It specifies the number of packets the core must fetchfor an IN endpoint before it switches to the endpoint pointed to by the Next Endpoint field of the Device Endpoint-n Control register (DIEPCTLn.NextEp)"]
    #[inline(always)]
    #[must_use]
    pub fn mc(&mut self) -> McW<DevgrpDieptsiz5Spec> {
        McW::new(self, 29)
    }
}
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz5::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz5::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDieptsiz5Spec;
impl crate::RegisterSpec for DevgrpDieptsiz5Spec {
    type Ux = u32;
    const OFFSET: u64 = 2480u64;
}
#[doc = "`read()` method returns [`devgrp_dieptsiz5::R`](R) reader structure"]
impl crate::Readable for DevgrpDieptsiz5Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_dieptsiz5::W`](W) writer structure"]
impl crate::Writable for DevgrpDieptsiz5Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_dieptsiz5 to value 0"]
impl crate::Resettable for DevgrpDieptsiz5Spec {
    const RESET_VALUE: u32 = 0;
}
