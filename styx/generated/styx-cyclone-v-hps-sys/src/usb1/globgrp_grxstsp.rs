// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_grxstsp` reader"]
pub type R = crate::R<GlobgrpGrxstspSpec>;
#[doc = "Register `globgrp_grxstsp` writer"]
pub type W = crate::W<GlobgrpGrxstspSpec>;
#[doc = "Field `chnum` reader - Mode: Host only. Indicates the channel number to which the current received packet belongs."]
pub type ChnumR = crate::FieldReader;
#[doc = "Field `chnum` writer - Mode: Host only. Indicates the channel number to which the current received packet belongs."]
pub type ChnumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `bcnt` reader - Mode: Host only. Indicates the byte count of the received IN data packet."]
pub type BcntR = crate::FieldReader<u16>;
#[doc = "Field `bcnt` writer - Mode: Host only. Indicates the byte count of the received IN data packet."]
pub type BcntW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Indicates the Data PID of the received OUT data packet.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dpid {
    #[doc = "0: `0`"]
    Data0 = 0,
    #[doc = "2: `10`"]
    Data1 = 2,
    #[doc = "1: `1`"]
    Data2 = 1,
    #[doc = "3: `11`"]
    Mdata = 3,
}
impl From<Dpid> for u8 {
    #[inline(always)]
    fn from(variant: Dpid) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Dpid {
    type Ux = u8;
}
#[doc = "Field `dpid` reader - Indicates the Data PID of the received OUT data packet."]
pub type DpidR = crate::FieldReader<Dpid>;
impl DpidR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dpid {
        match self.bits {
            0 => Dpid::Data0,
            2 => Dpid::Data1,
            1 => Dpid::Data2,
            3 => Dpid::Mdata,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_data0(&self) -> bool {
        *self == Dpid::Data0
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_data1(&self) -> bool {
        *self == Dpid::Data1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_data2(&self) -> bool {
        *self == Dpid::Data2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_mdata(&self) -> bool {
        *self == Dpid::Mdata
    }
}
#[doc = "Field `dpid` writer - Indicates the Data PID of the received OUT data packet."]
pub type DpidW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Mode: Host only. Others: Reserved. Indicates the status of the received packet\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Pktsts {
    #[doc = "0: `0`"]
    Data0 = 0,
    #[doc = "2: `10`"]
    Data1 = 2,
    #[doc = "1: `1`"]
    Data2 = 1,
    #[doc = "3: `11`"]
    Mdata = 3,
}
impl From<Pktsts> for u8 {
    #[inline(always)]
    fn from(variant: Pktsts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Pktsts {
    type Ux = u8;
}
#[doc = "Field `pktsts` reader - Mode: Host only. Others: Reserved. Indicates the status of the received packet"]
pub type PktstsR = crate::FieldReader<Pktsts>;
impl PktstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Pktsts> {
        match self.bits {
            0 => Some(Pktsts::Data0),
            2 => Some(Pktsts::Data1),
            1 => Some(Pktsts::Data2),
            3 => Some(Pktsts::Mdata),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_data0(&self) -> bool {
        *self == Pktsts::Data0
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_data1(&self) -> bool {
        *self == Pktsts::Data1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_data2(&self) -> bool {
        *self == Pktsts::Data2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_mdata(&self) -> bool {
        *self == Pktsts::Mdata
    }
}
#[doc = "Field `pktsts` writer - Mode: Host only. Others: Reserved. Indicates the status of the received packet"]
pub type PktstsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `fn` reader - Mode: Device only. This is the least significant 4 bits of the (micro)Frame number in which the packet is received on the USB. This field is supported only when isochronous OUT endpoints are supported."]
pub type FnR = crate::FieldReader;
#[doc = "Field `fn` writer - Mode: Device only. This is the least significant 4 bits of the (micro)Frame number in which the packet is received on the USB. This field is supported only when isochronous OUT endpoints are supported."]
pub type FnW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Mode: Host only. Indicates the channel number to which the current received packet belongs."]
    #[inline(always)]
    pub fn chnum(&self) -> ChnumR {
        ChnumR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:14 - Mode: Host only. Indicates the byte count of the received IN data packet."]
    #[inline(always)]
    pub fn bcnt(&self) -> BcntR {
        BcntR::new(((self.bits >> 4) & 0x07ff) as u16)
    }
    #[doc = "Bits 15:16 - Indicates the Data PID of the received OUT data packet."]
    #[inline(always)]
    pub fn dpid(&self) -> DpidR {
        DpidR::new(((self.bits >> 15) & 3) as u8)
    }
    #[doc = "Bits 17:20 - Mode: Host only. Others: Reserved. Indicates the status of the received packet"]
    #[inline(always)]
    pub fn pktsts(&self) -> PktstsR {
        PktstsR::new(((self.bits >> 17) & 0x0f) as u8)
    }
    #[doc = "Bits 21:24 - Mode: Device only. This is the least significant 4 bits of the (micro)Frame number in which the packet is received on the USB. This field is supported only when isochronous OUT endpoints are supported."]
    #[inline(always)]
    pub fn fn_(&self) -> FnR {
        FnR::new(((self.bits >> 21) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Mode: Host only. Indicates the channel number to which the current received packet belongs."]
    #[inline(always)]
    #[must_use]
    pub fn chnum(&mut self) -> ChnumW<GlobgrpGrxstspSpec> {
        ChnumW::new(self, 0)
    }
    #[doc = "Bits 4:14 - Mode: Host only. Indicates the byte count of the received IN data packet."]
    #[inline(always)]
    #[must_use]
    pub fn bcnt(&mut self) -> BcntW<GlobgrpGrxstspSpec> {
        BcntW::new(self, 4)
    }
    #[doc = "Bits 15:16 - Indicates the Data PID of the received OUT data packet."]
    #[inline(always)]
    #[must_use]
    pub fn dpid(&mut self) -> DpidW<GlobgrpGrxstspSpec> {
        DpidW::new(self, 15)
    }
    #[doc = "Bits 17:20 - Mode: Host only. Others: Reserved. Indicates the status of the received packet"]
    #[inline(always)]
    #[must_use]
    pub fn pktsts(&mut self) -> PktstsW<GlobgrpGrxstspSpec> {
        PktstsW::new(self, 17)
    }
    #[doc = "Bits 21:24 - Mode: Device only. This is the least significant 4 bits of the (micro)Frame number in which the packet is received on the USB. This field is supported only when isochronous OUT endpoints are supported."]
    #[inline(always)]
    #[must_use]
    pub fn fn_(&mut self) -> FnW<GlobgrpGrxstspSpec> {
        FnW::new(self, 21)
    }
}
#[doc = "A read to the Receive Status Read and Pop register additionally pops the: top data entry out of the RxFIFO. The receive status contents must be interpreted differently in Host and Device modes. The core ignores the receive status pop/read when the receive FIFO is empty and returns a value of 0. The application must only pop the Receive Status FIFO when the Receive FIFO Non-Empty bit of the Core Interrupt register (GINTSTS.RxFLvl) is asserted. Use of these fields vary based on whether the HS OTG core is functioning as a host or a device. Do not read this register'ss reset value before configuring the core because the read value is \"X\" in the simulation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_grxstsp::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGrxstspSpec;
impl crate::RegisterSpec for GlobgrpGrxstspSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`globgrp_grxstsp::R`](R) reader structure"]
impl crate::Readable for GlobgrpGrxstspSpec {}
#[doc = "`reset()` method sets globgrp_grxstsp to value 0"]
impl crate::Resettable for GlobgrpGrxstspSpec {
    const RESET_VALUE: u32 = 0;
}
