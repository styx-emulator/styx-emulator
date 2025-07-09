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
#[doc = "Register `hostgrp_hctsiz6` reader"]
pub type R = crate::R<HostgrpHctsiz6Spec>;
#[doc = "Register `hostgrp_hctsiz6` writer"]
pub type W = crate::W<HostgrpHctsiz6Spec>;
#[doc = "Field `xfersize` reader - for an OUT, this field is the number of data bytes the host sends during the transfer. for an IN, this field is the buffer size that the application has Reserved for the transfer. The application is expected to program this field as an integer multiple of the maximum packet size for IN transactions (periodic and non-periodic).The width of this counter is specified as 19 bits."]
pub type XfersizeR = crate::FieldReader<u32>;
#[doc = "Field `xfersize` writer - for an OUT, this field is the number of data bytes the host sends during the transfer. for an IN, this field is the buffer size that the application has Reserved for the transfer. The application is expected to program this field as an integer multiple of the maximum packet size for IN transactions (periodic and non-periodic).The width of this counter is specified as 19 bits."]
pub type XfersizeW<'a, REG> = crate::FieldWriter<'a, REG, 19, u32>;
#[doc = "Field `pktcnt` reader - This field is programmed by the application with the expected number of packets to be transmitted (OUT) or received (IN). The host decrements this count on every successful transmission or reception of an OUT/IN packet. Once this count reaches zero, the application is interrupted to indicate normal completion. The width of this counter is specified as 10 bits."]
pub type PktcntR = crate::FieldReader<u16>;
#[doc = "Field `pktcnt` writer - This field is programmed by the application with the expected number of packets to be transmitted (OUT) or received (IN). The host decrements this count on every successful transmission or reception of an OUT/IN packet. Once this count reaches zero, the application is interrupted to indicate normal completion. The width of this counter is specified as 10 bits."]
pub type PktcntW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "The application programs this field with the type of PID to use forthe initial transaction. The host maintains this field for the rest of the transfer.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Pid {
    #[doc = "0: `0`"]
    Data0 = 0,
    #[doc = "1: `1`"]
    Data2 = 1,
    #[doc = "2: `10`"]
    Data1 = 2,
    #[doc = "3: `11`"]
    Mdata = 3,
}
impl From<Pid> for u8 {
    #[inline(always)]
    fn from(variant: Pid) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Pid {
    type Ux = u8;
}
#[doc = "Field `pid` reader - The application programs this field with the type of PID to use forthe initial transaction. The host maintains this field for the rest of the transfer."]
pub type PidR = crate::FieldReader<Pid>;
impl PidR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Pid {
        match self.bits {
            0 => Pid::Data0,
            1 => Pid::Data2,
            2 => Pid::Data1,
            3 => Pid::Mdata,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_data0(&self) -> bool {
        *self == Pid::Data0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_data2(&self) -> bool {
        *self == Pid::Data2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_data1(&self) -> bool {
        *self == Pid::Data1
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_mdata(&self) -> bool {
        *self == Pid::Mdata
    }
}
#[doc = "Field `pid` writer - The application programs this field with the type of PID to use forthe initial transaction. The host maintains this field for the rest of the transfer."]
pub type PidW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Pid>;
impl<'a, REG> PidW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn data0(self) -> &'a mut crate::W<REG> {
        self.variant(Pid::Data0)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn data2(self) -> &'a mut crate::W<REG> {
        self.variant(Pid::Data2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn data1(self) -> &'a mut crate::W<REG> {
        self.variant(Pid::Data1)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn mdata(self) -> &'a mut crate::W<REG> {
        self.variant(Pid::Mdata)
    }
}
#[doc = "This bit is used only for OUT transfers.Setting this field to 1 directs the host to do PING protocol. Do not Set this bit for IN transfers. If this bit is set for IN transfers it disables the channel.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dopng {
    #[doc = "0: `0`"]
    Noping = 0,
    #[doc = "1: `1`"]
    Ping = 1,
}
impl From<Dopng> for bool {
    #[inline(always)]
    fn from(variant: Dopng) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dopng` reader - This bit is used only for OUT transfers.Setting this field to 1 directs the host to do PING protocol. Do not Set this bit for IN transfers. If this bit is set for IN transfers it disables the channel."]
pub type DopngR = crate::BitReader<Dopng>;
impl DopngR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dopng {
        match self.bits {
            false => Dopng::Noping,
            true => Dopng::Ping,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noping(&self) -> bool {
        *self == Dopng::Noping
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ping(&self) -> bool {
        *self == Dopng::Ping
    }
}
#[doc = "Field `dopng` writer - This bit is used only for OUT transfers.Setting this field to 1 directs the host to do PING protocol. Do not Set this bit for IN transfers. If this bit is set for IN transfers it disables the channel."]
pub type DopngW<'a, REG> = crate::BitWriter<'a, REG, Dopng>;
impl<'a, REG> DopngW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noping(self) -> &'a mut crate::W<REG> {
        self.variant(Dopng::Noping)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ping(self) -> &'a mut crate::W<REG> {
        self.variant(Dopng::Ping)
    }
}
impl R {
    #[doc = "Bits 0:18 - for an OUT, this field is the number of data bytes the host sends during the transfer. for an IN, this field is the buffer size that the application has Reserved for the transfer. The application is expected to program this field as an integer multiple of the maximum packet size for IN transactions (periodic and non-periodic).The width of this counter is specified as 19 bits."]
    #[inline(always)]
    pub fn xfersize(&self) -> XfersizeR {
        XfersizeR::new(self.bits & 0x0007_ffff)
    }
    #[doc = "Bits 19:28 - This field is programmed by the application with the expected number of packets to be transmitted (OUT) or received (IN). The host decrements this count on every successful transmission or reception of an OUT/IN packet. Once this count reaches zero, the application is interrupted to indicate normal completion. The width of this counter is specified as 10 bits."]
    #[inline(always)]
    pub fn pktcnt(&self) -> PktcntR {
        PktcntR::new(((self.bits >> 19) & 0x03ff) as u16)
    }
    #[doc = "Bits 29:30 - The application programs this field with the type of PID to use forthe initial transaction. The host maintains this field for the rest of the transfer."]
    #[inline(always)]
    pub fn pid(&self) -> PidR {
        PidR::new(((self.bits >> 29) & 3) as u8)
    }
    #[doc = "Bit 31 - This bit is used only for OUT transfers.Setting this field to 1 directs the host to do PING protocol. Do not Set this bit for IN transfers. If this bit is set for IN transfers it disables the channel."]
    #[inline(always)]
    pub fn dopng(&self) -> DopngR {
        DopngR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:18 - for an OUT, this field is the number of data bytes the host sends during the transfer. for an IN, this field is the buffer size that the application has Reserved for the transfer. The application is expected to program this field as an integer multiple of the maximum packet size for IN transactions (periodic and non-periodic).The width of this counter is specified as 19 bits."]
    #[inline(always)]
    #[must_use]
    pub fn xfersize(&mut self) -> XfersizeW<HostgrpHctsiz6Spec> {
        XfersizeW::new(self, 0)
    }
    #[doc = "Bits 19:28 - This field is programmed by the application with the expected number of packets to be transmitted (OUT) or received (IN). The host decrements this count on every successful transmission or reception of an OUT/IN packet. Once this count reaches zero, the application is interrupted to indicate normal completion. The width of this counter is specified as 10 bits."]
    #[inline(always)]
    #[must_use]
    pub fn pktcnt(&mut self) -> PktcntW<HostgrpHctsiz6Spec> {
        PktcntW::new(self, 19)
    }
    #[doc = "Bits 29:30 - The application programs this field with the type of PID to use forthe initial transaction. The host maintains this field for the rest of the transfer."]
    #[inline(always)]
    #[must_use]
    pub fn pid(&mut self) -> PidW<HostgrpHctsiz6Spec> {
        PidW::new(self, 29)
    }
    #[doc = "Bit 31 - This bit is used only for OUT transfers.Setting this field to 1 directs the host to do PING protocol. Do not Set this bit for IN transfers. If this bit is set for IN transfers it disables the channel."]
    #[inline(always)]
    #[must_use]
    pub fn dopng(&mut self) -> DopngW<HostgrpHctsiz6Spec> {
        DopngW::new(self, 31)
    }
}
#[doc = "Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz6::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz6::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHctsiz6Spec;
impl crate::RegisterSpec for HostgrpHctsiz6Spec {
    type Ux = u32;
    const OFFSET: u64 = 1488u64;
}
#[doc = "`read()` method returns [`hostgrp_hctsiz6::R`](R) reader structure"]
impl crate::Readable for HostgrpHctsiz6Spec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hctsiz6::W`](W) writer structure"]
impl crate::Writable for HostgrpHctsiz6Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hctsiz6 to value 0"]
impl crate::Resettable for HostgrpHctsiz6Spec {
    const RESET_VALUE: u32 = 0;
}
