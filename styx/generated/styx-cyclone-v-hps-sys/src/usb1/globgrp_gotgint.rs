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
#[doc = "Register `globgrp_gotgint` reader"]
pub type R = crate::R<GlobgrpGotgintSpec>;
#[doc = "Register `globgrp_gotgint` writer"]
pub type W = crate::W<GlobgrpGotgintSpec>;
#[doc = "Mode:Host and Device.This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sesenddet {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Sesenddet> for bool {
    #[inline(always)]
    fn from(variant: Sesenddet) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sesenddet` reader - Mode:Host and Device.This bit can be set only by the core and the application should write 1 to clear it."]
pub type SesenddetR = crate::BitReader<Sesenddet>;
impl SesenddetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sesenddet {
        match self.bits {
            false => Sesenddet::Inactive,
            true => Sesenddet::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Sesenddet::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Sesenddet::Active
    }
}
#[doc = "Field `sesenddet` writer - Mode:Host and Device.This bit can be set only by the core and the application should write 1 to clear it."]
pub type SesenddetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host and Device. The core sets this bit on the success or failure of a session request. The application must read the Session Request Success bit in the OTG Control and Status register (GOTGCTL.SesReqScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sesreqsucstschng {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Sesreqsucstschng> for bool {
    #[inline(always)]
    fn from(variant: Sesreqsucstschng) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sesreqsucstschng` reader - Mode: Host and Device. The core sets this bit on the success or failure of a session request. The application must read the Session Request Success bit in the OTG Control and Status register (GOTGCTL.SesReqScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it."]
pub type SesreqsucstschngR = crate::BitReader<Sesreqsucstschng>;
impl SesreqsucstschngR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sesreqsucstschng {
        match self.bits {
            false => Sesreqsucstschng::Inactive,
            true => Sesreqsucstschng::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Sesreqsucstschng::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Sesreqsucstschng::Active
    }
}
#[doc = "Field `sesreqsucstschng` writer - Mode: Host and Device. The core sets this bit on the success or failure of a session request. The application must read the Session Request Success bit in the OTG Control and Status register (GOTGCTL.SesReqScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it."]
pub type SesreqsucstschngW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host and Device. The core sets this bit on the success or failure of a USB host negotiation request. The application must read the Host Negotiation Success bit of the OTG Control and Status register (GOTGCTL.HstNegScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hstnegsucstschng {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Hstnegsucstschng> for bool {
    #[inline(always)]
    fn from(variant: Hstnegsucstschng) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hstnegsucstschng` reader - Mode: Host and Device. The core sets this bit on the success or failure of a USB host negotiation request. The application must read the Host Negotiation Success bit of the OTG Control and Status register (GOTGCTL.HstNegScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it."]
pub type HstnegsucstschngR = crate::BitReader<Hstnegsucstschng>;
impl HstnegsucstschngR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hstnegsucstschng {
        match self.bits {
            false => Hstnegsucstschng::Inactive,
            true => Hstnegsucstschng::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Hstnegsucstschng::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Hstnegsucstschng::Active
    }
}
#[doc = "Field `hstnegsucstschng` writer - Mode: Host and Device. The core sets this bit on the success or failure of a USB host negotiation request. The application must read the Host Negotiation Success bit of the OTG Control and Status register (GOTGCTL.HstNegScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it."]
pub type HstnegsucstschngW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. The core sets this bit when it detects a host negotiation request on the USB. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hstnegdet {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Hstnegdet> for bool {
    #[inline(always)]
    fn from(variant: Hstnegdet) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hstnegdet` reader - Mode:Host and Device. The core sets this bit when it detects a host negotiation request on the USB. This bit can be set only by the core and the application should write 1 to clear it."]
pub type HstnegdetR = crate::BitReader<Hstnegdet>;
impl HstnegdetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hstnegdet {
        match self.bits {
            false => Hstnegdet::Inactive,
            true => Hstnegdet::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Hstnegdet::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Hstnegdet::Active
    }
}
#[doc = "Field `hstnegdet` writer - Mode:Host and Device. The core sets this bit when it detects a host negotiation request on the USB. This bit can be set only by the core and the application should write 1 to clear it."]
pub type HstnegdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. The core sets this bit to indicate that the A-device has timed out WHILE waiting FOR the B-device to connect. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adevtoutchg {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Adevtoutchg> for bool {
    #[inline(always)]
    fn from(variant: Adevtoutchg) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `adevtoutchg` reader - Mode:Host and Device. The core sets this bit to indicate that the A-device has timed out WHILE waiting FOR the B-device to connect. This bit can be set only by the core and the application should write 1 to clear it."]
pub type AdevtoutchgR = crate::BitReader<Adevtoutchg>;
impl AdevtoutchgR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Adevtoutchg {
        match self.bits {
            false => Adevtoutchg::Inactive,
            true => Adevtoutchg::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Adevtoutchg::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Adevtoutchg::Active
    }
}
#[doc = "Field `adevtoutchg` writer - Mode:Host and Device. The core sets this bit to indicate that the A-device has timed out WHILE waiting FOR the B-device to connect. This bit can be set only by the core and the application should write 1 to clear it."]
pub type AdevtoutchgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host only. The core sets this bit when the debounce is completed after the device connect. The application can start driving USB reset after seeing this interrupt. This bit is only valid when the HNP Capable or SRP Capable bit is SET in the Core USB Configuration register (GUSBCFG.HNPCap or GUSBCFG.SRPCap, respectively). This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dbncedone {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Dbncedone> for bool {
    #[inline(always)]
    fn from(variant: Dbncedone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dbncedone` reader - Mode: Host only. The core sets this bit when the debounce is completed after the device connect. The application can start driving USB reset after seeing this interrupt. This bit is only valid when the HNP Capable or SRP Capable bit is SET in the Core USB Configuration register (GUSBCFG.HNPCap or GUSBCFG.SRPCap, respectively). This bit can be set only by the core and the application should write 1 to clear it."]
pub type DbncedoneR = crate::BitReader<Dbncedone>;
impl DbncedoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dbncedone {
        match self.bits {
            false => Dbncedone::Inactive,
            true => Dbncedone::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Dbncedone::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Dbncedone::Active
    }
}
#[doc = "Field `dbncedone` writer - Mode: Host only. The core sets this bit when the debounce is completed after the device connect. The application can start driving USB reset after seeing this interrupt. This bit is only valid when the HNP Capable or SRP Capable bit is SET in the Core USB Configuration register (GUSBCFG.HNPCap or GUSBCFG.SRPCap, respectively). This bit can be set only by the core and the application should write 1 to clear it."]
pub type DbncedoneW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 2 - Mode:Host and Device.This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn sesenddet(&self) -> SesenddetR {
        SesenddetR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 8 - Mode: Host and Device. The core sets this bit on the success or failure of a session request. The application must read the Session Request Success bit in the OTG Control and Status register (GOTGCTL.SesReqScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn sesreqsucstschng(&self) -> SesreqsucstschngR {
        SesreqsucstschngR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Mode: Host and Device. The core sets this bit on the success or failure of a USB host negotiation request. The application must read the Host Negotiation Success bit of the OTG Control and Status register (GOTGCTL.HstNegScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn hstnegsucstschng(&self) -> HstnegsucstschngR {
        HstnegsucstschngR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 17 - Mode:Host and Device. The core sets this bit when it detects a host negotiation request on the USB. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn hstnegdet(&self) -> HstnegdetR {
        HstnegdetR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Mode:Host and Device. The core sets this bit to indicate that the A-device has timed out WHILE waiting FOR the B-device to connect. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn adevtoutchg(&self) -> AdevtoutchgR {
        AdevtoutchgR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Mode: Host only. The core sets this bit when the debounce is completed after the device connect. The application can start driving USB reset after seeing this interrupt. This bit is only valid when the HNP Capable or SRP Capable bit is SET in the Core USB Configuration register (GUSBCFG.HNPCap or GUSBCFG.SRPCap, respectively). This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn dbncedone(&self) -> DbncedoneR {
        DbncedoneR::new(((self.bits >> 19) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 2 - Mode:Host and Device.This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn sesenddet(&mut self) -> SesenddetW<GlobgrpGotgintSpec> {
        SesenddetW::new(self, 2)
    }
    #[doc = "Bit 8 - Mode: Host and Device. The core sets this bit on the success or failure of a session request. The application must read the Session Request Success bit in the OTG Control and Status register (GOTGCTL.SesReqScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn sesreqsucstschng(&mut self) -> SesreqsucstschngW<GlobgrpGotgintSpec> {
        SesreqsucstschngW::new(self, 8)
    }
    #[doc = "Bit 9 - Mode: Host and Device. The core sets this bit on the success or failure of a USB host negotiation request. The application must read the Host Negotiation Success bit of the OTG Control and Status register (GOTGCTL.HstNegScs) to check for success or failure. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn hstnegsucstschng(&mut self) -> HstnegsucstschngW<GlobgrpGotgintSpec> {
        HstnegsucstschngW::new(self, 9)
    }
    #[doc = "Bit 17 - Mode:Host and Device. The core sets this bit when it detects a host negotiation request on the USB. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn hstnegdet(&mut self) -> HstnegdetW<GlobgrpGotgintSpec> {
        HstnegdetW::new(self, 17)
    }
    #[doc = "Bit 18 - Mode:Host and Device. The core sets this bit to indicate that the A-device has timed out WHILE waiting FOR the B-device to connect. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn adevtoutchg(&mut self) -> AdevtoutchgW<GlobgrpGotgintSpec> {
        AdevtoutchgW::new(self, 18)
    }
    #[doc = "Bit 19 - Mode: Host only. The core sets this bit when the debounce is completed after the device connect. The application can start driving USB reset after seeing this interrupt. This bit is only valid when the HNP Capable or SRP Capable bit is SET in the Core USB Configuration register (GUSBCFG.HNPCap or GUSBCFG.SRPCap, respectively). This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn dbncedone(&mut self) -> DbncedoneW<GlobgrpGotgintSpec> {
        DbncedoneW::new(self, 19)
    }
}
#[doc = "The application reads this register whenever there is an OTG interrupt and clears the bits in this register to clear the OTG interrupt.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gotgint::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGotgintSpec;
impl crate::RegisterSpec for GlobgrpGotgintSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`globgrp_gotgint::R`](R) reader structure"]
impl crate::Readable for GlobgrpGotgintSpec {}
#[doc = "`reset()` method sets globgrp_gotgint to value 0"]
impl crate::Resettable for GlobgrpGotgintSpec {
    const RESET_VALUE: u32 = 0;
}
