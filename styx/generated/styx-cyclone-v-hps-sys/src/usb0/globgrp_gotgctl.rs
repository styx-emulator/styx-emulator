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
#[doc = "Register `globgrp_gotgctl` reader"]
pub type R = crate::R<GlobgrpGotgctlSpec>;
#[doc = "Register `globgrp_gotgctl` writer"]
pub type W = crate::W<GlobgrpGotgctlSpec>;
#[doc = "This bit is set when a session request initiation is successful. This bit is valid only For Device Only configuration when OTG_MODE == 3 or OTG_MODE == 4. Applies for device only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sesreqscs {
    #[doc = "0: `0`"]
    Fail = 0,
    #[doc = "1: `1`"]
    Success = 1,
}
impl From<Sesreqscs> for bool {
    #[inline(always)]
    fn from(variant: Sesreqscs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sesreqscs` reader - This bit is set when a session request initiation is successful. This bit is valid only For Device Only configuration when OTG_MODE == 3 or OTG_MODE == 4. Applies for device only."]
pub type SesreqscsR = crate::BitReader<Sesreqscs>;
impl SesreqscsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sesreqscs {
        match self.bits {
            false => Sesreqscs::Fail,
            true => Sesreqscs::Success,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fail(&self) -> bool {
        *self == Sesreqscs::Fail
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_success(&self) -> bool {
        *self == Sesreqscs::Success
    }
}
#[doc = "Field `sesreqscs` writer - This bit is set when a session request initiation is successful. This bit is valid only For Device Only configuration when OTG_MODE == 3 or OTG_MODE == 4. Applies for device only."]
pub type SesreqscsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The application sets this bit to initiate a session request on the USB. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET. The core clears this bit when the HstNegSucStsChng bit is cleared. If you use the USB 1.1 Full-Speed Serial Transceiver interface to initiate the session request, the application must wait until the VBUS discharges to 0.2 V, after the B-Session Valid bit in this register (GOTGCTL.BSesVld) is cleared. This discharge time varies between different PHYs and can be obtained from the PHY vendor.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sesreq {
    #[doc = "0: `0`"]
    Norequest = 0,
    #[doc = "1: `1`"]
    Request = 1,
}
impl From<Sesreq> for bool {
    #[inline(always)]
    fn from(variant: Sesreq) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `sesreq` reader - The application sets this bit to initiate a session request on the USB. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET. The core clears this bit when the HstNegSucStsChng bit is cleared. If you use the USB 1.1 Full-Speed Serial Transceiver interface to initiate the session request, the application must wait until the VBUS discharges to 0.2 V, after the B-Session Valid bit in this register (GOTGCTL.BSesVld) is cleared. This discharge time varies between different PHYs and can be obtained from the PHY vendor."]
pub type SesreqR = crate::BitReader<Sesreq>;
impl SesreqR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Sesreq {
        match self.bits {
            false => Sesreq::Norequest,
            true => Sesreq::Request,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_norequest(&self) -> bool {
        *self == Sesreq::Norequest
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_request(&self) -> bool {
        *self == Sesreq::Request
    }
}
#[doc = "Field `sesreq` writer - The application sets this bit to initiate a session request on the USB. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET. The core clears this bit when the HstNegSucStsChng bit is cleared. If you use the USB 1.1 Full-Speed Serial Transceiver interface to initiate the session request, the application must wait until the VBUS discharges to 0.2 V, after the B-Session Valid bit in this register (GOTGCTL.BSesVld) is cleared. This discharge time varies between different PHYs and can be obtained from the PHY vendor."]
pub type SesreqW<'a, REG> = crate::BitWriter<'a, REG, Sesreq>;
impl<'a, REG> SesreqW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn norequest(self) -> &'a mut crate::W<REG> {
        self.variant(Sesreq::Norequest)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn request(self) -> &'a mut crate::W<REG> {
        self.variant(Sesreq::Request)
    }
}
#[doc = "This bit is used to enable/disable the software to override the vbus-valid signal using the GOTGCTL.vbvalidOvVal..\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vbvalidoven {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Vbvalidoven> for bool {
    #[inline(always)]
    fn from(variant: Vbvalidoven) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vbvalidoven` reader - This bit is used to enable/disable the software to override the vbus-valid signal using the GOTGCTL.vbvalidOvVal.."]
pub type VbvalidovenR = crate::BitReader<Vbvalidoven>;
impl VbvalidovenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Vbvalidoven {
        match self.bits {
            false => Vbvalidoven::Disabled,
            true => Vbvalidoven::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Vbvalidoven::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Vbvalidoven::Enabled
    }
}
#[doc = "Field `vbvalidoven` writer - This bit is used to enable/disable the software to override the vbus-valid signal using the GOTGCTL.vbvalidOvVal.."]
pub type VbvalidovenW<'a, REG> = crate::BitWriter<'a, REG, Vbvalidoven>;
impl<'a, REG> VbvalidovenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Vbvalidoven::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Vbvalidoven::Enabled)
    }
}
#[doc = "This bit is used to set Override value for vbus valid signal when GOTGCTL.VbvalidOvEn is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vbvalidovval {
    #[doc = "0: `0`"]
    Set0 = 0,
    #[doc = "1: `1`"]
    Set1 = 1,
}
impl From<Vbvalidovval> for bool {
    #[inline(always)]
    fn from(variant: Vbvalidovval) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vbvalidovval` reader - This bit is used to set Override value for vbus valid signal when GOTGCTL.VbvalidOvEn is set."]
pub type VbvalidovvalR = crate::BitReader<Vbvalidovval>;
impl VbvalidovvalR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Vbvalidovval {
        match self.bits {
            false => Vbvalidovval::Set0,
            true => Vbvalidovval::Set1,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_set0(&self) -> bool {
        *self == Vbvalidovval::Set0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set1(&self) -> bool {
        *self == Vbvalidovval::Set1
    }
}
#[doc = "Field `vbvalidovval` writer - This bit is used to set Override value for vbus valid signal when GOTGCTL.VbvalidOvEn is set."]
pub type VbvalidovvalW<'a, REG> = crate::BitWriter<'a, REG, Vbvalidovval>;
impl<'a, REG> VbvalidovvalW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn set0(self) -> &'a mut crate::W<REG> {
        self.variant(Vbvalidovval::Set0)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn set1(self) -> &'a mut crate::W<REG> {
        self.variant(Vbvalidovval::Set1)
    }
}
#[doc = "This bit is used to enable/disable the software to override the Avalid signal using the GOTGCTL.AvalidOvVal.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Avalidoven {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Avalidoven> for bool {
    #[inline(always)]
    fn from(variant: Avalidoven) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `avalidoven` reader - This bit is used to enable/disable the software to override the Avalid signal using the GOTGCTL.AvalidOvVal."]
pub type AvalidovenR = crate::BitReader<Avalidoven>;
impl AvalidovenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Avalidoven {
        match self.bits {
            false => Avalidoven::Disabled,
            true => Avalidoven::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Avalidoven::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Avalidoven::Enabled
    }
}
#[doc = "Field `avalidoven` writer - This bit is used to enable/disable the software to override the Avalid signal using the GOTGCTL.AvalidOvVal."]
pub type AvalidovenW<'a, REG> = crate::BitWriter<'a, REG, Avalidoven>;
impl<'a, REG> AvalidovenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Avalidoven::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Avalidoven::Enabled)
    }
}
#[doc = "This bit is used to set Override value for Avalid signal when GOTGCTL.BvalidOvEn is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Avalidovval {
    #[doc = "0: `0`"]
    Value0 = 0,
    #[doc = "1: `1`"]
    Value1 = 1,
}
impl From<Avalidovval> for bool {
    #[inline(always)]
    fn from(variant: Avalidovval) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `avalidovval` reader - This bit is used to set Override value for Avalid signal when GOTGCTL.BvalidOvEn is set."]
pub type AvalidovvalR = crate::BitReader<Avalidovval>;
impl AvalidovvalR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Avalidovval {
        match self.bits {
            false => Avalidovval::Value0,
            true => Avalidovval::Value1,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_value0(&self) -> bool {
        *self == Avalidovval::Value0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_value1(&self) -> bool {
        *self == Avalidovval::Value1
    }
}
#[doc = "Field `avalidovval` writer - This bit is used to set Override value for Avalid signal when GOTGCTL.BvalidOvEn is set."]
pub type AvalidovvalW<'a, REG> = crate::BitWriter<'a, REG, Avalidovval>;
impl<'a, REG> AvalidovvalW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn value0(self) -> &'a mut crate::W<REG> {
        self.variant(Avalidovval::Value0)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn value1(self) -> &'a mut crate::W<REG> {
        self.variant(Avalidovval::Value1)
    }
}
#[doc = "This bit is used to enable/disable the software to override the Bvalid signal using the GOTGCTL.BvalidOvVal.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bvalidoven {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Bvalidoven> for bool {
    #[inline(always)]
    fn from(variant: Bvalidoven) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bvalidoven` reader - This bit is used to enable/disable the software to override the Bvalid signal using the GOTGCTL.BvalidOvVal."]
pub type BvalidovenR = crate::BitReader<Bvalidoven>;
impl BvalidovenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bvalidoven {
        match self.bits {
            false => Bvalidoven::Disabled,
            true => Bvalidoven::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Bvalidoven::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Bvalidoven::Enabled
    }
}
#[doc = "Field `bvalidoven` writer - This bit is used to enable/disable the software to override the Bvalid signal using the GOTGCTL.BvalidOvVal."]
pub type BvalidovenW<'a, REG> = crate::BitWriter<'a, REG, Bvalidoven>;
impl<'a, REG> BvalidovenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Bvalidoven::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Bvalidoven::Enabled)
    }
}
#[doc = "This bit is used to set Override value for Bvalid signalwhen GOTGCTL.BvalidOvEn is set.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bvalidovval {
    #[doc = "0: `0`"]
    Value0 = 0,
    #[doc = "1: `1`"]
    Value1 = 1,
}
impl From<Bvalidovval> for bool {
    #[inline(always)]
    fn from(variant: Bvalidovval) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bvalidovval` reader - This bit is used to set Override value for Bvalid signalwhen GOTGCTL.BvalidOvEn is set."]
pub type BvalidovvalR = crate::BitReader<Bvalidovval>;
impl BvalidovvalR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bvalidovval {
        match self.bits {
            false => Bvalidovval::Value0,
            true => Bvalidovval::Value1,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_value0(&self) -> bool {
        *self == Bvalidovval::Value0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_value1(&self) -> bool {
        *self == Bvalidovval::Value1
    }
}
#[doc = "Field `bvalidovval` writer - This bit is used to set Override value for Bvalid signalwhen GOTGCTL.BvalidOvEn is set."]
pub type BvalidovvalW<'a, REG> = crate::BitWriter<'a, REG, Bvalidovval>;
impl<'a, REG> BvalidovvalW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn value0(self) -> &'a mut crate::W<REG> {
        self.variant(Bvalidovval::Value0)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn value1(self) -> &'a mut crate::W<REG> {
        self.variant(Bvalidovval::Value1)
    }
}
#[doc = "Mode: Device only. Host Negotiation Success (HstNegScs) The core sets this bit when host negotiation is successful. The core clears this bit when the HNP Request (HNPReq) bit in this register is SET.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hstnegscs {
    #[doc = "0: `0`"]
    Fail = 0,
    #[doc = "1: `1`"]
    Success = 1,
}
impl From<Hstnegscs> for bool {
    #[inline(always)]
    fn from(variant: Hstnegscs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hstnegscs` reader - Mode: Device only. Host Negotiation Success (HstNegScs) The core sets this bit when host negotiation is successful. The core clears this bit when the HNP Request (HNPReq) bit in this register is SET."]
pub type HstnegscsR = crate::BitReader<Hstnegscs>;
impl HstnegscsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hstnegscs {
        match self.bits {
            false => Hstnegscs::Fail,
            true => Hstnegscs::Success,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fail(&self) -> bool {
        *self == Hstnegscs::Fail
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_success(&self) -> bool {
        *self == Hstnegscs::Success
    }
}
#[doc = "Field `hstnegscs` writer - Mode: Device only. Host Negotiation Success (HstNegScs) The core sets this bit when host negotiation is successful. The core clears this bit when the HNP Request (HNPReq) bit in this register is SET."]
pub type HstnegscsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. The application sets this bit to initiate an HNP request to the connected USB host. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET.The core clears this bit when the HstNegSucStsChng bit iscleared.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hnpreq {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Hnpreq> for bool {
    #[inline(always)]
    fn from(variant: Hnpreq) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hnpreq` reader - Mode: Device only. The application sets this bit to initiate an HNP request to the connected USB host. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET.The core clears this bit when the HstNegSucStsChng bit iscleared."]
pub type HnpreqR = crate::BitReader<Hnpreq>;
impl HnpreqR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hnpreq {
        match self.bits {
            false => Hnpreq::Disabled,
            true => Hnpreq::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hnpreq::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Hnpreq::Enabled
    }
}
#[doc = "Field `hnpreq` writer - Mode: Device only. The application sets this bit to initiate an HNP request to the connected USB host. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET.The core clears this bit when the HstNegSucStsChng bit iscleared."]
pub type HnpreqW<'a, REG> = crate::BitWriter<'a, REG, Hnpreq>;
impl<'a, REG> HnpreqW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hnpreq::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hnpreq::Enabled)
    }
}
#[doc = "Mode: Host only. The application sets this bit when it has successfully enabled HNP (using the SetFeature.SetHNPEnable command) on the connected device.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hstsethnpen {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Hstsethnpen> for bool {
    #[inline(always)]
    fn from(variant: Hstsethnpen) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hstsethnpen` reader - Mode: Host only. The application sets this bit when it has successfully enabled HNP (using the SetFeature.SetHNPEnable command) on the connected device."]
pub type HstsethnpenR = crate::BitReader<Hstsethnpen>;
impl HstsethnpenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hstsethnpen {
        match self.bits {
            false => Hstsethnpen::Disabled,
            true => Hstsethnpen::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hstsethnpen::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Hstsethnpen::Enabled
    }
}
#[doc = "Field `hstsethnpen` writer - Mode: Host only. The application sets this bit when it has successfully enabled HNP (using the SetFeature.SetHNPEnable command) on the connected device."]
pub type HstsethnpenW<'a, REG> = crate::BitWriter<'a, REG, Hstsethnpen>;
impl<'a, REG> HstsethnpenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hstsethnpen::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hstsethnpen::Enabled)
    }
}
#[doc = "Mode: Device only. The application sets this bit when it successfully receives a SetFeature.SetHNPEnable command from the connected USB host.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Devhnpen {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Devhnpen> for bool {
    #[inline(always)]
    fn from(variant: Devhnpen) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `devhnpen` reader - Mode: Device only. The application sets this bit when it successfully receives a SetFeature.SetHNPEnable command from the connected USB host."]
pub type DevhnpenR = crate::BitReader<Devhnpen>;
impl DevhnpenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Devhnpen {
        match self.bits {
            false => Devhnpen::Disabled,
            true => Devhnpen::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Devhnpen::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Devhnpen::Enabled
    }
}
#[doc = "Field `devhnpen` writer - Mode: Device only. The application sets this bit when it successfully receives a SetFeature.SetHNPEnable command from the connected USB host."]
pub type DevhnpenW<'a, REG> = crate::BitWriter<'a, REG, Devhnpen>;
impl<'a, REG> DevhnpenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Devhnpen::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Devhnpen::Enabled)
    }
}
#[doc = "Mode: Host and Device. Indicates the connector ID status on a connect event.This bit is valid only for Host and Device mode.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conidsts {
    #[doc = "0: `0`"]
    Modea = 0,
    #[doc = "1: `1`"]
    Modeb = 1,
}
impl From<Conidsts> for bool {
    #[inline(always)]
    fn from(variant: Conidsts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `conidsts` reader - Mode: Host and Device. Indicates the connector ID status on a connect event.This bit is valid only for Host and Device mode."]
pub type ConidstsR = crate::BitReader<Conidsts>;
impl ConidstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Conidsts {
        match self.bits {
            false => Conidsts::Modea,
            true => Conidsts::Modeb,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_modea(&self) -> bool {
        *self == Conidsts::Modea
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_modeb(&self) -> bool {
        *self == Conidsts::Modeb
    }
}
#[doc = "Field `conidsts` writer - Mode: Host and Device. Indicates the connector ID status on a connect event.This bit is valid only for Host and Device mode."]
pub type ConidstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host only. Indicates the debounce time of a detected connection.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dbnctime {
    #[doc = "0: `0`"]
    Long = 0,
    #[doc = "1: `1`"]
    Short = 1,
}
impl From<Dbnctime> for bool {
    #[inline(always)]
    fn from(variant: Dbnctime) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dbnctime` reader - Mode: Host only. Indicates the debounce time of a detected connection."]
pub type DbnctimeR = crate::BitReader<Dbnctime>;
impl DbnctimeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Dbnctime {
        match self.bits {
            false => Dbnctime::Long,
            true => Dbnctime::Short,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_long(&self) -> bool {
        *self == Dbnctime::Long
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_short(&self) -> bool {
        *self == Dbnctime::Short
    }
}
#[doc = "Field `dbnctime` writer - Mode: Host only. Indicates the debounce time of a detected connection."]
pub type DbnctimeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Host only. Indicates the Host mode transceiver status. If you do not enabled OTG features (such as SRP and HNP), the read reset value will be 1.The vbus assigns the values internally for non-SRP or non-HNP configurations.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asesvld {
    #[doc = "0: `0`"]
    Valid = 0,
    #[doc = "1: `1`"]
    Notvalid = 1,
}
impl From<Asesvld> for bool {
    #[inline(always)]
    fn from(variant: Asesvld) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `asesvld` reader - Mode: Host only. Indicates the Host mode transceiver status. If you do not enabled OTG features (such as SRP and HNP), the read reset value will be 1.The vbus assigns the values internally for non-SRP or non-HNP configurations."]
pub type AsesvldR = crate::BitReader<Asesvld>;
impl AsesvldR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Asesvld {
        match self.bits {
            false => Asesvld::Valid,
            true => Asesvld::Notvalid,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        *self == Asesvld::Valid
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_notvalid(&self) -> bool {
        *self == Asesvld::Notvalid
    }
}
#[doc = "Field `asesvld` writer - Mode: Host only. Indicates the Host mode transceiver status. If you do not enabled OTG features (such as SRP and HNP), the read reset value will be 1.The vbus assigns the values internally for non-SRP or non-HNP configurations."]
pub type AsesvldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode: Device only. Indicates the Device mode transceiver status. In OTG mode, you can use this bit to determine IF the device is connected or disconnected. If you do not enable OTG features (such as SRP and HNP), the read reset value will be 1. The vbus assigns the values internally for non-SRP or non-HNP configurations.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bsesvld {
    #[doc = "0: `0`"]
    Notvalid = 0,
    #[doc = "1: `1`"]
    Valid = 1,
}
impl From<Bsesvld> for bool {
    #[inline(always)]
    fn from(variant: Bsesvld) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bsesvld` reader - Mode: Device only. Indicates the Device mode transceiver status. In OTG mode, you can use this bit to determine IF the device is connected or disconnected. If you do not enable OTG features (such as SRP and HNP), the read reset value will be 1. The vbus assigns the values internally for non-SRP or non-HNP configurations."]
pub type BsesvldR = crate::BitReader<Bsesvld>;
impl BsesvldR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bsesvld {
        match self.bits {
            false => Bsesvld::Notvalid,
            true => Bsesvld::Valid,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notvalid(&self) -> bool {
        *self == Bsesvld::Notvalid
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        *self == Bsesvld::Valid
    }
}
#[doc = "Field `bsesvld` writer - Mode: Device only. Indicates the Device mode transceiver status. In OTG mode, you can use this bit to determine IF the device is connected or disconnected. If you do not enable OTG features (such as SRP and HNP), the read reset value will be 1. The vbus assigns the values internally for non-SRP or non-HNP configurations."]
pub type BsesvldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates the OTG revision. In OTG Version 1.3. the core supports Data line pulsing and VBus pulsing for SRP. In OTG Version 2.0 the core supports only Data line pulsing for SRP.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Otgver {
    #[doc = "0: `0`"]
    Ver13 = 0,
    #[doc = "1: `1`"]
    Ver20 = 1,
}
impl From<Otgver> for bool {
    #[inline(always)]
    fn from(variant: Otgver) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `otgver` reader - Indicates the OTG revision. In OTG Version 1.3. the core supports Data line pulsing and VBus pulsing for SRP. In OTG Version 2.0 the core supports only Data line pulsing for SRP."]
pub type OtgverR = crate::BitReader<Otgver>;
impl OtgverR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Otgver {
        match self.bits {
            false => Otgver::Ver13,
            true => Otgver::Ver20,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ver13(&self) -> bool {
        *self == Otgver::Ver13
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ver20(&self) -> bool {
        *self == Otgver::Ver20
    }
}
#[doc = "Field `otgver` writer - Indicates the OTG revision. In OTG Version 1.3. the core supports Data line pulsing and VBus pulsing for SRP. In OTG Version 2.0 the core supports only Data line pulsing for SRP."]
pub type OtgverW<'a, REG> = crate::BitWriter<'a, REG, Otgver>;
impl<'a, REG> OtgverW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ver13(self) -> &'a mut crate::W<REG> {
        self.variant(Otgver::Ver13)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ver20(self) -> &'a mut crate::W<REG> {
        self.variant(Otgver::Ver20)
    }
}
impl R {
    #[doc = "Bit 0 - This bit is set when a session request initiation is successful. This bit is valid only For Device Only configuration when OTG_MODE == 3 or OTG_MODE == 4. Applies for device only."]
    #[inline(always)]
    pub fn sesreqscs(&self) -> SesreqscsR {
        SesreqscsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - The application sets this bit to initiate a session request on the USB. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET. The core clears this bit when the HstNegSucStsChng bit is cleared. If you use the USB 1.1 Full-Speed Serial Transceiver interface to initiate the session request, the application must wait until the VBUS discharges to 0.2 V, after the B-Session Valid bit in this register (GOTGCTL.BSesVld) is cleared. This discharge time varies between different PHYs and can be obtained from the PHY vendor."]
    #[inline(always)]
    pub fn sesreq(&self) -> SesreqR {
        SesreqR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit is used to enable/disable the software to override the vbus-valid signal using the GOTGCTL.vbvalidOvVal.."]
    #[inline(always)]
    pub fn vbvalidoven(&self) -> VbvalidovenR {
        VbvalidovenR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit is used to set Override value for vbus valid signal when GOTGCTL.VbvalidOvEn is set."]
    #[inline(always)]
    pub fn vbvalidovval(&self) -> VbvalidovvalR {
        VbvalidovvalR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is used to enable/disable the software to override the Avalid signal using the GOTGCTL.AvalidOvVal."]
    #[inline(always)]
    pub fn avalidoven(&self) -> AvalidovenR {
        AvalidovenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is used to set Override value for Avalid signal when GOTGCTL.BvalidOvEn is set."]
    #[inline(always)]
    pub fn avalidovval(&self) -> AvalidovvalR {
        AvalidovvalR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit is used to enable/disable the software to override the Bvalid signal using the GOTGCTL.BvalidOvVal."]
    #[inline(always)]
    pub fn bvalidoven(&self) -> BvalidovenR {
        BvalidovenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is used to set Override value for Bvalid signalwhen GOTGCTL.BvalidOvEn is set."]
    #[inline(always)]
    pub fn bvalidovval(&self) -> BvalidovvalR {
        BvalidovvalR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Mode: Device only. Host Negotiation Success (HstNegScs) The core sets this bit when host negotiation is successful. The core clears this bit when the HNP Request (HNPReq) bit in this register is SET."]
    #[inline(always)]
    pub fn hstnegscs(&self) -> HstnegscsR {
        HstnegscsR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Mode: Device only. The application sets this bit to initiate an HNP request to the connected USB host. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET.The core clears this bit when the HstNegSucStsChng bit iscleared."]
    #[inline(always)]
    pub fn hnpreq(&self) -> HnpreqR {
        HnpreqR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Mode: Host only. The application sets this bit when it has successfully enabled HNP (using the SetFeature.SetHNPEnable command) on the connected device."]
    #[inline(always)]
    pub fn hstsethnpen(&self) -> HstsethnpenR {
        HstsethnpenR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Mode: Device only. The application sets this bit when it successfully receives a SetFeature.SetHNPEnable command from the connected USB host."]
    #[inline(always)]
    pub fn devhnpen(&self) -> DevhnpenR {
        DevhnpenR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 16 - Mode: Host and Device. Indicates the connector ID status on a connect event.This bit is valid only for Host and Device mode."]
    #[inline(always)]
    pub fn conidsts(&self) -> ConidstsR {
        ConidstsR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Mode: Host only. Indicates the debounce time of a detected connection."]
    #[inline(always)]
    pub fn dbnctime(&self) -> DbnctimeR {
        DbnctimeR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Mode: Host only. Indicates the Host mode transceiver status. If you do not enabled OTG features (such as SRP and HNP), the read reset value will be 1.The vbus assigns the values internally for non-SRP or non-HNP configurations."]
    #[inline(always)]
    pub fn asesvld(&self) -> AsesvldR {
        AsesvldR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Mode: Device only. Indicates the Device mode transceiver status. In OTG mode, you can use this bit to determine IF the device is connected or disconnected. If you do not enable OTG features (such as SRP and HNP), the read reset value will be 1. The vbus assigns the values internally for non-SRP or non-HNP configurations."]
    #[inline(always)]
    pub fn bsesvld(&self) -> BsesvldR {
        BsesvldR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Indicates the OTG revision. In OTG Version 1.3. the core supports Data line pulsing and VBus pulsing for SRP. In OTG Version 2.0 the core supports only Data line pulsing for SRP."]
    #[inline(always)]
    pub fn otgver(&self) -> OtgverR {
        OtgverR::new(((self.bits >> 20) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is set when a session request initiation is successful. This bit is valid only For Device Only configuration when OTG_MODE == 3 or OTG_MODE == 4. Applies for device only."]
    #[inline(always)]
    #[must_use]
    pub fn sesreqscs(&mut self) -> SesreqscsW<GlobgrpGotgctlSpec> {
        SesreqscsW::new(self, 0)
    }
    #[doc = "Bit 1 - The application sets this bit to initiate a session request on the USB. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET. The core clears this bit when the HstNegSucStsChng bit is cleared. If you use the USB 1.1 Full-Speed Serial Transceiver interface to initiate the session request, the application must wait until the VBUS discharges to 0.2 V, after the B-Session Valid bit in this register (GOTGCTL.BSesVld) is cleared. This discharge time varies between different PHYs and can be obtained from the PHY vendor."]
    #[inline(always)]
    #[must_use]
    pub fn sesreq(&mut self) -> SesreqW<GlobgrpGotgctlSpec> {
        SesreqW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit is used to enable/disable the software to override the vbus-valid signal using the GOTGCTL.vbvalidOvVal.."]
    #[inline(always)]
    #[must_use]
    pub fn vbvalidoven(&mut self) -> VbvalidovenW<GlobgrpGotgctlSpec> {
        VbvalidovenW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit is used to set Override value for vbus valid signal when GOTGCTL.VbvalidOvEn is set."]
    #[inline(always)]
    #[must_use]
    pub fn vbvalidovval(&mut self) -> VbvalidovvalW<GlobgrpGotgctlSpec> {
        VbvalidovvalW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit is used to enable/disable the software to override the Avalid signal using the GOTGCTL.AvalidOvVal."]
    #[inline(always)]
    #[must_use]
    pub fn avalidoven(&mut self) -> AvalidovenW<GlobgrpGotgctlSpec> {
        AvalidovenW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is used to set Override value for Avalid signal when GOTGCTL.BvalidOvEn is set."]
    #[inline(always)]
    #[must_use]
    pub fn avalidovval(&mut self) -> AvalidovvalW<GlobgrpGotgctlSpec> {
        AvalidovvalW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit is used to enable/disable the software to override the Bvalid signal using the GOTGCTL.BvalidOvVal."]
    #[inline(always)]
    #[must_use]
    pub fn bvalidoven(&mut self) -> BvalidovenW<GlobgrpGotgctlSpec> {
        BvalidovenW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is used to set Override value for Bvalid signalwhen GOTGCTL.BvalidOvEn is set."]
    #[inline(always)]
    #[must_use]
    pub fn bvalidovval(&mut self) -> BvalidovvalW<GlobgrpGotgctlSpec> {
        BvalidovvalW::new(self, 7)
    }
    #[doc = "Bit 8 - Mode: Device only. Host Negotiation Success (HstNegScs) The core sets this bit when host negotiation is successful. The core clears this bit when the HNP Request (HNPReq) bit in this register is SET."]
    #[inline(always)]
    #[must_use]
    pub fn hstnegscs(&mut self) -> HstnegscsW<GlobgrpGotgctlSpec> {
        HstnegscsW::new(self, 8)
    }
    #[doc = "Bit 9 - Mode: Device only. The application sets this bit to initiate an HNP request to the connected USB host. The application can clear this bit by writing a 0 when the Host Negotiation Success Status Change bit in the OTG Interrupt register (GOTGINT.HstNegSucStsChng) is SET.The core clears this bit when the HstNegSucStsChng bit iscleared."]
    #[inline(always)]
    #[must_use]
    pub fn hnpreq(&mut self) -> HnpreqW<GlobgrpGotgctlSpec> {
        HnpreqW::new(self, 9)
    }
    #[doc = "Bit 10 - Mode: Host only. The application sets this bit when it has successfully enabled HNP (using the SetFeature.SetHNPEnable command) on the connected device."]
    #[inline(always)]
    #[must_use]
    pub fn hstsethnpen(&mut self) -> HstsethnpenW<GlobgrpGotgctlSpec> {
        HstsethnpenW::new(self, 10)
    }
    #[doc = "Bit 11 - Mode: Device only. The application sets this bit when it successfully receives a SetFeature.SetHNPEnable command from the connected USB host."]
    #[inline(always)]
    #[must_use]
    pub fn devhnpen(&mut self) -> DevhnpenW<GlobgrpGotgctlSpec> {
        DevhnpenW::new(self, 11)
    }
    #[doc = "Bit 16 - Mode: Host and Device. Indicates the connector ID status on a connect event.This bit is valid only for Host and Device mode."]
    #[inline(always)]
    #[must_use]
    pub fn conidsts(&mut self) -> ConidstsW<GlobgrpGotgctlSpec> {
        ConidstsW::new(self, 16)
    }
    #[doc = "Bit 17 - Mode: Host only. Indicates the debounce time of a detected connection."]
    #[inline(always)]
    #[must_use]
    pub fn dbnctime(&mut self) -> DbnctimeW<GlobgrpGotgctlSpec> {
        DbnctimeW::new(self, 17)
    }
    #[doc = "Bit 18 - Mode: Host only. Indicates the Host mode transceiver status. If you do not enabled OTG features (such as SRP and HNP), the read reset value will be 1.The vbus assigns the values internally for non-SRP or non-HNP configurations."]
    #[inline(always)]
    #[must_use]
    pub fn asesvld(&mut self) -> AsesvldW<GlobgrpGotgctlSpec> {
        AsesvldW::new(self, 18)
    }
    #[doc = "Bit 19 - Mode: Device only. Indicates the Device mode transceiver status. In OTG mode, you can use this bit to determine IF the device is connected or disconnected. If you do not enable OTG features (such as SRP and HNP), the read reset value will be 1. The vbus assigns the values internally for non-SRP or non-HNP configurations."]
    #[inline(always)]
    #[must_use]
    pub fn bsesvld(&mut self) -> BsesvldW<GlobgrpGotgctlSpec> {
        BsesvldW::new(self, 19)
    }
    #[doc = "Bit 20 - Indicates the OTG revision. In OTG Version 1.3. the core supports Data line pulsing and VBus pulsing for SRP. In OTG Version 2.0 the core supports only Data line pulsing for SRP."]
    #[inline(always)]
    #[must_use]
    pub fn otgver(&mut self) -> OtgverW<GlobgrpGotgctlSpec> {
        OtgverW::new(self, 20)
    }
}
#[doc = "The OTG Control and Status register controls the behavior and reflects the status of the OTG function.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gotgctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gotgctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGotgctlSpec;
impl crate::RegisterSpec for GlobgrpGotgctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`globgrp_gotgctl::R`](R) reader structure"]
impl crate::Readable for GlobgrpGotgctlSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_gotgctl::W`](W) writer structure"]
impl crate::Writable for GlobgrpGotgctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_gotgctl to value 0x0001_0000"]
impl crate::Resettable for GlobgrpGotgctlSpec {
    const RESET_VALUE: u32 = 0x0001_0000;
}
