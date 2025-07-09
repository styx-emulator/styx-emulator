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
#[doc = "Register `dmagrp_AXI_Bus_Mode` reader"]
pub type R = crate::R<DmagrpAxiBusModeSpec>;
#[doc = "Register `dmagrp_AXI_Bus_Mode` writer"]
pub type W = crate::W<DmagrpAxiBusModeSpec>;
#[doc = "This bit is read-only bit and indicates the complement (invert) value of Bit 16 (FB) in Register 0 (Bus Mode Register\\[16\\]). * When this bit is set to 1, the GMAC-AXI is allowed to perform any burst length equal to or below the maximum allowed burst length programmed in Bits\\[7:1\\]. * When this bit is set to 0, the GMAC-AXI is allowed to perform only fixed burst lengths as indicated by BLEN16, BLEN8, or BLEN4, or a burst length of 1.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Undefined {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Undefined> for bool {
    #[inline(always)]
    fn from(variant: Undefined) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `undefined` reader - This bit is read-only bit and indicates the complement (invert) value of Bit 16 (FB) in Register 0 (Bus Mode Register\\[16\\]). * When this bit is set to 1, the GMAC-AXI is allowed to perform any burst length equal to or below the maximum allowed burst length programmed in Bits\\[7:1\\]. * When this bit is set to 0, the GMAC-AXI is allowed to perform only fixed burst lengths as indicated by BLEN16, BLEN8, or BLEN4, or a burst length of 1."]
pub type UndefinedR = crate::BitReader<Undefined>;
impl UndefinedR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Undefined {
        match self.bits {
            false => Undefined::Disabled,
            true => Undefined::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Undefined::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Undefined::Enabled
    }
}
#[doc = "Field `undefined` writer - This bit is read-only bit and indicates the complement (invert) value of Bit 16 (FB) in Register 0 (Bus Mode Register\\[16\\]). * When this bit is set to 1, the GMAC-AXI is allowed to perform any burst length equal to or below the maximum allowed burst length programmed in Bits\\[7:1\\]. * When this bit is set to 0, the GMAC-AXI is allowed to perform only fixed burst lengths as indicated by BLEN16, BLEN8, or BLEN4, or a burst length of 1."]
pub type UndefinedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 4 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blen4 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Blen4> for bool {
    #[inline(always)]
    fn from(variant: Blen4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `blen4` reader - When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 4 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1."]
pub type Blen4R = crate::BitReader<Blen4>;
impl Blen4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Blen4 {
        match self.bits {
            false => Blen4::Disabled,
            true => Blen4::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Blen4::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Blen4::Enabled
    }
}
#[doc = "Field `blen4` writer - When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 4 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1."]
pub type Blen4W<'a, REG> = crate::BitWriter<'a, REG, Blen4>;
impl<'a, REG> Blen4W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Blen4::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Blen4::Enabled)
    }
}
#[doc = "When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 8 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blen8 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Blen8> for bool {
    #[inline(always)]
    fn from(variant: Blen8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `blen8` reader - When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 8 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1."]
pub type Blen8R = crate::BitReader<Blen8>;
impl Blen8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Blen8 {
        match self.bits {
            false => Blen8::Disabled,
            true => Blen8::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Blen8::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Blen8::Enabled
    }
}
#[doc = "Field `blen8` writer - When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 8 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1."]
pub type Blen8W<'a, REG> = crate::BitWriter<'a, REG, Blen8>;
impl<'a, REG> Blen8W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Blen8::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Blen8::Enabled)
    }
}
#[doc = "When this bit is set to 1 or UNDEFINED is set to 1, the GMAC-AXI is allowed to select a burst length of 16 on the AXI Master interface.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blen16 {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Blen16> for bool {
    #[inline(always)]
    fn from(variant: Blen16) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `blen16` reader - When this bit is set to 1 or UNDEFINED is set to 1, the GMAC-AXI is allowed to select a burst length of 16 on the AXI Master interface."]
pub type Blen16R = crate::BitReader<Blen16>;
impl Blen16R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Blen16 {
        match self.bits {
            false => Blen16::Disabled,
            true => Blen16::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Blen16::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Blen16::Enabled
    }
}
#[doc = "Field `blen16` writer - When this bit is set to 1 or UNDEFINED is set to 1, the GMAC-AXI is allowed to select a burst length of 16 on the AXI Master interface."]
pub type Blen16W<'a, REG> = crate::BitWriter<'a, REG, Blen16>;
impl<'a, REG> Blen16W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Blen16::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Blen16::Enabled)
    }
}
#[doc = "This bit is read-only bit and reflects the Bit 25 (AAL) of Register 0 (Bus Mode Register). When this bit is set to 1, the GMAC-AXI performs address-aligned burst transfers on both read and write channels.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AxiAal {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<AxiAal> for bool {
    #[inline(always)]
    fn from(variant: AxiAal) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `axi_aal` reader - This bit is read-only bit and reflects the Bit 25 (AAL) of Register 0 (Bus Mode Register). When this bit is set to 1, the GMAC-AXI performs address-aligned burst transfers on both read and write channels."]
pub type AxiAalR = crate::BitReader<AxiAal>;
impl AxiAalR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> AxiAal {
        match self.bits {
            false => AxiAal::Disabled,
            true => AxiAal::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == AxiAal::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == AxiAal::Enabled
    }
}
#[doc = "Field `axi_aal` writer - This bit is read-only bit and reflects the Bit 25 (AAL) of Register 0 (Bus Mode Register). When this bit is set to 1, the GMAC-AXI performs address-aligned burst transfers on both read and write channels."]
pub type AxiAalW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "1 KB Boundary Crossing Enable for the GMAC-AXI Master When set, the GMAC-AXI Master performs burst transfers that do not cross 1 KB boundary. When reset, the GMAC-AXI Master performs burst transfers that do not cross 4 KB boundary.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Onekbbe {
    #[doc = "0: `0`"]
    FourKBoundary = 0,
    #[doc = "1: `1`"]
    OneKBoundary = 1,
}
impl From<Onekbbe> for bool {
    #[inline(always)]
    fn from(variant: Onekbbe) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `onekbbe` reader - 1 KB Boundary Crossing Enable for the GMAC-AXI Master When set, the GMAC-AXI Master performs burst transfers that do not cross 1 KB boundary. When reset, the GMAC-AXI Master performs burst transfers that do not cross 4 KB boundary."]
pub type OnekbbeR = crate::BitReader<Onekbbe>;
impl OnekbbeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Onekbbe {
        match self.bits {
            false => Onekbbe::FourKBoundary,
            true => Onekbbe::OneKBoundary,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_four_k_boundary(&self) -> bool {
        *self == Onekbbe::FourKBoundary
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_one_k_boundary(&self) -> bool {
        *self == Onekbbe::OneKBoundary
    }
}
#[doc = "Field `onekbbe` writer - 1 KB Boundary Crossing Enable for the GMAC-AXI Master When set, the GMAC-AXI Master performs burst transfers that do not cross 1 KB boundary. When reset, the GMAC-AXI Master performs burst transfers that do not cross 4 KB boundary."]
pub type OnekbbeW<'a, REG> = crate::BitWriter<'a, REG, Onekbbe>;
impl<'a, REG> OnekbbeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn four_k_boundary(self) -> &'a mut crate::W<REG> {
        self.variant(Onekbbe::FourKBoundary)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn one_k_boundary(self) -> &'a mut crate::W<REG> {
        self.variant(Onekbbe::OneKBoundary)
    }
}
#[doc = "Field `rd_osr_lmt` reader - This value limits the maximum outstanding request on the AXI read interface. Maximum outstanding requests = RD_OSR_LMT+1"]
pub type RdOsrLmtR = crate::FieldReader;
#[doc = "Field `rd_osr_lmt` writer - This value limits the maximum outstanding request on the AXI read interface. Maximum outstanding requests = RD_OSR_LMT+1"]
pub type RdOsrLmtW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `wr_osr_lmt` reader - AXI Maximum Write OutStanding Request Limit"]
pub type WrOsrLmtR = crate::FieldReader;
#[doc = "Field `wr_osr_lmt` writer - AXI Maximum Write OutStanding Request Limit"]
pub type WrOsrLmtW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "When set to 1, this bit enables the GMAC-AXI to come out of the LPI mode only when the Magic Packet or Remote Wake Up Packet is received. When set to 0, this bit enables the GMAC-AXI to come out of LPI mode when any frame is received.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LpiXitFrm {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<LpiXitFrm> for bool {
    #[inline(always)]
    fn from(variant: LpiXitFrm) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `lpi_xit_frm` reader - When set to 1, this bit enables the GMAC-AXI to come out of the LPI mode only when the Magic Packet or Remote Wake Up Packet is received. When set to 0, this bit enables the GMAC-AXI to come out of LPI mode when any frame is received."]
pub type LpiXitFrmR = crate::BitReader<LpiXitFrm>;
impl LpiXitFrmR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> LpiXitFrm {
        match self.bits {
            false => LpiXitFrm::Disabled,
            true => LpiXitFrm::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == LpiXitFrm::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == LpiXitFrm::Enabled
    }
}
#[doc = "Field `lpi_xit_frm` writer - When set to 1, this bit enables the GMAC-AXI to come out of the LPI mode only when the Magic Packet or Remote Wake Up Packet is received. When set to 0, this bit enables the GMAC-AXI to come out of LPI mode when any frame is received."]
pub type LpiXitFrmW<'a, REG> = crate::BitWriter<'a, REG, LpiXitFrm>;
impl<'a, REG> LpiXitFrmW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(LpiXitFrm::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(LpiXitFrm::Enabled)
    }
}
#[doc = "When set to 1, this bit enables the LPI mode supported by the AXI master and accepts the LPI request from the AXI System Clock controller. When set to 0, this bit disables the LPI mode and always denies the LPI request from the AXI System Clock controller.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnLpi {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<EnLpi> for bool {
    #[inline(always)]
    fn from(variant: EnLpi) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `en_lpi` reader - When set to 1, this bit enables the LPI mode supported by the AXI master and accepts the LPI request from the AXI System Clock controller. When set to 0, this bit disables the LPI mode and always denies the LPI request from the AXI System Clock controller."]
pub type EnLpiR = crate::BitReader<EnLpi>;
impl EnLpiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> EnLpi {
        match self.bits {
            false => EnLpi::Disabled,
            true => EnLpi::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == EnLpi::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == EnLpi::Enabled
    }
}
#[doc = "Field `en_lpi` writer - When set to 1, this bit enables the LPI mode supported by the AXI master and accepts the LPI request from the AXI System Clock controller. When set to 0, this bit disables the LPI mode and always denies the LPI request from the AXI System Clock controller."]
pub type EnLpiW<'a, REG> = crate::BitWriter<'a, REG, EnLpi>;
impl<'a, REG> EnLpiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(EnLpi::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(EnLpi::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - This bit is read-only bit and indicates the complement (invert) value of Bit 16 (FB) in Register 0 (Bus Mode Register\\[16\\]). * When this bit is set to 1, the GMAC-AXI is allowed to perform any burst length equal to or below the maximum allowed burst length programmed in Bits\\[7:1\\]. * When this bit is set to 0, the GMAC-AXI is allowed to perform only fixed burst lengths as indicated by BLEN16, BLEN8, or BLEN4, or a burst length of 1."]
    #[inline(always)]
    pub fn undefined(&self) -> UndefinedR {
        UndefinedR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 4 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1."]
    #[inline(always)]
    pub fn blen4(&self) -> Blen4R {
        Blen4R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 8 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1."]
    #[inline(always)]
    pub fn blen8(&self) -> Blen8R {
        Blen8R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When this bit is set to 1 or UNDEFINED is set to 1, the GMAC-AXI is allowed to select a burst length of 16 on the AXI Master interface."]
    #[inline(always)]
    pub fn blen16(&self) -> Blen16R {
        Blen16R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 12 - This bit is read-only bit and reflects the Bit 25 (AAL) of Register 0 (Bus Mode Register). When this bit is set to 1, the GMAC-AXI performs address-aligned burst transfers on both read and write channels."]
    #[inline(always)]
    pub fn axi_aal(&self) -> AxiAalR {
        AxiAalR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - 1 KB Boundary Crossing Enable for the GMAC-AXI Master When set, the GMAC-AXI Master performs burst transfers that do not cross 1 KB boundary. When reset, the GMAC-AXI Master performs burst transfers that do not cross 4 KB boundary."]
    #[inline(always)]
    pub fn onekbbe(&self) -> OnekbbeR {
        OnekbbeR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 16:19 - This value limits the maximum outstanding request on the AXI read interface. Maximum outstanding requests = RD_OSR_LMT+1"]
    #[inline(always)]
    pub fn rd_osr_lmt(&self) -> RdOsrLmtR {
        RdOsrLmtR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:23 - AXI Maximum Write OutStanding Request Limit"]
    #[inline(always)]
    pub fn wr_osr_lmt(&self) -> WrOsrLmtR {
        WrOsrLmtR::new(((self.bits >> 20) & 0x0f) as u8)
    }
    #[doc = "Bit 30 - When set to 1, this bit enables the GMAC-AXI to come out of the LPI mode only when the Magic Packet or Remote Wake Up Packet is received. When set to 0, this bit enables the GMAC-AXI to come out of LPI mode when any frame is received."]
    #[inline(always)]
    pub fn lpi_xit_frm(&self) -> LpiXitFrmR {
        LpiXitFrmR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - When set to 1, this bit enables the LPI mode supported by the AXI master and accepts the LPI request from the AXI System Clock controller. When set to 0, this bit disables the LPI mode and always denies the LPI request from the AXI System Clock controller."]
    #[inline(always)]
    pub fn en_lpi(&self) -> EnLpiR {
        EnLpiR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is read-only bit and indicates the complement (invert) value of Bit 16 (FB) in Register 0 (Bus Mode Register\\[16\\]). * When this bit is set to 1, the GMAC-AXI is allowed to perform any burst length equal to or below the maximum allowed burst length programmed in Bits\\[7:1\\]. * When this bit is set to 0, the GMAC-AXI is allowed to perform only fixed burst lengths as indicated by BLEN16, BLEN8, or BLEN4, or a burst length of 1."]
    #[inline(always)]
    #[must_use]
    pub fn undefined(&mut self) -> UndefinedW<DmagrpAxiBusModeSpec> {
        UndefinedW::new(self, 0)
    }
    #[doc = "Bit 1 - When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 4 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1."]
    #[inline(always)]
    #[must_use]
    pub fn blen4(&mut self) -> Blen4W<DmagrpAxiBusModeSpec> {
        Blen4W::new(self, 1)
    }
    #[doc = "Bit 2 - When this bit is set to 1, the GMAC-AXI is allowed to select a burst length of 8 on the AXI Master interface. Setting this bit has no effect when UNDEFINED is set to 1."]
    #[inline(always)]
    #[must_use]
    pub fn blen8(&mut self) -> Blen8W<DmagrpAxiBusModeSpec> {
        Blen8W::new(self, 2)
    }
    #[doc = "Bit 3 - When this bit is set to 1 or UNDEFINED is set to 1, the GMAC-AXI is allowed to select a burst length of 16 on the AXI Master interface."]
    #[inline(always)]
    #[must_use]
    pub fn blen16(&mut self) -> Blen16W<DmagrpAxiBusModeSpec> {
        Blen16W::new(self, 3)
    }
    #[doc = "Bit 12 - This bit is read-only bit and reflects the Bit 25 (AAL) of Register 0 (Bus Mode Register). When this bit is set to 1, the GMAC-AXI performs address-aligned burst transfers on both read and write channels."]
    #[inline(always)]
    #[must_use]
    pub fn axi_aal(&mut self) -> AxiAalW<DmagrpAxiBusModeSpec> {
        AxiAalW::new(self, 12)
    }
    #[doc = "Bit 13 - 1 KB Boundary Crossing Enable for the GMAC-AXI Master When set, the GMAC-AXI Master performs burst transfers that do not cross 1 KB boundary. When reset, the GMAC-AXI Master performs burst transfers that do not cross 4 KB boundary."]
    #[inline(always)]
    #[must_use]
    pub fn onekbbe(&mut self) -> OnekbbeW<DmagrpAxiBusModeSpec> {
        OnekbbeW::new(self, 13)
    }
    #[doc = "Bits 16:19 - This value limits the maximum outstanding request on the AXI read interface. Maximum outstanding requests = RD_OSR_LMT+1"]
    #[inline(always)]
    #[must_use]
    pub fn rd_osr_lmt(&mut self) -> RdOsrLmtW<DmagrpAxiBusModeSpec> {
        RdOsrLmtW::new(self, 16)
    }
    #[doc = "Bits 20:23 - AXI Maximum Write OutStanding Request Limit"]
    #[inline(always)]
    #[must_use]
    pub fn wr_osr_lmt(&mut self) -> WrOsrLmtW<DmagrpAxiBusModeSpec> {
        WrOsrLmtW::new(self, 20)
    }
    #[doc = "Bit 30 - When set to 1, this bit enables the GMAC-AXI to come out of the LPI mode only when the Magic Packet or Remote Wake Up Packet is received. When set to 0, this bit enables the GMAC-AXI to come out of LPI mode when any frame is received."]
    #[inline(always)]
    #[must_use]
    pub fn lpi_xit_frm(&mut self) -> LpiXitFrmW<DmagrpAxiBusModeSpec> {
        LpiXitFrmW::new(self, 30)
    }
    #[doc = "Bit 31 - When set to 1, this bit enables the LPI mode supported by the AXI master and accepts the LPI request from the AXI System Clock controller. When set to 0, this bit disables the LPI mode and always denies the LPI request from the AXI System Clock controller."]
    #[inline(always)]
    #[must_use]
    pub fn en_lpi(&mut self) -> EnLpiW<DmagrpAxiBusModeSpec> {
        EnLpiW::new(self, 31)
    }
}
#[doc = "The AXI Bus Mode Register controls the behavior of the AXI master. It is mainly used to control the burst splitting and the number of outstanding requests.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_axi_bus_mode::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_axi_bus_mode::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpAxiBusModeSpec;
impl crate::RegisterSpec for DmagrpAxiBusModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 4136u64;
}
#[doc = "`read()` method returns [`dmagrp_axi_bus_mode::R`](R) reader structure"]
impl crate::Readable for DmagrpAxiBusModeSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_axi_bus_mode::W`](W) writer structure"]
impl crate::Writable for DmagrpAxiBusModeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_AXI_Bus_Mode to value 0x0011_0001"]
impl crate::Resettable for DmagrpAxiBusModeSpec {
    const RESET_VALUE: u32 = 0x0011_0001;
}
