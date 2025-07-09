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
#[doc = "Register `emacgrp_ctrl` reader"]
pub type R = crate::R<EmacgrpCtrlSpec>;
#[doc = "Register `emacgrp_ctrl` writer"]
pub type W = crate::W<EmacgrpCtrlSpec>;
#[doc = "Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Physel0 {
    #[doc = "0: `0`"]
    GmiiMii = 0,
    #[doc = "1: `1`"]
    Rgmii = 1,
    #[doc = "2: `10`"]
    Rmii = 2,
}
impl From<Physel0> for u8 {
    #[inline(always)]
    fn from(variant: Physel0) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Physel0 {
    type Ux = u8;
}
#[doc = "Field `physel_0` reader - Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index."]
pub type Physel0R = crate::FieldReader<Physel0>;
impl Physel0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Physel0> {
        match self.bits {
            0 => Some(Physel0::GmiiMii),
            1 => Some(Physel0::Rgmii),
            2 => Some(Physel0::Rmii),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_gmii_mii(&self) -> bool {
        *self == Physel0::GmiiMii
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rgmii(&self) -> bool {
        *self == Physel0::Rgmii
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_rmii(&self) -> bool {
        *self == Physel0::Rmii
    }
}
#[doc = "Field `physel_0` writer - Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index."]
pub type Physel0W<'a, REG> = crate::FieldWriter<'a, REG, 2, Physel0>;
impl<'a, REG> Physel0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn gmii_mii(self) -> &'a mut crate::W<REG> {
        self.variant(Physel0::GmiiMii)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn rgmii(self) -> &'a mut crate::W<REG> {
        self.variant(Physel0::Rgmii)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn rmii(self) -> &'a mut crate::W<REG> {
        self.variant(Physel0::Rmii)
    }
}
#[doc = "Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Physel1 {
    #[doc = "0: `0`"]
    GmiiMii = 0,
    #[doc = "1: `1`"]
    Rgmii = 1,
    #[doc = "2: `10`"]
    Rmii = 2,
}
impl From<Physel1> for u8 {
    #[inline(always)]
    fn from(variant: Physel1) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Physel1 {
    type Ux = u8;
}
#[doc = "Field `physel_1` reader - Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index."]
pub type Physel1R = crate::FieldReader<Physel1>;
impl Physel1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Physel1> {
        match self.bits {
            0 => Some(Physel1::GmiiMii),
            1 => Some(Physel1::Rgmii),
            2 => Some(Physel1::Rmii),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_gmii_mii(&self) -> bool {
        *self == Physel1::GmiiMii
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rgmii(&self) -> bool {
        *self == Physel1::Rgmii
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_rmii(&self) -> bool {
        *self == Physel1::Rmii
    }
}
#[doc = "Field `physel_1` writer - Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index."]
pub type Physel1W<'a, REG> = crate::FieldWriter<'a, REG, 2, Physel1>;
impl<'a, REG> Physel1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn gmii_mii(self) -> &'a mut crate::W<REG> {
        self.variant(Physel1::GmiiMii)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn rgmii(self) -> &'a mut crate::W<REG> {
        self.variant(Physel1::Rgmii)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn rmii(self) -> &'a mut crate::W<REG> {
        self.variant(Physel1::Rmii)
    }
}
#[doc = "Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ptpclksel0 {
    #[doc = "0: `0`"]
    Osc1Clk = 0,
    #[doc = "1: `1`"]
    FpgaPtpRefClk = 1,
}
impl From<Ptpclksel0> for bool {
    #[inline(always)]
    fn from(variant: Ptpclksel0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ptpclksel_0` reader - Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index."]
pub type Ptpclksel0R = crate::BitReader<Ptpclksel0>;
impl Ptpclksel0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ptpclksel0 {
        match self.bits {
            false => Ptpclksel0::Osc1Clk,
            true => Ptpclksel0::FpgaPtpRefClk,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_osc1_clk(&self) -> bool {
        *self == Ptpclksel0::Osc1Clk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fpga_ptp_ref_clk(&self) -> bool {
        *self == Ptpclksel0::FpgaPtpRefClk
    }
}
#[doc = "Field `ptpclksel_0` writer - Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index."]
pub type Ptpclksel0W<'a, REG> = crate::BitWriter<'a, REG, Ptpclksel0>;
impl<'a, REG> Ptpclksel0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn osc1_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Ptpclksel0::Osc1Clk)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn fpga_ptp_ref_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Ptpclksel0::FpgaPtpRefClk)
    }
}
#[doc = "Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ptpclksel1 {
    #[doc = "0: `0`"]
    Osc1Clk = 0,
    #[doc = "1: `1`"]
    FpgaPtpRefClk = 1,
}
impl From<Ptpclksel1> for bool {
    #[inline(always)]
    fn from(variant: Ptpclksel1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ptpclksel_1` reader - Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index."]
pub type Ptpclksel1R = crate::BitReader<Ptpclksel1>;
impl Ptpclksel1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ptpclksel1 {
        match self.bits {
            false => Ptpclksel1::Osc1Clk,
            true => Ptpclksel1::FpgaPtpRefClk,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_osc1_clk(&self) -> bool {
        *self == Ptpclksel1::Osc1Clk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fpga_ptp_ref_clk(&self) -> bool {
        *self == Ptpclksel1::FpgaPtpRefClk
    }
}
#[doc = "Field `ptpclksel_1` writer - Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index."]
pub type Ptpclksel1W<'a, REG> = crate::BitWriter<'a, REG, Ptpclksel1>;
impl<'a, REG> Ptpclksel1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn osc1_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Ptpclksel1::Osc1Clk)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn fpga_ptp_ref_clk(self) -> &'a mut crate::W<REG> {
        self.variant(Ptpclksel1::FpgaPtpRefClk)
    }
}
impl R {
    #[doc = "Bits 0:1 - Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    pub fn physel_0(&self) -> Physel0R {
        Physel0R::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    pub fn physel_1(&self) -> Physel1R {
        Physel1R::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bit 4 - Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    pub fn ptpclksel_0(&self) -> Ptpclksel0R {
        Ptpclksel0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    pub fn ptpclksel_1(&self) -> Ptpclksel1R {
        Ptpclksel1R::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    #[must_use]
    pub fn physel_0(&mut self) -> Physel0W<EmacgrpCtrlSpec> {
        Physel0W::new(self, 0)
    }
    #[doc = "Bits 2:3 - Controls the PHY interface selection of the EMACs. This is sampled by an EMAC module when it exits from reset. The associated enum defines the allowed values. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    #[must_use]
    pub fn physel_1(&mut self) -> Physel1W<EmacgrpCtrlSpec> {
        Physel1W::new(self, 2)
    }
    #[doc = "Bit 4 - Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    #[must_use]
    pub fn ptpclksel_0(&mut self) -> Ptpclksel0W<EmacgrpCtrlSpec> {
        Ptpclksel0W::new(self, 4)
    }
    #[doc = "Bit 5 - Selects the source of the 1588 PTP reference clock. This is sampled by an EMAC module when it exits from reset. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    #[must_use]
    pub fn ptpclksel_1(&mut self) -> Ptpclksel1W<EmacgrpCtrlSpec> {
        Ptpclksel1W::new(self, 5)
    }
}
#[doc = "Registers used by the EMACs. All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`emacgrp_ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`emacgrp_ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EmacgrpCtrlSpec;
impl crate::RegisterSpec for EmacgrpCtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`emacgrp_ctrl::R`](R) reader structure"]
impl crate::Readable for EmacgrpCtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`emacgrp_ctrl::W`](W) writer structure"]
impl crate::Writable for EmacgrpCtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets emacgrp_ctrl to value 0x0a"]
impl crate::Resettable for EmacgrpCtrlSpec {
    const RESET_VALUE: u32 = 0x0a;
}
