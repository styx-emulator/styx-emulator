// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `sdmmcgrp_ctrl` reader"]
pub type R = crate::R<SdmmcgrpCtrlSpec>;
#[doc = "Register `sdmmcgrp_ctrl` writer"]
pub type W = crate::W<SdmmcgrpCtrlSpec>;
#[doc = "Select which phase shift of the clock for cclk_in_drv.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Drvsel {
    #[doc = "0: `0`"]
    Degrees0 = 0,
    #[doc = "1: `1`"]
    Degrees45 = 1,
    #[doc = "2: `10`"]
    Degrees90 = 2,
    #[doc = "3: `11`"]
    Degrees135 = 3,
    #[doc = "4: `100`"]
    Degrees180 = 4,
    #[doc = "5: `101`"]
    Degrees225 = 5,
    #[doc = "6: `110`"]
    Degrees270 = 6,
    #[doc = "7: `111`"]
    Degrees315 = 7,
}
impl From<Drvsel> for u8 {
    #[inline(always)]
    fn from(variant: Drvsel) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Drvsel {
    type Ux = u8;
}
#[doc = "Field `drvsel` reader - Select which phase shift of the clock for cclk_in_drv."]
pub type DrvselR = crate::FieldReader<Drvsel>;
impl DrvselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Drvsel {
        match self.bits {
            0 => Drvsel::Degrees0,
            1 => Drvsel::Degrees45,
            2 => Drvsel::Degrees90,
            3 => Drvsel::Degrees135,
            4 => Drvsel::Degrees180,
            5 => Drvsel::Degrees225,
            6 => Drvsel::Degrees270,
            7 => Drvsel::Degrees315,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_degrees0(&self) -> bool {
        *self == Drvsel::Degrees0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_degrees45(&self) -> bool {
        *self == Drvsel::Degrees45
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_degrees90(&self) -> bool {
        *self == Drvsel::Degrees90
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_degrees135(&self) -> bool {
        *self == Drvsel::Degrees135
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_degrees180(&self) -> bool {
        *self == Drvsel::Degrees180
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_degrees225(&self) -> bool {
        *self == Drvsel::Degrees225
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_degrees270(&self) -> bool {
        *self == Drvsel::Degrees270
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_degrees315(&self) -> bool {
        *self == Drvsel::Degrees315
    }
}
#[doc = "Field `drvsel` writer - Select which phase shift of the clock for cclk_in_drv."]
pub type DrvselW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Drvsel>;
impl<'a, REG> DrvselW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn degrees0(self) -> &'a mut crate::W<REG> {
        self.variant(Drvsel::Degrees0)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn degrees45(self) -> &'a mut crate::W<REG> {
        self.variant(Drvsel::Degrees45)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn degrees90(self) -> &'a mut crate::W<REG> {
        self.variant(Drvsel::Degrees90)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn degrees135(self) -> &'a mut crate::W<REG> {
        self.variant(Drvsel::Degrees135)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn degrees180(self) -> &'a mut crate::W<REG> {
        self.variant(Drvsel::Degrees180)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn degrees225(self) -> &'a mut crate::W<REG> {
        self.variant(Drvsel::Degrees225)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn degrees270(self) -> &'a mut crate::W<REG> {
        self.variant(Drvsel::Degrees270)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn degrees315(self) -> &'a mut crate::W<REG> {
        self.variant(Drvsel::Degrees315)
    }
}
#[doc = "Select which phase shift of the clock for cclk_in_sample.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Smplsel {
    #[doc = "0: `0`"]
    Degrees0 = 0,
    #[doc = "1: `1`"]
    Degrees45 = 1,
    #[doc = "2: `10`"]
    Degrees90 = 2,
    #[doc = "3: `11`"]
    Degrees135 = 3,
    #[doc = "4: `100`"]
    Degrees180 = 4,
    #[doc = "5: `101`"]
    Degrees225 = 5,
    #[doc = "6: `110`"]
    Degrees270 = 6,
    #[doc = "7: `111`"]
    Degrees315 = 7,
}
impl From<Smplsel> for u8 {
    #[inline(always)]
    fn from(variant: Smplsel) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Smplsel {
    type Ux = u8;
}
#[doc = "Field `smplsel` reader - Select which phase shift of the clock for cclk_in_sample."]
pub type SmplselR = crate::FieldReader<Smplsel>;
impl SmplselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Smplsel {
        match self.bits {
            0 => Smplsel::Degrees0,
            1 => Smplsel::Degrees45,
            2 => Smplsel::Degrees90,
            3 => Smplsel::Degrees135,
            4 => Smplsel::Degrees180,
            5 => Smplsel::Degrees225,
            6 => Smplsel::Degrees270,
            7 => Smplsel::Degrees315,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_degrees0(&self) -> bool {
        *self == Smplsel::Degrees0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_degrees45(&self) -> bool {
        *self == Smplsel::Degrees45
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_degrees90(&self) -> bool {
        *self == Smplsel::Degrees90
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_degrees135(&self) -> bool {
        *self == Smplsel::Degrees135
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_degrees180(&self) -> bool {
        *self == Smplsel::Degrees180
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_degrees225(&self) -> bool {
        *self == Smplsel::Degrees225
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_degrees270(&self) -> bool {
        *self == Smplsel::Degrees270
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_degrees315(&self) -> bool {
        *self == Smplsel::Degrees315
    }
}
#[doc = "Field `smplsel` writer - Select which phase shift of the clock for cclk_in_sample."]
pub type SmplselW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Smplsel>;
impl<'a, REG> SmplselW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn degrees0(self) -> &'a mut crate::W<REG> {
        self.variant(Smplsel::Degrees0)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn degrees45(self) -> &'a mut crate::W<REG> {
        self.variant(Smplsel::Degrees45)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn degrees90(self) -> &'a mut crate::W<REG> {
        self.variant(Smplsel::Degrees90)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn degrees135(self) -> &'a mut crate::W<REG> {
        self.variant(Smplsel::Degrees135)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn degrees180(self) -> &'a mut crate::W<REG> {
        self.variant(Smplsel::Degrees180)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn degrees225(self) -> &'a mut crate::W<REG> {
        self.variant(Smplsel::Degrees225)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn degrees270(self) -> &'a mut crate::W<REG> {
        self.variant(Smplsel::Degrees270)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn degrees315(self) -> &'a mut crate::W<REG> {
        self.variant(Smplsel::Degrees315)
    }
}
#[doc = "Field `fbclksel` reader - Select which fb_clk to be used as cclk_in_sample. If 0, cclk_in_sample is driven by internal phase shifted cclk_in. If 1, cclk_in_sample is driven by fb_clk_in. No phase shifting is provided internally on cclk_in_sample. Note: Using the feedback clock (setting this bit to 1) is not a supported use model."]
pub type FbclkselR = crate::BitReader;
#[doc = "Field `fbclksel` writer - Select which fb_clk to be used as cclk_in_sample. If 0, cclk_in_sample is driven by internal phase shifted cclk_in. If 1, cclk_in_sample is driven by fb_clk_in. No phase shifting is provided internally on cclk_in_sample. Note: Using the feedback clock (setting this bit to 1) is not a supported use model."]
pub type FbclkselW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:2 - Select which phase shift of the clock for cclk_in_drv."]
    #[inline(always)]
    pub fn drvsel(&self) -> DrvselR {
        DrvselR::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 3:5 - Select which phase shift of the clock for cclk_in_sample."]
    #[inline(always)]
    pub fn smplsel(&self) -> SmplselR {
        SmplselR::new(((self.bits >> 3) & 7) as u8)
    }
    #[doc = "Bit 6 - Select which fb_clk to be used as cclk_in_sample. If 0, cclk_in_sample is driven by internal phase shifted cclk_in. If 1, cclk_in_sample is driven by fb_clk_in. No phase shifting is provided internally on cclk_in_sample. Note: Using the feedback clock (setting this bit to 1) is not a supported use model."]
    #[inline(always)]
    pub fn fbclksel(&self) -> FbclkselR {
        FbclkselR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - Select which phase shift of the clock for cclk_in_drv."]
    #[inline(always)]
    #[must_use]
    pub fn drvsel(&mut self) -> DrvselW<SdmmcgrpCtrlSpec> {
        DrvselW::new(self, 0)
    }
    #[doc = "Bits 3:5 - Select which phase shift of the clock for cclk_in_sample."]
    #[inline(always)]
    #[must_use]
    pub fn smplsel(&mut self) -> SmplselW<SdmmcgrpCtrlSpec> {
        SmplselW::new(self, 3)
    }
    #[doc = "Bit 6 - Select which fb_clk to be used as cclk_in_sample. If 0, cclk_in_sample is driven by internal phase shifted cclk_in. If 1, cclk_in_sample is driven by fb_clk_in. No phase shifting is provided internally on cclk_in_sample. Note: Using the feedback clock (setting this bit to 1) is not a supported use model."]
    #[inline(always)]
    #[must_use]
    pub fn fbclksel(&mut self) -> FbclkselW<SdmmcgrpCtrlSpec> {
        FbclkselW::new(self, 6)
    }
}
#[doc = "Registers used by the SDMMC Controller. All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdmmcgrp_ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdmmcgrp_ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SdmmcgrpCtrlSpec;
impl crate::RegisterSpec for SdmmcgrpCtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 264u64;
}
#[doc = "`read()` method returns [`sdmmcgrp_ctrl::R`](R) reader structure"]
impl crate::Readable for SdmmcgrpCtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`sdmmcgrp_ctrl::W`](W) writer structure"]
impl crate::Writable for SdmmcgrpCtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets sdmmcgrp_ctrl to value 0"]
impl crate::Resettable for SdmmcgrpCtrlSpec {
    const RESET_VALUE: u32 = 0;
}
