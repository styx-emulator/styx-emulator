// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `wdt_comp_param_1` reader"]
pub type R = crate::R<WdtCompParam1Spec>;
#[doc = "Register `wdt_comp_param_1` writer"]
pub type W = crate::W<WdtCompParam1Spec>;
#[doc = "Specifies whether watchdog starts after reset or not.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpWdtAlwaysEn {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<CpWdtAlwaysEn> for bool {
    #[inline(always)]
    fn from(variant: CpWdtAlwaysEn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cp_wdt_always_en` reader - Specifies whether watchdog starts after reset or not."]
pub type CpWdtAlwaysEnR = crate::BitReader<CpWdtAlwaysEn>;
impl CpWdtAlwaysEnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtAlwaysEn> {
        match self.bits {
            false => Some(CpWdtAlwaysEn::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == CpWdtAlwaysEn::Disabled
    }
}
#[doc = "Field `cp_wdt_always_en` writer - Specifies whether watchdog starts after reset or not."]
pub type CpWdtAlwaysEnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies default output response mode after reset.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpWdtDfltRmod {
    #[doc = "0: `0`"]
    Rstreq = 0,
}
impl From<CpWdtDfltRmod> for bool {
    #[inline(always)]
    fn from(variant: CpWdtDfltRmod) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cp_wdt_dflt_rmod` reader - Specifies default output response mode after reset."]
pub type CpWdtDfltRmodR = crate::BitReader<CpWdtDfltRmod>;
impl CpWdtDfltRmodR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtDfltRmod> {
        match self.bits {
            false => Some(CpWdtDfltRmod::Rstreq),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rstreq(&self) -> bool {
        *self == CpWdtDfltRmod::Rstreq
    }
}
#[doc = "Field `cp_wdt_dflt_rmod` writer - Specifies default output response mode after reset."]
pub type CpWdtDfltRmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies whether a second timeout period that is used for initialization prior to the first kick is present or not.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpWdtDualTop {
    #[doc = "1: `1`"]
    Dualtop = 1,
}
impl From<CpWdtDualTop> for bool {
    #[inline(always)]
    fn from(variant: CpWdtDualTop) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cp_wdt_dual_top` reader - Specifies whether a second timeout period that is used for initialization prior to the first kick is present or not."]
pub type CpWdtDualTopR = crate::BitReader<CpWdtDualTop>;
impl CpWdtDualTopR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtDualTop> {
        match self.bits {
            true => Some(CpWdtDualTop::Dualtop),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_dualtop(&self) -> bool {
        *self == CpWdtDualTop::Dualtop
    }
}
#[doc = "Field `cp_wdt_dual_top` writer - Specifies whether a second timeout period that is used for initialization prior to the first kick is present or not."]
pub type CpWdtDualTopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies if response mode (when counter reaches 0) is programmable or hardcoded.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpWdtHcRmod {
    #[doc = "0: `0`"]
    Programmable = 0,
}
impl From<CpWdtHcRmod> for bool {
    #[inline(always)]
    fn from(variant: CpWdtHcRmod) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cp_wdt_hc_rmod` reader - Specifies if response mode (when counter reaches 0) is programmable or hardcoded."]
pub type CpWdtHcRmodR = crate::BitReader<CpWdtHcRmod>;
impl CpWdtHcRmodR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtHcRmod> {
        match self.bits {
            false => Some(CpWdtHcRmod::Programmable),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_programmable(&self) -> bool {
        *self == CpWdtHcRmod::Programmable
    }
}
#[doc = "Field `cp_wdt_hc_rmod` writer - Specifies if response mode (when counter reaches 0) is programmable or hardcoded."]
pub type CpWdtHcRmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies if the reset pulse length is programmable or hardcoded.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpWdtHcRpl {
    #[doc = "1: `1`"]
    Hardcoded = 1,
}
impl From<CpWdtHcRpl> for bool {
    #[inline(always)]
    fn from(variant: CpWdtHcRpl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cp_wdt_hc_rpl` reader - Specifies if the reset pulse length is programmable or hardcoded."]
pub type CpWdtHcRplR = crate::BitReader<CpWdtHcRpl>;
impl CpWdtHcRplR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtHcRpl> {
        match self.bits {
            true => Some(CpWdtHcRpl::Hardcoded),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_hardcoded(&self) -> bool {
        *self == CpWdtHcRpl::Hardcoded
    }
}
#[doc = "Field `cp_wdt_hc_rpl` writer - Specifies if the reset pulse length is programmable or hardcoded."]
pub type CpWdtHcRplW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies if the timeout period is programmable or hardcoded.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpWdtHcTop {
    #[doc = "0: `0`"]
    Programmable = 0,
}
impl From<CpWdtHcTop> for bool {
    #[inline(always)]
    fn from(variant: CpWdtHcTop) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cp_wdt_hc_top` reader - Specifies if the timeout period is programmable or hardcoded."]
pub type CpWdtHcTopR = crate::BitReader<CpWdtHcTop>;
impl CpWdtHcTopR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtHcTop> {
        match self.bits {
            false => Some(CpWdtHcTop::Programmable),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_programmable(&self) -> bool {
        *self == CpWdtHcTop::Programmable
    }
}
#[doc = "Field `cp_wdt_hc_top` writer - Specifies if the timeout period is programmable or hardcoded."]
pub type CpWdtHcTopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies if the watchdog uses the pre-defined timeout values or if these were overriden with customer values when the watchdog was configured.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpWdtUseFixTop {
    #[doc = "1: `1`"]
    Predefined = 1,
}
impl From<CpWdtUseFixTop> for bool {
    #[inline(always)]
    fn from(variant: CpWdtUseFixTop) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cp_wdt_use_fix_top` reader - Specifies if the watchdog uses the pre-defined timeout values or if these were overriden with customer values when the watchdog was configured."]
pub type CpWdtUseFixTopR = crate::BitReader<CpWdtUseFixTop>;
impl CpWdtUseFixTopR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtUseFixTop> {
        match self.bits {
            true => Some(CpWdtUseFixTop::Predefined),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_predefined(&self) -> bool {
        *self == CpWdtUseFixTop::Predefined
    }
}
#[doc = "Field `cp_wdt_use_fix_top` writer - Specifies if the watchdog uses the pre-defined timeout values or if these were overriden with customer values when the watchdog was configured."]
pub type CpWdtUseFixTopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `cp_wdt_pause` reader - Should specify if the pause input is included or not. However, this field is always hardwired to 0 so you can't figure this out by reading this field. The pause input is included and can be used to pause the watchdog when the MPU is in debug mode."]
pub type CpWdtPauseR = crate::BitReader;
#[doc = "Field `cp_wdt_pause` writer - Should specify if the pause input is included or not. However, this field is always hardwired to 0 so you can't figure this out by reading this field. The pause input is included and can be used to pause the watchdog when the MPU is in debug mode."]
pub type CpWdtPauseW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "APB Bus Width\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CpWdtApbDataWidth {
    #[doc = "2: `10`"]
    Width32bits = 2,
}
impl From<CpWdtApbDataWidth> for u8 {
    #[inline(always)]
    fn from(variant: CpWdtApbDataWidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for CpWdtApbDataWidth {
    type Ux = u8;
}
#[doc = "Field `cp_wdt_apb_data_width` reader - APB Bus Width"]
pub type CpWdtApbDataWidthR = crate::FieldReader<CpWdtApbDataWidth>;
impl CpWdtApbDataWidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtApbDataWidth> {
        match self.bits {
            2 => Some(CpWdtApbDataWidth::Width32bits),
            _ => None,
        }
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_width32bits(&self) -> bool {
        *self == CpWdtApbDataWidth::Width32bits
    }
}
#[doc = "Field `cp_wdt_apb_data_width` writer - APB Bus Width"]
pub type CpWdtApbDataWidthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Specifies the reset pulse length in cycles.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CpWdtDfltRpl {
    #[doc = "0: `0`"]
    Pulse2cycles = 0,
}
impl From<CpWdtDfltRpl> for u8 {
    #[inline(always)]
    fn from(variant: CpWdtDfltRpl) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for CpWdtDfltRpl {
    type Ux = u8;
}
#[doc = "Field `cp_wdt_dflt_rpl` reader - Specifies the reset pulse length in cycles."]
pub type CpWdtDfltRplR = crate::FieldReader<CpWdtDfltRpl>;
impl CpWdtDfltRplR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtDfltRpl> {
        match self.bits {
            0 => Some(CpWdtDfltRpl::Pulse2cycles),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_pulse2cycles(&self) -> bool {
        *self == CpWdtDfltRpl::Pulse2cycles
    }
}
#[doc = "Field `cp_wdt_dflt_rpl` writer - Specifies the reset pulse length in cycles."]
pub type CpWdtDfltRplW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Specifies the timeout period that is available directly after reset.\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CpWdtDfltTop {
    #[doc = "15: `1111`"]
    Timeout15 = 15,
}
impl From<CpWdtDfltTop> for u8 {
    #[inline(always)]
    fn from(variant: CpWdtDfltTop) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for CpWdtDfltTop {
    type Ux = u8;
}
#[doc = "Field `cp_wdt_dflt_top` reader - Specifies the timeout period that is available directly after reset."]
pub type CpWdtDfltTopR = crate::FieldReader<CpWdtDfltTop>;
impl CpWdtDfltTopR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtDfltTop> {
        match self.bits {
            15 => Some(CpWdtDfltTop::Timeout15),
            _ => None,
        }
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_timeout15(&self) -> bool {
        *self == CpWdtDfltTop::Timeout15
    }
}
#[doc = "Field `cp_wdt_dflt_top` writer - Specifies the timeout period that is available directly after reset."]
pub type CpWdtDfltTopW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Specifies the initial timeout period that is available directly after reset.\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CpWdtDfltTopInit {
    #[doc = "15: `1111`"]
    Timeout15 = 15,
}
impl From<CpWdtDfltTopInit> for u8 {
    #[inline(always)]
    fn from(variant: CpWdtDfltTopInit) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for CpWdtDfltTopInit {
    type Ux = u8;
}
#[doc = "Field `cp_wdt_dflt_top_init` reader - Specifies the initial timeout period that is available directly after reset."]
pub type CpWdtDfltTopInitR = crate::FieldReader<CpWdtDfltTopInit>;
impl CpWdtDfltTopInitR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtDfltTopInit> {
        match self.bits {
            15 => Some(CpWdtDfltTopInit::Timeout15),
            _ => None,
        }
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_timeout15(&self) -> bool {
        *self == CpWdtDfltTopInit::Timeout15
    }
}
#[doc = "Field `cp_wdt_dflt_top_init` writer - Specifies the initial timeout period that is available directly after reset."]
pub type CpWdtDfltTopInitW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Width of counter in bits less 16.\n\nValue on reset: 16"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CpWdtCntWidth {
    #[doc = "16: `10000`"]
    Width32bits = 16,
}
impl From<CpWdtCntWidth> for u8 {
    #[inline(always)]
    fn from(variant: CpWdtCntWidth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for CpWdtCntWidth {
    type Ux = u8;
}
#[doc = "Field `cp_wdt_cnt_width` reader - Width of counter in bits less 16."]
pub type CpWdtCntWidthR = crate::FieldReader<CpWdtCntWidth>;
impl CpWdtCntWidthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<CpWdtCntWidth> {
        match self.bits {
            16 => Some(CpWdtCntWidth::Width32bits),
            _ => None,
        }
    }
    #[doc = "`10000`"]
    #[inline(always)]
    pub fn is_width32bits(&self) -> bool {
        *self == CpWdtCntWidth::Width32bits
    }
}
#[doc = "Field `cp_wdt_cnt_width` writer - Width of counter in bits less 16."]
pub type CpWdtCntWidthW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bit 0 - Specifies whether watchdog starts after reset or not."]
    #[inline(always)]
    pub fn cp_wdt_always_en(&self) -> CpWdtAlwaysEnR {
        CpWdtAlwaysEnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Specifies default output response mode after reset."]
    #[inline(always)]
    pub fn cp_wdt_dflt_rmod(&self) -> CpWdtDfltRmodR {
        CpWdtDfltRmodR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Specifies whether a second timeout period that is used for initialization prior to the first kick is present or not."]
    #[inline(always)]
    pub fn cp_wdt_dual_top(&self) -> CpWdtDualTopR {
        CpWdtDualTopR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Specifies if response mode (when counter reaches 0) is programmable or hardcoded."]
    #[inline(always)]
    pub fn cp_wdt_hc_rmod(&self) -> CpWdtHcRmodR {
        CpWdtHcRmodR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Specifies if the reset pulse length is programmable or hardcoded."]
    #[inline(always)]
    pub fn cp_wdt_hc_rpl(&self) -> CpWdtHcRplR {
        CpWdtHcRplR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Specifies if the timeout period is programmable or hardcoded."]
    #[inline(always)]
    pub fn cp_wdt_hc_top(&self) -> CpWdtHcTopR {
        CpWdtHcTopR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Specifies if the watchdog uses the pre-defined timeout values or if these were overriden with customer values when the watchdog was configured."]
    #[inline(always)]
    pub fn cp_wdt_use_fix_top(&self) -> CpWdtUseFixTopR {
        CpWdtUseFixTopR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Should specify if the pause input is included or not. However, this field is always hardwired to 0 so you can't figure this out by reading this field. The pause input is included and can be used to pause the watchdog when the MPU is in debug mode."]
    #[inline(always)]
    pub fn cp_wdt_pause(&self) -> CpWdtPauseR {
        CpWdtPauseR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:9 - APB Bus Width"]
    #[inline(always)]
    pub fn cp_wdt_apb_data_width(&self) -> CpWdtApbDataWidthR {
        CpWdtApbDataWidthR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bits 10:12 - Specifies the reset pulse length in cycles."]
    #[inline(always)]
    pub fn cp_wdt_dflt_rpl(&self) -> CpWdtDfltRplR {
        CpWdtDfltRplR::new(((self.bits >> 10) & 7) as u8)
    }
    #[doc = "Bits 16:19 - Specifies the timeout period that is available directly after reset."]
    #[inline(always)]
    pub fn cp_wdt_dflt_top(&self) -> CpWdtDfltTopR {
        CpWdtDfltTopR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:23 - Specifies the initial timeout period that is available directly after reset."]
    #[inline(always)]
    pub fn cp_wdt_dflt_top_init(&self) -> CpWdtDfltTopInitR {
        CpWdtDfltTopInitR::new(((self.bits >> 20) & 0x0f) as u8)
    }
    #[doc = "Bits 24:28 - Width of counter in bits less 16."]
    #[inline(always)]
    pub fn cp_wdt_cnt_width(&self) -> CpWdtCntWidthR {
        CpWdtCntWidthR::new(((self.bits >> 24) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Specifies whether watchdog starts after reset or not."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_always_en(&mut self) -> CpWdtAlwaysEnW<WdtCompParam1Spec> {
        CpWdtAlwaysEnW::new(self, 0)
    }
    #[doc = "Bit 1 - Specifies default output response mode after reset."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_dflt_rmod(&mut self) -> CpWdtDfltRmodW<WdtCompParam1Spec> {
        CpWdtDfltRmodW::new(self, 1)
    }
    #[doc = "Bit 2 - Specifies whether a second timeout period that is used for initialization prior to the first kick is present or not."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_dual_top(&mut self) -> CpWdtDualTopW<WdtCompParam1Spec> {
        CpWdtDualTopW::new(self, 2)
    }
    #[doc = "Bit 3 - Specifies if response mode (when counter reaches 0) is programmable or hardcoded."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_hc_rmod(&mut self) -> CpWdtHcRmodW<WdtCompParam1Spec> {
        CpWdtHcRmodW::new(self, 3)
    }
    #[doc = "Bit 4 - Specifies if the reset pulse length is programmable or hardcoded."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_hc_rpl(&mut self) -> CpWdtHcRplW<WdtCompParam1Spec> {
        CpWdtHcRplW::new(self, 4)
    }
    #[doc = "Bit 5 - Specifies if the timeout period is programmable or hardcoded."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_hc_top(&mut self) -> CpWdtHcTopW<WdtCompParam1Spec> {
        CpWdtHcTopW::new(self, 5)
    }
    #[doc = "Bit 6 - Specifies if the watchdog uses the pre-defined timeout values or if these were overriden with customer values when the watchdog was configured."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_use_fix_top(&mut self) -> CpWdtUseFixTopW<WdtCompParam1Spec> {
        CpWdtUseFixTopW::new(self, 6)
    }
    #[doc = "Bit 7 - Should specify if the pause input is included or not. However, this field is always hardwired to 0 so you can't figure this out by reading this field. The pause input is included and can be used to pause the watchdog when the MPU is in debug mode."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_pause(&mut self) -> CpWdtPauseW<WdtCompParam1Spec> {
        CpWdtPauseW::new(self, 7)
    }
    #[doc = "Bits 8:9 - APB Bus Width"]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_apb_data_width(&mut self) -> CpWdtApbDataWidthW<WdtCompParam1Spec> {
        CpWdtApbDataWidthW::new(self, 8)
    }
    #[doc = "Bits 10:12 - Specifies the reset pulse length in cycles."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_dflt_rpl(&mut self) -> CpWdtDfltRplW<WdtCompParam1Spec> {
        CpWdtDfltRplW::new(self, 10)
    }
    #[doc = "Bits 16:19 - Specifies the timeout period that is available directly after reset."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_dflt_top(&mut self) -> CpWdtDfltTopW<WdtCompParam1Spec> {
        CpWdtDfltTopW::new(self, 16)
    }
    #[doc = "Bits 20:23 - Specifies the initial timeout period that is available directly after reset."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_dflt_top_init(&mut self) -> CpWdtDfltTopInitW<WdtCompParam1Spec> {
        CpWdtDfltTopInitW::new(self, 20)
    }
    #[doc = "Bits 24:28 - Width of counter in bits less 16."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_cnt_width(&mut self) -> CpWdtCntWidthW<WdtCompParam1Spec> {
        CpWdtCntWidthW::new(self, 24)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_comp_param_1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtCompParam1Spec;
impl crate::RegisterSpec for WdtCompParam1Spec {
    type Ux = u32;
    const OFFSET: u64 = 244u64;
}
#[doc = "`read()` method returns [`wdt_comp_param_1::R`](R) reader structure"]
impl crate::Readable for WdtCompParam1Spec {}
#[doc = "`reset()` method sets wdt_comp_param_1 to value 0x10ff_0254"]
impl crate::Resettable for WdtCompParam1Spec {
    const RESET_VALUE: u32 = 0x10ff_0254;
}
