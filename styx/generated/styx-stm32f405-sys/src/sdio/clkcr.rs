// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CLKCR` reader"]
pub type R = crate::R<ClkcrSpec>;
#[doc = "Register `CLKCR` writer"]
pub type W = crate::W<ClkcrSpec>;
#[doc = "Field `CLKDIV` reader - Clock divide factor"]
pub type ClkdivR = crate::FieldReader;
#[doc = "Field `CLKDIV` writer - Clock divide factor"]
pub type ClkdivW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `CLKEN` reader - Clock enable bit"]
pub type ClkenR = crate::BitReader;
#[doc = "Field `CLKEN` writer - Clock enable bit"]
pub type ClkenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PWRSAV` reader - Power saving configuration bit"]
pub type PwrsavR = crate::BitReader;
#[doc = "Field `PWRSAV` writer - Power saving configuration bit"]
pub type PwrsavW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BYPASS` reader - Clock divider bypass enable bit"]
pub type BypassR = crate::BitReader;
#[doc = "Field `BYPASS` writer - Clock divider bypass enable bit"]
pub type BypassW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WIDBUS` reader - Wide bus mode enable bit"]
pub type WidbusR = crate::FieldReader;
#[doc = "Field `WIDBUS` writer - Wide bus mode enable bit"]
pub type WidbusW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `NEGEDGE` reader - SDIO_CK dephasing selection bit"]
pub type NegedgeR = crate::BitReader;
#[doc = "Field `NEGEDGE` writer - SDIO_CK dephasing selection bit"]
pub type NegedgeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HWFC_EN` reader - HW Flow Control enable"]
pub type HwfcEnR = crate::BitReader;
#[doc = "Field `HWFC_EN` writer - HW Flow Control enable"]
pub type HwfcEnW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - Clock divide factor"]
    #[inline(always)]
    pub fn clkdiv(&self) -> ClkdivR {
        ClkdivR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bit 8 - Clock enable bit"]
    #[inline(always)]
    pub fn clken(&self) -> ClkenR {
        ClkenR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Power saving configuration bit"]
    #[inline(always)]
    pub fn pwrsav(&self) -> PwrsavR {
        PwrsavR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Clock divider bypass enable bit"]
    #[inline(always)]
    pub fn bypass(&self) -> BypassR {
        BypassR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bits 11:12 - Wide bus mode enable bit"]
    #[inline(always)]
    pub fn widbus(&self) -> WidbusR {
        WidbusR::new(((self.bits >> 11) & 3) as u8)
    }
    #[doc = "Bit 13 - SDIO_CK dephasing selection bit"]
    #[inline(always)]
    pub fn negedge(&self) -> NegedgeR {
        NegedgeR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - HW Flow Control enable"]
    #[inline(always)]
    pub fn hwfc_en(&self) -> HwfcEnR {
        HwfcEnR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - Clock divide factor"]
    #[inline(always)]
    #[must_use]
    pub fn clkdiv(&mut self) -> ClkdivW<ClkcrSpec> {
        ClkdivW::new(self, 0)
    }
    #[doc = "Bit 8 - Clock enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn clken(&mut self) -> ClkenW<ClkcrSpec> {
        ClkenW::new(self, 8)
    }
    #[doc = "Bit 9 - Power saving configuration bit"]
    #[inline(always)]
    #[must_use]
    pub fn pwrsav(&mut self) -> PwrsavW<ClkcrSpec> {
        PwrsavW::new(self, 9)
    }
    #[doc = "Bit 10 - Clock divider bypass enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn bypass(&mut self) -> BypassW<ClkcrSpec> {
        BypassW::new(self, 10)
    }
    #[doc = "Bits 11:12 - Wide bus mode enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn widbus(&mut self) -> WidbusW<ClkcrSpec> {
        WidbusW::new(self, 11)
    }
    #[doc = "Bit 13 - SDIO_CK dephasing selection bit"]
    #[inline(always)]
    #[must_use]
    pub fn negedge(&mut self) -> NegedgeW<ClkcrSpec> {
        NegedgeW::new(self, 13)
    }
    #[doc = "Bit 14 - HW Flow Control enable"]
    #[inline(always)]
    #[must_use]
    pub fn hwfc_en(&mut self) -> HwfcEnW<ClkcrSpec> {
        HwfcEnW::new(self, 14)
    }
}
#[doc = "SDI clock control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clkcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`clkcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ClkcrSpec;
impl crate::RegisterSpec for ClkcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`clkcr::R`](R) reader structure"]
impl crate::Readable for ClkcrSpec {}
#[doc = "`write(|w| ..)` method takes [`clkcr::W`](W) writer structure"]
impl crate::Writable for ClkcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CLKCR to value 0"]
impl crate::Resettable for ClkcrSpec {
    const RESET_VALUE: u32 = 0;
}
