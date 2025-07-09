// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CCR` reader"]
pub type R = crate::R<CcrSpec>;
#[doc = "Register `CCR` writer"]
pub type W = crate::W<CcrSpec>;
#[doc = "Field `MULT` reader - Multi ADC mode selection"]
pub type MultR = crate::FieldReader;
#[doc = "Field `MULT` writer - Multi ADC mode selection"]
pub type MultW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `DELAY` reader - Delay between 2 sampling phases"]
pub type DelayR = crate::FieldReader;
#[doc = "Field `DELAY` writer - Delay between 2 sampling phases"]
pub type DelayW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `DDS` reader - DMA disable selection for multi-ADC mode"]
pub type DdsR = crate::BitReader;
#[doc = "Field `DDS` writer - DMA disable selection for multi-ADC mode"]
pub type DdsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMA` reader - Direct memory access mode for multi ADC mode"]
pub type DmaR = crate::FieldReader;
#[doc = "Field `DMA` writer - Direct memory access mode for multi ADC mode"]
pub type DmaW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ADCPRE` reader - ADC prescaler"]
pub type AdcpreR = crate::FieldReader;
#[doc = "Field `ADCPRE` writer - ADC prescaler"]
pub type AdcpreW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `VBATE` reader - VBAT enable"]
pub type VbateR = crate::BitReader;
#[doc = "Field `VBATE` writer - VBAT enable"]
pub type VbateW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSVREFE` reader - Temperature sensor and VREFINT enable"]
pub type TsvrefeR = crate::BitReader;
#[doc = "Field `TSVREFE` writer - Temperature sensor and VREFINT enable"]
pub type TsvrefeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:4 - Multi ADC mode selection"]
    #[inline(always)]
    pub fn mult(&self) -> MultR {
        MultR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 8:11 - Delay between 2 sampling phases"]
    #[inline(always)]
    pub fn delay(&self) -> DelayR {
        DelayR::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bit 13 - DMA disable selection for multi-ADC mode"]
    #[inline(always)]
    pub fn dds(&self) -> DdsR {
        DdsR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 14:15 - Direct memory access mode for multi ADC mode"]
    #[inline(always)]
    pub fn dma(&self) -> DmaR {
        DmaR::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bits 16:17 - ADC prescaler"]
    #[inline(always)]
    pub fn adcpre(&self) -> AdcpreR {
        AdcpreR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bit 22 - VBAT enable"]
    #[inline(always)]
    pub fn vbate(&self) -> VbateR {
        VbateR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Temperature sensor and VREFINT enable"]
    #[inline(always)]
    pub fn tsvrefe(&self) -> TsvrefeR {
        TsvrefeR::new(((self.bits >> 23) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:4 - Multi ADC mode selection"]
    #[inline(always)]
    #[must_use]
    pub fn mult(&mut self) -> MultW<CcrSpec> {
        MultW::new(self, 0)
    }
    #[doc = "Bits 8:11 - Delay between 2 sampling phases"]
    #[inline(always)]
    #[must_use]
    pub fn delay(&mut self) -> DelayW<CcrSpec> {
        DelayW::new(self, 8)
    }
    #[doc = "Bit 13 - DMA disable selection for multi-ADC mode"]
    #[inline(always)]
    #[must_use]
    pub fn dds(&mut self) -> DdsW<CcrSpec> {
        DdsW::new(self, 13)
    }
    #[doc = "Bits 14:15 - Direct memory access mode for multi ADC mode"]
    #[inline(always)]
    #[must_use]
    pub fn dma(&mut self) -> DmaW<CcrSpec> {
        DmaW::new(self, 14)
    }
    #[doc = "Bits 16:17 - ADC prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn adcpre(&mut self) -> AdcpreW<CcrSpec> {
        AdcpreW::new(self, 16)
    }
    #[doc = "Bit 22 - VBAT enable"]
    #[inline(always)]
    #[must_use]
    pub fn vbate(&mut self) -> VbateW<CcrSpec> {
        VbateW::new(self, 22)
    }
    #[doc = "Bit 23 - Temperature sensor and VREFINT enable"]
    #[inline(always)]
    #[must_use]
    pub fn tsvrefe(&mut self) -> TsvrefeW<CcrSpec> {
        TsvrefeW::new(self, 23)
    }
}
#[doc = "ADC common control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CcrSpec;
impl crate::RegisterSpec for CcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`ccr::R`](R) reader structure"]
impl crate::Readable for CcrSpec {}
#[doc = "`write(|w| ..)` method takes [`ccr::W`](W) writer structure"]
impl crate::Writable for CcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CCR to value 0"]
impl crate::Resettable for CcrSpec {
    const RESET_VALUE: u32 = 0;
}
