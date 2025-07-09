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
#[doc = "Register `CR2` reader"]
pub type R = crate::R<Cr2Spec>;
#[doc = "Register `CR2` writer"]
pub type W = crate::W<Cr2Spec>;
#[doc = "Field `ADON` reader - A/D Converter ON / OFF"]
pub type AdonR = crate::BitReader;
#[doc = "Field `ADON` writer - A/D Converter ON / OFF"]
pub type AdonW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CONT` reader - Continuous conversion"]
pub type ContR = crate::BitReader;
#[doc = "Field `CONT` writer - Continuous conversion"]
pub type ContW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMA` reader - Direct memory access mode (for single ADC mode)"]
pub type DmaR = crate::BitReader;
#[doc = "Field `DMA` writer - Direct memory access mode (for single ADC mode)"]
pub type DmaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DDS` reader - DMA disable selection (for single ADC mode)"]
pub type DdsR = crate::BitReader;
#[doc = "Field `DDS` writer - DMA disable selection (for single ADC mode)"]
pub type DdsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOCS` reader - End of conversion selection"]
pub type EocsR = crate::BitReader;
#[doc = "Field `EOCS` writer - End of conversion selection"]
pub type EocsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ALIGN` reader - Data alignment"]
pub type AlignR = crate::BitReader;
#[doc = "Field `ALIGN` writer - Data alignment"]
pub type AlignW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JEXTSEL` reader - External event select for injected group"]
pub type JextselR = crate::FieldReader;
#[doc = "Field `JEXTSEL` writer - External event select for injected group"]
pub type JextselW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `JEXTEN` reader - External trigger enable for injected channels"]
pub type JextenR = crate::FieldReader;
#[doc = "Field `JEXTEN` writer - External trigger enable for injected channels"]
pub type JextenW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `JSWSTART` reader - Start conversion of injected channels"]
pub type JswstartR = crate::BitReader;
#[doc = "Field `JSWSTART` writer - Start conversion of injected channels"]
pub type JswstartW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EXTSEL` reader - External event select for regular group"]
pub type ExtselR = crate::FieldReader;
#[doc = "Field `EXTSEL` writer - External event select for regular group"]
pub type ExtselW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `EXTEN` reader - External trigger enable for regular channels"]
pub type ExtenR = crate::FieldReader;
#[doc = "Field `EXTEN` writer - External trigger enable for regular channels"]
pub type ExtenW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `SWSTART` reader - Start conversion of regular channels"]
pub type SwstartR = crate::BitReader;
#[doc = "Field `SWSTART` writer - Start conversion of regular channels"]
pub type SwstartW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - A/D Converter ON / OFF"]
    #[inline(always)]
    pub fn adon(&self) -> AdonR {
        AdonR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Continuous conversion"]
    #[inline(always)]
    pub fn cont(&self) -> ContR {
        ContR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 8 - Direct memory access mode (for single ADC mode)"]
    #[inline(always)]
    pub fn dma(&self) -> DmaR {
        DmaR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - DMA disable selection (for single ADC mode)"]
    #[inline(always)]
    pub fn dds(&self) -> DdsR {
        DdsR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - End of conversion selection"]
    #[inline(always)]
    pub fn eocs(&self) -> EocsR {
        EocsR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Data alignment"]
    #[inline(always)]
    pub fn align(&self) -> AlignR {
        AlignR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bits 16:19 - External event select for injected group"]
    #[inline(always)]
    pub fn jextsel(&self) -> JextselR {
        JextselR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:21 - External trigger enable for injected channels"]
    #[inline(always)]
    pub fn jexten(&self) -> JextenR {
        JextenR::new(((self.bits >> 20) & 3) as u8)
    }
    #[doc = "Bit 22 - Start conversion of injected channels"]
    #[inline(always)]
    pub fn jswstart(&self) -> JswstartR {
        JswstartR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bits 24:27 - External event select for regular group"]
    #[inline(always)]
    pub fn extsel(&self) -> ExtselR {
        ExtselR::new(((self.bits >> 24) & 0x0f) as u8)
    }
    #[doc = "Bits 28:29 - External trigger enable for regular channels"]
    #[inline(always)]
    pub fn exten(&self) -> ExtenR {
        ExtenR::new(((self.bits >> 28) & 3) as u8)
    }
    #[doc = "Bit 30 - Start conversion of regular channels"]
    #[inline(always)]
    pub fn swstart(&self) -> SwstartR {
        SwstartR::new(((self.bits >> 30) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - A/D Converter ON / OFF"]
    #[inline(always)]
    #[must_use]
    pub fn adon(&mut self) -> AdonW<Cr2Spec> {
        AdonW::new(self, 0)
    }
    #[doc = "Bit 1 - Continuous conversion"]
    #[inline(always)]
    #[must_use]
    pub fn cont(&mut self) -> ContW<Cr2Spec> {
        ContW::new(self, 1)
    }
    #[doc = "Bit 8 - Direct memory access mode (for single ADC mode)"]
    #[inline(always)]
    #[must_use]
    pub fn dma(&mut self) -> DmaW<Cr2Spec> {
        DmaW::new(self, 8)
    }
    #[doc = "Bit 9 - DMA disable selection (for single ADC mode)"]
    #[inline(always)]
    #[must_use]
    pub fn dds(&mut self) -> DdsW<Cr2Spec> {
        DdsW::new(self, 9)
    }
    #[doc = "Bit 10 - End of conversion selection"]
    #[inline(always)]
    #[must_use]
    pub fn eocs(&mut self) -> EocsW<Cr2Spec> {
        EocsW::new(self, 10)
    }
    #[doc = "Bit 11 - Data alignment"]
    #[inline(always)]
    #[must_use]
    pub fn align(&mut self) -> AlignW<Cr2Spec> {
        AlignW::new(self, 11)
    }
    #[doc = "Bits 16:19 - External event select for injected group"]
    #[inline(always)]
    #[must_use]
    pub fn jextsel(&mut self) -> JextselW<Cr2Spec> {
        JextselW::new(self, 16)
    }
    #[doc = "Bits 20:21 - External trigger enable for injected channels"]
    #[inline(always)]
    #[must_use]
    pub fn jexten(&mut self) -> JextenW<Cr2Spec> {
        JextenW::new(self, 20)
    }
    #[doc = "Bit 22 - Start conversion of injected channels"]
    #[inline(always)]
    #[must_use]
    pub fn jswstart(&mut self) -> JswstartW<Cr2Spec> {
        JswstartW::new(self, 22)
    }
    #[doc = "Bits 24:27 - External event select for regular group"]
    #[inline(always)]
    #[must_use]
    pub fn extsel(&mut self) -> ExtselW<Cr2Spec> {
        ExtselW::new(self, 24)
    }
    #[doc = "Bits 28:29 - External trigger enable for regular channels"]
    #[inline(always)]
    #[must_use]
    pub fn exten(&mut self) -> ExtenW<Cr2Spec> {
        ExtenW::new(self, 28)
    }
    #[doc = "Bit 30 - Start conversion of regular channels"]
    #[inline(always)]
    #[must_use]
    pub fn swstart(&mut self) -> SwstartW<Cr2Spec> {
        SwstartW::new(self, 30)
    }
}
#[doc = "control register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr2Spec;
impl crate::RegisterSpec for Cr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`cr2::R`](R) reader structure"]
impl crate::Readable for Cr2Spec {}
#[doc = "`write(|w| ..)` method takes [`cr2::W`](W) writer structure"]
impl crate::Writable for Cr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR2 to value 0"]
impl crate::Resettable for Cr2Spec {
    const RESET_VALUE: u32 = 0;
}
