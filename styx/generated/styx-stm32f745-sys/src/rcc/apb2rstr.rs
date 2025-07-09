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
#[doc = "Register `APB2RSTR` reader"]
pub type R = crate::R<Apb2rstrSpec>;
#[doc = "Register `APB2RSTR` writer"]
pub type W = crate::W<Apb2rstrSpec>;
#[doc = "Field `TIM1RST` reader - TIM1 reset"]
pub type Tim1rstR = crate::BitReader;
#[doc = "Field `TIM1RST` writer - TIM1 reset"]
pub type Tim1rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM8RST` reader - TIM8 reset"]
pub type Tim8rstR = crate::BitReader;
#[doc = "Field `TIM8RST` writer - TIM8 reset"]
pub type Tim8rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USART1RST` reader - USART1 reset"]
pub type Usart1rstR = crate::BitReader;
#[doc = "Field `USART1RST` writer - USART1 reset"]
pub type Usart1rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USART6RST` reader - USART6 reset"]
pub type Usart6rstR = crate::BitReader;
#[doc = "Field `USART6RST` writer - USART6 reset"]
pub type Usart6rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADCRST` reader - ADC interface reset (common to all ADCs)"]
pub type AdcrstR = crate::BitReader;
#[doc = "Field `ADCRST` writer - ADC interface reset (common to all ADCs)"]
pub type AdcrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDMMC1RST` reader - SDMMC1 reset"]
pub type Sdmmc1rstR = crate::BitReader;
#[doc = "Field `SDMMC1RST` writer - SDMMC1 reset"]
pub type Sdmmc1rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI1RST` reader - SPI 1 reset"]
pub type Spi1rstR = crate::BitReader;
#[doc = "Field `SPI1RST` writer - SPI 1 reset"]
pub type Spi1rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI4RST` reader - SPI4 reset"]
pub type Spi4rstR = crate::BitReader;
#[doc = "Field `SPI4RST` writer - SPI4 reset"]
pub type Spi4rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SYSCFGRST` reader - System configuration controller reset"]
pub type SyscfgrstR = crate::BitReader;
#[doc = "Field `SYSCFGRST` writer - System configuration controller reset"]
pub type SyscfgrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM9RST` reader - TIM9 reset"]
pub type Tim9rstR = crate::BitReader;
#[doc = "Field `TIM9RST` writer - TIM9 reset"]
pub type Tim9rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM10RST` reader - TIM10 reset"]
pub type Tim10rstR = crate::BitReader;
#[doc = "Field `TIM10RST` writer - TIM10 reset"]
pub type Tim10rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM11RST` reader - TIM11 reset"]
pub type Tim11rstR = crate::BitReader;
#[doc = "Field `TIM11RST` writer - TIM11 reset"]
pub type Tim11rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI5RST` reader - SPI5 reset"]
pub type Spi5rstR = crate::BitReader;
#[doc = "Field `SPI5RST` writer - SPI5 reset"]
pub type Spi5rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI6RST` reader - SPI6 reset"]
pub type Spi6rstR = crate::BitReader;
#[doc = "Field `SPI6RST` writer - SPI6 reset"]
pub type Spi6rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SAI1RST` reader - SAI1 reset"]
pub type Sai1rstR = crate::BitReader;
#[doc = "Field `SAI1RST` writer - SAI1 reset"]
pub type Sai1rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SAI2RST` reader - SAI2 reset"]
pub type Sai2rstR = crate::BitReader;
#[doc = "Field `SAI2RST` writer - SAI2 reset"]
pub type Sai2rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LTDCRST` reader - LTDC reset"]
pub type LtdcrstR = crate::BitReader;
#[doc = "Field `LTDCRST` writer - LTDC reset"]
pub type LtdcrstW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TIM1 reset"]
    #[inline(always)]
    pub fn tim1rst(&self) -> Tim1rstR {
        Tim1rstR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TIM8 reset"]
    #[inline(always)]
    pub fn tim8rst(&self) -> Tim8rstR {
        Tim8rstR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 4 - USART1 reset"]
    #[inline(always)]
    pub fn usart1rst(&self) -> Usart1rstR {
        Usart1rstR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - USART6 reset"]
    #[inline(always)]
    pub fn usart6rst(&self) -> Usart6rstR {
        Usart6rstR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - ADC interface reset (common to all ADCs)"]
    #[inline(always)]
    pub fn adcrst(&self) -> AdcrstR {
        AdcrstR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 11 - SDMMC1 reset"]
    #[inline(always)]
    pub fn sdmmc1rst(&self) -> Sdmmc1rstR {
        Sdmmc1rstR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - SPI 1 reset"]
    #[inline(always)]
    pub fn spi1rst(&self) -> Spi1rstR {
        Spi1rstR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - SPI4 reset"]
    #[inline(always)]
    pub fn spi4rst(&self) -> Spi4rstR {
        Spi4rstR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - System configuration controller reset"]
    #[inline(always)]
    pub fn syscfgrst(&self) -> SyscfgrstR {
        SyscfgrstR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 16 - TIM9 reset"]
    #[inline(always)]
    pub fn tim9rst(&self) -> Tim9rstR {
        Tim9rstR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - TIM10 reset"]
    #[inline(always)]
    pub fn tim10rst(&self) -> Tim10rstR {
        Tim10rstR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - TIM11 reset"]
    #[inline(always)]
    pub fn tim11rst(&self) -> Tim11rstR {
        Tim11rstR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 20 - SPI5 reset"]
    #[inline(always)]
    pub fn spi5rst(&self) -> Spi5rstR {
        Spi5rstR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - SPI6 reset"]
    #[inline(always)]
    pub fn spi6rst(&self) -> Spi6rstR {
        Spi6rstR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - SAI1 reset"]
    #[inline(always)]
    pub fn sai1rst(&self) -> Sai1rstR {
        Sai1rstR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - SAI2 reset"]
    #[inline(always)]
    pub fn sai2rst(&self) -> Sai2rstR {
        Sai2rstR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 26 - LTDC reset"]
    #[inline(always)]
    pub fn ltdcrst(&self) -> LtdcrstR {
        LtdcrstR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TIM1 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim1rst(&mut self) -> Tim1rstW<Apb2rstrSpec> {
        Tim1rstW::new(self, 0)
    }
    #[doc = "Bit 1 - TIM8 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim8rst(&mut self) -> Tim8rstW<Apb2rstrSpec> {
        Tim8rstW::new(self, 1)
    }
    #[doc = "Bit 4 - USART1 reset"]
    #[inline(always)]
    #[must_use]
    pub fn usart1rst(&mut self) -> Usart1rstW<Apb2rstrSpec> {
        Usart1rstW::new(self, 4)
    }
    #[doc = "Bit 5 - USART6 reset"]
    #[inline(always)]
    #[must_use]
    pub fn usart6rst(&mut self) -> Usart6rstW<Apb2rstrSpec> {
        Usart6rstW::new(self, 5)
    }
    #[doc = "Bit 8 - ADC interface reset (common to all ADCs)"]
    #[inline(always)]
    #[must_use]
    pub fn adcrst(&mut self) -> AdcrstW<Apb2rstrSpec> {
        AdcrstW::new(self, 8)
    }
    #[doc = "Bit 11 - SDMMC1 reset"]
    #[inline(always)]
    #[must_use]
    pub fn sdmmc1rst(&mut self) -> Sdmmc1rstW<Apb2rstrSpec> {
        Sdmmc1rstW::new(self, 11)
    }
    #[doc = "Bit 12 - SPI 1 reset"]
    #[inline(always)]
    #[must_use]
    pub fn spi1rst(&mut self) -> Spi1rstW<Apb2rstrSpec> {
        Spi1rstW::new(self, 12)
    }
    #[doc = "Bit 13 - SPI4 reset"]
    #[inline(always)]
    #[must_use]
    pub fn spi4rst(&mut self) -> Spi4rstW<Apb2rstrSpec> {
        Spi4rstW::new(self, 13)
    }
    #[doc = "Bit 14 - System configuration controller reset"]
    #[inline(always)]
    #[must_use]
    pub fn syscfgrst(&mut self) -> SyscfgrstW<Apb2rstrSpec> {
        SyscfgrstW::new(self, 14)
    }
    #[doc = "Bit 16 - TIM9 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim9rst(&mut self) -> Tim9rstW<Apb2rstrSpec> {
        Tim9rstW::new(self, 16)
    }
    #[doc = "Bit 17 - TIM10 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim10rst(&mut self) -> Tim10rstW<Apb2rstrSpec> {
        Tim10rstW::new(self, 17)
    }
    #[doc = "Bit 18 - TIM11 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim11rst(&mut self) -> Tim11rstW<Apb2rstrSpec> {
        Tim11rstW::new(self, 18)
    }
    #[doc = "Bit 20 - SPI5 reset"]
    #[inline(always)]
    #[must_use]
    pub fn spi5rst(&mut self) -> Spi5rstW<Apb2rstrSpec> {
        Spi5rstW::new(self, 20)
    }
    #[doc = "Bit 21 - SPI6 reset"]
    #[inline(always)]
    #[must_use]
    pub fn spi6rst(&mut self) -> Spi6rstW<Apb2rstrSpec> {
        Spi6rstW::new(self, 21)
    }
    #[doc = "Bit 22 - SAI1 reset"]
    #[inline(always)]
    #[must_use]
    pub fn sai1rst(&mut self) -> Sai1rstW<Apb2rstrSpec> {
        Sai1rstW::new(self, 22)
    }
    #[doc = "Bit 23 - SAI2 reset"]
    #[inline(always)]
    #[must_use]
    pub fn sai2rst(&mut self) -> Sai2rstW<Apb2rstrSpec> {
        Sai2rstW::new(self, 23)
    }
    #[doc = "Bit 26 - LTDC reset"]
    #[inline(always)]
    #[must_use]
    pub fn ltdcrst(&mut self) -> LtdcrstW<Apb2rstrSpec> {
        LtdcrstW::new(self, 26)
    }
}
#[doc = "APB2 peripheral reset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`apb2rstr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`apb2rstr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Apb2rstrSpec;
impl crate::RegisterSpec for Apb2rstrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`apb2rstr::R`](R) reader structure"]
impl crate::Readable for Apb2rstrSpec {}
#[doc = "`write(|w| ..)` method takes [`apb2rstr::W`](W) writer structure"]
impl crate::Writable for Apb2rstrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets APB2RSTR to value 0"]
impl crate::Resettable for Apb2rstrSpec {
    const RESET_VALUE: u32 = 0;
}
