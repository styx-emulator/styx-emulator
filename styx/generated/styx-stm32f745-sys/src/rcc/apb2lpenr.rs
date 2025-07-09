// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `APB2LPENR` reader"]
pub type R = crate::R<Apb2lpenrSpec>;
#[doc = "Register `APB2LPENR` writer"]
pub type W = crate::W<Apb2lpenrSpec>;
#[doc = "Field `TIM1LPEN` reader - TIM1 clock enable during Sleep mode"]
pub type Tim1lpenR = crate::BitReader;
#[doc = "Field `TIM1LPEN` writer - TIM1 clock enable during Sleep mode"]
pub type Tim1lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM8LPEN` reader - TIM8 clock enable during Sleep mode"]
pub type Tim8lpenR = crate::BitReader;
#[doc = "Field `TIM8LPEN` writer - TIM8 clock enable during Sleep mode"]
pub type Tim8lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USART1LPEN` reader - USART1 clock enable during Sleep mode"]
pub type Usart1lpenR = crate::BitReader;
#[doc = "Field `USART1LPEN` writer - USART1 clock enable during Sleep mode"]
pub type Usart1lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USART6LPEN` reader - USART6 clock enable during Sleep mode"]
pub type Usart6lpenR = crate::BitReader;
#[doc = "Field `USART6LPEN` writer - USART6 clock enable during Sleep mode"]
pub type Usart6lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADC1LPEN` reader - ADC1 clock enable during Sleep mode"]
pub type Adc1lpenR = crate::BitReader;
#[doc = "Field `ADC1LPEN` writer - ADC1 clock enable during Sleep mode"]
pub type Adc1lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADC2LPEN` reader - ADC2 clock enable during Sleep mode"]
pub type Adc2lpenR = crate::BitReader;
#[doc = "Field `ADC2LPEN` writer - ADC2 clock enable during Sleep mode"]
pub type Adc2lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADC3LPEN` reader - ADC 3 clock enable during Sleep mode"]
pub type Adc3lpenR = crate::BitReader;
#[doc = "Field `ADC3LPEN` writer - ADC 3 clock enable during Sleep mode"]
pub type Adc3lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDMMC1LPEN` reader - SDMMC1 clock enable during Sleep mode"]
pub type Sdmmc1lpenR = crate::BitReader;
#[doc = "Field `SDMMC1LPEN` writer - SDMMC1 clock enable during Sleep mode"]
pub type Sdmmc1lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI1LPEN` reader - SPI 1 clock enable during Sleep mode"]
pub type Spi1lpenR = crate::BitReader;
#[doc = "Field `SPI1LPEN` writer - SPI 1 clock enable during Sleep mode"]
pub type Spi1lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI4LPEN` reader - SPI 4 clock enable during Sleep mode"]
pub type Spi4lpenR = crate::BitReader;
#[doc = "Field `SPI4LPEN` writer - SPI 4 clock enable during Sleep mode"]
pub type Spi4lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SYSCFGLPEN` reader - System configuration controller clock enable during Sleep mode"]
pub type SyscfglpenR = crate::BitReader;
#[doc = "Field `SYSCFGLPEN` writer - System configuration controller clock enable during Sleep mode"]
pub type SyscfglpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM9LPEN` reader - TIM9 clock enable during sleep mode"]
pub type Tim9lpenR = crate::BitReader;
#[doc = "Field `TIM9LPEN` writer - TIM9 clock enable during sleep mode"]
pub type Tim9lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM10LPEN` reader - TIM10 clock enable during Sleep mode"]
pub type Tim10lpenR = crate::BitReader;
#[doc = "Field `TIM10LPEN` writer - TIM10 clock enable during Sleep mode"]
pub type Tim10lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM11LPEN` reader - TIM11 clock enable during Sleep mode"]
pub type Tim11lpenR = crate::BitReader;
#[doc = "Field `TIM11LPEN` writer - TIM11 clock enable during Sleep mode"]
pub type Tim11lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI5LPEN` reader - SPI 5 clock enable during Sleep mode"]
pub type Spi5lpenR = crate::BitReader;
#[doc = "Field `SPI5LPEN` writer - SPI 5 clock enable during Sleep mode"]
pub type Spi5lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI6LPEN` reader - SPI 6 clock enable during Sleep mode"]
pub type Spi6lpenR = crate::BitReader;
#[doc = "Field `SPI6LPEN` writer - SPI 6 clock enable during Sleep mode"]
pub type Spi6lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SAI1LPEN` reader - SAI1 clock enable during sleep mode"]
pub type Sai1lpenR = crate::BitReader;
#[doc = "Field `SAI1LPEN` writer - SAI1 clock enable during sleep mode"]
pub type Sai1lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SAI2LPEN` reader - SAI2 clock enable during sleep mode"]
pub type Sai2lpenR = crate::BitReader;
#[doc = "Field `SAI2LPEN` writer - SAI2 clock enable during sleep mode"]
pub type Sai2lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LTDCLPEN` reader - LTDC clock enable during sleep mode"]
pub type LtdclpenR = crate::BitReader;
#[doc = "Field `LTDCLPEN` writer - LTDC clock enable during sleep mode"]
pub type LtdclpenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TIM1 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim1lpen(&self) -> Tim1lpenR {
        Tim1lpenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TIM8 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim8lpen(&self) -> Tim8lpenR {
        Tim8lpenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 4 - USART1 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn usart1lpen(&self) -> Usart1lpenR {
        Usart1lpenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - USART6 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn usart6lpen(&self) -> Usart6lpenR {
        Usart6lpenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - ADC1 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn adc1lpen(&self) -> Adc1lpenR {
        Adc1lpenR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - ADC2 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn adc2lpen(&self) -> Adc2lpenR {
        Adc2lpenR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - ADC 3 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn adc3lpen(&self) -> Adc3lpenR {
        Adc3lpenR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - SDMMC1 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn sdmmc1lpen(&self) -> Sdmmc1lpenR {
        Sdmmc1lpenR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - SPI 1 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn spi1lpen(&self) -> Spi1lpenR {
        Spi1lpenR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - SPI 4 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn spi4lpen(&self) -> Spi4lpenR {
        Spi4lpenR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - System configuration controller clock enable during Sleep mode"]
    #[inline(always)]
    pub fn syscfglpen(&self) -> SyscfglpenR {
        SyscfglpenR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 16 - TIM9 clock enable during sleep mode"]
    #[inline(always)]
    pub fn tim9lpen(&self) -> Tim9lpenR {
        Tim9lpenR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - TIM10 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim10lpen(&self) -> Tim10lpenR {
        Tim10lpenR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - TIM11 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim11lpen(&self) -> Tim11lpenR {
        Tim11lpenR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 20 - SPI 5 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn spi5lpen(&self) -> Spi5lpenR {
        Spi5lpenR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - SPI 6 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn spi6lpen(&self) -> Spi6lpenR {
        Spi6lpenR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - SAI1 clock enable during sleep mode"]
    #[inline(always)]
    pub fn sai1lpen(&self) -> Sai1lpenR {
        Sai1lpenR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - SAI2 clock enable during sleep mode"]
    #[inline(always)]
    pub fn sai2lpen(&self) -> Sai2lpenR {
        Sai2lpenR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 26 - LTDC clock enable during sleep mode"]
    #[inline(always)]
    pub fn ltdclpen(&self) -> LtdclpenR {
        LtdclpenR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TIM1 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim1lpen(&mut self) -> Tim1lpenW<Apb2lpenrSpec> {
        Tim1lpenW::new(self, 0)
    }
    #[doc = "Bit 1 - TIM8 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim8lpen(&mut self) -> Tim8lpenW<Apb2lpenrSpec> {
        Tim8lpenW::new(self, 1)
    }
    #[doc = "Bit 4 - USART1 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn usart1lpen(&mut self) -> Usart1lpenW<Apb2lpenrSpec> {
        Usart1lpenW::new(self, 4)
    }
    #[doc = "Bit 5 - USART6 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn usart6lpen(&mut self) -> Usart6lpenW<Apb2lpenrSpec> {
        Usart6lpenW::new(self, 5)
    }
    #[doc = "Bit 8 - ADC1 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn adc1lpen(&mut self) -> Adc1lpenW<Apb2lpenrSpec> {
        Adc1lpenW::new(self, 8)
    }
    #[doc = "Bit 9 - ADC2 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn adc2lpen(&mut self) -> Adc2lpenW<Apb2lpenrSpec> {
        Adc2lpenW::new(self, 9)
    }
    #[doc = "Bit 10 - ADC 3 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn adc3lpen(&mut self) -> Adc3lpenW<Apb2lpenrSpec> {
        Adc3lpenW::new(self, 10)
    }
    #[doc = "Bit 11 - SDMMC1 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn sdmmc1lpen(&mut self) -> Sdmmc1lpenW<Apb2lpenrSpec> {
        Sdmmc1lpenW::new(self, 11)
    }
    #[doc = "Bit 12 - SPI 1 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn spi1lpen(&mut self) -> Spi1lpenW<Apb2lpenrSpec> {
        Spi1lpenW::new(self, 12)
    }
    #[doc = "Bit 13 - SPI 4 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn spi4lpen(&mut self) -> Spi4lpenW<Apb2lpenrSpec> {
        Spi4lpenW::new(self, 13)
    }
    #[doc = "Bit 14 - System configuration controller clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn syscfglpen(&mut self) -> SyscfglpenW<Apb2lpenrSpec> {
        SyscfglpenW::new(self, 14)
    }
    #[doc = "Bit 16 - TIM9 clock enable during sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim9lpen(&mut self) -> Tim9lpenW<Apb2lpenrSpec> {
        Tim9lpenW::new(self, 16)
    }
    #[doc = "Bit 17 - TIM10 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim10lpen(&mut self) -> Tim10lpenW<Apb2lpenrSpec> {
        Tim10lpenW::new(self, 17)
    }
    #[doc = "Bit 18 - TIM11 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim11lpen(&mut self) -> Tim11lpenW<Apb2lpenrSpec> {
        Tim11lpenW::new(self, 18)
    }
    #[doc = "Bit 20 - SPI 5 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn spi5lpen(&mut self) -> Spi5lpenW<Apb2lpenrSpec> {
        Spi5lpenW::new(self, 20)
    }
    #[doc = "Bit 21 - SPI 6 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn spi6lpen(&mut self) -> Spi6lpenW<Apb2lpenrSpec> {
        Spi6lpenW::new(self, 21)
    }
    #[doc = "Bit 22 - SAI1 clock enable during sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn sai1lpen(&mut self) -> Sai1lpenW<Apb2lpenrSpec> {
        Sai1lpenW::new(self, 22)
    }
    #[doc = "Bit 23 - SAI2 clock enable during sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn sai2lpen(&mut self) -> Sai2lpenW<Apb2lpenrSpec> {
        Sai2lpenW::new(self, 23)
    }
    #[doc = "Bit 26 - LTDC clock enable during sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn ltdclpen(&mut self) -> LtdclpenW<Apb2lpenrSpec> {
        LtdclpenW::new(self, 26)
    }
}
#[doc = "APB2 peripheral clock enabled in low power mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`apb2lpenr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`apb2lpenr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Apb2lpenrSpec;
impl crate::RegisterSpec for Apb2lpenrSpec {
    type Ux = u32;
    const OFFSET: u64 = 100u64;
}
#[doc = "`read()` method returns [`apb2lpenr::R`](R) reader structure"]
impl crate::Readable for Apb2lpenrSpec {}
#[doc = "`write(|w| ..)` method takes [`apb2lpenr::W`](W) writer structure"]
impl crate::Writable for Apb2lpenrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets APB2LPENR to value 0x0007_5f33"]
impl crate::Resettable for Apb2lpenrSpec {
    const RESET_VALUE: u32 = 0x0007_5f33;
}
