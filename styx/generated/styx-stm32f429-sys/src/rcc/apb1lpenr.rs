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
#[doc = "Register `APB1LPENR` reader"]
pub type R = crate::R<Apb1lpenrSpec>;
#[doc = "Register `APB1LPENR` writer"]
pub type W = crate::W<Apb1lpenrSpec>;
#[doc = "Field `TIM2LPEN` reader - TIM2 clock enable during Sleep mode"]
pub type Tim2lpenR = crate::BitReader;
#[doc = "Field `TIM2LPEN` writer - TIM2 clock enable during Sleep mode"]
pub type Tim2lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM3LPEN` reader - TIM3 clock enable during Sleep mode"]
pub type Tim3lpenR = crate::BitReader;
#[doc = "Field `TIM3LPEN` writer - TIM3 clock enable during Sleep mode"]
pub type Tim3lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM4LPEN` reader - TIM4 clock enable during Sleep mode"]
pub type Tim4lpenR = crate::BitReader;
#[doc = "Field `TIM4LPEN` writer - TIM4 clock enable during Sleep mode"]
pub type Tim4lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM5LPEN` reader - TIM5 clock enable during Sleep mode"]
pub type Tim5lpenR = crate::BitReader;
#[doc = "Field `TIM5LPEN` writer - TIM5 clock enable during Sleep mode"]
pub type Tim5lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM6LPEN` reader - TIM6 clock enable during Sleep mode"]
pub type Tim6lpenR = crate::BitReader;
#[doc = "Field `TIM6LPEN` writer - TIM6 clock enable during Sleep mode"]
pub type Tim6lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM7LPEN` reader - TIM7 clock enable during Sleep mode"]
pub type Tim7lpenR = crate::BitReader;
#[doc = "Field `TIM7LPEN` writer - TIM7 clock enable during Sleep mode"]
pub type Tim7lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM12LPEN` reader - TIM12 clock enable during Sleep mode"]
pub type Tim12lpenR = crate::BitReader;
#[doc = "Field `TIM12LPEN` writer - TIM12 clock enable during Sleep mode"]
pub type Tim12lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM13LPEN` reader - TIM13 clock enable during Sleep mode"]
pub type Tim13lpenR = crate::BitReader;
#[doc = "Field `TIM13LPEN` writer - TIM13 clock enable during Sleep mode"]
pub type Tim13lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM14LPEN` reader - TIM14 clock enable during Sleep mode"]
pub type Tim14lpenR = crate::BitReader;
#[doc = "Field `TIM14LPEN` writer - TIM14 clock enable during Sleep mode"]
pub type Tim14lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WWDGLPEN` reader - Window watchdog clock enable during Sleep mode"]
pub type WwdglpenR = crate::BitReader;
#[doc = "Field `WWDGLPEN` writer - Window watchdog clock enable during Sleep mode"]
pub type WwdglpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI2LPEN` reader - SPI2 clock enable during Sleep mode"]
pub type Spi2lpenR = crate::BitReader;
#[doc = "Field `SPI2LPEN` writer - SPI2 clock enable during Sleep mode"]
pub type Spi2lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI3LPEN` reader - SPI3 clock enable during Sleep mode"]
pub type Spi3lpenR = crate::BitReader;
#[doc = "Field `SPI3LPEN` writer - SPI3 clock enable during Sleep mode"]
pub type Spi3lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USART2LPEN` reader - USART2 clock enable during Sleep mode"]
pub type Usart2lpenR = crate::BitReader;
#[doc = "Field `USART2LPEN` writer - USART2 clock enable during Sleep mode"]
pub type Usart2lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USART3LPEN` reader - USART3 clock enable during Sleep mode"]
pub type Usart3lpenR = crate::BitReader;
#[doc = "Field `USART3LPEN` writer - USART3 clock enable during Sleep mode"]
pub type Usart3lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UART4LPEN` reader - UART4 clock enable during Sleep mode"]
pub type Uart4lpenR = crate::BitReader;
#[doc = "Field `UART4LPEN` writer - UART4 clock enable during Sleep mode"]
pub type Uart4lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UART5LPEN` reader - UART5 clock enable during Sleep mode"]
pub type Uart5lpenR = crate::BitReader;
#[doc = "Field `UART5LPEN` writer - UART5 clock enable during Sleep mode"]
pub type Uart5lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2C1LPEN` reader - I2C1 clock enable during Sleep mode"]
pub type I2c1lpenR = crate::BitReader;
#[doc = "Field `I2C1LPEN` writer - I2C1 clock enable during Sleep mode"]
pub type I2c1lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2C2LPEN` reader - I2C2 clock enable during Sleep mode"]
pub type I2c2lpenR = crate::BitReader;
#[doc = "Field `I2C2LPEN` writer - I2C2 clock enable during Sleep mode"]
pub type I2c2lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2C3LPEN` reader - I2C3 clock enable during Sleep mode"]
pub type I2c3lpenR = crate::BitReader;
#[doc = "Field `I2C3LPEN` writer - I2C3 clock enable during Sleep mode"]
pub type I2c3lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAN1LPEN` reader - CAN 1 clock enable during Sleep mode"]
pub type Can1lpenR = crate::BitReader;
#[doc = "Field `CAN1LPEN` writer - CAN 1 clock enable during Sleep mode"]
pub type Can1lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAN2LPEN` reader - CAN 2 clock enable during Sleep mode"]
pub type Can2lpenR = crate::BitReader;
#[doc = "Field `CAN2LPEN` writer - CAN 2 clock enable during Sleep mode"]
pub type Can2lpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PWRLPEN` reader - Power interface clock enable during Sleep mode"]
pub type PwrlpenR = crate::BitReader;
#[doc = "Field `PWRLPEN` writer - Power interface clock enable during Sleep mode"]
pub type PwrlpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DACLPEN` reader - DAC interface clock enable during Sleep mode"]
pub type DaclpenR = crate::BitReader;
#[doc = "Field `DACLPEN` writer - DAC interface clock enable during Sleep mode"]
pub type DaclpenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TIM2 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim2lpen(&self) -> Tim2lpenR {
        Tim2lpenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TIM3 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim3lpen(&self) -> Tim3lpenR {
        Tim3lpenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - TIM4 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim4lpen(&self) -> Tim4lpenR {
        Tim4lpenR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - TIM5 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim5lpen(&self) -> Tim5lpenR {
        Tim5lpenR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - TIM6 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim6lpen(&self) -> Tim6lpenR {
        Tim6lpenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - TIM7 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim7lpen(&self) -> Tim7lpenR {
        Tim7lpenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - TIM12 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim12lpen(&self) -> Tim12lpenR {
        Tim12lpenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - TIM13 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim13lpen(&self) -> Tim13lpenR {
        Tim13lpenR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - TIM14 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn tim14lpen(&self) -> Tim14lpenR {
        Tim14lpenR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 11 - Window watchdog clock enable during Sleep mode"]
    #[inline(always)]
    pub fn wwdglpen(&self) -> WwdglpenR {
        WwdglpenR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 14 - SPI2 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn spi2lpen(&self) -> Spi2lpenR {
        Spi2lpenR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - SPI3 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn spi3lpen(&self) -> Spi3lpenR {
        Spi3lpenR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 17 - USART2 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn usart2lpen(&self) -> Usart2lpenR {
        Usart2lpenR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - USART3 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn usart3lpen(&self) -> Usart3lpenR {
        Usart3lpenR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - UART4 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn uart4lpen(&self) -> Uart4lpenR {
        Uart4lpenR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - UART5 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn uart5lpen(&self) -> Uart5lpenR {
        Uart5lpenR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - I2C1 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn i2c1lpen(&self) -> I2c1lpenR {
        I2c1lpenR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - I2C2 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn i2c2lpen(&self) -> I2c2lpenR {
        I2c2lpenR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - I2C3 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn i2c3lpen(&self) -> I2c3lpenR {
        I2c3lpenR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 25 - CAN 1 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn can1lpen(&self) -> Can1lpenR {
        Can1lpenR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - CAN 2 clock enable during Sleep mode"]
    #[inline(always)]
    pub fn can2lpen(&self) -> Can2lpenR {
        Can2lpenR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 28 - Power interface clock enable during Sleep mode"]
    #[inline(always)]
    pub fn pwrlpen(&self) -> PwrlpenR {
        PwrlpenR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - DAC interface clock enable during Sleep mode"]
    #[inline(always)]
    pub fn daclpen(&self) -> DaclpenR {
        DaclpenR::new(((self.bits >> 29) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TIM2 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim2lpen(&mut self) -> Tim2lpenW<Apb1lpenrSpec> {
        Tim2lpenW::new(self, 0)
    }
    #[doc = "Bit 1 - TIM3 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim3lpen(&mut self) -> Tim3lpenW<Apb1lpenrSpec> {
        Tim3lpenW::new(self, 1)
    }
    #[doc = "Bit 2 - TIM4 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim4lpen(&mut self) -> Tim4lpenW<Apb1lpenrSpec> {
        Tim4lpenW::new(self, 2)
    }
    #[doc = "Bit 3 - TIM5 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim5lpen(&mut self) -> Tim5lpenW<Apb1lpenrSpec> {
        Tim5lpenW::new(self, 3)
    }
    #[doc = "Bit 4 - TIM6 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim6lpen(&mut self) -> Tim6lpenW<Apb1lpenrSpec> {
        Tim6lpenW::new(self, 4)
    }
    #[doc = "Bit 5 - TIM7 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim7lpen(&mut self) -> Tim7lpenW<Apb1lpenrSpec> {
        Tim7lpenW::new(self, 5)
    }
    #[doc = "Bit 6 - TIM12 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim12lpen(&mut self) -> Tim12lpenW<Apb1lpenrSpec> {
        Tim12lpenW::new(self, 6)
    }
    #[doc = "Bit 7 - TIM13 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim13lpen(&mut self) -> Tim13lpenW<Apb1lpenrSpec> {
        Tim13lpenW::new(self, 7)
    }
    #[doc = "Bit 8 - TIM14 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn tim14lpen(&mut self) -> Tim14lpenW<Apb1lpenrSpec> {
        Tim14lpenW::new(self, 8)
    }
    #[doc = "Bit 11 - Window watchdog clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn wwdglpen(&mut self) -> WwdglpenW<Apb1lpenrSpec> {
        WwdglpenW::new(self, 11)
    }
    #[doc = "Bit 14 - SPI2 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn spi2lpen(&mut self) -> Spi2lpenW<Apb1lpenrSpec> {
        Spi2lpenW::new(self, 14)
    }
    #[doc = "Bit 15 - SPI3 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn spi3lpen(&mut self) -> Spi3lpenW<Apb1lpenrSpec> {
        Spi3lpenW::new(self, 15)
    }
    #[doc = "Bit 17 - USART2 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn usart2lpen(&mut self) -> Usart2lpenW<Apb1lpenrSpec> {
        Usart2lpenW::new(self, 17)
    }
    #[doc = "Bit 18 - USART3 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn usart3lpen(&mut self) -> Usart3lpenW<Apb1lpenrSpec> {
        Usart3lpenW::new(self, 18)
    }
    #[doc = "Bit 19 - UART4 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn uart4lpen(&mut self) -> Uart4lpenW<Apb1lpenrSpec> {
        Uart4lpenW::new(self, 19)
    }
    #[doc = "Bit 20 - UART5 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn uart5lpen(&mut self) -> Uart5lpenW<Apb1lpenrSpec> {
        Uart5lpenW::new(self, 20)
    }
    #[doc = "Bit 21 - I2C1 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn i2c1lpen(&mut self) -> I2c1lpenW<Apb1lpenrSpec> {
        I2c1lpenW::new(self, 21)
    }
    #[doc = "Bit 22 - I2C2 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn i2c2lpen(&mut self) -> I2c2lpenW<Apb1lpenrSpec> {
        I2c2lpenW::new(self, 22)
    }
    #[doc = "Bit 23 - I2C3 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn i2c3lpen(&mut self) -> I2c3lpenW<Apb1lpenrSpec> {
        I2c3lpenW::new(self, 23)
    }
    #[doc = "Bit 25 - CAN 1 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn can1lpen(&mut self) -> Can1lpenW<Apb1lpenrSpec> {
        Can1lpenW::new(self, 25)
    }
    #[doc = "Bit 26 - CAN 2 clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn can2lpen(&mut self) -> Can2lpenW<Apb1lpenrSpec> {
        Can2lpenW::new(self, 26)
    }
    #[doc = "Bit 28 - Power interface clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn pwrlpen(&mut self) -> PwrlpenW<Apb1lpenrSpec> {
        PwrlpenW::new(self, 28)
    }
    #[doc = "Bit 29 - DAC interface clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn daclpen(&mut self) -> DaclpenW<Apb1lpenrSpec> {
        DaclpenW::new(self, 29)
    }
}
#[doc = "APB1 peripheral clock enable in low power mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`apb1lpenr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`apb1lpenr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Apb1lpenrSpec;
impl crate::RegisterSpec for Apb1lpenrSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`apb1lpenr::R`](R) reader structure"]
impl crate::Readable for Apb1lpenrSpec {}
#[doc = "`write(|w| ..)` method takes [`apb1lpenr::W`](W) writer structure"]
impl crate::Writable for Apb1lpenrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets APB1LPENR to value 0x36fe_c9ff"]
impl crate::Resettable for Apb1lpenrSpec {
    const RESET_VALUE: u32 = 0x36fe_c9ff;
}
