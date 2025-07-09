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
#[doc = "Register `APB1RSTR` reader"]
pub type R = crate::R<Apb1rstrSpec>;
#[doc = "Register `APB1RSTR` writer"]
pub type W = crate::W<Apb1rstrSpec>;
#[doc = "Field `TIM2RST` reader - TIM2 reset"]
pub type Tim2rstR = crate::BitReader;
#[doc = "Field `TIM2RST` writer - TIM2 reset"]
pub type Tim2rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM3RST` reader - TIM3 reset"]
pub type Tim3rstR = crate::BitReader;
#[doc = "Field `TIM3RST` writer - TIM3 reset"]
pub type Tim3rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM4RST` reader - TIM4 reset"]
pub type Tim4rstR = crate::BitReader;
#[doc = "Field `TIM4RST` writer - TIM4 reset"]
pub type Tim4rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM5RST` reader - TIM5 reset"]
pub type Tim5rstR = crate::BitReader;
#[doc = "Field `TIM5RST` writer - TIM5 reset"]
pub type Tim5rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM6RST` reader - TIM6 reset"]
pub type Tim6rstR = crate::BitReader;
#[doc = "Field `TIM6RST` writer - TIM6 reset"]
pub type Tim6rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM7RST` reader - TIM7 reset"]
pub type Tim7rstR = crate::BitReader;
#[doc = "Field `TIM7RST` writer - TIM7 reset"]
pub type Tim7rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM12RST` reader - TIM12 reset"]
pub type Tim12rstR = crate::BitReader;
#[doc = "Field `TIM12RST` writer - TIM12 reset"]
pub type Tim12rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM13RST` reader - TIM13 reset"]
pub type Tim13rstR = crate::BitReader;
#[doc = "Field `TIM13RST` writer - TIM13 reset"]
pub type Tim13rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM14RST` reader - TIM14 reset"]
pub type Tim14rstR = crate::BitReader;
#[doc = "Field `TIM14RST` writer - TIM14 reset"]
pub type Tim14rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WWDGRST` reader - Window watchdog reset"]
pub type WwdgrstR = crate::BitReader;
#[doc = "Field `WWDGRST` writer - Window watchdog reset"]
pub type WwdgrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI2RST` reader - SPI 2 reset"]
pub type Spi2rstR = crate::BitReader;
#[doc = "Field `SPI2RST` writer - SPI 2 reset"]
pub type Spi2rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI3RST` reader - SPI 3 reset"]
pub type Spi3rstR = crate::BitReader;
#[doc = "Field `SPI3RST` writer - SPI 3 reset"]
pub type Spi3rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UART2RST` reader - USART 2 reset"]
pub type Uart2rstR = crate::BitReader;
#[doc = "Field `UART2RST` writer - USART 2 reset"]
pub type Uart2rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UART3RST` reader - USART 3 reset"]
pub type Uart3rstR = crate::BitReader;
#[doc = "Field `UART3RST` writer - USART 3 reset"]
pub type Uart3rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UART4RST` reader - USART 4 reset"]
pub type Uart4rstR = crate::BitReader;
#[doc = "Field `UART4RST` writer - USART 4 reset"]
pub type Uart4rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UART5RST` reader - USART 5 reset"]
pub type Uart5rstR = crate::BitReader;
#[doc = "Field `UART5RST` writer - USART 5 reset"]
pub type Uart5rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2C1RST` reader - I2C 1 reset"]
pub type I2c1rstR = crate::BitReader;
#[doc = "Field `I2C1RST` writer - I2C 1 reset"]
pub type I2c1rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2C2RST` reader - I2C 2 reset"]
pub type I2c2rstR = crate::BitReader;
#[doc = "Field `I2C2RST` writer - I2C 2 reset"]
pub type I2c2rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `I2C3RST` reader - I2C3 reset"]
pub type I2c3rstR = crate::BitReader;
#[doc = "Field `I2C3RST` writer - I2C3 reset"]
pub type I2c3rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAN1RST` reader - CAN1 reset"]
pub type Can1rstR = crate::BitReader;
#[doc = "Field `CAN1RST` writer - CAN1 reset"]
pub type Can1rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAN2RST` reader - CAN2 reset"]
pub type Can2rstR = crate::BitReader;
#[doc = "Field `CAN2RST` writer - CAN2 reset"]
pub type Can2rstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PWRRST` reader - Power interface reset"]
pub type PwrrstR = crate::BitReader;
#[doc = "Field `PWRRST` writer - Power interface reset"]
pub type PwrrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DACRST` reader - DAC reset"]
pub type DacrstR = crate::BitReader;
#[doc = "Field `DACRST` writer - DAC reset"]
pub type DacrstW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TIM2 reset"]
    #[inline(always)]
    pub fn tim2rst(&self) -> Tim2rstR {
        Tim2rstR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TIM3 reset"]
    #[inline(always)]
    pub fn tim3rst(&self) -> Tim3rstR {
        Tim3rstR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - TIM4 reset"]
    #[inline(always)]
    pub fn tim4rst(&self) -> Tim4rstR {
        Tim4rstR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - TIM5 reset"]
    #[inline(always)]
    pub fn tim5rst(&self) -> Tim5rstR {
        Tim5rstR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - TIM6 reset"]
    #[inline(always)]
    pub fn tim6rst(&self) -> Tim6rstR {
        Tim6rstR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - TIM7 reset"]
    #[inline(always)]
    pub fn tim7rst(&self) -> Tim7rstR {
        Tim7rstR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - TIM12 reset"]
    #[inline(always)]
    pub fn tim12rst(&self) -> Tim12rstR {
        Tim12rstR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - TIM13 reset"]
    #[inline(always)]
    pub fn tim13rst(&self) -> Tim13rstR {
        Tim13rstR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - TIM14 reset"]
    #[inline(always)]
    pub fn tim14rst(&self) -> Tim14rstR {
        Tim14rstR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 11 - Window watchdog reset"]
    #[inline(always)]
    pub fn wwdgrst(&self) -> WwdgrstR {
        WwdgrstR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 14 - SPI 2 reset"]
    #[inline(always)]
    pub fn spi2rst(&self) -> Spi2rstR {
        Spi2rstR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - SPI 3 reset"]
    #[inline(always)]
    pub fn spi3rst(&self) -> Spi3rstR {
        Spi3rstR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 17 - USART 2 reset"]
    #[inline(always)]
    pub fn uart2rst(&self) -> Uart2rstR {
        Uart2rstR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - USART 3 reset"]
    #[inline(always)]
    pub fn uart3rst(&self) -> Uart3rstR {
        Uart3rstR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - USART 4 reset"]
    #[inline(always)]
    pub fn uart4rst(&self) -> Uart4rstR {
        Uart4rstR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - USART 5 reset"]
    #[inline(always)]
    pub fn uart5rst(&self) -> Uart5rstR {
        Uart5rstR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - I2C 1 reset"]
    #[inline(always)]
    pub fn i2c1rst(&self) -> I2c1rstR {
        I2c1rstR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - I2C 2 reset"]
    #[inline(always)]
    pub fn i2c2rst(&self) -> I2c2rstR {
        I2c2rstR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - I2C3 reset"]
    #[inline(always)]
    pub fn i2c3rst(&self) -> I2c3rstR {
        I2c3rstR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 25 - CAN1 reset"]
    #[inline(always)]
    pub fn can1rst(&self) -> Can1rstR {
        Can1rstR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - CAN2 reset"]
    #[inline(always)]
    pub fn can2rst(&self) -> Can2rstR {
        Can2rstR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 28 - Power interface reset"]
    #[inline(always)]
    pub fn pwrrst(&self) -> PwrrstR {
        PwrrstR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - DAC reset"]
    #[inline(always)]
    pub fn dacrst(&self) -> DacrstR {
        DacrstR::new(((self.bits >> 29) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TIM2 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim2rst(&mut self) -> Tim2rstW<Apb1rstrSpec> {
        Tim2rstW::new(self, 0)
    }
    #[doc = "Bit 1 - TIM3 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim3rst(&mut self) -> Tim3rstW<Apb1rstrSpec> {
        Tim3rstW::new(self, 1)
    }
    #[doc = "Bit 2 - TIM4 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim4rst(&mut self) -> Tim4rstW<Apb1rstrSpec> {
        Tim4rstW::new(self, 2)
    }
    #[doc = "Bit 3 - TIM5 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim5rst(&mut self) -> Tim5rstW<Apb1rstrSpec> {
        Tim5rstW::new(self, 3)
    }
    #[doc = "Bit 4 - TIM6 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim6rst(&mut self) -> Tim6rstW<Apb1rstrSpec> {
        Tim6rstW::new(self, 4)
    }
    #[doc = "Bit 5 - TIM7 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim7rst(&mut self) -> Tim7rstW<Apb1rstrSpec> {
        Tim7rstW::new(self, 5)
    }
    #[doc = "Bit 6 - TIM12 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim12rst(&mut self) -> Tim12rstW<Apb1rstrSpec> {
        Tim12rstW::new(self, 6)
    }
    #[doc = "Bit 7 - TIM13 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim13rst(&mut self) -> Tim13rstW<Apb1rstrSpec> {
        Tim13rstW::new(self, 7)
    }
    #[doc = "Bit 8 - TIM14 reset"]
    #[inline(always)]
    #[must_use]
    pub fn tim14rst(&mut self) -> Tim14rstW<Apb1rstrSpec> {
        Tim14rstW::new(self, 8)
    }
    #[doc = "Bit 11 - Window watchdog reset"]
    #[inline(always)]
    #[must_use]
    pub fn wwdgrst(&mut self) -> WwdgrstW<Apb1rstrSpec> {
        WwdgrstW::new(self, 11)
    }
    #[doc = "Bit 14 - SPI 2 reset"]
    #[inline(always)]
    #[must_use]
    pub fn spi2rst(&mut self) -> Spi2rstW<Apb1rstrSpec> {
        Spi2rstW::new(self, 14)
    }
    #[doc = "Bit 15 - SPI 3 reset"]
    #[inline(always)]
    #[must_use]
    pub fn spi3rst(&mut self) -> Spi3rstW<Apb1rstrSpec> {
        Spi3rstW::new(self, 15)
    }
    #[doc = "Bit 17 - USART 2 reset"]
    #[inline(always)]
    #[must_use]
    pub fn uart2rst(&mut self) -> Uart2rstW<Apb1rstrSpec> {
        Uart2rstW::new(self, 17)
    }
    #[doc = "Bit 18 - USART 3 reset"]
    #[inline(always)]
    #[must_use]
    pub fn uart3rst(&mut self) -> Uart3rstW<Apb1rstrSpec> {
        Uart3rstW::new(self, 18)
    }
    #[doc = "Bit 19 - USART 4 reset"]
    #[inline(always)]
    #[must_use]
    pub fn uart4rst(&mut self) -> Uart4rstW<Apb1rstrSpec> {
        Uart4rstW::new(self, 19)
    }
    #[doc = "Bit 20 - USART 5 reset"]
    #[inline(always)]
    #[must_use]
    pub fn uart5rst(&mut self) -> Uart5rstW<Apb1rstrSpec> {
        Uart5rstW::new(self, 20)
    }
    #[doc = "Bit 21 - I2C 1 reset"]
    #[inline(always)]
    #[must_use]
    pub fn i2c1rst(&mut self) -> I2c1rstW<Apb1rstrSpec> {
        I2c1rstW::new(self, 21)
    }
    #[doc = "Bit 22 - I2C 2 reset"]
    #[inline(always)]
    #[must_use]
    pub fn i2c2rst(&mut self) -> I2c2rstW<Apb1rstrSpec> {
        I2c2rstW::new(self, 22)
    }
    #[doc = "Bit 23 - I2C3 reset"]
    #[inline(always)]
    #[must_use]
    pub fn i2c3rst(&mut self) -> I2c3rstW<Apb1rstrSpec> {
        I2c3rstW::new(self, 23)
    }
    #[doc = "Bit 25 - CAN1 reset"]
    #[inline(always)]
    #[must_use]
    pub fn can1rst(&mut self) -> Can1rstW<Apb1rstrSpec> {
        Can1rstW::new(self, 25)
    }
    #[doc = "Bit 26 - CAN2 reset"]
    #[inline(always)]
    #[must_use]
    pub fn can2rst(&mut self) -> Can2rstW<Apb1rstrSpec> {
        Can2rstW::new(self, 26)
    }
    #[doc = "Bit 28 - Power interface reset"]
    #[inline(always)]
    #[must_use]
    pub fn pwrrst(&mut self) -> PwrrstW<Apb1rstrSpec> {
        PwrrstW::new(self, 28)
    }
    #[doc = "Bit 29 - DAC reset"]
    #[inline(always)]
    #[must_use]
    pub fn dacrst(&mut self) -> DacrstW<Apb1rstrSpec> {
        DacrstW::new(self, 29)
    }
}
#[doc = "APB1 peripheral reset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`apb1rstr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`apb1rstr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Apb1rstrSpec;
impl crate::RegisterSpec for Apb1rstrSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`apb1rstr::R`](R) reader structure"]
impl crate::Readable for Apb1rstrSpec {}
#[doc = "`write(|w| ..)` method takes [`apb1rstr::W`](W) writer structure"]
impl crate::Writable for Apb1rstrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets APB1RSTR to value 0"]
impl crate::Resettable for Apb1rstrSpec {
    const RESET_VALUE: u32 = 0;
}
