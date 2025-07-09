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
#[doc = "Register `DKCFGR2` reader"]
pub type R = crate::R<Dkcfgr2Spec>;
#[doc = "Register `DKCFGR2` writer"]
pub type W = crate::W<Dkcfgr2Spec>;
#[doc = "Field `USART1SEL` reader - USART 1 clock source selection"]
pub type Usart1selR = crate::FieldReader;
#[doc = "Field `USART1SEL` writer - USART 1 clock source selection"]
pub type Usart1selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `USART2SEL` reader - USART 2 clock source selection"]
pub type Usart2selR = crate::FieldReader;
#[doc = "Field `USART2SEL` writer - USART 2 clock source selection"]
pub type Usart2selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `USART3SEL` reader - USART 3 clock source selection"]
pub type Usart3selR = crate::FieldReader;
#[doc = "Field `USART3SEL` writer - USART 3 clock source selection"]
pub type Usart3selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `UART4SEL` reader - UART 4 clock source selection"]
pub type Uart4selR = crate::FieldReader;
#[doc = "Field `UART4SEL` writer - UART 4 clock source selection"]
pub type Uart4selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `UART5SEL` reader - UART 5 clock source selection"]
pub type Uart5selR = crate::FieldReader;
#[doc = "Field `UART5SEL` writer - UART 5 clock source selection"]
pub type Uart5selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `USART6SEL` reader - USART 6 clock source selection"]
pub type Usart6selR = crate::FieldReader;
#[doc = "Field `USART6SEL` writer - USART 6 clock source selection"]
pub type Usart6selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `UART7SEL` reader - UART 7 clock source selection"]
pub type Uart7selR = crate::FieldReader;
#[doc = "Field `UART7SEL` writer - UART 7 clock source selection"]
pub type Uart7selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `UART8SEL` reader - UART 8 clock source selection"]
pub type Uart8selR = crate::FieldReader;
#[doc = "Field `UART8SEL` writer - UART 8 clock source selection"]
pub type Uart8selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `I2C1SEL` reader - I2C1 clock source selection"]
pub type I2c1selR = crate::FieldReader;
#[doc = "Field `I2C1SEL` writer - I2C1 clock source selection"]
pub type I2c1selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `I2C2SEL` reader - I2C2 clock source selection"]
pub type I2c2selR = crate::FieldReader;
#[doc = "Field `I2C2SEL` writer - I2C2 clock source selection"]
pub type I2c2selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `I2C3SEL` reader - I2C3 clock source selection"]
pub type I2c3selR = crate::FieldReader;
#[doc = "Field `I2C3SEL` writer - I2C3 clock source selection"]
pub type I2c3selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `I2C4SEL` reader - I2C4 clock source selection"]
pub type I2c4selR = crate::FieldReader;
#[doc = "Field `I2C4SEL` writer - I2C4 clock source selection"]
pub type I2c4selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `LPTIM1SEL` reader - Low power timer 1 clock source selection"]
pub type Lptim1selR = crate::FieldReader;
#[doc = "Field `LPTIM1SEL` writer - Low power timer 1 clock source selection"]
pub type Lptim1selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `CECSEL` reader - HDMI-CEC clock source selection"]
pub type CecselR = crate::BitReader;
#[doc = "Field `CECSEL` writer - HDMI-CEC clock source selection"]
pub type CecselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CK48MSEL` reader - 48MHz clock source selection"]
pub type Ck48mselR = crate::BitReader;
#[doc = "Field `CK48MSEL` writer - 48MHz clock source selection"]
pub type Ck48mselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDMMCSEL` reader - SDMMC clock source selection"]
pub type SdmmcselR = crate::BitReader;
#[doc = "Field `SDMMCSEL` writer - SDMMC clock source selection"]
pub type SdmmcselW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - USART 1 clock source selection"]
    #[inline(always)]
    pub fn usart1sel(&self) -> Usart1selR {
        Usart1selR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - USART 2 clock source selection"]
    #[inline(always)]
    pub fn usart2sel(&self) -> Usart2selR {
        Usart2selR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:5 - USART 3 clock source selection"]
    #[inline(always)]
    pub fn usart3sel(&self) -> Usart3selR {
        Usart3selR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bits 6:7 - UART 4 clock source selection"]
    #[inline(always)]
    pub fn uart4sel(&self) -> Uart4selR {
        Uart4selR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bits 8:9 - UART 5 clock source selection"]
    #[inline(always)]
    pub fn uart5sel(&self) -> Uart5selR {
        Uart5selR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bits 10:11 - USART 6 clock source selection"]
    #[inline(always)]
    pub fn usart6sel(&self) -> Usart6selR {
        Usart6selR::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bits 12:13 - UART 7 clock source selection"]
    #[inline(always)]
    pub fn uart7sel(&self) -> Uart7selR {
        Uart7selR::new(((self.bits >> 12) & 3) as u8)
    }
    #[doc = "Bits 14:15 - UART 8 clock source selection"]
    #[inline(always)]
    pub fn uart8sel(&self) -> Uart8selR {
        Uart8selR::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bits 16:17 - I2C1 clock source selection"]
    #[inline(always)]
    pub fn i2c1sel(&self) -> I2c1selR {
        I2c1selR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 18:19 - I2C2 clock source selection"]
    #[inline(always)]
    pub fn i2c2sel(&self) -> I2c2selR {
        I2c2selR::new(((self.bits >> 18) & 3) as u8)
    }
    #[doc = "Bits 20:21 - I2C3 clock source selection"]
    #[inline(always)]
    pub fn i2c3sel(&self) -> I2c3selR {
        I2c3selR::new(((self.bits >> 20) & 3) as u8)
    }
    #[doc = "Bits 22:23 - I2C4 clock source selection"]
    #[inline(always)]
    pub fn i2c4sel(&self) -> I2c4selR {
        I2c4selR::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bits 24:25 - Low power timer 1 clock source selection"]
    #[inline(always)]
    pub fn lptim1sel(&self) -> Lptim1selR {
        Lptim1selR::new(((self.bits >> 24) & 3) as u8)
    }
    #[doc = "Bit 26 - HDMI-CEC clock source selection"]
    #[inline(always)]
    pub fn cecsel(&self) -> CecselR {
        CecselR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - 48MHz clock source selection"]
    #[inline(always)]
    pub fn ck48msel(&self) -> Ck48mselR {
        Ck48mselR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - SDMMC clock source selection"]
    #[inline(always)]
    pub fn sdmmcsel(&self) -> SdmmcselR {
        SdmmcselR::new(((self.bits >> 28) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - USART 1 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn usart1sel(&mut self) -> Usart1selW<Dkcfgr2Spec> {
        Usart1selW::new(self, 0)
    }
    #[doc = "Bits 2:3 - USART 2 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn usart2sel(&mut self) -> Usart2selW<Dkcfgr2Spec> {
        Usart2selW::new(self, 2)
    }
    #[doc = "Bits 4:5 - USART 3 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn usart3sel(&mut self) -> Usart3selW<Dkcfgr2Spec> {
        Usart3selW::new(self, 4)
    }
    #[doc = "Bits 6:7 - UART 4 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn uart4sel(&mut self) -> Uart4selW<Dkcfgr2Spec> {
        Uart4selW::new(self, 6)
    }
    #[doc = "Bits 8:9 - UART 5 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn uart5sel(&mut self) -> Uart5selW<Dkcfgr2Spec> {
        Uart5selW::new(self, 8)
    }
    #[doc = "Bits 10:11 - USART 6 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn usart6sel(&mut self) -> Usart6selW<Dkcfgr2Spec> {
        Usart6selW::new(self, 10)
    }
    #[doc = "Bits 12:13 - UART 7 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn uart7sel(&mut self) -> Uart7selW<Dkcfgr2Spec> {
        Uart7selW::new(self, 12)
    }
    #[doc = "Bits 14:15 - UART 8 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn uart8sel(&mut self) -> Uart8selW<Dkcfgr2Spec> {
        Uart8selW::new(self, 14)
    }
    #[doc = "Bits 16:17 - I2C1 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn i2c1sel(&mut self) -> I2c1selW<Dkcfgr2Spec> {
        I2c1selW::new(self, 16)
    }
    #[doc = "Bits 18:19 - I2C2 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn i2c2sel(&mut self) -> I2c2selW<Dkcfgr2Spec> {
        I2c2selW::new(self, 18)
    }
    #[doc = "Bits 20:21 - I2C3 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn i2c3sel(&mut self) -> I2c3selW<Dkcfgr2Spec> {
        I2c3selW::new(self, 20)
    }
    #[doc = "Bits 22:23 - I2C4 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn i2c4sel(&mut self) -> I2c4selW<Dkcfgr2Spec> {
        I2c4selW::new(self, 22)
    }
    #[doc = "Bits 24:25 - Low power timer 1 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn lptim1sel(&mut self) -> Lptim1selW<Dkcfgr2Spec> {
        Lptim1selW::new(self, 24)
    }
    #[doc = "Bit 26 - HDMI-CEC clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn cecsel(&mut self) -> CecselW<Dkcfgr2Spec> {
        CecselW::new(self, 26)
    }
    #[doc = "Bit 27 - 48MHz clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn ck48msel(&mut self) -> Ck48mselW<Dkcfgr2Spec> {
        Ck48mselW::new(self, 27)
    }
    #[doc = "Bit 28 - SDMMC clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn sdmmcsel(&mut self) -> SdmmcselW<Dkcfgr2Spec> {
        SdmmcselW::new(self, 28)
    }
}
#[doc = "dedicated clocks configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dkcfgr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dkcfgr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dkcfgr2Spec;
impl crate::RegisterSpec for Dkcfgr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 144u64;
}
#[doc = "`read()` method returns [`dkcfgr2::R`](R) reader structure"]
impl crate::Readable for Dkcfgr2Spec {}
#[doc = "`write(|w| ..)` method takes [`dkcfgr2::W`](W) writer structure"]
impl crate::Writable for Dkcfgr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DKCFGR2 to value 0x2000_3000"]
impl crate::Resettable for Dkcfgr2Spec {
    const RESET_VALUE: u32 = 0x2000_3000;
}
