// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `APB2ENR` reader"]
pub type R = crate::R<Apb2enrSpec>;
#[doc = "Register `APB2ENR` writer"]
pub type W = crate::W<Apb2enrSpec>;
#[doc = "Field `TIM1EN` reader - TIM1 clock enable"]
pub type Tim1enR = crate::BitReader;
#[doc = "Field `TIM1EN` writer - TIM1 clock enable"]
pub type Tim1enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM8EN` reader - TIM8 clock enable"]
pub type Tim8enR = crate::BitReader;
#[doc = "Field `TIM8EN` writer - TIM8 clock enable"]
pub type Tim8enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USART1EN` reader - USART1 clock enable"]
pub type Usart1enR = crate::BitReader;
#[doc = "Field `USART1EN` writer - USART1 clock enable"]
pub type Usart1enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USART6EN` reader - USART6 clock enable"]
pub type Usart6enR = crate::BitReader;
#[doc = "Field `USART6EN` writer - USART6 clock enable"]
pub type Usart6enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADC1EN` reader - ADC1 clock enable"]
pub type Adc1enR = crate::BitReader;
#[doc = "Field `ADC1EN` writer - ADC1 clock enable"]
pub type Adc1enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADC2EN` reader - ADC2 clock enable"]
pub type Adc2enR = crate::BitReader;
#[doc = "Field `ADC2EN` writer - ADC2 clock enable"]
pub type Adc2enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADC3EN` reader - ADC3 clock enable"]
pub type Adc3enR = crate::BitReader;
#[doc = "Field `ADC3EN` writer - ADC3 clock enable"]
pub type Adc3enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDIOEN` reader - SDIO clock enable"]
pub type SdioenR = crate::BitReader;
#[doc = "Field `SDIOEN` writer - SDIO clock enable"]
pub type SdioenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPI1EN` reader - SPI1 clock enable"]
pub type Spi1enR = crate::BitReader;
#[doc = "Field `SPI1EN` writer - SPI1 clock enable"]
pub type Spi1enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SYSCFGEN` reader - System configuration controller clock enable"]
pub type SyscfgenR = crate::BitReader;
#[doc = "Field `SYSCFGEN` writer - System configuration controller clock enable"]
pub type SyscfgenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM9EN` reader - TIM9 clock enable"]
pub type Tim9enR = crate::BitReader;
#[doc = "Field `TIM9EN` writer - TIM9 clock enable"]
pub type Tim9enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM10EN` reader - TIM10 clock enable"]
pub type Tim10enR = crate::BitReader;
#[doc = "Field `TIM10EN` writer - TIM10 clock enable"]
pub type Tim10enW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIM11EN` reader - TIM11 clock enable"]
pub type Tim11enR = crate::BitReader;
#[doc = "Field `TIM11EN` writer - TIM11 clock enable"]
pub type Tim11enW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TIM1 clock enable"]
    #[inline(always)]
    pub fn tim1en(&self) -> Tim1enR {
        Tim1enR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TIM8 clock enable"]
    #[inline(always)]
    pub fn tim8en(&self) -> Tim8enR {
        Tim8enR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 4 - USART1 clock enable"]
    #[inline(always)]
    pub fn usart1en(&self) -> Usart1enR {
        Usart1enR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - USART6 clock enable"]
    #[inline(always)]
    pub fn usart6en(&self) -> Usart6enR {
        Usart6enR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - ADC1 clock enable"]
    #[inline(always)]
    pub fn adc1en(&self) -> Adc1enR {
        Adc1enR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - ADC2 clock enable"]
    #[inline(always)]
    pub fn adc2en(&self) -> Adc2enR {
        Adc2enR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - ADC3 clock enable"]
    #[inline(always)]
    pub fn adc3en(&self) -> Adc3enR {
        Adc3enR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - SDIO clock enable"]
    #[inline(always)]
    pub fn sdioen(&self) -> SdioenR {
        SdioenR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - SPI1 clock enable"]
    #[inline(always)]
    pub fn spi1en(&self) -> Spi1enR {
        Spi1enR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 14 - System configuration controller clock enable"]
    #[inline(always)]
    pub fn syscfgen(&self) -> SyscfgenR {
        SyscfgenR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 16 - TIM9 clock enable"]
    #[inline(always)]
    pub fn tim9en(&self) -> Tim9enR {
        Tim9enR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - TIM10 clock enable"]
    #[inline(always)]
    pub fn tim10en(&self) -> Tim10enR {
        Tim10enR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - TIM11 clock enable"]
    #[inline(always)]
    pub fn tim11en(&self) -> Tim11enR {
        Tim11enR::new(((self.bits >> 18) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TIM1 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn tim1en(&mut self) -> Tim1enW<Apb2enrSpec> {
        Tim1enW::new(self, 0)
    }
    #[doc = "Bit 1 - TIM8 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn tim8en(&mut self) -> Tim8enW<Apb2enrSpec> {
        Tim8enW::new(self, 1)
    }
    #[doc = "Bit 4 - USART1 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn usart1en(&mut self) -> Usart1enW<Apb2enrSpec> {
        Usart1enW::new(self, 4)
    }
    #[doc = "Bit 5 - USART6 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn usart6en(&mut self) -> Usart6enW<Apb2enrSpec> {
        Usart6enW::new(self, 5)
    }
    #[doc = "Bit 8 - ADC1 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn adc1en(&mut self) -> Adc1enW<Apb2enrSpec> {
        Adc1enW::new(self, 8)
    }
    #[doc = "Bit 9 - ADC2 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn adc2en(&mut self) -> Adc2enW<Apb2enrSpec> {
        Adc2enW::new(self, 9)
    }
    #[doc = "Bit 10 - ADC3 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn adc3en(&mut self) -> Adc3enW<Apb2enrSpec> {
        Adc3enW::new(self, 10)
    }
    #[doc = "Bit 11 - SDIO clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn sdioen(&mut self) -> SdioenW<Apb2enrSpec> {
        SdioenW::new(self, 11)
    }
    #[doc = "Bit 12 - SPI1 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn spi1en(&mut self) -> Spi1enW<Apb2enrSpec> {
        Spi1enW::new(self, 12)
    }
    #[doc = "Bit 14 - System configuration controller clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn syscfgen(&mut self) -> SyscfgenW<Apb2enrSpec> {
        SyscfgenW::new(self, 14)
    }
    #[doc = "Bit 16 - TIM9 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn tim9en(&mut self) -> Tim9enW<Apb2enrSpec> {
        Tim9enW::new(self, 16)
    }
    #[doc = "Bit 17 - TIM10 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn tim10en(&mut self) -> Tim10enW<Apb2enrSpec> {
        Tim10enW::new(self, 17)
    }
    #[doc = "Bit 18 - TIM11 clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn tim11en(&mut self) -> Tim11enW<Apb2enrSpec> {
        Tim11enW::new(self, 18)
    }
}
#[doc = "APB2 peripheral clock enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`apb2enr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`apb2enr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Apb2enrSpec;
impl crate::RegisterSpec for Apb2enrSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`apb2enr::R`](R) reader structure"]
impl crate::Readable for Apb2enrSpec {}
#[doc = "`write(|w| ..)` method takes [`apb2enr::W`](W) writer structure"]
impl crate::Writable for Apb2enrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets APB2ENR to value 0"]
impl crate::Resettable for Apb2enrSpec {
    const RESET_VALUE: u32 = 0;
}
