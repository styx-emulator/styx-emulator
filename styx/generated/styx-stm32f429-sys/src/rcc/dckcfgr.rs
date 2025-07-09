// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DCKCFGR` reader"]
pub type R = crate::R<DckcfgrSpec>;
#[doc = "Register `DCKCFGR` writer"]
pub type W = crate::W<DckcfgrSpec>;
#[doc = "Field `PLLI2SDIVQ` reader - PLLI2S division factor for SAI1 clock"]
pub type Plli2sdivqR = crate::FieldReader;
#[doc = "Field `PLLI2SDIVQ` writer - PLLI2S division factor for SAI1 clock"]
pub type Plli2sdivqW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `PLLSAIDIVQ` reader - PLLSAI division factor for SAI1 clock"]
pub type PllsaidivqR = crate::FieldReader;
#[doc = "Field `PLLSAIDIVQ` writer - PLLSAI division factor for SAI1 clock"]
pub type PllsaidivqW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `PLLSAIDIVR` reader - division factor for LCD_CLK"]
pub type PllsaidivrR = crate::FieldReader;
#[doc = "Field `PLLSAIDIVR` writer - division factor for LCD_CLK"]
pub type PllsaidivrW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `SAI1ASRC` reader - SAI1-A clock source selection"]
pub type Sai1asrcR = crate::FieldReader;
#[doc = "Field `SAI1ASRC` writer - SAI1-A clock source selection"]
pub type Sai1asrcW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `SAI1BSRC` reader - SAI1-B clock source selection"]
pub type Sai1bsrcR = crate::FieldReader;
#[doc = "Field `SAI1BSRC` writer - SAI1-B clock source selection"]
pub type Sai1bsrcW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TIMPRE` reader - Timers clocks prescalers selection"]
pub type TimpreR = crate::BitReader;
#[doc = "Field `TIMPRE` writer - Timers clocks prescalers selection"]
pub type TimpreW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:4 - PLLI2S division factor for SAI1 clock"]
    #[inline(always)]
    pub fn plli2sdivq(&self) -> Plli2sdivqR {
        Plli2sdivqR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 8:12 - PLLSAI division factor for SAI1 clock"]
    #[inline(always)]
    pub fn pllsaidivq(&self) -> PllsaidivqR {
        PllsaidivqR::new(((self.bits >> 8) & 0x1f) as u8)
    }
    #[doc = "Bits 16:17 - division factor for LCD_CLK"]
    #[inline(always)]
    pub fn pllsaidivr(&self) -> PllsaidivrR {
        PllsaidivrR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 20:21 - SAI1-A clock source selection"]
    #[inline(always)]
    pub fn sai1asrc(&self) -> Sai1asrcR {
        Sai1asrcR::new(((self.bits >> 20) & 3) as u8)
    }
    #[doc = "Bits 22:23 - SAI1-B clock source selection"]
    #[inline(always)]
    pub fn sai1bsrc(&self) -> Sai1bsrcR {
        Sai1bsrcR::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bit 24 - Timers clocks prescalers selection"]
    #[inline(always)]
    pub fn timpre(&self) -> TimpreR {
        TimpreR::new(((self.bits >> 24) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:4 - PLLI2S division factor for SAI1 clock"]
    #[inline(always)]
    #[must_use]
    pub fn plli2sdivq(&mut self) -> Plli2sdivqW<DckcfgrSpec> {
        Plli2sdivqW::new(self, 0)
    }
    #[doc = "Bits 8:12 - PLLSAI division factor for SAI1 clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllsaidivq(&mut self) -> PllsaidivqW<DckcfgrSpec> {
        PllsaidivqW::new(self, 8)
    }
    #[doc = "Bits 16:17 - division factor for LCD_CLK"]
    #[inline(always)]
    #[must_use]
    pub fn pllsaidivr(&mut self) -> PllsaidivrW<DckcfgrSpec> {
        PllsaidivrW::new(self, 16)
    }
    #[doc = "Bits 20:21 - SAI1-A clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn sai1asrc(&mut self) -> Sai1asrcW<DckcfgrSpec> {
        Sai1asrcW::new(self, 20)
    }
    #[doc = "Bits 22:23 - SAI1-B clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn sai1bsrc(&mut self) -> Sai1bsrcW<DckcfgrSpec> {
        Sai1bsrcW::new(self, 22)
    }
    #[doc = "Bit 24 - Timers clocks prescalers selection"]
    #[inline(always)]
    #[must_use]
    pub fn timpre(&mut self) -> TimpreW<DckcfgrSpec> {
        TimpreW::new(self, 24)
    }
}
#[doc = "RCC Dedicated Clock Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dckcfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dckcfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DckcfgrSpec;
impl crate::RegisterSpec for DckcfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 140u64;
}
#[doc = "`read()` method returns [`dckcfgr::R`](R) reader structure"]
impl crate::Readable for DckcfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`dckcfgr::W`](W) writer structure"]
impl crate::Writable for DckcfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DCKCFGR to value 0"]
impl crate::Resettable for DckcfgrSpec {
    const RESET_VALUE: u32 = 0;
}
