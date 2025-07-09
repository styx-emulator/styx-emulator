// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PLLCFGR` reader"]
pub type R = crate::R<PllcfgrSpec>;
#[doc = "Register `PLLCFGR` writer"]
pub type W = crate::W<PllcfgrSpec>;
#[doc = "Field `PLLM0` reader - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm0R = crate::BitReader;
#[doc = "Field `PLLM0` writer - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLM1` reader - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm1R = crate::BitReader;
#[doc = "Field `PLLM1` writer - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLM2` reader - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm2R = crate::BitReader;
#[doc = "Field `PLLM2` writer - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLM3` reader - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm3R = crate::BitReader;
#[doc = "Field `PLLM3` writer - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLM4` reader - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm4R = crate::BitReader;
#[doc = "Field `PLLM4` writer - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLM5` reader - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm5R = crate::BitReader;
#[doc = "Field `PLLM5` writer - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
pub type Pllm5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN0` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln0R = crate::BitReader;
#[doc = "Field `PLLN0` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN1` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln1R = crate::BitReader;
#[doc = "Field `PLLN1` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN2` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln2R = crate::BitReader;
#[doc = "Field `PLLN2` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN3` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln3R = crate::BitReader;
#[doc = "Field `PLLN3` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN4` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln4R = crate::BitReader;
#[doc = "Field `PLLN4` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN5` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln5R = crate::BitReader;
#[doc = "Field `PLLN5` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN6` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln6R = crate::BitReader;
#[doc = "Field `PLLN6` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN7` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln7R = crate::BitReader;
#[doc = "Field `PLLN7` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLN8` reader - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln8R = crate::BitReader;
#[doc = "Field `PLLN8` writer - Main PLL (PLL) multiplication factor for VCO"]
pub type Plln8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLP0` reader - Main PLL (PLL) division factor for main system clock"]
pub type Pllp0R = crate::BitReader;
#[doc = "Field `PLLP0` writer - Main PLL (PLL) division factor for main system clock"]
pub type Pllp0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLP1` reader - Main PLL (PLL) division factor for main system clock"]
pub type Pllp1R = crate::BitReader;
#[doc = "Field `PLLP1` writer - Main PLL (PLL) division factor for main system clock"]
pub type Pllp1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLSRC` reader - Main PLL(PLL) and audio PLL (PLLI2S) entry clock source"]
pub type PllsrcR = crate::BitReader;
#[doc = "Field `PLLSRC` writer - Main PLL(PLL) and audio PLL (PLLI2S) entry clock source"]
pub type PllsrcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLQ0` reader - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
pub type Pllq0R = crate::BitReader;
#[doc = "Field `PLLQ0` writer - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
pub type Pllq0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLQ1` reader - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
pub type Pllq1R = crate::BitReader;
#[doc = "Field `PLLQ1` writer - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
pub type Pllq1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLQ2` reader - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
pub type Pllq2R = crate::BitReader;
#[doc = "Field `PLLQ2` writer - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
pub type Pllq2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLQ3` reader - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
pub type Pllq3R = crate::BitReader;
#[doc = "Field `PLLQ3` writer - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
pub type Pllq3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    pub fn pllm0(&self) -> Pllm0R {
        Pllm0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    pub fn pllm1(&self) -> Pllm1R {
        Pllm1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    pub fn pllm2(&self) -> Pllm2R {
        Pllm2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    pub fn pllm3(&self) -> Pllm3R {
        Pllm3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    pub fn pllm4(&self) -> Pllm4R {
        Pllm4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    pub fn pllm5(&self) -> Pllm5R {
        Pllm5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln0(&self) -> Plln0R {
        Plln0R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln1(&self) -> Plln1R {
        Plln1R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln2(&self) -> Plln2R {
        Plln2R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln3(&self) -> Plln3R {
        Plln3R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln4(&self) -> Plln4R {
        Plln4R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln5(&self) -> Plln5R {
        Plln5R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln6(&self) -> Plln6R {
        Plln6R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln7(&self) -> Plln7R {
        Plln7R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    pub fn plln8(&self) -> Plln8R {
        Plln8R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 16 - Main PLL (PLL) division factor for main system clock"]
    #[inline(always)]
    pub fn pllp0(&self) -> Pllp0R {
        Pllp0R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Main PLL (PLL) division factor for main system clock"]
    #[inline(always)]
    pub fn pllp1(&self) -> Pllp1R {
        Pllp1R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 22 - Main PLL(PLL) and audio PLL (PLLI2S) entry clock source"]
    #[inline(always)]
    pub fn pllsrc(&self) -> PllsrcR {
        PllsrcR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 24 - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
    #[inline(always)]
    pub fn pllq0(&self) -> Pllq0R {
        Pllq0R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
    #[inline(always)]
    pub fn pllq1(&self) -> Pllq1R {
        Pllq1R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
    #[inline(always)]
    pub fn pllq2(&self) -> Pllq2R {
        Pllq2R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
    #[inline(always)]
    pub fn pllq3(&self) -> Pllq3R {
        Pllq3R::new(((self.bits >> 27) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllm0(&mut self) -> Pllm0W<PllcfgrSpec> {
        Pllm0W::new(self, 0)
    }
    #[doc = "Bit 1 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllm1(&mut self) -> Pllm1W<PllcfgrSpec> {
        Pllm1W::new(self, 1)
    }
    #[doc = "Bit 2 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllm2(&mut self) -> Pllm2W<PllcfgrSpec> {
        Pllm2W::new(self, 2)
    }
    #[doc = "Bit 3 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllm3(&mut self) -> Pllm3W<PllcfgrSpec> {
        Pllm3W::new(self, 3)
    }
    #[doc = "Bit 4 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllm4(&mut self) -> Pllm4W<PllcfgrSpec> {
        Pllm4W::new(self, 4)
    }
    #[doc = "Bit 5 - Division factor for the main PLL (PLL) and audio PLL (PLLI2S) input clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllm5(&mut self) -> Pllm5W<PllcfgrSpec> {
        Pllm5W::new(self, 5)
    }
    #[doc = "Bit 6 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln0(&mut self) -> Plln0W<PllcfgrSpec> {
        Plln0W::new(self, 6)
    }
    #[doc = "Bit 7 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln1(&mut self) -> Plln1W<PllcfgrSpec> {
        Plln1W::new(self, 7)
    }
    #[doc = "Bit 8 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln2(&mut self) -> Plln2W<PllcfgrSpec> {
        Plln2W::new(self, 8)
    }
    #[doc = "Bit 9 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln3(&mut self) -> Plln3W<PllcfgrSpec> {
        Plln3W::new(self, 9)
    }
    #[doc = "Bit 10 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln4(&mut self) -> Plln4W<PllcfgrSpec> {
        Plln4W::new(self, 10)
    }
    #[doc = "Bit 11 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln5(&mut self) -> Plln5W<PllcfgrSpec> {
        Plln5W::new(self, 11)
    }
    #[doc = "Bit 12 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln6(&mut self) -> Plln6W<PllcfgrSpec> {
        Plln6W::new(self, 12)
    }
    #[doc = "Bit 13 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln7(&mut self) -> Plln7W<PllcfgrSpec> {
        Plln7W::new(self, 13)
    }
    #[doc = "Bit 14 - Main PLL (PLL) multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plln8(&mut self) -> Plln8W<PllcfgrSpec> {
        Plln8W::new(self, 14)
    }
    #[doc = "Bit 16 - Main PLL (PLL) division factor for main system clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllp0(&mut self) -> Pllp0W<PllcfgrSpec> {
        Pllp0W::new(self, 16)
    }
    #[doc = "Bit 17 - Main PLL (PLL) division factor for main system clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllp1(&mut self) -> Pllp1W<PllcfgrSpec> {
        Pllp1W::new(self, 17)
    }
    #[doc = "Bit 22 - Main PLL(PLL) and audio PLL (PLLI2S) entry clock source"]
    #[inline(always)]
    #[must_use]
    pub fn pllsrc(&mut self) -> PllsrcW<PllcfgrSpec> {
        PllsrcW::new(self, 22)
    }
    #[doc = "Bit 24 - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
    #[inline(always)]
    #[must_use]
    pub fn pllq0(&mut self) -> Pllq0W<PllcfgrSpec> {
        Pllq0W::new(self, 24)
    }
    #[doc = "Bit 25 - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
    #[inline(always)]
    #[must_use]
    pub fn pllq1(&mut self) -> Pllq1W<PllcfgrSpec> {
        Pllq1W::new(self, 25)
    }
    #[doc = "Bit 26 - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
    #[inline(always)]
    #[must_use]
    pub fn pllq2(&mut self) -> Pllq2W<PllcfgrSpec> {
        Pllq2W::new(self, 26)
    }
    #[doc = "Bit 27 - Main PLL (PLL) division factor for USB OTG FS, SDIO and random number generator clocks"]
    #[inline(always)]
    #[must_use]
    pub fn pllq3(&mut self) -> Pllq3W<PllcfgrSpec> {
        Pllq3W::new(self, 27)
    }
}
#[doc = "PLL configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pllcfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pllcfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PllcfgrSpec;
impl crate::RegisterSpec for PllcfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`pllcfgr::R`](R) reader structure"]
impl crate::Readable for PllcfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`pllcfgr::W`](W) writer structure"]
impl crate::Writable for PllcfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PLLCFGR to value 0x2400_3010"]
impl crate::Resettable for PllcfgrSpec {
    const RESET_VALUE: u32 = 0x2400_3010;
}
