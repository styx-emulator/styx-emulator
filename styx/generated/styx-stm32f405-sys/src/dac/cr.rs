// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR` reader"]
pub type R = crate::R<CrSpec>;
#[doc = "Register `CR` writer"]
pub type W = crate::W<CrSpec>;
#[doc = "Field `EN1` reader - DAC channel1 enable"]
pub type En1R = crate::BitReader;
#[doc = "Field `EN1` writer - DAC channel1 enable"]
pub type En1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BOFF1` reader - DAC channel1 output buffer disable"]
pub type Boff1R = crate::BitReader;
#[doc = "Field `BOFF1` writer - DAC channel1 output buffer disable"]
pub type Boff1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEN1` reader - DAC channel1 trigger enable"]
pub type Ten1R = crate::BitReader;
#[doc = "Field `TEN1` writer - DAC channel1 trigger enable"]
pub type Ten1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSEL1` reader - DAC channel1 trigger selection"]
pub type Tsel1R = crate::FieldReader;
#[doc = "Field `TSEL1` writer - DAC channel1 trigger selection"]
pub type Tsel1W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `WAVE1` reader - DAC channel1 noise/triangle wave generation enable"]
pub type Wave1R = crate::FieldReader;
#[doc = "Field `WAVE1` writer - DAC channel1 noise/triangle wave generation enable"]
pub type Wave1W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MAMP1` reader - DAC channel1 mask/amplitude selector"]
pub type Mamp1R = crate::FieldReader;
#[doc = "Field `MAMP1` writer - DAC channel1 mask/amplitude selector"]
pub type Mamp1W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `DMAEN1` reader - DAC channel1 DMA enable"]
pub type Dmaen1R = crate::BitReader;
#[doc = "Field `DMAEN1` writer - DAC channel1 DMA enable"]
pub type Dmaen1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMAUDRIE1` reader - DAC channel1 DMA Underrun Interrupt enable"]
pub type Dmaudrie1R = crate::BitReader;
#[doc = "Field `DMAUDRIE1` writer - DAC channel1 DMA Underrun Interrupt enable"]
pub type Dmaudrie1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EN2` reader - DAC channel2 enable"]
pub type En2R = crate::BitReader;
#[doc = "Field `EN2` writer - DAC channel2 enable"]
pub type En2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BOFF2` reader - DAC channel2 output buffer disable"]
pub type Boff2R = crate::BitReader;
#[doc = "Field `BOFF2` writer - DAC channel2 output buffer disable"]
pub type Boff2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TEN2` reader - DAC channel2 trigger enable"]
pub type Ten2R = crate::BitReader;
#[doc = "Field `TEN2` writer - DAC channel2 trigger enable"]
pub type Ten2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSEL2` reader - DAC channel2 trigger selection"]
pub type Tsel2R = crate::FieldReader;
#[doc = "Field `TSEL2` writer - DAC channel2 trigger selection"]
pub type Tsel2W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `WAVE2` reader - DAC channel2 noise/triangle wave generation enable"]
pub type Wave2R = crate::FieldReader;
#[doc = "Field `WAVE2` writer - DAC channel2 noise/triangle wave generation enable"]
pub type Wave2W<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MAMP2` reader - DAC channel2 mask/amplitude selector"]
pub type Mamp2R = crate::FieldReader;
#[doc = "Field `MAMP2` writer - DAC channel2 mask/amplitude selector"]
pub type Mamp2W<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `DMAEN2` reader - DAC channel2 DMA enable"]
pub type Dmaen2R = crate::BitReader;
#[doc = "Field `DMAEN2` writer - DAC channel2 DMA enable"]
pub type Dmaen2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMAUDRIE2` reader - DAC channel2 DMA underrun interrupt enable"]
pub type Dmaudrie2R = crate::BitReader;
#[doc = "Field `DMAUDRIE2` writer - DAC channel2 DMA underrun interrupt enable"]
pub type Dmaudrie2W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - DAC channel1 enable"]
    #[inline(always)]
    pub fn en1(&self) -> En1R {
        En1R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - DAC channel1 output buffer disable"]
    #[inline(always)]
    pub fn boff1(&self) -> Boff1R {
        Boff1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - DAC channel1 trigger enable"]
    #[inline(always)]
    pub fn ten1(&self) -> Ten1R {
        Ten1R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:5 - DAC channel1 trigger selection"]
    #[inline(always)]
    pub fn tsel1(&self) -> Tsel1R {
        Tsel1R::new(((self.bits >> 3) & 7) as u8)
    }
    #[doc = "Bits 6:7 - DAC channel1 noise/triangle wave generation enable"]
    #[inline(always)]
    pub fn wave1(&self) -> Wave1R {
        Wave1R::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bits 8:11 - DAC channel1 mask/amplitude selector"]
    #[inline(always)]
    pub fn mamp1(&self) -> Mamp1R {
        Mamp1R::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bit 12 - DAC channel1 DMA enable"]
    #[inline(always)]
    pub fn dmaen1(&self) -> Dmaen1R {
        Dmaen1R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - DAC channel1 DMA Underrun Interrupt enable"]
    #[inline(always)]
    pub fn dmaudrie1(&self) -> Dmaudrie1R {
        Dmaudrie1R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 16 - DAC channel2 enable"]
    #[inline(always)]
    pub fn en2(&self) -> En2R {
        En2R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - DAC channel2 output buffer disable"]
    #[inline(always)]
    pub fn boff2(&self) -> Boff2R {
        Boff2R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - DAC channel2 trigger enable"]
    #[inline(always)]
    pub fn ten2(&self) -> Ten2R {
        Ten2R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bits 19:21 - DAC channel2 trigger selection"]
    #[inline(always)]
    pub fn tsel2(&self) -> Tsel2R {
        Tsel2R::new(((self.bits >> 19) & 7) as u8)
    }
    #[doc = "Bits 22:23 - DAC channel2 noise/triangle wave generation enable"]
    #[inline(always)]
    pub fn wave2(&self) -> Wave2R {
        Wave2R::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bits 24:27 - DAC channel2 mask/amplitude selector"]
    #[inline(always)]
    pub fn mamp2(&self) -> Mamp2R {
        Mamp2R::new(((self.bits >> 24) & 0x0f) as u8)
    }
    #[doc = "Bit 28 - DAC channel2 DMA enable"]
    #[inline(always)]
    pub fn dmaen2(&self) -> Dmaen2R {
        Dmaen2R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - DAC channel2 DMA underrun interrupt enable"]
    #[inline(always)]
    pub fn dmaudrie2(&self) -> Dmaudrie2R {
        Dmaudrie2R::new(((self.bits >> 29) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - DAC channel1 enable"]
    #[inline(always)]
    #[must_use]
    pub fn en1(&mut self) -> En1W<CrSpec> {
        En1W::new(self, 0)
    }
    #[doc = "Bit 1 - DAC channel1 output buffer disable"]
    #[inline(always)]
    #[must_use]
    pub fn boff1(&mut self) -> Boff1W<CrSpec> {
        Boff1W::new(self, 1)
    }
    #[doc = "Bit 2 - DAC channel1 trigger enable"]
    #[inline(always)]
    #[must_use]
    pub fn ten1(&mut self) -> Ten1W<CrSpec> {
        Ten1W::new(self, 2)
    }
    #[doc = "Bits 3:5 - DAC channel1 trigger selection"]
    #[inline(always)]
    #[must_use]
    pub fn tsel1(&mut self) -> Tsel1W<CrSpec> {
        Tsel1W::new(self, 3)
    }
    #[doc = "Bits 6:7 - DAC channel1 noise/triangle wave generation enable"]
    #[inline(always)]
    #[must_use]
    pub fn wave1(&mut self) -> Wave1W<CrSpec> {
        Wave1W::new(self, 6)
    }
    #[doc = "Bits 8:11 - DAC channel1 mask/amplitude selector"]
    #[inline(always)]
    #[must_use]
    pub fn mamp1(&mut self) -> Mamp1W<CrSpec> {
        Mamp1W::new(self, 8)
    }
    #[doc = "Bit 12 - DAC channel1 DMA enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmaen1(&mut self) -> Dmaen1W<CrSpec> {
        Dmaen1W::new(self, 12)
    }
    #[doc = "Bit 13 - DAC channel1 DMA Underrun Interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmaudrie1(&mut self) -> Dmaudrie1W<CrSpec> {
        Dmaudrie1W::new(self, 13)
    }
    #[doc = "Bit 16 - DAC channel2 enable"]
    #[inline(always)]
    #[must_use]
    pub fn en2(&mut self) -> En2W<CrSpec> {
        En2W::new(self, 16)
    }
    #[doc = "Bit 17 - DAC channel2 output buffer disable"]
    #[inline(always)]
    #[must_use]
    pub fn boff2(&mut self) -> Boff2W<CrSpec> {
        Boff2W::new(self, 17)
    }
    #[doc = "Bit 18 - DAC channel2 trigger enable"]
    #[inline(always)]
    #[must_use]
    pub fn ten2(&mut self) -> Ten2W<CrSpec> {
        Ten2W::new(self, 18)
    }
    #[doc = "Bits 19:21 - DAC channel2 trigger selection"]
    #[inline(always)]
    #[must_use]
    pub fn tsel2(&mut self) -> Tsel2W<CrSpec> {
        Tsel2W::new(self, 19)
    }
    #[doc = "Bits 22:23 - DAC channel2 noise/triangle wave generation enable"]
    #[inline(always)]
    #[must_use]
    pub fn wave2(&mut self) -> Wave2W<CrSpec> {
        Wave2W::new(self, 22)
    }
    #[doc = "Bits 24:27 - DAC channel2 mask/amplitude selector"]
    #[inline(always)]
    #[must_use]
    pub fn mamp2(&mut self) -> Mamp2W<CrSpec> {
        Mamp2W::new(self, 24)
    }
    #[doc = "Bit 28 - DAC channel2 DMA enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmaen2(&mut self) -> Dmaen2W<CrSpec> {
        Dmaen2W::new(self, 28)
    }
    #[doc = "Bit 29 - DAC channel2 DMA underrun interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmaudrie2(&mut self) -> Dmaudrie2W<CrSpec> {
        Dmaudrie2W::new(self, 29)
    }
}
#[doc = "control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CrSpec;
impl crate::RegisterSpec for CrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr::R`](R) reader structure"]
impl crate::Readable for CrSpec {}
#[doc = "`write(|w| ..)` method takes [`cr::W`](W) writer structure"]
impl crate::Writable for CrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR to value 0"]
impl crate::Resettable for CrSpec {
    const RESET_VALUE: u32 = 0;
}
