// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DIER` reader"]
pub type R = crate::R<DierSpec>;
#[doc = "Register `DIER` writer"]
pub type W = crate::W<DierSpec>;
#[doc = "Field `UIE` reader - Update interrupt enable"]
pub type UieR = crate::BitReader;
#[doc = "Field `UIE` writer - Update interrupt enable"]
pub type UieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CC1IE` reader - Capture/Compare 1 interrupt enable"]
pub type Cc1ieR = crate::BitReader;
#[doc = "Field `CC1IE` writer - Capture/Compare 1 interrupt enable"]
pub type Cc1ieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CC2IE` reader - Capture/Compare 2 interrupt enable"]
pub type Cc2ieR = crate::BitReader;
#[doc = "Field `CC2IE` writer - Capture/Compare 2 interrupt enable"]
pub type Cc2ieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CC3IE` reader - Capture/Compare 3 interrupt enable"]
pub type Cc3ieR = crate::BitReader;
#[doc = "Field `CC3IE` writer - Capture/Compare 3 interrupt enable"]
pub type Cc3ieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CC4IE` reader - Capture/Compare 4 interrupt enable"]
pub type Cc4ieR = crate::BitReader;
#[doc = "Field `CC4IE` writer - Capture/Compare 4 interrupt enable"]
pub type Cc4ieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `COMIE` reader - COM interrupt enable"]
pub type ComieR = crate::BitReader;
#[doc = "Field `COMIE` writer - COM interrupt enable"]
pub type ComieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIE` reader - Trigger interrupt enable"]
pub type TieR = crate::BitReader;
#[doc = "Field `TIE` writer - Trigger interrupt enable"]
pub type TieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BIE` reader - Break interrupt enable"]
pub type BieR = crate::BitReader;
#[doc = "Field `BIE` writer - Break interrupt enable"]
pub type BieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UDE` reader - Update DMA request enable"]
pub type UdeR = crate::BitReader;
#[doc = "Field `UDE` writer - Update DMA request enable"]
pub type UdeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CC1DE` reader - Capture/Compare 1 DMA request enable"]
pub type Cc1deR = crate::BitReader;
#[doc = "Field `CC1DE` writer - Capture/Compare 1 DMA request enable"]
pub type Cc1deW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CC2DE` reader - Capture/Compare 2 DMA request enable"]
pub type Cc2deR = crate::BitReader;
#[doc = "Field `CC2DE` writer - Capture/Compare 2 DMA request enable"]
pub type Cc2deW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CC3DE` reader - Capture/Compare 3 DMA request enable"]
pub type Cc3deR = crate::BitReader;
#[doc = "Field `CC3DE` writer - Capture/Compare 3 DMA request enable"]
pub type Cc3deW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CC4DE` reader - Capture/Compare 4 DMA request enable"]
pub type Cc4deR = crate::BitReader;
#[doc = "Field `CC4DE` writer - Capture/Compare 4 DMA request enable"]
pub type Cc4deW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `COMDE` reader - COM DMA request enable"]
pub type ComdeR = crate::BitReader;
#[doc = "Field `COMDE` writer - COM DMA request enable"]
pub type ComdeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TDE` reader - Trigger DMA request enable"]
pub type TdeR = crate::BitReader;
#[doc = "Field `TDE` writer - Trigger DMA request enable"]
pub type TdeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Update interrupt enable"]
    #[inline(always)]
    pub fn uie(&self) -> UieR {
        UieR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Capture/Compare 1 interrupt enable"]
    #[inline(always)]
    pub fn cc1ie(&self) -> Cc1ieR {
        Cc1ieR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Capture/Compare 2 interrupt enable"]
    #[inline(always)]
    pub fn cc2ie(&self) -> Cc2ieR {
        Cc2ieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Capture/Compare 3 interrupt enable"]
    #[inline(always)]
    pub fn cc3ie(&self) -> Cc3ieR {
        Cc3ieR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Capture/Compare 4 interrupt enable"]
    #[inline(always)]
    pub fn cc4ie(&self) -> Cc4ieR {
        Cc4ieR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - COM interrupt enable"]
    #[inline(always)]
    pub fn comie(&self) -> ComieR {
        ComieR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Trigger interrupt enable"]
    #[inline(always)]
    pub fn tie(&self) -> TieR {
        TieR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Break interrupt enable"]
    #[inline(always)]
    pub fn bie(&self) -> BieR {
        BieR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Update DMA request enable"]
    #[inline(always)]
    pub fn ude(&self) -> UdeR {
        UdeR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Capture/Compare 1 DMA request enable"]
    #[inline(always)]
    pub fn cc1de(&self) -> Cc1deR {
        Cc1deR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Capture/Compare 2 DMA request enable"]
    #[inline(always)]
    pub fn cc2de(&self) -> Cc2deR {
        Cc2deR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Capture/Compare 3 DMA request enable"]
    #[inline(always)]
    pub fn cc3de(&self) -> Cc3deR {
        Cc3deR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Capture/Compare 4 DMA request enable"]
    #[inline(always)]
    pub fn cc4de(&self) -> Cc4deR {
        Cc4deR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - COM DMA request enable"]
    #[inline(always)]
    pub fn comde(&self) -> ComdeR {
        ComdeR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Trigger DMA request enable"]
    #[inline(always)]
    pub fn tde(&self) -> TdeR {
        TdeR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Update interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn uie(&mut self) -> UieW<DierSpec> {
        UieW::new(self, 0)
    }
    #[doc = "Bit 1 - Capture/Compare 1 interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn cc1ie(&mut self) -> Cc1ieW<DierSpec> {
        Cc1ieW::new(self, 1)
    }
    #[doc = "Bit 2 - Capture/Compare 2 interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn cc2ie(&mut self) -> Cc2ieW<DierSpec> {
        Cc2ieW::new(self, 2)
    }
    #[doc = "Bit 3 - Capture/Compare 3 interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn cc3ie(&mut self) -> Cc3ieW<DierSpec> {
        Cc3ieW::new(self, 3)
    }
    #[doc = "Bit 4 - Capture/Compare 4 interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn cc4ie(&mut self) -> Cc4ieW<DierSpec> {
        Cc4ieW::new(self, 4)
    }
    #[doc = "Bit 5 - COM interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn comie(&mut self) -> ComieW<DierSpec> {
        ComieW::new(self, 5)
    }
    #[doc = "Bit 6 - Trigger interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tie(&mut self) -> TieW<DierSpec> {
        TieW::new(self, 6)
    }
    #[doc = "Bit 7 - Break interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn bie(&mut self) -> BieW<DierSpec> {
        BieW::new(self, 7)
    }
    #[doc = "Bit 8 - Update DMA request enable"]
    #[inline(always)]
    #[must_use]
    pub fn ude(&mut self) -> UdeW<DierSpec> {
        UdeW::new(self, 8)
    }
    #[doc = "Bit 9 - Capture/Compare 1 DMA request enable"]
    #[inline(always)]
    #[must_use]
    pub fn cc1de(&mut self) -> Cc1deW<DierSpec> {
        Cc1deW::new(self, 9)
    }
    #[doc = "Bit 10 - Capture/Compare 2 DMA request enable"]
    #[inline(always)]
    #[must_use]
    pub fn cc2de(&mut self) -> Cc2deW<DierSpec> {
        Cc2deW::new(self, 10)
    }
    #[doc = "Bit 11 - Capture/Compare 3 DMA request enable"]
    #[inline(always)]
    #[must_use]
    pub fn cc3de(&mut self) -> Cc3deW<DierSpec> {
        Cc3deW::new(self, 11)
    }
    #[doc = "Bit 12 - Capture/Compare 4 DMA request enable"]
    #[inline(always)]
    #[must_use]
    pub fn cc4de(&mut self) -> Cc4deW<DierSpec> {
        Cc4deW::new(self, 12)
    }
    #[doc = "Bit 13 - COM DMA request enable"]
    #[inline(always)]
    #[must_use]
    pub fn comde(&mut self) -> ComdeW<DierSpec> {
        ComdeW::new(self, 13)
    }
    #[doc = "Bit 14 - Trigger DMA request enable"]
    #[inline(always)]
    #[must_use]
    pub fn tde(&mut self) -> TdeW<DierSpec> {
        TdeW::new(self, 14)
    }
}
#[doc = "DMA/Interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dier::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dier::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DierSpec;
impl crate::RegisterSpec for DierSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`dier::R`](R) reader structure"]
impl crate::Readable for DierSpec {}
#[doc = "`write(|w| ..)` method takes [`dier::W`](W) writer structure"]
impl crate::Writable for DierSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DIER to value 0"]
impl crate::Resettable for DierSpec {
    const RESET_VALUE: u32 = 0;
}
