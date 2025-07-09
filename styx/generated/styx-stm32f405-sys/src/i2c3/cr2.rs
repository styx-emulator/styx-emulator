// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR2` reader"]
pub type R = crate::R<Cr2Spec>;
#[doc = "Register `CR2` writer"]
pub type W = crate::W<Cr2Spec>;
#[doc = "Field `FREQ` reader - Peripheral clock frequency"]
pub type FreqR = crate::FieldReader;
#[doc = "Field `FREQ` writer - Peripheral clock frequency"]
pub type FreqW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `ITERREN` reader - Error interrupt enable"]
pub type IterrenR = crate::BitReader;
#[doc = "Field `ITERREN` writer - Error interrupt enable"]
pub type IterrenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ITEVTEN` reader - Event interrupt enable"]
pub type ItevtenR = crate::BitReader;
#[doc = "Field `ITEVTEN` writer - Event interrupt enable"]
pub type ItevtenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ITBUFEN` reader - Buffer interrupt enable"]
pub type ItbufenR = crate::BitReader;
#[doc = "Field `ITBUFEN` writer - Buffer interrupt enable"]
pub type ItbufenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMAEN` reader - DMA requests enable"]
pub type DmaenR = crate::BitReader;
#[doc = "Field `DMAEN` writer - DMA requests enable"]
pub type DmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LAST` reader - DMA last transfer"]
pub type LastR = crate::BitReader;
#[doc = "Field `LAST` writer - DMA last transfer"]
pub type LastW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:5 - Peripheral clock frequency"]
    #[inline(always)]
    pub fn freq(&self) -> FreqR {
        FreqR::new((self.bits & 0x3f) as u8)
    }
    #[doc = "Bit 8 - Error interrupt enable"]
    #[inline(always)]
    pub fn iterren(&self) -> IterrenR {
        IterrenR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Event interrupt enable"]
    #[inline(always)]
    pub fn itevten(&self) -> ItevtenR {
        ItevtenR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Buffer interrupt enable"]
    #[inline(always)]
    pub fn itbufen(&self) -> ItbufenR {
        ItbufenR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - DMA requests enable"]
    #[inline(always)]
    pub fn dmaen(&self) -> DmaenR {
        DmaenR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - DMA last transfer"]
    #[inline(always)]
    pub fn last(&self) -> LastR {
        LastR::new(((self.bits >> 12) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:5 - Peripheral clock frequency"]
    #[inline(always)]
    #[must_use]
    pub fn freq(&mut self) -> FreqW<Cr2Spec> {
        FreqW::new(self, 0)
    }
    #[doc = "Bit 8 - Error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn iterren(&mut self) -> IterrenW<Cr2Spec> {
        IterrenW::new(self, 8)
    }
    #[doc = "Bit 9 - Event interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn itevten(&mut self) -> ItevtenW<Cr2Spec> {
        ItevtenW::new(self, 9)
    }
    #[doc = "Bit 10 - Buffer interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn itbufen(&mut self) -> ItbufenW<Cr2Spec> {
        ItbufenW::new(self, 10)
    }
    #[doc = "Bit 11 - DMA requests enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmaen(&mut self) -> DmaenW<Cr2Spec> {
        DmaenW::new(self, 11)
    }
    #[doc = "Bit 12 - DMA last transfer"]
    #[inline(always)]
    #[must_use]
    pub fn last(&mut self) -> LastW<Cr2Spec> {
        LastW::new(self, 12)
    }
}
#[doc = "Control register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr2Spec;
impl crate::RegisterSpec for Cr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`cr2::R`](R) reader structure"]
impl crate::Readable for Cr2Spec {}
#[doc = "`write(|w| ..)` method takes [`cr2::W`](W) writer structure"]
impl crate::Writable for Cr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR2 to value 0"]
impl crate::Resettable for Cr2Spec {
    const RESET_VALUE: u32 = 0;
}
