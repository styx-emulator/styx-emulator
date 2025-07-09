// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SDTR2` reader"]
pub type R = crate::R<Sdtr2Spec>;
#[doc = "Register `SDTR2` writer"]
pub type W = crate::W<Sdtr2Spec>;
#[doc = "Field `TMRD` reader - Load Mode Register to Active"]
pub type TmrdR = crate::FieldReader;
#[doc = "Field `TMRD` writer - Load Mode Register to Active"]
pub type TmrdW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TXSR` reader - Exit self-refresh delay"]
pub type TxsrR = crate::FieldReader;
#[doc = "Field `TXSR` writer - Exit self-refresh delay"]
pub type TxsrW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TRAS` reader - Self refresh time"]
pub type TrasR = crate::FieldReader;
#[doc = "Field `TRAS` writer - Self refresh time"]
pub type TrasW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TRC` reader - Row cycle delay"]
pub type TrcR = crate::FieldReader;
#[doc = "Field `TRC` writer - Row cycle delay"]
pub type TrcW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TWR` reader - Recovery delay"]
pub type TwrR = crate::FieldReader;
#[doc = "Field `TWR` writer - Recovery delay"]
pub type TwrW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TRP` reader - Row precharge delay"]
pub type TrpR = crate::FieldReader;
#[doc = "Field `TRP` writer - Row precharge delay"]
pub type TrpW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `TRCD` reader - Row to column delay"]
pub type TrcdR = crate::FieldReader;
#[doc = "Field `TRCD` writer - Row to column delay"]
pub type TrcdW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Load Mode Register to Active"]
    #[inline(always)]
    pub fn tmrd(&self) -> TmrdR {
        TmrdR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - Exit self-refresh delay"]
    #[inline(always)]
    pub fn txsr(&self) -> TxsrR {
        TxsrR::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bits 8:11 - Self refresh time"]
    #[inline(always)]
    pub fn tras(&self) -> TrasR {
        TrasR::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bits 12:15 - Row cycle delay"]
    #[inline(always)]
    pub fn trc(&self) -> TrcR {
        TrcR::new(((self.bits >> 12) & 0x0f) as u8)
    }
    #[doc = "Bits 16:19 - Recovery delay"]
    #[inline(always)]
    pub fn twr(&self) -> TwrR {
        TwrR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:23 - Row precharge delay"]
    #[inline(always)]
    pub fn trp(&self) -> TrpR {
        TrpR::new(((self.bits >> 20) & 0x0f) as u8)
    }
    #[doc = "Bits 24:27 - Row to column delay"]
    #[inline(always)]
    pub fn trcd(&self) -> TrcdR {
        TrcdR::new(((self.bits >> 24) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Load Mode Register to Active"]
    #[inline(always)]
    #[must_use]
    pub fn tmrd(&mut self) -> TmrdW<Sdtr2Spec> {
        TmrdW::new(self, 0)
    }
    #[doc = "Bits 4:7 - Exit self-refresh delay"]
    #[inline(always)]
    #[must_use]
    pub fn txsr(&mut self) -> TxsrW<Sdtr2Spec> {
        TxsrW::new(self, 4)
    }
    #[doc = "Bits 8:11 - Self refresh time"]
    #[inline(always)]
    #[must_use]
    pub fn tras(&mut self) -> TrasW<Sdtr2Spec> {
        TrasW::new(self, 8)
    }
    #[doc = "Bits 12:15 - Row cycle delay"]
    #[inline(always)]
    #[must_use]
    pub fn trc(&mut self) -> TrcW<Sdtr2Spec> {
        TrcW::new(self, 12)
    }
    #[doc = "Bits 16:19 - Recovery delay"]
    #[inline(always)]
    #[must_use]
    pub fn twr(&mut self) -> TwrW<Sdtr2Spec> {
        TwrW::new(self, 16)
    }
    #[doc = "Bits 20:23 - Row precharge delay"]
    #[inline(always)]
    #[must_use]
    pub fn trp(&mut self) -> TrpW<Sdtr2Spec> {
        TrpW::new(self, 20)
    }
    #[doc = "Bits 24:27 - Row to column delay"]
    #[inline(always)]
    #[must_use]
    pub fn trcd(&mut self) -> TrcdW<Sdtr2Spec> {
        TrcdW::new(self, 24)
    }
}
#[doc = "SDRAM Timing register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdtr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdtr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Sdtr2Spec;
impl crate::RegisterSpec for Sdtr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 332u64;
}
#[doc = "`read()` method returns [`sdtr2::R`](R) reader structure"]
impl crate::Readable for Sdtr2Spec {}
#[doc = "`write(|w| ..)` method takes [`sdtr2::W`](W) writer structure"]
impl crate::Writable for Sdtr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SDTR2 to value 0x0fff_ffff"]
impl crate::Resettable for Sdtr2Spec {
    const RESET_VALUE: u32 = 0x0fff_ffff;
}
