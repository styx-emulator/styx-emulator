// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TIMEOUTR` reader"]
pub type R = crate::R<TimeoutrSpec>;
#[doc = "Register `TIMEOUTR` writer"]
pub type W = crate::W<TimeoutrSpec>;
#[doc = "Field `TIMEOUTA` reader - Bus timeout A"]
pub type TimeoutaR = crate::FieldReader<u16>;
#[doc = "Field `TIMEOUTA` writer - Bus timeout A"]
pub type TimeoutaW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `TIDLE` reader - Idle clock timeout detection"]
pub type TidleR = crate::BitReader;
#[doc = "Field `TIDLE` writer - Idle clock timeout detection"]
pub type TidleW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIMOUTEN` reader - Clock timeout enable"]
pub type TimoutenR = crate::BitReader;
#[doc = "Field `TIMOUTEN` writer - Clock timeout enable"]
pub type TimoutenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIMEOUTB` reader - Bus timeout B"]
pub type TimeoutbR = crate::FieldReader<u16>;
#[doc = "Field `TIMEOUTB` writer - Bus timeout B"]
pub type TimeoutbW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `TEXTEN` reader - Extended clock timeout enable"]
pub type TextenR = crate::BitReader;
#[doc = "Field `TEXTEN` writer - Extended clock timeout enable"]
pub type TextenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:11 - Bus timeout A"]
    #[inline(always)]
    pub fn timeouta(&self) -> TimeoutaR {
        TimeoutaR::new((self.bits & 0x0fff) as u16)
    }
    #[doc = "Bit 12 - Idle clock timeout detection"]
    #[inline(always)]
    pub fn tidle(&self) -> TidleR {
        TidleR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 15 - Clock timeout enable"]
    #[inline(always)]
    pub fn timouten(&self) -> TimoutenR {
        TimoutenR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bits 16:27 - Bus timeout B"]
    #[inline(always)]
    pub fn timeoutb(&self) -> TimeoutbR {
        TimeoutbR::new(((self.bits >> 16) & 0x0fff) as u16)
    }
    #[doc = "Bit 31 - Extended clock timeout enable"]
    #[inline(always)]
    pub fn texten(&self) -> TextenR {
        TextenR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:11 - Bus timeout A"]
    #[inline(always)]
    #[must_use]
    pub fn timeouta(&mut self) -> TimeoutaW<TimeoutrSpec> {
        TimeoutaW::new(self, 0)
    }
    #[doc = "Bit 12 - Idle clock timeout detection"]
    #[inline(always)]
    #[must_use]
    pub fn tidle(&mut self) -> TidleW<TimeoutrSpec> {
        TidleW::new(self, 12)
    }
    #[doc = "Bit 15 - Clock timeout enable"]
    #[inline(always)]
    #[must_use]
    pub fn timouten(&mut self) -> TimoutenW<TimeoutrSpec> {
        TimoutenW::new(self, 15)
    }
    #[doc = "Bits 16:27 - Bus timeout B"]
    #[inline(always)]
    #[must_use]
    pub fn timeoutb(&mut self) -> TimeoutbW<TimeoutrSpec> {
        TimeoutbW::new(self, 16)
    }
    #[doc = "Bit 31 - Extended clock timeout enable"]
    #[inline(always)]
    #[must_use]
    pub fn texten(&mut self) -> TextenW<TimeoutrSpec> {
        TextenW::new(self, 31)
    }
}
#[doc = "Status register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timeoutr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`timeoutr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TimeoutrSpec;
impl crate::RegisterSpec for TimeoutrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`timeoutr::R`](R) reader structure"]
impl crate::Readable for TimeoutrSpec {}
#[doc = "`write(|w| ..)` method takes [`timeoutr::W`](W) writer structure"]
impl crate::Writable for TimeoutrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets TIMEOUTR to value 0"]
impl crate::Resettable for TimeoutrSpec {
    const RESET_VALUE: u32 = 0;
}
