// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR1` reader"]
pub type R = crate::R<Cr1Spec>;
#[doc = "Register `CR1` writer"]
pub type W = crate::W<Cr1Spec>;
#[doc = "Field `AWDCH` reader - Analog watchdog channel select bits"]
pub type AwdchR = crate::FieldReader;
#[doc = "Field `AWDCH` writer - Analog watchdog channel select bits"]
pub type AwdchW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `EOCIE` reader - Interrupt enable for EOC"]
pub type EocieR = crate::BitReader;
#[doc = "Field `EOCIE` writer - Interrupt enable for EOC"]
pub type EocieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AWDIE` reader - Analog watchdog interrupt enable"]
pub type AwdieR = crate::BitReader;
#[doc = "Field `AWDIE` writer - Analog watchdog interrupt enable"]
pub type AwdieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JEOCIE` reader - Interrupt enable for injected channels"]
pub type JeocieR = crate::BitReader;
#[doc = "Field `JEOCIE` writer - Interrupt enable for injected channels"]
pub type JeocieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SCAN` reader - Scan mode"]
pub type ScanR = crate::BitReader;
#[doc = "Field `SCAN` writer - Scan mode"]
pub type ScanW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AWDSGL` reader - Enable the watchdog on a single channel in scan mode"]
pub type AwdsglR = crate::BitReader;
#[doc = "Field `AWDSGL` writer - Enable the watchdog on a single channel in scan mode"]
pub type AwdsglW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JAUTO` reader - Automatic injected group conversion"]
pub type JautoR = crate::BitReader;
#[doc = "Field `JAUTO` writer - Automatic injected group conversion"]
pub type JautoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISCEN` reader - Discontinuous mode on regular channels"]
pub type DiscenR = crate::BitReader;
#[doc = "Field `DISCEN` writer - Discontinuous mode on regular channels"]
pub type DiscenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JDISCEN` reader - Discontinuous mode on injected channels"]
pub type JdiscenR = crate::BitReader;
#[doc = "Field `JDISCEN` writer - Discontinuous mode on injected channels"]
pub type JdiscenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISCNUM` reader - Discontinuous mode channel count"]
pub type DiscnumR = crate::FieldReader;
#[doc = "Field `DISCNUM` writer - Discontinuous mode channel count"]
pub type DiscnumW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `JAWDEN` reader - Analog watchdog enable on injected channels"]
pub type JawdenR = crate::BitReader;
#[doc = "Field `JAWDEN` writer - Analog watchdog enable on injected channels"]
pub type JawdenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AWDEN` reader - Analog watchdog enable on regular channels"]
pub type AwdenR = crate::BitReader;
#[doc = "Field `AWDEN` writer - Analog watchdog enable on regular channels"]
pub type AwdenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RES` reader - Resolution"]
pub type ResR = crate::FieldReader;
#[doc = "Field `RES` writer - Resolution"]
pub type ResW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OVRIE` reader - Overrun interrupt enable"]
pub type OvrieR = crate::BitReader;
#[doc = "Field `OVRIE` writer - Overrun interrupt enable"]
pub type OvrieW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:4 - Analog watchdog channel select bits"]
    #[inline(always)]
    pub fn awdch(&self) -> AwdchR {
        AwdchR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bit 5 - Interrupt enable for EOC"]
    #[inline(always)]
    pub fn eocie(&self) -> EocieR {
        EocieR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Analog watchdog interrupt enable"]
    #[inline(always)]
    pub fn awdie(&self) -> AwdieR {
        AwdieR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Interrupt enable for injected channels"]
    #[inline(always)]
    pub fn jeocie(&self) -> JeocieR {
        JeocieR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Scan mode"]
    #[inline(always)]
    pub fn scan(&self) -> ScanR {
        ScanR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Enable the watchdog on a single channel in scan mode"]
    #[inline(always)]
    pub fn awdsgl(&self) -> AwdsglR {
        AwdsglR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Automatic injected group conversion"]
    #[inline(always)]
    pub fn jauto(&self) -> JautoR {
        JautoR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Discontinuous mode on regular channels"]
    #[inline(always)]
    pub fn discen(&self) -> DiscenR {
        DiscenR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Discontinuous mode on injected channels"]
    #[inline(always)]
    pub fn jdiscen(&self) -> JdiscenR {
        JdiscenR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bits 13:15 - Discontinuous mode channel count"]
    #[inline(always)]
    pub fn discnum(&self) -> DiscnumR {
        DiscnumR::new(((self.bits >> 13) & 7) as u8)
    }
    #[doc = "Bit 22 - Analog watchdog enable on injected channels"]
    #[inline(always)]
    pub fn jawden(&self) -> JawdenR {
        JawdenR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Analog watchdog enable on regular channels"]
    #[inline(always)]
    pub fn awden(&self) -> AwdenR {
        AwdenR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bits 24:25 - Resolution"]
    #[inline(always)]
    pub fn res(&self) -> ResR {
        ResR::new(((self.bits >> 24) & 3) as u8)
    }
    #[doc = "Bit 26 - Overrun interrupt enable"]
    #[inline(always)]
    pub fn ovrie(&self) -> OvrieR {
        OvrieR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:4 - Analog watchdog channel select bits"]
    #[inline(always)]
    #[must_use]
    pub fn awdch(&mut self) -> AwdchW<Cr1Spec> {
        AwdchW::new(self, 0)
    }
    #[doc = "Bit 5 - Interrupt enable for EOC"]
    #[inline(always)]
    #[must_use]
    pub fn eocie(&mut self) -> EocieW<Cr1Spec> {
        EocieW::new(self, 5)
    }
    #[doc = "Bit 6 - Analog watchdog interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn awdie(&mut self) -> AwdieW<Cr1Spec> {
        AwdieW::new(self, 6)
    }
    #[doc = "Bit 7 - Interrupt enable for injected channels"]
    #[inline(always)]
    #[must_use]
    pub fn jeocie(&mut self) -> JeocieW<Cr1Spec> {
        JeocieW::new(self, 7)
    }
    #[doc = "Bit 8 - Scan mode"]
    #[inline(always)]
    #[must_use]
    pub fn scan(&mut self) -> ScanW<Cr1Spec> {
        ScanW::new(self, 8)
    }
    #[doc = "Bit 9 - Enable the watchdog on a single channel in scan mode"]
    #[inline(always)]
    #[must_use]
    pub fn awdsgl(&mut self) -> AwdsglW<Cr1Spec> {
        AwdsglW::new(self, 9)
    }
    #[doc = "Bit 10 - Automatic injected group conversion"]
    #[inline(always)]
    #[must_use]
    pub fn jauto(&mut self) -> JautoW<Cr1Spec> {
        JautoW::new(self, 10)
    }
    #[doc = "Bit 11 - Discontinuous mode on regular channels"]
    #[inline(always)]
    #[must_use]
    pub fn discen(&mut self) -> DiscenW<Cr1Spec> {
        DiscenW::new(self, 11)
    }
    #[doc = "Bit 12 - Discontinuous mode on injected channels"]
    #[inline(always)]
    #[must_use]
    pub fn jdiscen(&mut self) -> JdiscenW<Cr1Spec> {
        JdiscenW::new(self, 12)
    }
    #[doc = "Bits 13:15 - Discontinuous mode channel count"]
    #[inline(always)]
    #[must_use]
    pub fn discnum(&mut self) -> DiscnumW<Cr1Spec> {
        DiscnumW::new(self, 13)
    }
    #[doc = "Bit 22 - Analog watchdog enable on injected channels"]
    #[inline(always)]
    #[must_use]
    pub fn jawden(&mut self) -> JawdenW<Cr1Spec> {
        JawdenW::new(self, 22)
    }
    #[doc = "Bit 23 - Analog watchdog enable on regular channels"]
    #[inline(always)]
    #[must_use]
    pub fn awden(&mut self) -> AwdenW<Cr1Spec> {
        AwdenW::new(self, 23)
    }
    #[doc = "Bits 24:25 - Resolution"]
    #[inline(always)]
    #[must_use]
    pub fn res(&mut self) -> ResW<Cr1Spec> {
        ResW::new(self, 24)
    }
    #[doc = "Bit 26 - Overrun interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn ovrie(&mut self) -> OvrieW<Cr1Spec> {
        OvrieW::new(self, 26)
    }
}
#[doc = "control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr1Spec;
impl crate::RegisterSpec for Cr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`cr1::R`](R) reader structure"]
impl crate::Readable for Cr1Spec {}
#[doc = "`write(|w| ..)` method takes [`cr1::W`](W) writer structure"]
impl crate::Writable for Cr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR1 to value 0"]
impl crate::Resettable for Cr1Spec {
    const RESET_VALUE: u32 = 0;
}
