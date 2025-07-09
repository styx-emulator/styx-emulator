// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CFGR` reader"]
pub type R = crate::R<CfgrSpec>;
#[doc = "Register `CFGR` writer"]
pub type W = crate::W<CfgrSpec>;
#[doc = "Field `CKSEL` reader - Clock selector"]
pub type CkselR = crate::BitReader;
#[doc = "Field `CKSEL` writer - Clock selector"]
pub type CkselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CKPOL` reader - Clock Polarity"]
pub type CkpolR = crate::FieldReader;
#[doc = "Field `CKPOL` writer - Clock Polarity"]
pub type CkpolW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `CKFLT` reader - Configurable digital filter for external clock"]
pub type CkfltR = crate::FieldReader;
#[doc = "Field `CKFLT` writer - Configurable digital filter for external clock"]
pub type CkfltW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TRGFLT` reader - Configurable digital filter for trigger"]
pub type TrgfltR = crate::FieldReader;
#[doc = "Field `TRGFLT` writer - Configurable digital filter for trigger"]
pub type TrgfltW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PRESC` reader - Clock prescaler"]
pub type PrescR = crate::FieldReader;
#[doc = "Field `PRESC` writer - Clock prescaler"]
pub type PrescW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `TRIGSEL` reader - Trigger selector"]
pub type TrigselR = crate::FieldReader;
#[doc = "Field `TRIGSEL` writer - Trigger selector"]
pub type TrigselW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `TRIGEN` reader - Trigger enable and polarity"]
pub type TrigenR = crate::FieldReader;
#[doc = "Field `TRIGEN` writer - Trigger enable and polarity"]
pub type TrigenW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TIMOUT` reader - Timeout enable"]
pub type TimoutR = crate::BitReader;
#[doc = "Field `TIMOUT` writer - Timeout enable"]
pub type TimoutW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WAVE` reader - Waveform shape"]
pub type WaveR = crate::BitReader;
#[doc = "Field `WAVE` writer - Waveform shape"]
pub type WaveW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WAVPOL` reader - Waveform shape polarity"]
pub type WavpolR = crate::BitReader;
#[doc = "Field `WAVPOL` writer - Waveform shape polarity"]
pub type WavpolW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PRELOAD` reader - Registers update mode"]
pub type PreloadR = crate::BitReader;
#[doc = "Field `PRELOAD` writer - Registers update mode"]
pub type PreloadW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `COUNTMODE` reader - counter mode enabled"]
pub type CountmodeR = crate::BitReader;
#[doc = "Field `COUNTMODE` writer - counter mode enabled"]
pub type CountmodeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ENC` reader - Encoder mode enable"]
pub type EncR = crate::BitReader;
#[doc = "Field `ENC` writer - Encoder mode enable"]
pub type EncW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clock selector"]
    #[inline(always)]
    pub fn cksel(&self) -> CkselR {
        CkselR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - Clock Polarity"]
    #[inline(always)]
    pub fn ckpol(&self) -> CkpolR {
        CkpolR::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bits 3:4 - Configurable digital filter for external clock"]
    #[inline(always)]
    pub fn ckflt(&self) -> CkfltR {
        CkfltR::new(((self.bits >> 3) & 3) as u8)
    }
    #[doc = "Bits 6:7 - Configurable digital filter for trigger"]
    #[inline(always)]
    pub fn trgflt(&self) -> TrgfltR {
        TrgfltR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bits 9:11 - Clock prescaler"]
    #[inline(always)]
    pub fn presc(&self) -> PrescR {
        PrescR::new(((self.bits >> 9) & 7) as u8)
    }
    #[doc = "Bits 13:15 - Trigger selector"]
    #[inline(always)]
    pub fn trigsel(&self) -> TrigselR {
        TrigselR::new(((self.bits >> 13) & 7) as u8)
    }
    #[doc = "Bits 17:18 - Trigger enable and polarity"]
    #[inline(always)]
    pub fn trigen(&self) -> TrigenR {
        TrigenR::new(((self.bits >> 17) & 3) as u8)
    }
    #[doc = "Bit 19 - Timeout enable"]
    #[inline(always)]
    pub fn timout(&self) -> TimoutR {
        TimoutR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Waveform shape"]
    #[inline(always)]
    pub fn wave(&self) -> WaveR {
        WaveR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Waveform shape polarity"]
    #[inline(always)]
    pub fn wavpol(&self) -> WavpolR {
        WavpolR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Registers update mode"]
    #[inline(always)]
    pub fn preload(&self) -> PreloadR {
        PreloadR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - counter mode enabled"]
    #[inline(always)]
    pub fn countmode(&self) -> CountmodeR {
        CountmodeR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Encoder mode enable"]
    #[inline(always)]
    pub fn enc(&self) -> EncR {
        EncR::new(((self.bits >> 24) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clock selector"]
    #[inline(always)]
    #[must_use]
    pub fn cksel(&mut self) -> CkselW<CfgrSpec> {
        CkselW::new(self, 0)
    }
    #[doc = "Bits 1:2 - Clock Polarity"]
    #[inline(always)]
    #[must_use]
    pub fn ckpol(&mut self) -> CkpolW<CfgrSpec> {
        CkpolW::new(self, 1)
    }
    #[doc = "Bits 3:4 - Configurable digital filter for external clock"]
    #[inline(always)]
    #[must_use]
    pub fn ckflt(&mut self) -> CkfltW<CfgrSpec> {
        CkfltW::new(self, 3)
    }
    #[doc = "Bits 6:7 - Configurable digital filter for trigger"]
    #[inline(always)]
    #[must_use]
    pub fn trgflt(&mut self) -> TrgfltW<CfgrSpec> {
        TrgfltW::new(self, 6)
    }
    #[doc = "Bits 9:11 - Clock prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn presc(&mut self) -> PrescW<CfgrSpec> {
        PrescW::new(self, 9)
    }
    #[doc = "Bits 13:15 - Trigger selector"]
    #[inline(always)]
    #[must_use]
    pub fn trigsel(&mut self) -> TrigselW<CfgrSpec> {
        TrigselW::new(self, 13)
    }
    #[doc = "Bits 17:18 - Trigger enable and polarity"]
    #[inline(always)]
    #[must_use]
    pub fn trigen(&mut self) -> TrigenW<CfgrSpec> {
        TrigenW::new(self, 17)
    }
    #[doc = "Bit 19 - Timeout enable"]
    #[inline(always)]
    #[must_use]
    pub fn timout(&mut self) -> TimoutW<CfgrSpec> {
        TimoutW::new(self, 19)
    }
    #[doc = "Bit 20 - Waveform shape"]
    #[inline(always)]
    #[must_use]
    pub fn wave(&mut self) -> WaveW<CfgrSpec> {
        WaveW::new(self, 20)
    }
    #[doc = "Bit 21 - Waveform shape polarity"]
    #[inline(always)]
    #[must_use]
    pub fn wavpol(&mut self) -> WavpolW<CfgrSpec> {
        WavpolW::new(self, 21)
    }
    #[doc = "Bit 22 - Registers update mode"]
    #[inline(always)]
    #[must_use]
    pub fn preload(&mut self) -> PreloadW<CfgrSpec> {
        PreloadW::new(self, 22)
    }
    #[doc = "Bit 23 - counter mode enabled"]
    #[inline(always)]
    #[must_use]
    pub fn countmode(&mut self) -> CountmodeW<CfgrSpec> {
        CountmodeW::new(self, 23)
    }
    #[doc = "Bit 24 - Encoder mode enable"]
    #[inline(always)]
    #[must_use]
    pub fn enc(&mut self) -> EncW<CfgrSpec> {
        EncW::new(self, 24)
    }
}
#[doc = "Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CfgrSpec;
impl crate::RegisterSpec for CfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`cfgr::R`](R) reader structure"]
impl crate::Readable for CfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`cfgr::W`](W) writer structure"]
impl crate::Writable for CfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CFGR to value 0"]
impl crate::Resettable for CfgrSpec {
    const RESET_VALUE: u32 = 0;
}
