// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ASR` reader"]
pub type R = crate::R<AsrSpec>;
#[doc = "Register `ASR` writer"]
pub type W = crate::W<AsrSpec>;
#[doc = "Field `OVRUDR` reader - Overrun / underrun"]
pub type OvrudrR = crate::BitReader;
#[doc = "Field `OVRUDR` writer - Overrun / underrun"]
pub type OvrudrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTEDET` reader - Mute detection"]
pub type MutedetR = crate::BitReader;
#[doc = "Field `MUTEDET` writer - Mute detection"]
pub type MutedetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WCKCFG` reader - Wrong clock configuration flag. This bit is read only."]
pub type WckcfgR = crate::BitReader;
#[doc = "Field `WCKCFG` writer - Wrong clock configuration flag. This bit is read only."]
pub type WckcfgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FREQ` reader - FIFO request"]
pub type FreqR = crate::BitReader;
#[doc = "Field `FREQ` writer - FIFO request"]
pub type FreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CNRDY` reader - Codec not ready"]
pub type CnrdyR = crate::BitReader;
#[doc = "Field `CNRDY` writer - Codec not ready"]
pub type CnrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AFSDET` reader - Anticipated frame synchronization detection"]
pub type AfsdetR = crate::BitReader;
#[doc = "Field `AFSDET` writer - Anticipated frame synchronization detection"]
pub type AfsdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LFSDET` reader - Late frame synchronization detection"]
pub type LfsdetR = crate::BitReader;
#[doc = "Field `LFSDET` writer - Late frame synchronization detection"]
pub type LfsdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FLVL` reader - FIFO level threshold"]
pub type FlvlR = crate::FieldReader;
#[doc = "Field `FLVL` writer - FIFO level threshold"]
pub type FlvlW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bit 0 - Overrun / underrun"]
    #[inline(always)]
    pub fn ovrudr(&self) -> OvrudrR {
        OvrudrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Mute detection"]
    #[inline(always)]
    pub fn mutedet(&self) -> MutedetR {
        MutedetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Wrong clock configuration flag. This bit is read only."]
    #[inline(always)]
    pub fn wckcfg(&self) -> WckcfgR {
        WckcfgR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - FIFO request"]
    #[inline(always)]
    pub fn freq(&self) -> FreqR {
        FreqR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Codec not ready"]
    #[inline(always)]
    pub fn cnrdy(&self) -> CnrdyR {
        CnrdyR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Anticipated frame synchronization detection"]
    #[inline(always)]
    pub fn afsdet(&self) -> AfsdetR {
        AfsdetR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Late frame synchronization detection"]
    #[inline(always)]
    pub fn lfsdet(&self) -> LfsdetR {
        LfsdetR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bits 16:18 - FIFO level threshold"]
    #[inline(always)]
    pub fn flvl(&self) -> FlvlR {
        FlvlR::new(((self.bits >> 16) & 7) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Overrun / underrun"]
    #[inline(always)]
    #[must_use]
    pub fn ovrudr(&mut self) -> OvrudrW<AsrSpec> {
        OvrudrW::new(self, 0)
    }
    #[doc = "Bit 1 - Mute detection"]
    #[inline(always)]
    #[must_use]
    pub fn mutedet(&mut self) -> MutedetW<AsrSpec> {
        MutedetW::new(self, 1)
    }
    #[doc = "Bit 2 - Wrong clock configuration flag. This bit is read only."]
    #[inline(always)]
    #[must_use]
    pub fn wckcfg(&mut self) -> WckcfgW<AsrSpec> {
        WckcfgW::new(self, 2)
    }
    #[doc = "Bit 3 - FIFO request"]
    #[inline(always)]
    #[must_use]
    pub fn freq(&mut self) -> FreqW<AsrSpec> {
        FreqW::new(self, 3)
    }
    #[doc = "Bit 4 - Codec not ready"]
    #[inline(always)]
    #[must_use]
    pub fn cnrdy(&mut self) -> CnrdyW<AsrSpec> {
        CnrdyW::new(self, 4)
    }
    #[doc = "Bit 5 - Anticipated frame synchronization detection"]
    #[inline(always)]
    #[must_use]
    pub fn afsdet(&mut self) -> AfsdetW<AsrSpec> {
        AfsdetW::new(self, 5)
    }
    #[doc = "Bit 6 - Late frame synchronization detection"]
    #[inline(always)]
    #[must_use]
    pub fn lfsdet(&mut self) -> LfsdetW<AsrSpec> {
        LfsdetW::new(self, 6)
    }
    #[doc = "Bits 16:18 - FIFO level threshold"]
    #[inline(always)]
    #[must_use]
    pub fn flvl(&mut self) -> FlvlW<AsrSpec> {
        FlvlW::new(self, 16)
    }
}
#[doc = "AStatus register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`asr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`asr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AsrSpec;
impl crate::RegisterSpec for AsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`asr::R`](R) reader structure"]
impl crate::Readable for AsrSpec {}
#[doc = "`write(|w| ..)` method takes [`asr::W`](W) writer structure"]
impl crate::Writable for AsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ASR to value 0"]
impl crate::Resettable for AsrSpec {
    const RESET_VALUE: u32 = 0;
}
