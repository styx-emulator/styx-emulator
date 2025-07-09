// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BCLRFR` reader"]
pub type R = crate::R<BclrfrSpec>;
#[doc = "Register `BCLRFR` writer"]
pub type W = crate::W<BclrfrSpec>;
#[doc = "Field `OVRUDR` reader - Clear overrun / underrun"]
pub type OvrudrR = crate::BitReader;
#[doc = "Field `OVRUDR` writer - Clear overrun / underrun"]
pub type OvrudrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTEDET` reader - Mute detection flag"]
pub type MutedetR = crate::BitReader;
#[doc = "Field `MUTEDET` writer - Mute detection flag"]
pub type MutedetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WCKCFG` reader - Clear wrong clock configuration flag"]
pub type WckcfgR = crate::BitReader;
#[doc = "Field `WCKCFG` writer - Clear wrong clock configuration flag"]
pub type WckcfgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CNRDY` reader - Clear codec not ready flag"]
pub type CnrdyR = crate::BitReader;
#[doc = "Field `CNRDY` writer - Clear codec not ready flag"]
pub type CnrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAFSDET` reader - Clear anticipated frame synchronization detection flag"]
pub type CafsdetR = crate::BitReader;
#[doc = "Field `CAFSDET` writer - Clear anticipated frame synchronization detection flag"]
pub type CafsdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LFSDET` reader - Clear late frame synchronization detection flag"]
pub type LfsdetR = crate::BitReader;
#[doc = "Field `LFSDET` writer - Clear late frame synchronization detection flag"]
pub type LfsdetW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clear overrun / underrun"]
    #[inline(always)]
    pub fn ovrudr(&self) -> OvrudrR {
        OvrudrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Mute detection flag"]
    #[inline(always)]
    pub fn mutedet(&self) -> MutedetR {
        MutedetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Clear wrong clock configuration flag"]
    #[inline(always)]
    pub fn wckcfg(&self) -> WckcfgR {
        WckcfgR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 4 - Clear codec not ready flag"]
    #[inline(always)]
    pub fn cnrdy(&self) -> CnrdyR {
        CnrdyR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Clear anticipated frame synchronization detection flag"]
    #[inline(always)]
    pub fn cafsdet(&self) -> CafsdetR {
        CafsdetR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Clear late frame synchronization detection flag"]
    #[inline(always)]
    pub fn lfsdet(&self) -> LfsdetR {
        LfsdetR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clear overrun / underrun"]
    #[inline(always)]
    #[must_use]
    pub fn ovrudr(&mut self) -> OvrudrW<BclrfrSpec> {
        OvrudrW::new(self, 0)
    }
    #[doc = "Bit 1 - Mute detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn mutedet(&mut self) -> MutedetW<BclrfrSpec> {
        MutedetW::new(self, 1)
    }
    #[doc = "Bit 2 - Clear wrong clock configuration flag"]
    #[inline(always)]
    #[must_use]
    pub fn wckcfg(&mut self) -> WckcfgW<BclrfrSpec> {
        WckcfgW::new(self, 2)
    }
    #[doc = "Bit 4 - Clear codec not ready flag"]
    #[inline(always)]
    #[must_use]
    pub fn cnrdy(&mut self) -> CnrdyW<BclrfrSpec> {
        CnrdyW::new(self, 4)
    }
    #[doc = "Bit 5 - Clear anticipated frame synchronization detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn cafsdet(&mut self) -> CafsdetW<BclrfrSpec> {
        CafsdetW::new(self, 5)
    }
    #[doc = "Bit 6 - Clear late frame synchronization detection flag"]
    #[inline(always)]
    #[must_use]
    pub fn lfsdet(&mut self) -> LfsdetW<BclrfrSpec> {
        LfsdetW::new(self, 6)
    }
}
#[doc = "BClear flag register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bclrfr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BclrfrSpec;
impl crate::RegisterSpec for BclrfrSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`write(|w| ..)` method takes [`bclrfr::W`](W) writer structure"]
impl crate::Writable for BclrfrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BCLRFR to value 0"]
impl crate::Resettable for BclrfrSpec {
    const RESET_VALUE: u32 = 0;
}
