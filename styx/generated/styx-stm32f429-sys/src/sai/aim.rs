// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AIM` reader"]
pub type R = crate::R<AimSpec>;
#[doc = "Register `AIM` writer"]
pub type W = crate::W<AimSpec>;
#[doc = "Field `OVRUDRIE` reader - Overrun/underrun interrupt enable"]
pub type OvrudrieR = crate::BitReader;
#[doc = "Field `OVRUDRIE` writer - Overrun/underrun interrupt enable"]
pub type OvrudrieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTEDET` reader - Mute detection interrupt enable"]
pub type MutedetR = crate::BitReader;
#[doc = "Field `MUTEDET` writer - Mute detection interrupt enable"]
pub type MutedetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WCKCFG` reader - Wrong clock configuration interrupt enable"]
pub type WckcfgR = crate::BitReader;
#[doc = "Field `WCKCFG` writer - Wrong clock configuration interrupt enable"]
pub type WckcfgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FREQIE` reader - FIFO request interrupt enable"]
pub type FreqieR = crate::BitReader;
#[doc = "Field `FREQIE` writer - FIFO request interrupt enable"]
pub type FreqieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CNRDYIE` reader - Codec not ready interrupt enable"]
pub type CnrdyieR = crate::BitReader;
#[doc = "Field `CNRDYIE` writer - Codec not ready interrupt enable"]
pub type CnrdyieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AFSDETIE` reader - Anticipated frame synchronization detection interrupt enable"]
pub type AfsdetieR = crate::BitReader;
#[doc = "Field `AFSDETIE` writer - Anticipated frame synchronization detection interrupt enable"]
pub type AfsdetieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LFSDET` reader - Late frame synchronization detection interrupt enable"]
pub type LfsdetR = crate::BitReader;
#[doc = "Field `LFSDET` writer - Late frame synchronization detection interrupt enable"]
pub type LfsdetW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Overrun/underrun interrupt enable"]
    #[inline(always)]
    pub fn ovrudrie(&self) -> OvrudrieR {
        OvrudrieR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Mute detection interrupt enable"]
    #[inline(always)]
    pub fn mutedet(&self) -> MutedetR {
        MutedetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Wrong clock configuration interrupt enable"]
    #[inline(always)]
    pub fn wckcfg(&self) -> WckcfgR {
        WckcfgR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - FIFO request interrupt enable"]
    #[inline(always)]
    pub fn freqie(&self) -> FreqieR {
        FreqieR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Codec not ready interrupt enable"]
    #[inline(always)]
    pub fn cnrdyie(&self) -> CnrdyieR {
        CnrdyieR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Anticipated frame synchronization detection interrupt enable"]
    #[inline(always)]
    pub fn afsdetie(&self) -> AfsdetieR {
        AfsdetieR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Late frame synchronization detection interrupt enable"]
    #[inline(always)]
    pub fn lfsdet(&self) -> LfsdetR {
        LfsdetR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Overrun/underrun interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn ovrudrie(&mut self) -> OvrudrieW<AimSpec> {
        OvrudrieW::new(self, 0)
    }
    #[doc = "Bit 1 - Mute detection interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn mutedet(&mut self) -> MutedetW<AimSpec> {
        MutedetW::new(self, 1)
    }
    #[doc = "Bit 2 - Wrong clock configuration interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn wckcfg(&mut self) -> WckcfgW<AimSpec> {
        WckcfgW::new(self, 2)
    }
    #[doc = "Bit 3 - FIFO request interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn freqie(&mut self) -> FreqieW<AimSpec> {
        FreqieW::new(self, 3)
    }
    #[doc = "Bit 4 - Codec not ready interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn cnrdyie(&mut self) -> CnrdyieW<AimSpec> {
        CnrdyieW::new(self, 4)
    }
    #[doc = "Bit 5 - Anticipated frame synchronization detection interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn afsdetie(&mut self) -> AfsdetieW<AimSpec> {
        AfsdetieW::new(self, 5)
    }
    #[doc = "Bit 6 - Late frame synchronization detection interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn lfsdet(&mut self) -> LfsdetW<AimSpec> {
        LfsdetW::new(self, 6)
    }
}
#[doc = "AInterrupt mask register2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`aim::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`aim::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AimSpec;
impl crate::RegisterSpec for AimSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`aim::R`](R) reader structure"]
impl crate::Readable for AimSpec {}
#[doc = "`write(|w| ..)` method takes [`aim::W`](W) writer structure"]
impl crate::Writable for AimSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AIM to value 0"]
impl crate::Resettable for AimSpec {
    const RESET_VALUE: u32 = 0;
}
