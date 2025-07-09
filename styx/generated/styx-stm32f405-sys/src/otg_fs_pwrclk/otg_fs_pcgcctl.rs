// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_PCGCCTL` reader"]
pub type R = crate::R<OtgFsPcgcctlSpec>;
#[doc = "Register `OTG_FS_PCGCCTL` writer"]
pub type W = crate::W<OtgFsPcgcctlSpec>;
#[doc = "Field `STPPCLK` reader - Stop PHY clock"]
pub type StppclkR = crate::BitReader;
#[doc = "Field `STPPCLK` writer - Stop PHY clock"]
pub type StppclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GATEHCLK` reader - Gate HCLK"]
pub type GatehclkR = crate::BitReader;
#[doc = "Field `GATEHCLK` writer - Gate HCLK"]
pub type GatehclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PHYSUSP` reader - PHY Suspended"]
pub type PhysuspR = crate::BitReader;
#[doc = "Field `PHYSUSP` writer - PHY Suspended"]
pub type PhysuspW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Stop PHY clock"]
    #[inline(always)]
    pub fn stppclk(&self) -> StppclkR {
        StppclkR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Gate HCLK"]
    #[inline(always)]
    pub fn gatehclk(&self) -> GatehclkR {
        GatehclkR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 4 - PHY Suspended"]
    #[inline(always)]
    pub fn physusp(&self) -> PhysuspR {
        PhysuspR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Stop PHY clock"]
    #[inline(always)]
    #[must_use]
    pub fn stppclk(&mut self) -> StppclkW<OtgFsPcgcctlSpec> {
        StppclkW::new(self, 0)
    }
    #[doc = "Bit 1 - Gate HCLK"]
    #[inline(always)]
    #[must_use]
    pub fn gatehclk(&mut self) -> GatehclkW<OtgFsPcgcctlSpec> {
        GatehclkW::new(self, 1)
    }
    #[doc = "Bit 4 - PHY Suspended"]
    #[inline(always)]
    #[must_use]
    pub fn physusp(&mut self) -> PhysuspW<OtgFsPcgcctlSpec> {
        PhysuspW::new(self, 4)
    }
}
#[doc = "OTG_FS power and clock gating control register (OTG_FS_PCGCCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_pcgcctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_pcgcctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsPcgcctlSpec;
impl crate::RegisterSpec for OtgFsPcgcctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`otg_fs_pcgcctl::R`](R) reader structure"]
impl crate::Readable for OtgFsPcgcctlSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_pcgcctl::W`](W) writer structure"]
impl crate::Writable for OtgFsPcgcctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_PCGCCTL to value 0"]
impl crate::Resettable for OtgFsPcgcctlSpec {
    const RESET_VALUE: u32 = 0;
}
