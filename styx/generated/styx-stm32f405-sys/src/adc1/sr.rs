// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `AWD` reader - Analog watchdog flag"]
pub type AwdR = crate::BitReader;
#[doc = "Field `AWD` writer - Analog watchdog flag"]
pub type AwdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOC` reader - Regular channel end of conversion"]
pub type EocR = crate::BitReader;
#[doc = "Field `EOC` writer - Regular channel end of conversion"]
pub type EocW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JEOC` reader - Injected channel end of conversion"]
pub type JeocR = crate::BitReader;
#[doc = "Field `JEOC` writer - Injected channel end of conversion"]
pub type JeocW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JSTRT` reader - Injected channel start flag"]
pub type JstrtR = crate::BitReader;
#[doc = "Field `JSTRT` writer - Injected channel start flag"]
pub type JstrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STRT` reader - Regular channel start flag"]
pub type StrtR = crate::BitReader;
#[doc = "Field `STRT` writer - Regular channel start flag"]
pub type StrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR` reader - Overrun"]
pub type OvrR = crate::BitReader;
#[doc = "Field `OVR` writer - Overrun"]
pub type OvrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Analog watchdog flag"]
    #[inline(always)]
    pub fn awd(&self) -> AwdR {
        AwdR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Regular channel end of conversion"]
    #[inline(always)]
    pub fn eoc(&self) -> EocR {
        EocR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Injected channel end of conversion"]
    #[inline(always)]
    pub fn jeoc(&self) -> JeocR {
        JeocR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Injected channel start flag"]
    #[inline(always)]
    pub fn jstrt(&self) -> JstrtR {
        JstrtR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Regular channel start flag"]
    #[inline(always)]
    pub fn strt(&self) -> StrtR {
        StrtR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Overrun"]
    #[inline(always)]
    pub fn ovr(&self) -> OvrR {
        OvrR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Analog watchdog flag"]
    #[inline(always)]
    #[must_use]
    pub fn awd(&mut self) -> AwdW<SrSpec> {
        AwdW::new(self, 0)
    }
    #[doc = "Bit 1 - Regular channel end of conversion"]
    #[inline(always)]
    #[must_use]
    pub fn eoc(&mut self) -> EocW<SrSpec> {
        EocW::new(self, 1)
    }
    #[doc = "Bit 2 - Injected channel end of conversion"]
    #[inline(always)]
    #[must_use]
    pub fn jeoc(&mut self) -> JeocW<SrSpec> {
        JeocW::new(self, 2)
    }
    #[doc = "Bit 3 - Injected channel start flag"]
    #[inline(always)]
    #[must_use]
    pub fn jstrt(&mut self) -> JstrtW<SrSpec> {
        JstrtW::new(self, 3)
    }
    #[doc = "Bit 4 - Regular channel start flag"]
    #[inline(always)]
    #[must_use]
    pub fn strt(&mut self) -> StrtW<SrSpec> {
        StrtW::new(self, 4)
    }
    #[doc = "Bit 5 - Overrun"]
    #[inline(always)]
    #[must_use]
    pub fn ovr(&mut self) -> OvrW<SrSpec> {
        OvrW::new(self, 5)
    }
}
#[doc = "status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`write(|w| ..)` method takes [`sr::W`](W) writer structure"]
impl crate::Writable for SrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SR to value 0"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0;
}
