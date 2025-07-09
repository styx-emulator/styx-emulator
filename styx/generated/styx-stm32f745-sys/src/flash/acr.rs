// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ACR` reader"]
pub type R = crate::R<AcrSpec>;
#[doc = "Register `ACR` writer"]
pub type W = crate::W<AcrSpec>;
#[doc = "Field `LATENCY` reader - Latency"]
pub type LatencyR = crate::FieldReader;
#[doc = "Field `LATENCY` writer - Latency"]
pub type LatencyW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `PRFTEN` reader - Prefetch enable"]
pub type PrftenR = crate::BitReader;
#[doc = "Field `PRFTEN` writer - Prefetch enable"]
pub type PrftenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARTEN` reader - ART Accelerator Enable"]
pub type ArtenR = crate::BitReader;
#[doc = "Field `ARTEN` writer - ART Accelerator Enable"]
pub type ArtenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARTRST` reader - ART Accelerator reset"]
pub type ArtrstR = crate::BitReader;
#[doc = "Field `ARTRST` writer - ART Accelerator reset"]
pub type ArtrstW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:3 - Latency"]
    #[inline(always)]
    pub fn latency(&self) -> LatencyR {
        LatencyR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bit 8 - Prefetch enable"]
    #[inline(always)]
    pub fn prften(&self) -> PrftenR {
        PrftenR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - ART Accelerator Enable"]
    #[inline(always)]
    pub fn arten(&self) -> ArtenR {
        ArtenR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 11 - ART Accelerator reset"]
    #[inline(always)]
    pub fn artrst(&self) -> ArtrstR {
        ArtrstR::new(((self.bits >> 11) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:3 - Latency"]
    #[inline(always)]
    #[must_use]
    pub fn latency(&mut self) -> LatencyW<AcrSpec> {
        LatencyW::new(self, 0)
    }
    #[doc = "Bit 8 - Prefetch enable"]
    #[inline(always)]
    #[must_use]
    pub fn prften(&mut self) -> PrftenW<AcrSpec> {
        PrftenW::new(self, 8)
    }
    #[doc = "Bit 9 - ART Accelerator Enable"]
    #[inline(always)]
    #[must_use]
    pub fn arten(&mut self) -> ArtenW<AcrSpec> {
        ArtenW::new(self, 9)
    }
    #[doc = "Bit 11 - ART Accelerator reset"]
    #[inline(always)]
    #[must_use]
    pub fn artrst(&mut self) -> ArtrstW<AcrSpec> {
        ArtrstW::new(self, 11)
    }
}
#[doc = "Flash access control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`acr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`acr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AcrSpec;
impl crate::RegisterSpec for AcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`acr::R`](R) reader structure"]
impl crate::Readable for AcrSpec {}
#[doc = "`write(|w| ..)` method takes [`acr::W`](W) writer structure"]
impl crate::Writable for AcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ACR to value 0"]
impl crate::Resettable for AcrSpec {
    const RESET_VALUE: u32 = 0;
}
