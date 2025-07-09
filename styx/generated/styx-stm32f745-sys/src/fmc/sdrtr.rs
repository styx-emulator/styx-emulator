// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SDRTR` reader"]
pub type R = crate::R<SdrtrSpec>;
#[doc = "Register `SDRTR` writer"]
pub type W = crate::W<SdrtrSpec>;
#[doc = "Field `CRE` reader - Clear Refresh error flag"]
pub type CreR = crate::BitReader;
#[doc = "Field `CRE` writer - Clear Refresh error flag"]
pub type CreW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `COUNT` reader - Refresh Timer Count"]
pub type CountR = crate::FieldReader<u16>;
#[doc = "Field `COUNT` writer - Refresh Timer Count"]
pub type CountW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
#[doc = "Field `REIE` reader - RES Interrupt Enable"]
pub type ReieR = crate::BitReader;
#[doc = "Field `REIE` writer - RES Interrupt Enable"]
pub type ReieW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clear Refresh error flag"]
    #[inline(always)]
    pub fn cre(&self) -> CreR {
        CreR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:13 - Refresh Timer Count"]
    #[inline(always)]
    pub fn count(&self) -> CountR {
        CountR::new(((self.bits >> 1) & 0x1fff) as u16)
    }
    #[doc = "Bit 14 - RES Interrupt Enable"]
    #[inline(always)]
    pub fn reie(&self) -> ReieR {
        ReieR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clear Refresh error flag"]
    #[inline(always)]
    #[must_use]
    pub fn cre(&mut self) -> CreW<SdrtrSpec> {
        CreW::new(self, 0)
    }
    #[doc = "Bits 1:13 - Refresh Timer Count"]
    #[inline(always)]
    #[must_use]
    pub fn count(&mut self) -> CountW<SdrtrSpec> {
        CountW::new(self, 1)
    }
    #[doc = "Bit 14 - RES Interrupt Enable"]
    #[inline(always)]
    #[must_use]
    pub fn reie(&mut self) -> ReieW<SdrtrSpec> {
        ReieW::new(self, 14)
    }
}
#[doc = "SDRAM Refresh Timer register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrtr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrtr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SdrtrSpec;
impl crate::RegisterSpec for SdrtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 340u64;
}
#[doc = "`read()` method returns [`sdrtr::R`](R) reader structure"]
impl crate::Readable for SdrtrSpec {}
#[doc = "`write(|w| ..)` method takes [`sdrtr::W`](W) writer structure"]
impl crate::Writable for SdrtrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SDRTR to value 0"]
impl crate::Resettable for SdrtrSpec {
    const RESET_VALUE: u32 = 0;
}
