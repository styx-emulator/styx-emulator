// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DTCMCR` reader"]
pub type R = crate::R<DtcmcrSpec>;
#[doc = "Register `DTCMCR` writer"]
pub type W = crate::W<DtcmcrSpec>;
#[doc = "Field `EN` reader - EN"]
pub type EnR = crate::BitReader;
#[doc = "Field `EN` writer - EN"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RMW` reader - RMW"]
pub type RmwR = crate::BitReader;
#[doc = "Field `RMW` writer - RMW"]
pub type RmwW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RETEN` reader - RETEN"]
pub type RetenR = crate::BitReader;
#[doc = "Field `RETEN` writer - RETEN"]
pub type RetenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SZ` reader - SZ"]
pub type SzR = crate::FieldReader;
#[doc = "Field `SZ` writer - SZ"]
pub type SzW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bit 0 - EN"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - RMW"]
    #[inline(always)]
    pub fn rmw(&self) -> RmwR {
        RmwR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - RETEN"]
    #[inline(always)]
    pub fn reten(&self) -> RetenR {
        RetenR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:6 - SZ"]
    #[inline(always)]
    pub fn sz(&self) -> SzR {
        SzR::new(((self.bits >> 3) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - EN"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<DtcmcrSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - RMW"]
    #[inline(always)]
    #[must_use]
    pub fn rmw(&mut self) -> RmwW<DtcmcrSpec> {
        RmwW::new(self, 1)
    }
    #[doc = "Bit 2 - RETEN"]
    #[inline(always)]
    #[must_use]
    pub fn reten(&mut self) -> RetenW<DtcmcrSpec> {
        RetenW::new(self, 2)
    }
    #[doc = "Bits 3:6 - SZ"]
    #[inline(always)]
    #[must_use]
    pub fn sz(&mut self) -> SzW<DtcmcrSpec> {
        SzW::new(self, 3)
    }
}
#[doc = "Instruction and Data Tightly-Coupled Memory Control Registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtcmcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dtcmcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DtcmcrSpec;
impl crate::RegisterSpec for DtcmcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`dtcmcr::R`](R) reader structure"]
impl crate::Readable for DtcmcrSpec {}
#[doc = "`write(|w| ..)` method takes [`dtcmcr::W`](W) writer structure"]
impl crate::Writable for DtcmcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DTCMCR to value 0"]
impl crate::Resettable for DtcmcrSpec {
    const RESET_VALUE: u32 = 0;
}
